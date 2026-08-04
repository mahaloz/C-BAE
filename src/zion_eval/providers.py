"""Non-interactive Codex and Claude Code provider adapters.

The adapters deliberately have a small surface area: a prompt, an explicit model,
an output schema, and an artifact directory.  They never invoke a shell and they
never put credentials on the command line.  Provider stdout/stderr is retained
after redacting credential-shaped environment values.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .artifacts import atomic_write_json, atomic_write_text, secure_directory


JsonObject = dict[str, Any]


# Codex 0.146 enables browser/app capabilities by default.  The evaluator needs
# shell access for DecLib, but browser, computer-use, connected-app, and remote
# plugin surfaces are outside the binary-only evidence boundary.
_CODEX_DISABLED_ONLINE_FEATURES = (
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "image_generation",
    "in_app_browser",
    "plugins",
    "remote_plugin",
    "skill_mcp_dependency_install",
    "skill_search",
    "standalone_web_search",
    "web_search_cached",
    "web_search_request",
)


class ProviderError(RuntimeError):
    """Base class for provider failures safe to include in run metadata."""


class ProviderInvocationError(ProviderError):
    """The provider executable failed or returned an unsuccessful result."""


class ProviderTimeoutError(ProviderError):
    """The provider exceeded the configured wall-clock timeout."""


class ProviderOutputError(ProviderError):
    """The provider did not return one strict, schema-valid JSON document."""


class DuplicateJsonKeyError(ValueError):
    """Raised before JSON object pairs can silently overwrite one another."""


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    stdin: str | None
    cwd: Path
    env: Mapping[str, str]
    timeout_seconds: float
    terminate_grace_seconds: float = 5.0


@dataclass(frozen=True)
class CompletedCommand:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandTimedOut(TimeoutError):
    def __init__(self, completed: CompletedCommand):
        super().__init__("command timed out")
        self.completed = completed


class CommandRunner(Protocol):
    def run(self, spec: CommandSpec) -> CompletedCommand: ...


class SubprocessRunner:
    """Run a command in its own process group and reap it on timeout."""

    def run(self, spec: CommandSpec) -> CompletedCommand:
        if not spec.argv:
            raise ValueError("argv must not be empty")
        if spec.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        started = time.monotonic()
        popen_kwargs: dict[str, Any] = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":  # pragma: no cover - exercised on Windows only
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        process = subprocess.Popen(
            list(spec.argv),
            stdin=subprocess.PIPE if spec.stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=spec.cwd,
            env=dict(spec.env),
            **popen_kwargs,
        )
        try:
            stdout, stderr = process.communicate(
                input=spec.stdin,
                timeout=spec.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            self._terminate_group(process)
            try:
                stdout, stderr = process.communicate(
                    timeout=max(0.1, spec.terminate_grace_seconds)
                )
            except subprocess.TimeoutExpired:
                self._kill_group(process)
                stdout, stderr = process.communicate()
            completed = CompletedCommand(
                returncode=process.returncode if process.returncode is not None else -1,
                stdout=stdout or "",
                stderr=stderr or "",
                duration_seconds=time.monotonic() - started,
            )
            raise CommandTimedOut(completed)

        return CompletedCommand(
            returncode=process.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    def _terminate_group(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:  # pragma: no cover - exercised on Windows only
                process.terminate()
        except ProcessLookupError:
            pass

    @staticmethod
    def _kill_group(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover - exercised on Windows only
                process.kill()
        except ProcessLookupError:
            pass


@dataclass(frozen=True)
class ProviderRequest:
    prompt: str
    model: str
    output_schema: Mapping[str, Any]
    cwd: Path
    artifact_dir: Path
    timeout_seconds: float = 21_600.0
    environment: Mapping[str, str] | None = None
    max_budget_usd: float | None = None
    reasoning_effort: str | None = None

    def __post_init__(self) -> None:
        if not self.prompt.strip():
            raise ValueError("provider prompt must not be empty")
        if not self.model.strip():
            raise ValueError("provider model must be explicit")
        if self.timeout_seconds <= 0:
            raise ValueError("provider timeout must be positive")
        if self.max_budget_usd is not None and self.max_budget_usd <= 0:
            raise ValueError("max_budget_usd must be positive")
        if self.reasoning_effort not in {None, "low", "medium", "high", "xhigh"}:
            raise ValueError("reasoning_effort must be low, medium, high, or xhigh")


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    model: str
    output: JsonObject
    command: tuple[str, ...]
    duration_seconds: float
    events_path: Path
    stderr_path: Path
    final_output_path: Path
    schema_path: Path


class ProviderAdapter(Protocol):
    name: str

    def run(self, request: ProviderRequest) -> ProviderResult: ...


@dataclass
class _BaseProvider:
    executable: str
    runner: CommandRunner = field(default_factory=SubprocessRunner)

    def _prepare(self, request: ProviderRequest) -> tuple[Path, Path, Path, dict[str, str]]:
        artifact_dir = secure_directory(request.artifact_dir)
        secure_directory(request.cwd)
        schema_path = artifact_dir / "output.schema.json"
        events_path = artifact_dir / "events.jsonl"
        stderr_path = artifact_dir / "stderr.log"
        atomic_write_json(schema_path, dict(request.output_schema))
        # A retry must never be allowed to consume a stale final answer.
        (artifact_dir / "final.json").unlink(missing_ok=True)
        env = dict(os.environ if request.environment is None else request.environment)
        return schema_path, events_path, stderr_path, env

    @staticmethod
    def _persist_command_output(
        completed: CompletedCommand,
        events_path: Path,
        stderr_path: Path,
        env: Mapping[str, str],
    ) -> None:
        secrets = _credential_values(env)
        atomic_write_text(events_path, _redact(completed.stdout, secrets))
        atomic_write_text(stderr_path, _redact(completed.stderr, secrets))

    def _invoke(
        self,
        spec: CommandSpec,
        events_path: Path,
        stderr_path: Path,
    ) -> CompletedCommand:
        try:
            completed = self.runner.run(spec)
        except CommandTimedOut as error:
            self._persist_command_output(
                error.completed, events_path, stderr_path, spec.env
            )
            raise ProviderTimeoutError(
                f"{self.executable} exceeded the {spec.timeout_seconds:g}s timeout"
            ) from error
        self._persist_command_output(completed, events_path, stderr_path, spec.env)
        if completed.returncode != 0:
            safe_tail = _redact(completed.stderr[-1000:], _credential_values(spec.env)).strip()
            detail = f": {safe_tail}" if safe_tail else ""
            raise ProviderInvocationError(
                f"{self.executable} exited with status {completed.returncode}{detail}"
            )
        return completed


@dataclass
class CodexProvider(_BaseProvider):
    name: str = field(default="codex", init=False)

    def run(self, request: ProviderRequest) -> ProviderResult:
        schema_path, events_path, stderr_path, env = self._prepare(request)
        final_path = request.artifact_dir / "final.json"
        command_parts = [
            self.executable,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
        ]
        for feature in _CODEX_DISABLED_ONLINE_FEATURES:
            command_parts.extend(("--disable", feature))
        command_parts.extend((
            "--model",
            request.model,
        ))
        if request.reasoning_effort is not None:
            command_parts.extend(
                ("--config", f'model_reasoning_effort="{request.reasoning_effort}"')
            )
        command_parts.extend((
            "--cd",
            str(request.cwd),
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(final_path),
            "--json",
            "-",
        ))
        command = tuple(command_parts)
        completed = self._invoke(
            CommandSpec(
                argv=command,
                stdin=request.prompt,
                cwd=request.cwd,
                env=env,
                timeout_seconds=request.timeout_seconds,
            ),
            events_path,
            stderr_path,
        )
        if not final_path.is_file():
            raise ProviderOutputError("Codex did not create its final JSON document")
        output = _load_strict_json_file(final_path)
        _validate_output(output, request.output_schema)
        try:
            final_path.chmod(0o600)
        except OSError:
            pass
        return ProviderResult(
            provider=self.name,
            model=request.model,
            output=output,
            command=command,
            duration_seconds=completed.duration_seconds,
            events_path=events_path,
            stderr_path=stderr_path,
            final_output_path=final_path,
            schema_path=schema_path,
        )


@dataclass
class ClaudeProvider(_BaseProvider):
    name: str = field(default="claude", init=False)

    def run(self, request: ProviderRequest) -> ProviderResult:
        schema_path, events_path, stderr_path, env = self._prepare(request)
        final_path = request.artifact_dir / "final.json"
        compact_schema = json.dumps(
            request.output_schema,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        command_parts = [
            self.executable,
            "--print",
            "--bare",
            "--no-session-persistence",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--dangerously-skip-permissions",
            "--tools",
            "Bash",
            "--model",
            request.model,
            "--output-format",
            "stream-json",
            "--verbose",
            "--json-schema",
            compact_schema,
        ]
        if request.max_budget_usd is not None:
            command_parts.extend(["--max-budget-usd", f"{request.max_budget_usd:g}"])
        command = tuple(command_parts)
        completed = self._invoke(
            CommandSpec(
                argv=command,
                stdin=request.prompt,
                cwd=request.cwd,
                env=env,
                timeout_seconds=request.timeout_seconds,
            ),
            events_path,
            stderr_path,
        )
        output = _structured_claude_result(completed.stdout)
        _validate_output(output, request.output_schema)
        atomic_write_json(final_path, output)
        return ProviderResult(
            provider=self.name,
            model=request.model,
            output=output,
            command=command,
            duration_seconds=completed.duration_seconds,
            events_path=events_path,
            stderr_path=stderr_path,
            final_output_path=final_path,
            schema_path=schema_path,
        )


def make_provider(
    name: str,
    *,
    executable: str | None = None,
    runner: CommandRunner | None = None,
) -> ProviderAdapter:
    """Construct a supported provider without choosing an implicit model."""

    normalized = name.strip().lower()
    actual_runner = runner or SubprocessRunner()
    if normalized == "codex":
        return CodexProvider(executable or "codex", runner=actual_runner)
    if normalized in {"claude", "claude-code", "claudecode"}:
        return ClaudeProvider(executable or "claude", runner=actual_runner)
    raise ValueError(f"unsupported provider {name!r}; expected 'codex' or 'claude'")


def decode_strict_json(text: str) -> Any:
    """Decode exactly one JSON value while rejecting duplicate object keys."""

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJsonKeyError(f"duplicate JSON object key: {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise ProviderOutputError(f"invalid strict JSON output: {error}") from error


def _load_strict_json_file(path: Path, max_bytes: int = 32 * 1024 * 1024) -> JsonObject:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ProviderOutputError(
                f"provider final output exceeds {max_bytes} bytes"
            )
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ProviderOutputError(f"could not read provider final output: {error}") from error
    value = decode_strict_json(text)
    if not isinstance(value, dict):
        raise ProviderOutputError("provider final output must be a JSON object")
    return value


def _structured_claude_result(stdout: str) -> JsonObject:
    result_events: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.strip():
            continue
        event = decode_strict_json(line)
        if not isinstance(event, dict):
            raise ProviderOutputError(
                f"Claude event on line {line_number} is not a JSON object"
            )
        if event.get("type") == "result":
            result_events.append(event)
    if len(result_events) != 1:
        raise ProviderOutputError(
            f"Claude emitted {len(result_events)} result events; expected exactly one"
        )
    result = result_events[0]
    if result.get("is_error") is True or result.get("subtype") not in {None, "success"}:
        raise ProviderInvocationError("Claude reported an unsuccessful result event")
    output = result.get("structured_output")
    if not isinstance(output, dict):
        raise ProviderOutputError(
            "Claude result did not contain a structured_output JSON object"
        )
    return dict(output)


def _validate_output(output: JsonObject, schema: Mapping[str, Any]) -> None:
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(output)
    except SchemaError as error:
        raise ValueError(f"invalid requested output schema: {error.message}") from error
    except ValidationError as error:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ProviderOutputError(
            f"provider JSON failed schema validation at {location}: {error.message}"
        ) from error


def _credential_values(env: Mapping[str, str]) -> tuple[str, ...]:
    markers = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    values = {
        value
        for key, value in env.items()
        if value and len(value) >= 4 and any(marker in key.upper() for marker in markers)
    }
    return tuple(sorted(values, key=len, reverse=True))


def _redact(text: str, credential_values: Sequence[str]) -> str:
    redacted = text
    for value in credential_values:
        variants = {
            value,
            json.dumps(value, ensure_ascii=False)[1:-1],
            urllib.parse.quote(value, safe=""),
        }
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                redacted = redacted.replace(variant, "[REDACTED]")
    return redacted

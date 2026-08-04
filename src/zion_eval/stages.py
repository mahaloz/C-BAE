"""Reverser/grader stage contracts and DecLib lifecycle management."""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .addresses import MAX_ADDRESS, Prediction, canonical_rva, parse_address
from .artifacts import (
    atomic_write_json,
    atomic_write_text,
    canonical_json_sha256,
    secure_directory,
    sha256_file,
)
from .prompts import (
    build_grader_prompt,
    build_reverse_prompt,
    grading_packet_schema,
    prediction_schema,
    verdict_schema,
)
from .providers import (
    CommandRunner,
    CommandSpec,
    CommandTimedOut,
    ProviderAdapter,
    ProviderRequest,
    ProviderResult,
    SubprocessRunner,
    decode_strict_json,
    make_provider,
)


SUPPORTED_BACKENDS = frozenset({"ida", "ghidra", "angr"})


class StageError(RuntimeError):
    """Base class for stage-local infrastructure or contract failures."""


class DecompilerError(StageError):
    """DecLib could not preload, enumerate, or clean up the target."""


class StageContractError(StageError):
    """An otherwise structured input violates an evaluation-stage contract."""


@dataclass(frozen=True)
class FunctionInfo:
    address: str
    size: int
    discovered_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "size": self.size,
            "discovered_name": self.discovered_name,
        }


@dataclass(frozen=True)
class _AddressTranslation:
    """A bijection between DecLib-lifted addresses and manifest RVAs."""

    raw_to_rva: Mapping[str, str]
    rva_to_raw: Mapping[str, str]
    snapshot_functions: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class StageResult:
    stage: str
    status: str
    provider: str
    model: str
    backend: str
    started_at: str
    finished_at: str
    duration_seconds: float
    requested_count: int
    produced_count: int
    artifacts: Mapping[str, str]
    provider_command: tuple[str, ...] = ()
    error_type: str | None = None
    error_message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "stage": self.stage,
            "status": self.status,
            "provider": self.provider,
            "model": self.model,
            "backend": self.backend,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "requested_count": self.requested_count,
            "produced_count": self.produced_count,
            "artifacts": dict(self.artifacts),
            "provider_command": list(self.provider_command),
        }
        if self.error_type is not None:
            value["error"] = {
                "type": self.error_type,
                "message": self.error_message or "",
            }
        return value


@dataclass(frozen=True)
class ReverseStageConfig:
    binary_path: Path
    output_dir: Path
    provider_name: str
    model: str
    state_dir: Path | None = None
    backend: str = "ida"
    count: int = 100
    image_base: int = 0
    timeout_seconds: float = 21_600.0
    decompiler_timeout_seconds: float = 3_600.0
    provider_executable: str | None = None
    decompiler_executable: str = "decompiler"
    environment: Mapping[str, str] | None = None
    max_budget_usd: float | None = None
    reasoning_effort: str | None = None


@dataclass(frozen=True)
class GradeStageConfig:
    binary_path: Path
    packet_path: Path
    output_dir: Path
    provider_name: str
    model: str
    state_dir: Path | None = None
    backend: str = "ida"
    image_base: int = 0
    timeout_seconds: float = 21_600.0
    decompiler_timeout_seconds: float = 3_600.0
    provider_executable: str | None = None
    decompiler_executable: str = "decompiler"
    environment: Mapping[str, str] | None = None
    max_budget_usd: float | None = None
    reasoning_effort: str | None = None


@dataclass(frozen=True)
class AnalysisStageConfig:
    """Provider-free construction of a pristine persistent project cache."""

    binary_path: Path
    output_dir: Path
    state_dir: Path | None = None
    backend: str = "ida"
    decompiler_timeout_seconds: float = 3_600.0
    decompiler_executable: str = "decompiler"
    environment: Mapping[str, str] | None = None
    provider_name: str = field(default="none", init=False)
    model: str = field(default="none", init=False)


@dataclass
class DeclibController:
    """Thin, injectable owner of one headless DecLib CLI server."""

    executable: str = "decompiler"
    runner: CommandRunner = field(default_factory=SubprocessRunner)

    def open(
        self,
        *,
        binary_path: Path,
        backend: str,
        project_dir: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
    ) -> "DeclibSession":
        server_id = f"zion-{uuid.uuid4().hex[:16]}"
        secure_directory(project_dir)
        command = (
            self.executable,
            "load",
            str(binary_path),
            "--backend",
            backend,
            "--id",
            server_id,
            "--timeout",
            str(timeout_seconds),
            "--project-dir",
            str(project_dir),
            "--json",
        )
        try:
            completed = self.runner.run(
                CommandSpec(
                    argv=command,
                    stdin=None,
                    cwd=project_dir.parent,
                    env=environment,
                    timeout_seconds=timeout_seconds,
                )
            )
        except CommandTimedOut as error:
            self._best_effort_stop(
                server_id, project_dir.parent, environment, min(timeout_seconds, 30.0)
            )
            raise DecompilerError(
                f"DecLib load exceeded the {timeout_seconds:g}s timeout"
            ) from error
        if completed.returncode != 0:
            self._best_effort_stop(
                server_id, project_dir.parent, environment, min(timeout_seconds, 30.0)
            )
            raise DecompilerError(
                f"DecLib load exited with status {completed.returncode}: "
                f"{completed.stderr[-1000:].strip()}"
            )
        try:
            response = decode_strict_json(completed.stdout)
            if not isinstance(response, dict):
                raise TypeError("response is not an object")
            if response.get("status") not in {"started", "already_loaded"}:
                raise ValueError(f"unexpected status {response.get('status')!r}")
            if response.get("id") != server_id:
                raise ValueError("DecLib returned a different server id")
        except Exception as error:
            self._best_effort_stop(
                server_id, project_dir.parent, environment, min(timeout_seconds, 30.0)
            )
            raise DecompilerError(f"invalid DecLib load response: {error}") from error
        try:
            binary_base_addr = self._read_binary_base_addr(
                server_id=server_id,
                cwd=project_dir.parent,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            self._best_effort_stop(
                server_id, project_dir.parent, environment, min(timeout_seconds, 30.0)
            )
            raise
        return DeclibSession(
            controller=self,
            server_id=server_id,
            binary_path=binary_path,
            backend=backend,
            cwd=project_dir.parent,
            environment=dict(environment),
            timeout_seconds=timeout_seconds,
            binary_base_addr=binary_base_addr,
        )

    def _read_binary_base_addr(
        self,
        *,
        server_id: str,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
    ) -> int:
        command = (
            self.executable,
            "exec",
            "print(hex(deci.binary_base_addr))",
            "--id",
            server_id,
            "--json",
        )
        try:
            completed = self.runner.run(
                CommandSpec(
                    argv=command,
                    stdin=None,
                    cwd=cwd,
                    env=environment,
                    timeout_seconds=timeout_seconds,
                )
            )
        except CommandTimedOut as error:
            raise DecompilerError(
                f"DecLib binary-base query exceeded the {timeout_seconds:g}s timeout"
            ) from error
        if completed.returncode != 0:
            raise DecompilerError(
                f"DecLib binary-base query exited with status {completed.returncode}: "
                f"{completed.stderr[-1000:].strip()}"
            )
        try:
            response = decode_strict_json(completed.stdout)
            if not isinstance(response, dict) or response.get("ok") is not True:
                raise ValueError("backend exec did not report success")
            stdout = response.get("stdout")
            if not isinstance(stdout, str):
                raise TypeError("backend exec stdout is not a string")
            lines = [line.strip() for line in stdout.splitlines() if line.strip()]
            if len(lines) != 1:
                raise ValueError("backend exec did not print exactly one base address")
            base = parse_address(lines[0])
        except Exception as error:
            raise DecompilerError(
                f"invalid DecLib binary-base response: {error}"
            ) from error
        return base

    def _best_effort_stop(
        self,
        server_id: str,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
    ) -> None:
        try:
            self.runner.run(
                CommandSpec(
                    argv=(self.executable, "stop", "--id", server_id, "--json"),
                    stdin=None,
                    cwd=cwd,
                    env=environment,
                    timeout_seconds=max(1.0, timeout_seconds),
                )
            )
        except Exception:
            pass


@dataclass
class DeclibSession:
    controller: DeclibController
    server_id: str
    binary_path: Path
    backend: str
    cwd: Path
    environment: Mapping[str, str]
    timeout_seconds: float
    binary_base_addr: int
    _closed: bool = field(default=False, init=False)

    def list_functions(self) -> tuple[FunctionInfo, ...]:
        if self._closed:
            raise DecompilerError("DecLib session is already closed")
        command = (
            self.controller.executable,
            "list_functions",
            "--id",
            self.server_id,
            "--json",
        )
        try:
            completed = self.controller.runner.run(
                CommandSpec(
                    argv=command,
                    stdin=None,
                    cwd=self.cwd,
                    env=self.environment,
                    timeout_seconds=self.timeout_seconds,
                )
            )
        except CommandTimedOut as error:
            raise DecompilerError(
                f"DecLib function enumeration exceeded the {self.timeout_seconds:g}s timeout"
            ) from error
        if completed.returncode != 0:
            raise DecompilerError(
                f"DecLib function enumeration exited with status {completed.returncode}: "
                f"{completed.stderr[-1000:].strip()}"
            )
        try:
            response = decode_strict_json(completed.stdout)
            if not isinstance(response, list):
                raise TypeError("response is not an array")
            functions: list[FunctionInfo] = []
            seen: set[int] = set()
            for position, entry in enumerate(response):
                if not isinstance(entry, dict):
                    raise TypeError(f"entry {position} is not an object")
                raw_address = entry.get("addr")
                if isinstance(raw_address, bool) or not isinstance(raw_address, int):
                    raise TypeError(f"entry {position}.addr is not an integer")
                if raw_address < 0:
                    raise ValueError(f"entry {position}.addr is negative")
                if raw_address in seen:
                    raise ValueError(f"duplicate function address 0x{raw_address:x}")
                seen.add(raw_address)
                raw_size = entry.get("size", 0)
                if isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0:
                    raise TypeError(f"entry {position}.size is not a nonnegative integer")
                raw_name = entry.get("name", "")
                if not isinstance(raw_name, str):
                    raise TypeError(f"entry {position}.name is not a string")
                functions.append(
                    FunctionInfo(
                        address=f"0x{raw_address:x}",
                        size=raw_size,
                        discovered_name=raw_name,
                    )
                )
            if not functions:
                raise ValueError("DecLib discovered no functions")
        except Exception as error:
            raise DecompilerError(
                f"invalid DecLib list_functions response: {error}"
            ) from error
        return tuple(functions)

    def save(self) -> None:
        if self._closed:
            raise DecompilerError("DecLib session is already closed")
        command = (
            self.controller.executable,
            "save",
            "--id",
            self.server_id,
            "--json",
        )
        try:
            completed = self.controller.runner.run(
                CommandSpec(
                    argv=command,
                    stdin=None,
                    cwd=self.cwd,
                    env=self.environment,
                    timeout_seconds=self.timeout_seconds,
                )
            )
        except CommandTimedOut as error:
            raise DecompilerError(
                f"DecLib save exceeded the {self.timeout_seconds:g}s timeout"
            ) from error
        if completed.returncode != 0:
            raise DecompilerError(
                f"DecLib save exited with status {completed.returncode}: "
                f"{completed.stderr[-1000:].strip()}"
            )
        try:
            response = decode_strict_json(completed.stdout)
            if not isinstance(response, dict) or response.get("saved") is not True:
                raise ValueError("backend did not confirm a successful save")
        except Exception as error:
            raise DecompilerError(f"invalid DecLib save response: {error}") from error

    def close(self, *, discard: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        command_parts = [
            self.controller.executable,
            "stop",
            "--id",
            self.server_id,
        ]
        if discard:
            command_parts.append("--discard")
        command_parts.append("--json")
        command = tuple(command_parts)
        try:
            completed = self.controller.runner.run(
                CommandSpec(
                    argv=command,
                    stdin=None,
                    cwd=self.cwd,
                    env=self.environment,
                    timeout_seconds=min(self.timeout_seconds, 30.0),
                )
            )
        except CommandTimedOut as error:
            raise DecompilerError("DecLib cleanup timed out") from error
        if completed.returncode != 0:
            raise DecompilerError(
                f"DecLib cleanup exited with status {completed.returncode}: "
                f"{completed.stderr[-1000:].strip()}"
            )
        try:
            response = decode_strict_json(completed.stdout)
            stopped = response.get("stopped") if isinstance(response, dict) else None
            if not isinstance(stopped, list) or not any(
                isinstance(entry, dict)
                and entry.get("id") == self.server_id
                and entry.get("stopped") is True
                for entry in stopped
            ):
                raise ValueError("server was not confirmed stopped")
        except Exception as error:
            raise DecompilerError(f"invalid DecLib cleanup response: {error}") from error


def run_analysis_stage(
    config: AnalysisStageConfig,
    *,
    decompiler_controller: DeclibController | None = None,
) -> StageResult:
    """Build and close one pristine persistent project before any provider runs."""

    started_at = _utc_now()
    started = time.monotonic()
    output_dir = secure_directory(config.output_dir)
    artifacts: dict[str, str] = {}
    function_count = 0
    error: Exception | None = None
    session: DeclibSession | Any | None = None

    try:
        _validate_analysis_config(config)
        state_root = secure_directory(config.state_dir or output_dir / "state")
        # Reuse the normal isolated HOME/XDG construction, but no provider is
        # ever invoked and the container receives no credential environment.
        _workspace, _provider_dir, _unused_project, _provider_env, decompiler_env = (
            _prepare_layout(output_dir, state_root, "codex", config.environment)
        )
        decompiler_binary = _stage_decompiler_binary(config.binary_path, state_root)
        project_dir = secure_directory(output_dir / "project")
        controller = decompiler_controller or DeclibController(
            executable=config.decompiler_executable
        )
        session = controller.open(
            binary_path=decompiler_binary,
            backend=config.backend,
            project_dir=project_dir,
            environment=decompiler_env,
            timeout_seconds=config.decompiler_timeout_seconds,
        )
        functions = tuple(session.list_functions())
        function_count = len(functions)
        analysis_document = _analysis_metadata(
            functions,
            binary_path=decompiler_binary,
            binary_base=session.binary_base_addr,
            backend=config.backend,
        )
        analysis_path = output_dir / "analysis.json"
        atomic_write_json(analysis_path, analysis_document)
        artifacts["analysis"] = str(analysis_path)
        artifacts["project"] = str(project_dir)

        # A successful explicit save followed by a discard-close keeps exactly
        # those saved baseline bytes while releasing the live project lock.
        session.save()
        session.close(discard=True)
        session = None
    except Exception as caught:
        error = caught
    finally:
        if session is not None:
            try:
                session.close()
            except Exception as cleanup_error:
                if error is None:
                    error = cleanup_error
                else:
                    error = StageError(
                        f"{error}; additionally, cleanup failed: {cleanup_error}"
                    )

    return _finish_stage(
        stage="analyze",
        config=config,
        started_at=started_at,
        started=started,
        output_dir=output_dir,
        artifacts=artifacts,
        provider_result=None,
        requested_count=0,
        produced_count=function_count,
        error=error,
    )


def run_reverse_stage(
    config: ReverseStageConfig,
    *,
    provider_adapter: ProviderAdapter | None = None,
    decompiler_controller: DeclibController | None = None,
) -> StageResult:
    """Run one blind reverser stage and always return/write stage metadata."""

    started_at = _utc_now()
    started = time.monotonic()
    output_dir = secure_directory(config.output_dir)
    artifacts: dict[str, str] = {}
    provider_result: ProviderResult | None = None
    produced_count = 0
    error: Exception | None = None
    session: DeclibSession | Any | None = None

    try:
        _validate_common_config(config)
        workspace, provider_dir, project_dir, provider_env, decompiler_env = _prepare_layout(
            output_dir, config.state_dir, config.provider_name, config.environment
        )
        decompiler_binary = _stage_decompiler_binary(
            config.binary_path, project_dir.parent
        )
        controller = decompiler_controller or DeclibController(
            executable=config.decompiler_executable
        )
        session = controller.open(
            binary_path=decompiler_binary,
            backend=config.backend,
            project_dir=project_dir,
            environment=decompiler_env,
            timeout_seconds=config.decompiler_timeout_seconds,
        )
        functions = tuple(session.list_functions())
        _validate_seeded_analysis(
            project_dir.parent,
            functions,
            binary_path=decompiler_binary,
            binary_base=session.binary_base_addr,
            backend=config.backend,
        )
        if len(functions) < config.count:
            raise StageContractError(
                f"DecLib discovered {len(functions)} functions, fewer than the "
                f"requested {config.count}"
            )
        translation = _build_address_translation(
            functions,
            decompiler_base=session.binary_base_addr,
            image_base=config.image_base,
        )
        snapshot_path = output_dir / "function_snapshot.json"
        snapshot_document = {
            "schema_version": 1,
            "address_space": "rva",
            "image_base": config.image_base,
            "decompiler_base": session.binary_base_addr,
            "backend": config.backend,
            "functions": list(translation.snapshot_functions),
        }
        atomic_write_json(snapshot_path, snapshot_document)
        # Give the agent a local, explicitly bounded-query catalog so a large
        # list_functions response does not have to enter model context. Expose
        # only one address convention: the exact DecLib address submissions
        # accept, never the host-only canonical RVA.
        agent_catalog = {
            "schema_version": 1,
            "address_space": "declib",
            "functions": [
                {
                    "address": entry["decompiler_address"],
                    "size": entry["size"],
                    "discovered_name": entry["discovered_name"],
                }
                for entry in translation.snapshot_functions
            ],
        }
        atomic_write_json(workspace / "function_catalog.json", agent_catalog)
        artifacts["function_snapshot"] = str(snapshot_path)

        schema = prediction_schema(config.count)
        schema_path = output_dir / "prediction_schema.json"
        atomic_write_json(schema_path, schema)
        artifacts["output_schema"] = str(schema_path)
        prompt = build_reverse_prompt(config.count, session.server_id, config.backend)
        prompt_path = output_dir / "prompt.txt"
        atomic_write_text(prompt_path, prompt)
        artifacts["prompt"] = str(prompt_path)

        adapter = provider_adapter or make_provider(
            config.provider_name, executable=config.provider_executable
        )
        if adapter.name != _canonical_provider_name(config.provider_name):
            raise StageContractError(
                f"injected provider {adapter.name!r} does not match requested provider "
                f"{config.provider_name!r}"
            )
        provider_result = adapter.run(
            ProviderRequest(
                prompt=prompt,
                model=config.model,
                output_schema=schema,
                cwd=workspace,
                artifact_dir=provider_dir,
                timeout_seconds=config.timeout_seconds,
                environment=provider_env,
                max_budget_usd=config.max_budget_usd,
                reasoning_effort=config.reasoning_effort,
            )
        )
        artifacts.update(_provider_artifacts(provider_result))

        # The provider shares the container UID and can see /output. Restore
        # pre-agent artifacts from trusted in-memory values after it exits.
        atomic_write_json(snapshot_path, snapshot_document)
        atomic_write_json(schema_path, schema)
        atomic_write_text(prompt_path, prompt)

        try:
            predictions = _validate_reverse_predictions(
                provider_result.output,
                translation.raw_to_rva,
                expected_count=config.count,
            )
        except Exception as validation_error:
            raise StageContractError(
                f"reverser prediction contract failed: {validation_error}"
            ) from validation_error
        produced_count = len(predictions)
        predictions_path = output_dir / "predictions.json"
        atomic_write_json(
            predictions_path,
            {prediction.rva: {"name": prediction.name} for prediction in predictions},
        )
        submitted_addresses_path = output_dir / "submitted_addresses.json"
        atomic_write_json(
            submitted_addresses_path,
            [prediction.to_dict() for prediction in predictions],
        )
        artifacts["predictions"] = str(predictions_path)
        artifacts["submitted_addresses"] = str(submitted_addresses_path)
    except Exception as caught:
        error = caught
    finally:
        if session is not None:
            try:
                session.close(discard=True)
            except Exception as cleanup_error:
                if error is None:
                    error = cleanup_error
                else:
                    error = StageError(f"{error}; additionally, cleanup failed: {cleanup_error}")

    return _finish_stage(
        stage="reverse",
        config=config,
        started_at=started_at,
        started=started,
        output_dir=output_dir,
        artifacts=artifacts,
        provider_result=provider_result,
        requested_count=config.count,
        produced_count=produced_count,
        error=error,
    )


def run_grade_stage(
    config: GradeStageConfig,
    *,
    provider_adapter: ProviderAdapter | None = None,
    decompiler_controller: DeclibController | None = None,
) -> StageResult:
    """Run one private semantic-grading stage and return/write metadata."""

    started_at = _utc_now()
    started = time.monotonic()
    output_dir = secure_directory(config.output_dir)
    artifacts: dict[str, str] = {}
    provider_result: ProviderResult | None = None
    produced_count = 0
    requested_count = 0
    error: Exception | None = None
    session: DeclibSession | Any | None = None

    try:
        _validate_common_config(config)
        packet = _load_grading_packet(config.packet_path)
        entries = packet["entries"]
        requested_count = len(entries)
        addresses = [entry["address"] for entry in entries]
        if len(set(addresses)) != len(addresses):
            raise StageContractError("grading packet contains duplicate addresses")
        for entry in entries:
            if entry["gradable"] and not entry["authoritative_names"]:
                raise StageContractError(
                    f"gradable packet entry {entry['address']} has no authoritative names"
                )
            if not entry["gradable"] and not entry.get("ungradable_reason"):
                raise StageContractError(
                    f"ungradable packet entry {entry['address']} has no ungradable_reason"
                )

        workspace, provider_dir, project_dir, provider_env, decompiler_env = _prepare_layout(
            output_dir, config.state_dir, config.provider_name, config.environment
        )
        decompiler_binary = _stage_decompiler_binary(
            config.binary_path, project_dir.parent
        )
        private_packet_path = workspace / "grading_packet.json"

        controller = decompiler_controller or DeclibController(
            executable=config.decompiler_executable
        )
        session = controller.open(
            binary_path=decompiler_binary,
            backend=config.backend,
            project_dir=project_dir,
            environment=decompiler_env,
            timeout_seconds=config.decompiler_timeout_seconds,
        )
        functions = tuple(session.list_functions())
        _validate_seeded_analysis(
            project_dir.parent,
            functions,
            binary_path=decompiler_binary,
            binary_base=session.binary_base_addr,
            backend=config.backend,
        )
        translation = _build_address_translation(
            functions,
            decompiler_base=session.binary_base_addr,
            image_base=config.image_base,
        )
        snapshot_path = output_dir / "function_snapshot.json"
        snapshot_document = {
            "schema_version": 1,
            "address_space": "rva",
            "image_base": config.image_base,
            "decompiler_base": session.binary_base_addr,
            "backend": config.backend,
            "functions": list(translation.snapshot_functions),
        }
        atomic_write_json(snapshot_path, snapshot_document)
        artifacts["function_snapshot"] = str(snapshot_path)
        agent_entries: list[dict[str, Any]] = []
        for entry in entries:
            address = entry["address"]
            raw_address = translation.rva_to_raw.get(address)
            if raw_address is None:
                raise StageContractError(
                    f"grading packet canonical RVA {address} is not in the "
                    "pre-agent function snapshot"
                )
            agent_entry = dict(entry)
            agent_entry["address"] = raw_address
            agent_entries.append(agent_entry)
        agent_packet = {"schema_version": 1, "entries": agent_entries}
        atomic_write_json(private_packet_path, agent_packet)
        artifacts["grading_packet"] = str(private_packet_path)

        raw_addresses = [entry["address"] for entry in agent_entries]
        schema = verdict_schema(raw_addresses)
        schema_path = output_dir / "verdict_schema.json"
        atomic_write_json(schema_path, schema)
        artifacts["output_schema"] = str(schema_path)
        prompt = build_grader_prompt(
            private_packet_path.name, session.server_id, config.backend
        )
        prompt_path = output_dir / "prompt.txt"
        atomic_write_text(prompt_path, prompt)
        artifacts["prompt"] = str(prompt_path)

        adapter = provider_adapter or make_provider(
            config.provider_name, executable=config.provider_executable
        )
        if adapter.name != _canonical_provider_name(config.provider_name):
            raise StageContractError(
                f"injected provider {adapter.name!r} does not match requested provider "
                f"{config.provider_name!r}"
            )
        provider_result = adapter.run(
            ProviderRequest(
                prompt=prompt,
                model=config.model,
                output_schema=schema,
                cwd=workspace,
                artifact_dir=provider_dir,
                timeout_seconds=config.timeout_seconds,
                environment=provider_env,
                max_budget_usd=config.max_budget_usd,
                reasoning_effort=config.reasoning_effort,
            )
        )
        artifacts.update(_provider_artifacts(provider_result))
        atomic_write_json(snapshot_path, snapshot_document)
        atomic_write_json(schema_path, schema)
        atomic_write_text(prompt_path, prompt)
        raw_verdicts = provider_result.output
        try:
            Draft202012Validator(schema).validate(raw_verdicts)
        except ValidationError as validation_error:
            raise StageContractError(
                f"grader verdict contract failed: {validation_error.message}"
            ) from validation_error
        # Provider validation already checks the schema. This enforces the packet's
        # explicit ungradable flag as a cross-document invariant.
        for entry in agent_entries:
            if (
                not entry["gradable"]
                and raw_verdicts[entry["address"]]["verdict"] != "ungradable"
            ):
                raise StageContractError(
                    f"grader must mark explicitly ungradable entry {entry['address']} ungradable"
                )
        verdicts: dict[str, Any] = {}
        for raw_address, verdict in raw_verdicts.items():
            rva = translation.raw_to_rva.get(raw_address)
            if rva is None:
                raise StageContractError(
                    f"grader returned unknown DecLib address {raw_address}"
                )
            if rva in verdicts:
                raise StageContractError(
                    f"multiple grader addresses translate to canonical RVA {rva}"
                )
            verdicts[rva] = verdict
        produced_count = len(verdicts)
        verdicts_path = output_dir / "verdicts.json"
        atomic_write_json(verdicts_path, verdicts)
        artifacts["verdicts"] = str(verdicts_path)
    except Exception as caught:
        error = caught
    finally:
        if session is not None:
            try:
                session.close(discard=True)
            except Exception as cleanup_error:
                if error is None:
                    error = cleanup_error
                else:
                    error = StageError(f"{error}; additionally, cleanup failed: {cleanup_error}")

    return _finish_stage(
        stage="grade",
        config=config,
        started_at=started_at,
        started=started,
        output_dir=output_dir,
        artifacts=artifacts,
        provider_result=provider_result,
        requested_count=requested_count,
        produced_count=produced_count,
        error=error,
    )


def _build_address_translation(
    functions: Sequence[FunctionInfo],
    *,
    decompiler_base: int,
    image_base: int,
) -> _AddressTranslation:
    """Translate DecLib's lifted addresses into manifest-relative addresses.

    DecLib defines lifted address zero at ``deci.binary_base_addr``. The
    manifest defines RVA zero at ``image_base``. Thus ``R = D + Bdec - Bimg``.
    Both maps are checked as a bijection even though a constant offset should be
    injective; treating collisions as infrastructure failures prevents silent
    overwrites if a backend emits malformed data.
    """

    if not functions:
        raise StageContractError("pre-agent function snapshot is empty")
    try:
        decompiler_base_value = parse_address(decompiler_base)
        image_base_value = parse_address(image_base)
    except Exception as error:
        raise StageContractError(f"invalid address-space base: {error}") from error

    raw_to_rva: dict[str, str] = {}
    rva_to_raw: dict[str, str] = {}
    snapshot_functions: list[Mapping[str, Any]] = []
    for function in functions:
        try:
            raw_value = parse_address(function.address)
        except Exception as error:
            raise StageContractError(
                f"invalid DecLib function address {function.address!r}: {error}"
            ) from error
        raw_address = canonical_rva(raw_value)
        if function.address != raw_address:
            raise StageContractError(
                f"DecLib function address {function.address!r} is not canonical {raw_address}"
            )
        if raw_address in raw_to_rva:
            raise StageContractError(
                f"duplicate DecLib function address {raw_address}"
            )
        lowered = raw_value + decompiler_base_value
        if lowered > MAX_ADDRESS:
            raise StageContractError(
                f"DecLib address {raw_address} plus base "
                f"{canonical_rva(decompiler_base_value)} overflows 64 bits"
            )
        if lowered < image_base_value:
            raise StageContractError(
                f"DecLib address {raw_address} lowers to {canonical_rva(lowered)}, "
                f"below manifest image base {canonical_rva(image_base_value)}"
            )
        rva = canonical_rva(lowered - image_base_value)
        if rva in rva_to_raw:
            raise StageContractError(
                f"DecLib addresses {rva_to_raw[rva]} and {raw_address} both "
                f"translate to canonical RVA {rva}"
            )
        raw_to_rva[raw_address] = rva
        rva_to_raw[rva] = raw_address
        snapshot_functions.append(
            {
                "decompiler_address": raw_address,
                "rva": rva,
                "size": function.size,
                "discovered_name": function.discovered_name,
            }
        )
    return _AddressTranslation(
        raw_to_rva=raw_to_rva,
        rva_to_raw=rva_to_raw,
        snapshot_functions=tuple(snapshot_functions),
    )


def _validate_reverse_predictions(
    output: Mapping[str, Any],
    raw_to_rva: Mapping[str, str],
    *,
    expected_count: int,
) -> tuple[Prediction, ...]:
    if set(output) != {"predictions"}:
        raise StageContractError(
            "reverse output must contain only the 'predictions' field"
        )
    items = output.get("predictions")
    if not isinstance(items, list):
        raise StageContractError("reverse output predictions must be an array")
    if len(items) != expected_count:
        raise StageContractError(
            f"reverse output has {len(items)} predictions; expected exactly {expected_count}"
        )

    predictions: list[Prediction] = []
    seen_raw_values: dict[int, str] = {}
    seen_rvas: dict[str, str] = {}
    for position, item in enumerate(items):
        if not isinstance(item, Mapping) or set(item) != {"address", "name"}:
            raise StageContractError(
                f"predictions[{position}] must contain only address and name"
            )
        address = item.get("address")
        name = item.get("name")
        if not isinstance(address, str):
            raise StageContractError(f"predictions[{position}].address must be a string")
        try:
            raw_value = parse_address(address)
        except Exception as error:
            raise StageContractError(
                f"predictions[{position}].address is invalid: {error}"
            ) from error
        if raw_value in seen_raw_values:
            raise StageContractError(
                f"duplicate submitted DecLib addresses {seen_raw_values[raw_value]!r} "
                f"and {address!r}"
            )
        seen_raw_values[raw_value] = address
        rva = raw_to_rva.get(address)
        if rva is None:
            raise StageContractError(
                f"submitted DecLib address {address} is not an exact address from the "
                "pre-agent function snapshot"
            )
        if rva in seen_rvas:
            raise StageContractError(
                f"submitted DecLib addresses {seen_rvas[rva]} and {address} both "
                f"translate to canonical RVA {rva}"
            )
        seen_rvas[rva] = address
        if not isinstance(name, str) or not name.strip():
            raise StageContractError(f"predictions[{position}].name must be nonempty")
        if len(name) > 32768 or any(ord(character) < 0x20 for character in name):
            raise StageContractError(
                f"predictions[{position}].name contains control characters or is too long"
            )
        predictions.append(
            Prediction(rva=rva, name=name, submitted_address=address)
        )
    return tuple(predictions)


def _load_grading_packet(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise StageContractError(f"could not read grading packet: {error}") from error
    try:
        packet = decode_strict_json(text)
    except Exception as error:
        raise StageContractError(f"invalid grading packet JSON: {error}") from error
    if not isinstance(packet, dict):
        raise StageContractError("grading packet must be a JSON object")
    try:
        Draft202012Validator(grading_packet_schema()).validate(packet)
    except ValidationError as error:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise StageContractError(
            f"grading packet failed schema validation at {location}: {error.message}"
        ) from error
    return packet


def _validate_analysis_config(config: AnalysisStageConfig) -> None:
    if not config.binary_path.is_file():
        raise StageContractError("binary_path must identify a regular file")
    if config.backend not in {"ida", "ghidra"}:
        raise StageContractError(
            "persistent analysis caching requires the 'ida' or 'ghidra' backend"
        )
    if config.decompiler_timeout_seconds <= 0:
        raise StageContractError("decompiler timeout must be positive")


def _validate_common_config(config: ReverseStageConfig | GradeStageConfig) -> None:
    if not config.binary_path.is_file():
        raise StageContractError("binary_path must identify a regular file")
    if not config.model.strip():
        raise StageContractError("model must be explicit")
    _canonical_provider_name(config.provider_name)
    if config.backend not in SUPPORTED_BACKENDS:
        raise StageContractError(
            f"unsupported backend {config.backend!r}; expected 'ida', 'ghidra', or 'angr'"
        )
    if config.timeout_seconds <= 0 or config.decompiler_timeout_seconds <= 0:
        raise StageContractError("stage timeouts must be positive")
    if config.reasoning_effort not in {None, "low", "medium", "high", "xhigh"}:
        raise StageContractError(
            "reasoning_effort must be low, medium, high, or xhigh"
        )
    if isinstance(config.image_base, bool) or not isinstance(config.image_base, int):
        raise StageContractError("image_base must be an integer")
    if config.image_base < 0 or config.image_base >= 1 << 64:
        raise StageContractError("image_base must be an unsigned 64-bit value")
    if isinstance(config, ReverseStageConfig):
        if isinstance(config.count, bool) or not isinstance(config.count, int) or config.count <= 0:
            raise StageContractError("reverse count must be a positive integer")


def _analysis_metadata(
    functions: Sequence[FunctionInfo],
    *,
    binary_path: Path,
    binary_base: int,
    backend: str,
) -> dict[str, Any]:
    normalized = sorted(
        (function.to_dict() for function in functions),
        key=lambda entry: parse_address(entry["address"]),
    )
    if not normalized:
        raise StageContractError("pre-agent analysis discovered no functions")
    return {
        "schema_version": 1,
        "backend": backend,
        "binary_sha256": sha256_file(binary_path),
        "binary_base": canonical_rva(binary_base),
        "function_count": len(normalized),
        "function_catalog_sha256": canonical_json_sha256(normalized),
    }


def _validate_seeded_analysis(
    state_root: Path,
    functions: Sequence[FunctionInfo],
    *,
    binary_path: Path,
    binary_base: int,
    backend: str,
) -> None:
    metadata_path = state_root / "decompiler-analysis.json"
    if not metadata_path.exists():
        return
    try:
        value = decode_strict_json(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise StageContractError(f"invalid seeded analysis metadata: {error}") from error
    if not isinstance(value, dict):
        raise StageContractError("seeded analysis metadata must be an object")
    actual = _analysis_metadata(
        functions,
        binary_path=binary_path,
        binary_base=binary_base,
        backend=backend,
    )
    if value != actual:
        raise StageContractError(
            "seeded decompiler project does not match the loaded binary analysis"
        )


def _stage_decompiler_binary(source: Path, state_root: Path) -> Path:
    """Copy the read-only mounted input into private writable stage state.

    Ghidra's importer opens its input with write access even though it does not
    need to modify the authoritative binary.  Keeping the external bind mount
    read-only protects the dataset; DecLib receives this byte-identical,
    ephemeral copy instead.
    """

    input_dir = secure_directory(state_root / "decompiler-input")
    destination = input_dir / "target"
    source_fd = -1
    temporary_fd = -1
    temporary_name: str | None = None
    try:
        resolved = source.resolve(strict=True)
        # ``resolved`` is a regular file from the orchestrator-controlled,
        # read-only bind. Docker Desktop's virtual bind filesystem rejects a
        # first open with O_NOFOLLOW even though the same file is readable, so
        # use the already-resolved path without that incompatible flag.
        source_fd = os.open(resolved, os.O_RDONLY)
        metadata = os.fstat(source_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise StageContractError("decompiler input must be a regular file")

        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=".target-", dir=str(input_dir)
        )
        os.fchmod(temporary_fd, 0o600)
        with os.fdopen(source_fd, "rb", closefd=False) as source_file, os.fdopen(
            temporary_fd, "wb", closefd=False
        ) as destination_file:
            shutil.copyfileobj(source_file, destination_file, length=1024 * 1024)
            destination_file.flush()
            os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(temporary_name, destination)
        temporary_name = None
        return destination
    except StageContractError:
        raise
    except (OSError, RuntimeError) as error:
        raise StageContractError(
            f"could not stage the decompiler input: {error}"
        ) from error
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _prepare_layout(
    output_dir: Path,
    state_dir: Path | None,
    provider_name: str,
    supplied_environment: Mapping[str, str] | None,
) -> tuple[Path, Path, Path, dict[str, str], dict[str, str]]:
    state_root = secure_directory(state_dir or output_dir)
    workspace = secure_directory(state_root / "agent-workspace")
    provider_dir = secure_directory(output_dir / "provider")
    project_dir = secure_directory(state_root / "decompiler-project")
    home = secure_directory(state_root / "home")
    codex_home = secure_directory(home / ".codex")
    claude_config_dir = secure_directory(home / ".claude")
    cache = secure_directory(state_root / "cache")
    config_home = secure_directory(state_root / "config")
    data_home = secure_directory(state_root / "data")
    xdg_state_home = secure_directory(state_root / "xdg-state")
    xdg_runtime_dir = secure_directory(state_root / "runtime")
    temporary = secure_directory(state_root / "tmp")
    ida_user = secure_directory(state_root / "ida-user")

    base = dict(os.environ if supplied_environment is None else supplied_environment)
    codex_auth_json = base.pop("CODEX_AUTH_JSON", None)
    if codex_auth_json is not None:
        try:
            codex_auth = json.loads(codex_auth_json)
            if not isinstance(codex_auth, dict):
                raise TypeError("credential document is not an object")
            atomic_write_json(codex_home / "auth.json", codex_auth)
        except (TypeError, ValueError, OSError) as error:
            raise StageContractError(
                f"could not initialize Codex authentication: {error}"
            ) from error
    ida_install_dir = base.get("IDA_INSTALL_DIR")
    if ida_install_dir:
        atomic_write_json(
            ida_user / "ida-config.json",
            {"Paths": {"ida-install-dir": ida_install_dir}},
        )
    base.update(
        {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_DATA_HOME": str(data_home),
            "XDG_STATE_HOME": str(xdg_state_home),
            "XDG_RUNTIME_DIR": str(xdg_runtime_dir),
            "TMPDIR": str(temporary),
            "IDAUSR": str(ida_user),
            "CODEX_HOME": str(codex_home),
            "CLAUDE_CONFIG_DIR": str(claude_config_dir),
        }
    )
    normalized_provider = _canonical_provider_name(provider_name)
    noncredential_env = {
        key: value
        for key, value in base.items()
        if not _credential_environment_name(key)
    }
    provider_env = dict(noncredential_env)
    allowed_credentials = (
        ("CODEX_API_KEY", "OPENAI_API_KEY")
        if normalized_provider == "codex"
        else ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")
    )
    for key in allowed_credentials:
        if key in base:
            provider_env[key] = base[key]

    decompiler_env = dict(noncredential_env)
    return workspace, provider_dir, project_dir, provider_env, decompiler_env


def _credential_environment_name(name: str) -> bool:
    upper = name.upper()
    exact = {
        "AWS_ACCESS_KEY_ID",
        "DOCKER_AUTH_CONFIG",
        "GPG_AGENT_INFO",
        "SSH_AGENT_PID",
        "SSH_AUTH_SOCK",
    }
    return upper in exact or any(
        marker in upper
        for marker in (
            "API_KEY",
            "ACCESS_KEY",
            "PRIVATE_KEY",
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "CREDENTIAL",
        )
    )


def _provider_artifacts(result: ProviderResult) -> dict[str, str]:
    return {
        "provider_events": str(result.events_path),
        "provider_stderr": str(result.stderr_path),
        "provider_final": str(result.final_output_path),
        "provider_schema": str(result.schema_path),
    }


def _canonical_provider_name(name: str) -> str:
    normalized = name.strip().lower()
    if normalized == "codex":
        return "codex"
    if normalized in {"claude", "claude-code", "claudecode"}:
        return "claude"
    raise StageContractError(
        f"unsupported provider {name!r}; expected 'codex' or 'claude'"
    )


def _finish_stage(
    *,
    stage: str,
    config: ReverseStageConfig | GradeStageConfig | AnalysisStageConfig,
    started_at: str,
    started: float,
    output_dir: Path,
    artifacts: dict[str, str],
    provider_result: ProviderResult | None,
    requested_count: int,
    produced_count: int,
    error: Exception | None,
) -> StageResult:
    result_path = output_dir / "stage_result.json"
    artifacts["stage_result"] = str(result_path)
    result = StageResult(
        stage=stage,
        status="completed" if error is None else "failed",
        provider=_display_provider_name(config.provider_name),
        model=config.model,
        backend=config.backend,
        started_at=started_at,
        finished_at=_utc_now(),
        duration_seconds=time.monotonic() - started,
        requested_count=requested_count,
        produced_count=produced_count,
        artifacts=dict(artifacts),
        provider_command=provider_result.command if provider_result else (),
        error_type=type(error).__name__ if error is not None else None,
        error_message=str(error) if error is not None else None,
    )
    atomic_write_json(result_path, result.to_dict())
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _display_provider_name(name: str) -> str:
    try:
        return _canonical_provider_name(name)
    except StageContractError:
        return name.strip().lower() or "invalid"

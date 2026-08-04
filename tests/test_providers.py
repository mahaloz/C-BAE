from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from zion_eval.providers import (
    ClaudeProvider,
    CodexProvider,
    CommandSpec,
    CommandTimedOut,
    CompletedCommand,
    ProviderOutputError,
    ProviderRequest,
    ProviderTimeoutError,
    SubprocessRunner,
    decode_strict_json,
)


SIMPLE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["answer"],
    "properties": {"answer": {"type": "string"}},
}


class CallbackRunner:
    def __init__(self, callback):
        self.callback = callback
        self.specs: list[CommandSpec] = []

    def run(self, spec: CommandSpec) -> CompletedCommand:
        self.specs.append(spec)
        return self.callback(spec)


def request(tmp_path: Path, **changes) -> ProviderRequest:
    values = {
        "prompt": "perform the evaluation",
        "model": "explicit-model-id",
        "output_schema": SIMPLE_SCHEMA,
        "cwd": tmp_path / "work",
        "artifact_dir": tmp_path / "provider",
        "timeout_seconds": 30,
        "environment": {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "openai-super-secret",
        },
    }
    values.update(changes)
    return ProviderRequest(**values)


def test_codex_uses_noninteractive_schema_and_redacts_logs(tmp_path: Path) -> None:
    secret = "openai-super-secret"

    def complete(spec: CommandSpec) -> CompletedCommand:
        final_path = Path(spec.argv[spec.argv.index("--output-last-message") + 1])
        final_path.write_text('{"answer":"ok"}\n', encoding="utf-8")
        return CompletedCommand(
            0,
            f'{{"type":"item.completed","debug":"{secret}"}}\n',
            f"diagnostic {secret}\n",
            1.25,
        )

    runner = CallbackRunner(complete)
    result = CodexProvider("fake-codex", runner=runner).run(request(tmp_path))

    spec = runner.specs[0]
    assert spec.stdin == "perform the evaluation"
    assert "--ephemeral" in spec.argv
    assert "--ignore-user-config" in spec.argv
    assert "--output-schema" in spec.argv
    disabled = {
        spec.argv[position + 1]
        for position, value in enumerate(spec.argv[:-1])
        if value == "--disable"
    }
    assert {
        "apps",
        "browser_use",
        "browser_use_external",
        "browser_use_full_cdp_access",
        "computer_use",
        "in_app_browser",
        "plugins",
        "remote_plugin",
        "standalone_web_search",
    } <= disabled
    assert spec.argv[spec.argv.index("--model") + 1] == "explicit-model-id"
    assert secret not in " ".join(spec.argv)
    assert result.output == {"answer": "ok"}
    assert secret not in result.events_path.read_text(encoding="utf-8")
    assert secret not in result.stderr_path.read_text(encoding="utf-8")
    assert "[REDACTED]" in result.events_path.read_text(encoding="utf-8")


def test_claude_requires_structured_result_and_passes_budget(tmp_path: Path) -> None:
    events = [
        {"type": "system", "subtype": "init"},
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "structured_output": {"answer": "semantic"},
        },
    ]
    stdout = "".join(json.dumps(event) + "\n" for event in events)
    runner = CallbackRunner(lambda spec: CompletedCommand(0, stdout, "", 2.0))
    result = ClaudeProvider("fake-claude", runner=runner).run(
        request(
            tmp_path,
            environment={"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "anthropic-secret"},
            max_budget_usd=7.5,
        )
    )

    spec = runner.specs[0]
    assert spec.stdin == "perform the evaluation"
    assert "--bare" in spec.argv
    assert "--no-session-persistence" in spec.argv
    assert spec.argv[spec.argv.index("--tools") + 1] == "Bash"
    assert spec.argv[spec.argv.index("--model") + 1] == "explicit-model-id"
    assert spec.argv[spec.argv.index("--max-budget-usd") + 1] == "7.5"
    assert result.output == {"answer": "semantic"}
    assert json.loads(result.final_output_path.read_text())["answer"] == "semantic"


def test_claude_does_not_repair_result_text_without_structured_output(tmp_path: Path) -> None:
    stdout = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": '{"answer":"tempting but not structured"}',
        }
    )
    runner = CallbackRunner(lambda spec: CompletedCommand(0, stdout + "\n", "", 0.1))
    with pytest.raises(ProviderOutputError, match="structured_output"):
        ClaudeProvider("fake-claude", runner=runner).run(request(tmp_path))


def test_duplicate_json_keys_are_rejected_before_overwrite() -> None:
    with pytest.raises(ProviderOutputError, match="duplicate JSON object key"):
        decode_strict_json('{"0x10":{"name":"a"},"0x10":{"name":"b"}}')


def test_timeout_is_reported_and_partial_logs_are_redacted(tmp_path: Path) -> None:
    secret = "openai-super-secret"

    def timeout(spec: CommandSpec) -> CompletedCommand:
        completed = CompletedCommand(-15, f"partial {secret}", f"error {secret}", 30.0)
        raise CommandTimedOut(completed)

    runner = CallbackRunner(timeout)
    provider = CodexProvider("fake-codex", runner=runner)
    with pytest.raises(ProviderTimeoutError, match="30s timeout"):
        provider.run(request(tmp_path))
    assert secret not in (tmp_path / "provider" / "events.jsonl").read_text()
    assert secret not in (tmp_path / "provider" / "stderr.log").read_text()


def test_subprocess_runner_enforces_timeout() -> None:
    runner = SubprocessRunner()
    with pytest.raises(CommandTimedOut) as caught:
        runner.run(
            CommandSpec(
                argv=(sys.executable, "-c", "import time; time.sleep(30)"),
                stdin=None,
                cwd=Path.cwd(),
                env={"PATH": str(Path(sys.executable).parent)},
                timeout_seconds=0.1,
                terminate_grace_seconds=0.1,
            )
        )
    assert caught.value.completed.duration_seconds < 5

from __future__ import annotations

import json
from pathlib import Path

from zion_eval.artifacts import (
    atomic_write_json,
    atomic_write_text,
    canonical_json_sha256,
    secure_directory,
    sha256_file,
)
from zion_eval.providers import CommandSpec, CompletedCommand, ProviderRequest, ProviderResult
from zion_eval.stages import (
    AnalysisStageConfig,
    ChooserStageConfig,
    DeclibController,
    FunctionInfo,
    GradeStageConfig,
    ReverseStageConfig,
    run_analysis_stage,
    run_chooser_stage,
    run_grade_stage,
    run_reverse_stage,
)


class FakeProvider:
    def __init__(self, name: str, output: dict):
        self.name = name
        self.output = output
        self.requests: list[ProviderRequest] = []

    def run(self, request: ProviderRequest) -> ProviderResult:
        self.requests.append(request)
        directory = secure_directory(request.artifact_dir)
        events = directory / "events.jsonl"
        stderr = directory / "stderr.log"
        final = directory / "final.json"
        schema = directory / "output.schema.json"
        atomic_write_text(events, '{"type":"fake"}\n')
        atomic_write_text(stderr, "")
        atomic_write_json(final, self.output)
        atomic_write_json(schema, request.output_schema)
        return ProviderResult(
            provider=self.name,
            model=request.model,
            output=self.output,
            command=("fake-provider", "--model", request.model),
            duration_seconds=0.01,
            events_path=events,
            stderr_path=stderr,
            final_output_path=final,
            schema_path=schema,
        )


class FakeSession:
    def __init__(self, functions: tuple[FunctionInfo, ...], binary_base_addr: int = 0):
        self.server_id = "fake-server"
        self.functions = functions
        self.binary_base_addr = binary_base_addr
        self.closed = False
        self.saved = False
        self.discarded = False

    def list_functions(self) -> tuple[FunctionInfo, ...]:
        return self.functions

    def save(self) -> None:
        self.saved = True

    def decompile_text(self, address: str) -> str:
        return "int selected() {\n  int a = 1;\n  a += 2;\n  a += 3;\n  a += 4;\n  a += 5;\n  a += 6;\n  return a;\n}\n"

    def close(self, *, discard: bool = False) -> None:
        self.closed = True
        self.discarded = discard


class FakeController:
    def __init__(self, functions: tuple[FunctionInfo, ...], binary_base_addr: int = 0):
        self.session = FakeSession(functions, binary_base_addr)
        self.calls: list[dict] = []

    def open(self, **kwargs) -> FakeSession:
        self.calls.append(kwargs)
        return self.session


FUNCTIONS = (
    FunctionInfo("0x10", 20, "FUN_10"),
    FunctionInfo("0x20", 40, "FUN_20"),
    FunctionInfo("0x30", 60, "FUN_30"),
)


def binary(tmp_path: Path) -> Path:
    path = tmp_path / "target"
    path.write_bytes(b"binary fixture")
    return path


def selection(tmp_path: Path, *rvas: str) -> Path:
    path = tmp_path / f"selection-{len(list(tmp_path.glob('selection-*')))}.json"
    atomic_write_json(
        path,
        {
            "schema_version": 1,
            "address_space": "rva",
            "count": len(rvas),
            "functions": [
                {
                    "rva": rva,
                    "submitted_address": rva,
                    "size": 20,
                    "decompiled_line_count": 7,
                }
                for rva in rvas
            ],
        },
    )
    return path


def test_analysis_stage_saves_and_closes_pristine_project_before_publish(
    tmp_path: Path,
) -> None:
    controller = FakeController(FUNCTIONS, binary_base_addr=0x400000)
    source = binary(tmp_path)
    result = run_analysis_stage(
        AnalysisStageConfig(
            binary_path=source,
            output_dir=tmp_path / "analysis-output",
            state_dir=tmp_path / "analysis-state",
            environment={"PATH": "/usr/bin", "CODEX_API_KEY": "must-not-leak"},
        ),
        decompiler_controller=controller,
    )

    assert result.succeeded
    assert result.produced_count == len(FUNCTIONS)
    assert controller.session.saved is True
    assert controller.session.closed is True
    assert controller.session.discarded is True
    call = controller.calls[0]
    assert call["project_dir"] == tmp_path / "analysis-output" / "project"
    assert "CODEX_API_KEY" not in call["environment"]
    analysis = json.loads(
        (tmp_path / "analysis-output" / "analysis.json").read_text(encoding="utf-8")
    )
    assert analysis["binary_sha256"] == sha256_file(source)
    assert analysis["binary_base"] == "0x400000"
    assert analysis["function_count"] == len(FUNCTIONS)


def test_seeded_analysis_mismatch_fails_before_provider_and_discards_clone(
    tmp_path: Path,
) -> None:
    source = binary(tmp_path)
    state = tmp_path / "seeded-state"
    state.mkdir()
    normalized = sorted(
        (function.to_dict() for function in FUNCTIONS),
        key=lambda entry: int(entry["address"], 0),
    )
    atomic_write_json(
        state / "decompiler-analysis.json",
        {
            "schema_version": 1,
            "backend": "ghidra",
            "binary_sha256": sha256_file(source),
            "binary_base": "0x0",
            "function_count": len(FUNCTIONS),
            # Deliberately differs from the loaded function catalog.
            "function_catalog_sha256": canonical_json_sha256(normalized[:-1]),
        },
    )
    provider = FakeProvider(
        "codex", {"predictions": [{"address": "0x10", "name": "guess"}]}
    )
    controller = FakeController(FUNCTIONS)

    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=source,
            selection_path=selection(tmp_path, "0x10"),
            output_dir=tmp_path / "reverse",
            state_dir=state,
            provider_name="codex",
            model="gpt-explicit",
            count=1,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert result.error_type == "StageContractError"
    assert "does not match" in (result.error_message or "")
    assert provider.requests == []
    assert controller.session.closed is True
    assert controller.session.discarded is True


def test_chooser_freezes_only_substantive_addresses_and_records_line_counts(
    tmp_path: Path,
) -> None:
    provider = FakeProvider(
        "codex",
        {"selections": [{"address": "0x10"}, {"address": "0x30"}]},
    )
    controller = FakeController(FUNCTIONS)
    result = run_chooser_stage(
        ChooserStageConfig(
            binary_path=binary(tmp_path),
            output_dir=tmp_path / "chooser",
            provider_name="codex",
            model="chooser-model",
            count=2,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert result.succeeded
    chosen = json.loads(Path(result.artifacts["selected_functions"]).read_text())
    assert [item["rva"] for item in chosen["functions"]] == ["0x10", "0x30"]
    assert all(item["decompiled_line_count"] > 5 for item in chosen["functions"])
    assert all("name" not in item for item in chosen["functions"])
    prompt = Path(result.artifacts["prompt"]).read_text()
    assert "not merely a generic library" in prompt
    assert "comparatively distinctive to this binary" in prompt
    assert "more than five meaningful code lines" in prompt


def test_chooser_rejects_a_selected_five_line_function(tmp_path: Path) -> None:
    provider = FakeProvider("codex", {"selections": [{"address": "0x10"}]})
    controller = FakeController(FUNCTIONS)
    controller.session.decompile_text = lambda _address: (  # type: ignore[method-assign]
        "int f() {\n  a();\n  b();\n  c();\n  d();\n  return 0;\n}\n"
    )
    result = run_chooser_stage(
        ChooserStageConfig(
            binary_path=binary(tmp_path),
            output_dir=tmp_path / "chooser-short",
            provider_name="codex",
            model="chooser-model",
            count=1,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert "five or fewer meaningful code lines" in (result.error_message or "")
    assert "selected_functions" not in result.artifacts


def test_reverse_stage_translates_declib_base_offset_and_cleans_up(tmp_path: Path) -> None:
    provider = FakeProvider(
        "codex",
        {
            "predictions": [
                {"address": "0x10", "name": "Widget::parse"},
                {"address": "0x20", "name": "Widget::emit"},
            ]
        },
    )
    controller = FakeController(FUNCTIONS, binary_base_addr=0x140001000)
    source_binary = binary(tmp_path)
    source_binary.chmod(0o444)
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=source_binary,
            selection_path=selection(tmp_path, "0x1010", "0x1020"),
            output_dir=tmp_path / "reverse",
            provider_name="codex",
            model="gpt-explicit",
            backend="ghidra",
            count=2,
            image_base=0x140000000,
            state_dir=tmp_path / "state",
            environment={
                "PATH": "/usr/bin",
                "XDG_CONFIG_HOME": "/home/zion/.config",
                "XDG_DATA_HOME": "/home/zion/.local/share",
                "XDG_STATE_HOME": "/home/zion/.local/state",
                "IDA_INSTALL_DIR": "/opt/idapro-9.2",
                "CODEX_AUTH_JSON": json.dumps(
                    {"auth_mode": "chatgpt", "tokens": {"access_token": "secret"}}
                ),
                "CODEX_API_KEY": "host-codex-secret",
                "OPENAI_API_KEY": "only-for-provider",
                "ANTHROPIC_API_KEY": "must-not-leak",
                "UNRELATED_API_KEY": "also-must-not-leak",
                "SSH_AUTH_SOCK": "/tmp/credential-socket",
            },
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert result.succeeded
    assert result.produced_count == 2
    assert controller.session.closed
    assert controller.session.discarded is True
    staged_binary = controller.calls[0]["binary_path"]
    assert staged_binary == tmp_path / "state" / "decompiler-input" / "target"
    assert staged_binary.read_bytes() == source_binary.read_bytes()
    assert staged_binary.stat().st_ino != source_binary.stat().st_ino
    assert staged_binary.stat().st_mode & 0o777 == 0o600
    assert "ANTHROPIC_API_KEY" not in provider.requests[0].environment
    assert "UNRELATED_API_KEY" not in provider.requests[0].environment
    assert "SSH_AUTH_SOCK" not in provider.requests[0].environment
    assert "OPENAI_API_KEY" in provider.requests[0].environment
    assert "CODEX_API_KEY" in provider.requests[0].environment
    assert "CODEX_AUTH_JSON" not in provider.requests[0].environment
    assert "OPENAI_API_KEY" not in controller.calls[0]["environment"]
    assert "CODEX_API_KEY" not in controller.calls[0]["environment"]
    assert "CODEX_AUTH_JSON" not in controller.calls[0]["environment"]
    assert json.loads(
        (tmp_path / "state" / "home" / ".codex" / "auth.json").read_text()
    )["auth_mode"] == "chatgpt"
    for environment in (
        provider.requests[0].environment,
        controller.calls[0]["environment"],
    ):
        assert environment["HOME"] == str(tmp_path / "state" / "home")
        assert environment["XDG_CONFIG_HOME"] == str(tmp_path / "state" / "config")
        assert environment["XDG_DATA_HOME"] == str(tmp_path / "state" / "data")
        assert environment["XDG_STATE_HOME"] == str(tmp_path / "state" / "xdg-state")
        assert environment["XDG_RUNTIME_DIR"] == str(tmp_path / "state" / "runtime")
        assert environment["IDAUSR"] == str(tmp_path / "state" / "ida-user")
        assert environment["CODEX_HOME"] == str(tmp_path / "state" / "home" / ".codex")
        assert environment["CLAUDE_CONFIG_DIR"] == str(
            tmp_path / "state" / "home" / ".claude"
        )
        for provider_home in (
            Path(environment["CODEX_HOME"]),
            Path(environment["CLAUDE_CONFIG_DIR"]),
            Path(environment["XDG_RUNTIME_DIR"]),
        ):
            assert provider_home.is_dir()
            assert provider_home.stat().st_mode & 0o777 == 0o700
    assert json.loads(
        (tmp_path / "state" / "ida-user" / "ida-config.json").read_text()
    ) == {"Paths": {"ida-install-dir": "/opt/idapro-9.2"}}
    predictions = json.loads(Path(result.artifacts["predictions"]).read_text())
    assert predictions == {
        "0x1010": {"name": "Widget::parse"},
        "0x1020": {"name": "Widget::emit"},
    }
    snapshot = json.loads(Path(result.artifacts["function_snapshot"]).read_text())
    assert snapshot["decompiler_base"] == 0x140001000
    assert snapshot["functions"][0]["decompiler_address"] == "0x10"
    assert snapshot["functions"][0]["rva"] == "0x1010"
    assert provider.requests[0].output_schema["required"] == ["predictions"]
    assert provider.requests[0].output_schema["properties"]["predictions"]["minItems"] == 2
    prompt = Path(result.artifacts["prompt"]).read_text()
    assert "exactly 2" in prompt
    assert "web browser" in prompt
    assert "function_catalog.json" in prompt
    assert "never print the whole catalog" in prompt
    assert "do not calculate or submit a VA/RVA" in prompt
    assert "at most five hours" in prompt
    assert "forcibly cut off five hours after it starts" in prompt
    catalog = json.loads(
        (provider.requests[0].cwd / "function_catalog.json").read_text()
    )
    assert catalog["address_space"] == "declib"
    assert catalog["functions"][0] == {
        "address": "0x10",
        "size": 20,
        "discovered_name": "FUN_10",
    }
    assert "rva" not in catalog["functions"][0]
    assert str(source_binary) not in prompt
    assert json.loads((tmp_path / "reverse" / "stage_result.json").read_text())["status"] == "completed"


def test_reverse_contract_failure_is_persisted_and_cleanup_still_runs(tmp_path: Path) -> None:
    provider = FakeProvider(
        "claude",
        {
            "predictions": [
                {"address": "0x999", "name": "not_a_discovered_function"}
            ]
        },
    )
    controller = FakeController(FUNCTIONS)
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10"),
            output_dir=tmp_path / "failed",
            provider_name="claude",
            model="claude-explicit",
            count=1,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert result.error_type == "StageContractError"
    assert "pre-agent function snapshot" in (result.error_message or "")
    assert controller.session.closed
    document = json.loads((tmp_path / "failed" / "stage_result.json").read_text())
    assert document["status"] == "failed"
    assert "predictions" not in document["artifacts"]


def test_reverse_rejects_substitution_for_chooser_address(tmp_path: Path) -> None:
    provider = FakeProvider(
        "codex", {"predictions": [{"address": "0x20", "name": "easier_guess"}]}
    )
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10"),
            output_dir=tmp_path / "substitution",
            provider_name="codex",
            model="reverse-model",
            count=1,
        ),
        provider_adapter=provider,
        decompiler_controller=FakeController(FUNCTIONS),
    )

    assert not result.succeeded
    assert "immutable address set" in (result.error_message or "")


def test_reverse_rejects_impossible_count_before_provider(tmp_path: Path) -> None:
    provider = FakeProvider("codex", {"predictions": []})
    controller = FakeController(FUNCTIONS[:1])

    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10", "0x20"),
            output_dir=tmp_path / "too-many",
            provider_name="codex",
            model="gpt-explicit",
            count=2,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert "fewer than the requested 2" in (result.error_message or "")
    assert provider.requests == []
    assert controller.session.closed


def test_reverse_rejects_address_translation_underflow(tmp_path: Path) -> None:
    provider = FakeProvider(
        "codex",
        {"predictions": [{"address": "0x10", "name": "guess"}]},
    )
    controller = FakeController(FUNCTIONS, binary_base_addr=0x1000)
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10"),
            output_dir=tmp_path / "underflow",
            provider_name="codex",
            model="gpt-explicit",
            count=1,
            image_base=0x2000,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert "below manifest image base" in (result.error_message or "")
    assert provider.requests == []
    assert controller.session.closed


def test_reverse_rejects_duplicate_raw_prediction_addresses(tmp_path: Path) -> None:
    provider = FakeProvider(
        "codex",
        {
            "predictions": [
                {"address": "0x10", "name": "first"},
                {"address": "0x10", "name": "second"},
            ]
        },
    )
    controller = FakeController(FUNCTIONS)
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10", "0x20"),
            output_dir=tmp_path / "duplicates",
            provider_name="codex",
            model="gpt-explicit",
            count=2,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert "duplicate submitted DecLib addresses" in (result.error_message or "")
    assert controller.session.closed


def test_reverse_rejects_duplicate_declib_snapshot_addresses(tmp_path: Path) -> None:
    duplicate_functions = (
        FunctionInfo("0x10", 20, "FUN_10"),
        FunctionInfo("0x10", 30, "FUN_10_DUPLICATE"),
    )
    provider = FakeProvider(
        "codex",
        {"predictions": [{"address": "0x10", "name": "guess"}]},
    )
    controller = FakeController(duplicate_functions)
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=binary(tmp_path),
            selection_path=selection(tmp_path, "0x10"),
            output_dir=tmp_path / "duplicate-snapshot",
            provider_name="codex",
            model="gpt-explicit",
            count=1,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert not result.succeeded
    assert "duplicate DecLib function address" in (result.error_message or "")
    assert provider.requests == []
    assert controller.session.closed


def test_grade_stage_uses_private_packet_and_qualified_role_prompt(tmp_path: Path) -> None:
    packet = {
        "schema_version": 1,
        "entries": [
            {
                "address": "0x1010",
                "predicted_name": "Widget::parse",
                "authoritative_names": ["Widget::parse"],
                "gradable": True,
            },
            {
                "address": "0x1020",
                "predicted_name": "emit",
                "authoritative_names": [],
                "gradable": False,
                "ungradable_reason": "missing usable source symbol",
            },
        ],
    }
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    provider = FakeProvider(
        "claude",
        {
            "0x10": {
                "verdict": "exact",
                "justification": "Literal identity.",
                "confidence": 1.0,
            },
            "0x20": {
                "verdict": "ungradable",
                "justification": "Truth is unavailable.",
                "confidence": 1.0,
            },
        },
    )
    controller = FakeController(FUNCTIONS, binary_base_addr=0x140001000)
    source_binary = binary(tmp_path)
    source_binary.chmod(0o444)
    result = run_grade_stage(
        GradeStageConfig(
            binary_path=source_binary,
            packet_path=packet_path,
            output_dir=tmp_path / "grade",
            state_dir=tmp_path / "grade-state",
            provider_name="claude",
            model="claude-explicit",
            image_base=0x140000000,
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )

    assert result.succeeded
    assert result.requested_count == result.produced_count == 2
    assert controller.session.closed
    assert controller.session.discarded is True
    staged_binary = controller.calls[0]["binary_path"]
    assert staged_binary == tmp_path / "grade-state" / "decompiler-input" / "target"
    assert staged_binary.read_bytes() == source_binary.read_bytes()
    assert staged_binary.stat().st_ino != source_binary.stat().st_ino
    assert staged_binary.stat().st_mode & 0o777 == 0o600
    request = provider.requests[0]
    assert request.environment["CODEX_HOME"] == str(
        tmp_path / "grade-state" / "home" / ".codex"
    )
    assert request.environment["CLAUDE_CONFIG_DIR"] == str(
        tmp_path / "grade-state" / "home" / ".claude"
    )
    assert request.environment["XDG_RUNTIME_DIR"] == str(
        tmp_path / "grade-state" / "runtime"
    )
    for provider_home in (
        Path(request.environment["CODEX_HOME"]),
        Path(request.environment["CLAUDE_CONFIG_DIR"]),
        Path(request.environment["XDG_RUNTIME_DIR"]),
    ):
        assert provider_home.is_dir()
        assert provider_home.stat().st_mode & 0o777 == 0o700
    assert request.cwd.joinpath("grading_packet.json").is_file()
    agent_packet = json.loads(request.cwd.joinpath("grading_packet.json").read_text())
    assert "provider" not in agent_packet
    assert [entry["address"] for entry in agent_packet["entries"]] == ["0x10", "0x20"]
    assert "Namespace/class" in request.prompt
    assert "xref_from" in request.prompt
    assert "get_callees" not in request.prompt
    assert set(json.loads(Path(result.artifacts["verdicts"]).read_text())) == {
        "0x1010",
        "0x1020",
    }


def test_grade_rejects_non_ungradable_verdict_for_missing_truth(tmp_path: Path) -> None:
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "address": "0x10",
                        "predicted_name": "guess",
                        "authoritative_names": [],
                        "gradable": False,
                        "ungradable_reason": "truth absent",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    provider = FakeProvider(
        "codex",
        {
            "0x10": {
                "verdict": "incorrect",
                "justification": "Bad model response.",
                "confidence": 0.5,
            }
        },
    )
    controller = FakeController(FUNCTIONS)
    result = run_grade_stage(
        GradeStageConfig(
            binary_path=binary(tmp_path),
            packet_path=packet_path,
            output_dir=tmp_path / "bad-grade",
            provider_name="codex",
            model="gpt-explicit",
        ),
        provider_adapter=provider,
        decompiler_controller=controller,
    )
    assert not result.succeeded
    assert result.error_type == "StageContractError"
    assert "must mark explicitly ungradable" in (result.error_message or "")
    assert controller.session.closed


def test_declib_controller_preloads_snapshots_and_confirms_cleanup(tmp_path: Path) -> None:
    class DecLibRunner:
        def __init__(self):
            self.specs: list[CommandSpec] = []

        def run(self, spec: CommandSpec) -> CompletedCommand:
            self.specs.append(spec)
            if spec.argv[1] == "load":
                server_id = spec.argv[spec.argv.index("--id") + 1]
                output = {"status": "started", "id": server_id}
            elif spec.argv[1] == "exec":
                output = {
                    "ok": True,
                    "result": "",
                    "stdout": "0x140001000\n",
                    "traceback": None,
                }
            elif spec.argv[1] == "list_functions":
                output = [
                    {"addr": 0x10, "size": 20, "name": "FUN_10"},
                    {"addr": 0x20, "size": 40, "name": "FUN_20"},
                ]
            elif spec.argv[1] == "save":
                output = {"saved": True, "path": None}
            elif spec.argv[1] == "stop":
                server_id = spec.argv[spec.argv.index("--id") + 1]
                output = {"stopped": [{"id": server_id, "stopped": True}]}
            else:  # pragma: no cover - test guard
                raise AssertionError(spec.argv)
            return CompletedCommand(0, json.dumps(output), "", 0.01)

    target = binary(tmp_path)
    runner = DecLibRunner()
    controller = DeclibController(executable="fake-decompiler", runner=runner)
    session = controller.open(
        binary_path=target,
        backend="ghidra",
        project_dir=tmp_path / "project",
        environment={"HOME": str(tmp_path / "home")},
        timeout_seconds=10,
    )
    functions = session.list_functions()
    session.save()
    session.close(discard=True)

    assert [function.address for function in functions] == ["0x10", "0x20"]
    assert [spec.argv[1] for spec in runner.specs] == [
        "load",
        "exec",
        "list_functions",
        "save",
        "stop",
    ]
    assert session.binary_base_addr == 0x140001000
    assert "--backend" in runner.specs[0].argv
    assert runner.specs[0].argv[runner.specs[0].argv.index("--timeout") + 1] == "10"
    assert runner.specs[1].argv[2] == "print(hex(deci.binary_base_addr))"
    assert runner.specs[2].argv[runner.specs[2].argv.index("--id") + 1] == session.server_id
    assert "--discard" in runner.specs[-1].argv


def test_declib_controller_stops_server_when_base_query_fails(tmp_path: Path) -> None:
    class FailedBaseRunner:
        def __init__(self):
            self.commands: list[str] = []

        def run(self, spec: CommandSpec) -> CompletedCommand:
            self.commands.append(spec.argv[1])
            server_id = spec.argv[spec.argv.index("--id") + 1]
            if spec.argv[1] == "load":
                output = {"status": "started", "id": server_id}
                return CompletedCommand(0, json.dumps(output), "", 0.01)
            if spec.argv[1] == "exec":
                output = {
                    "ok": False,
                    "result": None,
                    "stdout": "",
                    "traceback": "backend failure",
                }
                return CompletedCommand(0, json.dumps(output), "", 0.01)
            if spec.argv[1] == "stop":
                return CompletedCommand(
                    0,
                    json.dumps({"stopped": [{"id": server_id, "stopped": True}]}),
                    "",
                    0.01,
                )
            raise AssertionError(spec.argv)  # pragma: no cover

    runner = FailedBaseRunner()
    controller = DeclibController(executable="fake-decompiler", runner=runner)
    try:
        controller.open(
            binary_path=binary(tmp_path),
            backend="ghidra",
            project_dir=tmp_path / "failed-base-project",
            environment={"HOME": str(tmp_path / "home")},
            timeout_seconds=10,
        )
    except Exception as error:
        assert "binary-base response" in str(error)
    else:  # pragma: no cover - must fail
        raise AssertionError("invalid binary-base response was accepted")
    assert runner.commands == ["load", "exec", "stop"]

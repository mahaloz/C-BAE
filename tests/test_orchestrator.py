from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zion_eval.addresses import Prediction
from zion_eval.artifacts import atomic_write_json, sha256_file
from zion_eval.docker_runner import (
    ContainerResult,
    DockerRunError,
    build_docker_command,
    neutral_agent_staging,
)
from zion_eval.orchestrator import (
    EvaluationRunConfig,
    OrchestrationError,
    RegradeConfig,
    RunLayout,
    _invoke_grade_container,
    _run_reverse_container,
    build_grading_packet,
    provider_credential_name,
    regrade_evaluation,
    reverse_mounts,
    run_evaluation,
)
from zion_eval.stages import _prepare_layout
from zion_eval.truth import TruthRecord


def test_reverse_mounts_never_include_private_tree(tmp_path: Path) -> None:
    binary = tmp_path / "stripped"
    binary.write_bytes(b"binary")
    layout = RunLayout.create(tmp_path / "runs", "fixture", "run-1")

    with neutral_agent_staging(
        binary_path=binary,
        output_dir=layout.reverse_output,
        state_dir=layout.reverse_state,
    ) as staging:
        mounts = reverse_mounts(staging)

        assert {mount.destination for mount in mounts} == {
            "/input/target",
            "/output",
            "/state",
        }
        assert {path.name for path in (staging.root / "input").iterdir()} == {
            "target"
        }
        assert all(
            mount.source.resolve().is_relative_to(staging.root.resolve())
            for mount in mounts
        )
        assert all(
            str(layout.private.resolve()) not in str(mount.source.resolve())
            for mount in mounts
        )


def _evaluation_config(tmp_path: Path, *, target_id: str, run_id: str) -> EvaluationRunConfig:
    return EvaluationRunConfig(
        manifest_path=tmp_path / "manifest.toml",
        target_id=target_id,
        image="zion-eval:test",
        reverser_provider="codex",
        reverser_model="reverse-model",
        grader_provider="claude",
        grader_model="grade-model",
        runs_directory=tmp_path / "runs",
        run_id=run_id,
        timeout_seconds=10,
        decompiler_timeout_seconds=10,
    )


def test_reverse_container_command_and_mountinfo_sources_are_identity_blind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id = "ultra-secret-target-id"
    run_id = "user-selected-run-id"
    original_root = tmp_path / f"original-binary-{target_id}"
    original_root.mkdir()
    binary = original_root / "descriptive-product-name.bin"
    binary.write_bytes(b"binary")
    layout = RunLayout.create(
        tmp_path / f"real-runs-{target_id}", target_id, run_id
    )
    project_seed = tmp_path / "content-addressed-cache" / "state-seed"
    cached_project = project_seed / "decompiler-project"
    cached_project.mkdir(parents=True)
    (cached_project / "database").write_text("pristine", encoding="utf-8")
    config = _evaluation_config(tmp_path, target_id=target_id, run_id=run_id)
    config = replace(
        config,
        timeout_seconds=10_000,
        decompiler_timeout_seconds=10_000,
    )
    captured: dict[str, object] = {}
    monkeypatch.setenv("CODEX_API_KEY", "test-key")
    monkeypatch.setattr("zion_eval.orchestrator.host_container_user", lambda: "123:456")

    def fake_run(spec: object) -> ContainerResult:
        captured["spec"] = spec
        command = build_docker_command(spec, "zion-agent-abcdef012345")  # type: ignore[arg-type]
        captured["command"] = command
        captured["staging_root"] = spec.mount_source_root  # type: ignore[attr-defined]
        by_destination = {
            mount.destination: mount for mount in spec.mounts  # type: ignore[attr-defined]
        }
        assert by_destination["/input/target"].read_only is True
        assert by_destination["/output"].read_only is False
        assert by_destination["/state"].read_only is False
        assert by_destination["/input/target"].source.read_bytes() == b"binary"
        assert {path.name for path in (spec.mount_source_root / "input").iterdir()} == {  # type: ignore[attr-defined]
            "target"
        }
        staged_database = by_destination["/state"].source / "decompiler-project" / "database"
        assert staged_database.read_text(encoding="utf-8") == "pristine"
        staged_database.write_text("reverse mutation", encoding="utf-8")
        (by_destination["/output"].source / "stage_result.json").write_text(
            '{"status":"completed"}', encoding="utf-8"
        )
        (by_destination["/output"].source / "prediction.json").write_text(
            "{}", encoding="utf-8"
        )
        (by_destination["/state"].source / "provider-cache").write_text(
            "cached", encoding="utf-8"
        )
        return ContainerResult(tuple(command), 0, "stdout", "stderr")

    monkeypatch.setattr("zion_eval.orchestrator.run_container", fake_run)
    _run_reverse_container(
        config, binary, 0, 1, "ghidra", layout, project_seed=project_seed
    )

    command_text = "\0".join(captured["command"])  # type: ignore[arg-type]
    for secret in (
        target_id,
        run_id,
        str(binary.resolve()),
        str(original_root.resolve()),
        str(layout.root.resolve()),
        str(project_seed.resolve()),
    ):
        assert secret not in command_text
    assert "/tmp/zion-agent-" in command_text
    staging_root = captured["staging_root"]
    assert isinstance(staging_root, Path)
    assert not staging_root.exists()
    assert captured["spec"].timeout_seconds == 5 * 60 * 60  # type: ignore[attr-defined]
    assert (layout.reverse_output / "prediction.json").read_text() == "{}"
    assert not (layout.reverse_state / "provider-cache").exists()
    assert (cached_project / "database").read_text(encoding="utf-8") == "pristine"
    persisted = (layout.reverse_output / "container.json").read_text(encoding="utf-8")
    assert str(staging_root) not in persisted
    assert "src=<neutral-staging>" in persisted


def test_reverse_copyback_runs_when_container_launch_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "original" / "target"
    binary.parent.mkdir()
    binary.write_bytes(b"binary")
    layout = RunLayout.create(tmp_path / "runs", "target", "run-on-failure")
    config = _evaluation_config(tmp_path, target_id="target", run_id="run-on-failure")
    captured_root: Path | None = None
    monkeypatch.setattr("zion_eval.orchestrator.host_container_user", lambda: "123:456")

    def fail_after_partial_output(spec: object) -> ContainerResult:
        nonlocal captured_root
        captured_root = spec.mount_source_root  # type: ignore[attr-defined]
        by_destination = {
            mount.destination: mount for mount in spec.mounts  # type: ignore[attr-defined]
        }
        (by_destination["/output"].source / "partial.log").write_text(
            "partial", encoding="utf-8"
        )
        (by_destination["/state"].source / "partial-state").write_text(
            "state", encoding="utf-8"
        )
        raise DockerRunError("simulated Docker failure")

    monkeypatch.setattr(
        "zion_eval.orchestrator.run_container", fail_after_partial_output
    )
    with pytest.raises(DockerRunError, match="simulated Docker failure"):
        _run_reverse_container(config, binary, 0, 1, "angr", layout)

    assert (layout.reverse_output / "partial.log").read_text() == "partial"
    assert not (layout.reverse_state / "partial-state").exists()
    assert captured_root is not None and not captured_root.exists()


def test_reverse_nonzero_exit_copies_failure_artifacts_before_status_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "source" / "target"
    binary.parent.mkdir()
    binary.write_bytes(b"binary")
    layout = RunLayout.create(tmp_path / "runs", "target", "nonzero-run")
    config = _evaluation_config(tmp_path, target_id="target", run_id="nonzero-run")
    captured_root: Path | None = None
    monkeypatch.setenv("CODEX_API_KEY", "test-key")
    monkeypatch.setattr("zion_eval.orchestrator.host_container_user", lambda: "123:456")

    def nonzero_result(spec: object) -> ContainerResult:
        nonlocal captured_root
        captured_root = spec.mount_source_root  # type: ignore[attr-defined]
        by_destination = {
            mount.destination: mount for mount in spec.mounts  # type: ignore[attr-defined]
        }
        (by_destination["/output"].source / "stage_result.json").write_text(
            '{"status":"failed","error":{"message":"model failed"}}',
            encoding="utf-8",
        )
        (by_destination["/output"].source / "provider-events.jsonl").write_text(
            "partial event", encoding="utf-8"
        )
        command = build_docker_command(spec, "zion-agent-001122334455")  # type: ignore[arg-type]
        return ContainerResult(tuple(command), 17, "partial stdout", "failure stderr")

    monkeypatch.setattr("zion_eval.orchestrator.run_container", nonzero_result)
    with pytest.raises(OrchestrationError, match="exited with 17"):
        _run_reverse_container(config, binary, 0, 1, "angr", layout)

    assert (layout.reverse_output / "provider-events.jsonl").read_text() == "partial event"
    assert (layout.reverse_output / "container.stderr.log").read_text() == "failure stderr"
    assert captured_root is not None and not captured_root.exists()


def test_grade_container_stages_private_packet_and_keeps_state_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id = "private-target-id"
    run_id = "private-user-run-id"
    binary = tmp_path / target_id / "original.exe"
    binary.parent.mkdir()
    binary.write_bytes(b"binary")
    layout = RunLayout.create(tmp_path / "real-runs", target_id, run_id)
    packet = layout.private / "grading_packet.json"
    packet.write_text('{"authoritative_names":["Secret::name"]}', encoding="utf-8")
    captured: dict[str, object] = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("zion_eval.orchestrator.host_container_user", lambda: "123:456")

    def fake_run(spec: object) -> ContainerResult:
        command = build_docker_command(spec, "zion-agent-fedcba987654")  # type: ignore[arg-type]
        captured["command"] = command
        captured["staging_root"] = spec.mount_source_root  # type: ignore[attr-defined]
        by_destination = {
            mount.destination: mount for mount in spec.mounts  # type: ignore[attr-defined]
        }
        assert by_destination["/input/target"].read_only is True
        assert by_destination["/input/grading_packet.json"].read_only is True
        assert by_destination["/output"].read_only is False
        assert by_destination["/state"].read_only is False
        assert "Secret::name" in by_destination[
            "/input/grading_packet.json"
        ].source.read_text(encoding="utf-8")
        (by_destination["/output"].source / "stage_result.json").write_text(
            '{"status":"completed"}', encoding="utf-8"
        )
        (by_destination["/state"].source / "agent-workspace").mkdir()
        (by_destination["/state"].source / "agent-workspace" / "packet-copy").write_text(
            "Secret::name", encoding="utf-8"
        )
        return ContainerResult(tuple(command), 0, "", "")

    monkeypatch.setattr("zion_eval.orchestrator.run_container", fake_run)
    _invoke_grade_container(
        image="zion-eval:test",
        binary_path=binary,
        image_base=0,
        backend="ghidra",
        packet_path=packet,
        output_dir=layout.grade_output,
        state_dir=layout.grade_state,
        provider="claude",
        model="grader-model",
        timeout_seconds=10,
        decompiler_timeout_seconds=10,
        max_budget_usd=None,
    )

    command_text = "\0".join(captured["command"])  # type: ignore[arg-type]
    for secret in (
        target_id,
        run_id,
        str(binary.resolve()),
        str(packet.resolve()),
        str(layout.root.resolve()),
    ):
        assert secret not in command_text
    staging_root = captured["staging_root"]
    assert isinstance(staging_root, Path)
    assert not staging_root.exists()
    assert layout.grade_state.resolve().is_relative_to(layout.private.resolve())
    assert RunLayout.open(layout.root).grade_state == layout.grade_state
    assert not (layout.root / "state" / "grade").exists()
    assert not (layout.grade_state / "agent-workspace").exists()
    persisted = json.loads(
        (layout.grade_output / "container.json").read_text(encoding="utf-8")
    )
    assert str(staging_root) not in json.dumps(persisted)


def test_grading_packet_contains_only_selected_truth() -> None:
    predictions = (
        Prediction(rva="0x10", name="parseMessage", submitted_address="0x10"),
        Prediction(rva="0x20", name="cleanup", submitted_address="0x20"),
    )
    truth = {
        "0x10": TruthRecord(
            rva="0x10",
            name="Protocol::parseMessage(void)",
            mangled_name="_ZN8Protocol12parseMessageEv",
            gradeable=True,
            ungradable_reason=None,
        ),
        "0x20": None,
        "0x30": TruthRecord(
            rva="0x30",
            name="Secret::notSelected()",
            mangled_name=None,
            gradeable=True,
            ungradable_reason=None,
        ),
    }

    packet = build_grading_packet(predictions, truth)

    assert [entry["address"] for entry in packet["entries"]] == ["0x10", "0x20"]
    assert all("Secret::notSelected" not in str(entry) for entry in packet["entries"])
    assert packet["entries"][1]["ungradable_reason"] == "missing_truth"


def test_run_id_cannot_escape_runs_directory(tmp_path: Path) -> None:
    with pytest.raises(OrchestrationError, match="run id"):
        RunLayout.create(tmp_path / "runs", "fixture", "../outside")


def test_grading_packet_drops_placeholder_alias_when_real_name_exists() -> None:
    predictions = (
        Prediction(rva="0x10", name="parse", submitted_address="0x10"),
    )
    truth = {
        "0x10": TruthRecord(
            rva="0x10",
            name="Protocol::parse()",
            mangled_name="sub_10",
            gradeable=True,
            ungradable_reason=None,
        )
    }

    packet = build_grading_packet(predictions, truth)

    assert packet["entries"][0]["authoritative_names"] == ["Protocol::parse()"]


def test_codex_credential_contract_reaches_only_provider(tmp_path: Path) -> None:
    credential = provider_credential_name("codex")
    assert credential == "CODEX_API_KEY"

    _workspace, _provider_dir, _project_dir, provider_env, decompiler_env = (
        _prepare_layout(
            tmp_path / "output",
            tmp_path / "state",
            "codex",
            {credential: "secret", "PATH": "/usr/bin"},
        )
    )

    assert provider_env[credential] == "secret"
    assert credential not in decompiler_env


def test_fresh_resume_and_regrade_pin_runtime_and_freeze_address_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "stripped.bin"
    truth = tmp_path / "truth.json"
    manifest = tmp_path / "manifest.toml"
    binary.write_bytes(b"fixture-binary")
    truth.write_text(
        json.dumps(
            {"0x10": {"name": "Real::parse()", "mangled_name": None}}
        ),
        encoding="utf-8",
    )
    manifest.write_text(
        f'''schema_version = 1

[defaults]
function_count = 1
decompiler_backend = "ghidra"

[[targets]]
id = "fixture"
binary = "stripped.bin"
truth = "truth.json"
binary_sha256 = "{sha256_file(binary)}"
truth_sha256 = "{sha256_file(truth)}"
format = "elf"
architecture = "x86_64"
truth_address_space = "rva"
image_base = 0
''',
        encoding="utf-8",
    )

    image_id = "sha256:" + "1" * 64
    runtime_image = {
        "requested_reference": "zion-eval:test",
        "image_id": image_id,
        "repo_digests": [],
        "platform": "linux/amd64",
        "runtime_version_labels": {"io.zion-eval.declib.version": "4.4.1"},
    }
    monkeypatch.setattr(
        "zion_eval.orchestrator.inspect_docker_image",
        lambda _image: dict(runtime_image),
    )
    monkeypatch.setenv("CODEX_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    snapshot = {
        "schema_version": 1,
        "address_space": "rva",
        "image_base": 0,
        "decompiler_base": 0,
        "backend": "ghidra",
        "functions": [
            {
                "decompiler_address": "0x10",
                "rva": "0x10",
                "size": 4,
                "discovered_name": "sub_10",
            }
        ],
    }
    verdicts = {
        "0x10": {
            "verdict": "equivalent",
            "justification": "same parse role",
            "confidence": 0.9,
        }
    }
    launched_images: list[str] = []

    cache_seed = tmp_path / "cache-seed"
    cache_seed.mkdir()
    cache_config = {
        "schema_version": 1,
        "key": "a" * 64,
        "analysis_recipe_version": 1,
        "manifest_sha256": "b" * 64,
    }
    cache_ensures: list[dict] = []

    def fake_ensure_cache(**arguments):
        cache_ensures.append(arguments)
        return SimpleNamespace(
            state_seed=cache_seed,
            configuration=lambda: dict(cache_config),
        )

    monkeypatch.setattr(
        "zion_eval.orchestrator.ensure_project_cache",
        fake_ensure_cache,
    )

    def fake_reverse(
        config, _binary, _base, _count, _backend, layout, *, project_seed=None
    ):
        launched_images.append(config.image)
        if (layout.reverse_output / "stage_result.json").exists():
            return False
        assert project_seed == cache_seed
        atomic_write_json(layout.reverse_output / "function_snapshot.json", snapshot)
        atomic_write_json(
            layout.reverse_output / "predictions.json",
            {"0x10": {"name": "parse"}},
        )
        atomic_write_json(
            layout.reverse_output / "submitted_addresses.json",
            [{"rva": "0x10", "name": "parse", "submitted_address": "0x10"}],
        )
        atomic_write_json(
            layout.reverse_output / "stage_result.json", {"status": "completed"}
        )
        return True

    def fake_grade(
        config, _binary, _base, _backend, _packet, layout, *, project_seed=None
    ):
        launched_images.append(config.image)
        if (layout.grade_output / "stage_result.json").exists():
            return False
        assert project_seed == cache_seed
        atomic_write_json(layout.grade_output / "function_snapshot.json", snapshot)
        atomic_write_json(layout.grade_output / "verdicts.json", verdicts)
        atomic_write_json(
            layout.grade_output / "stage_result.json", {"status": "completed"}
        )
        return True

    monkeypatch.setattr("zion_eval.orchestrator._run_reverse_container", fake_reverse)
    monkeypatch.setattr("zion_eval.orchestrator._run_grade_container", fake_grade)

    config = EvaluationRunConfig(
        manifest_path=manifest,
        target_id="fixture",
        image="zion-eval:test",
        reverser_provider="codex",
        reverser_model="reverse-v1",
        grader_provider="claude",
        grader_model="grade-v1",
        runs_directory=tmp_path / "runs",
        run_id="integration-run",
        count=1,
    )
    layout = run_evaluation(config)
    assert json.loads((layout.root / "scores.json").read_text(encoding="utf-8"))[
        "semantic_accuracy"
    ] == 1.0
    monkeypatch.delenv("CODEX_API_KEY")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    run_evaluation(replace(config, resume=True))
    assert len(cache_ensures) == 1
    monkeypatch.setenv("CODEX_API_KEY", "test-key")

    def fake_regrade(**arguments):
        launched_images.append(arguments["image"])
        output_dir = arguments["output_dir"]
        atomic_write_json(output_dir / "function_snapshot.json", snapshot)
        atomic_write_json(output_dir / "verdicts.json", verdicts)
        atomic_write_json(output_dir / "stage_result.json", {"status": "completed"})

    monkeypatch.setattr("zion_eval.orchestrator._invoke_grade_container", fake_regrade)
    regrade = regrade_evaluation(
        RegradeConfig(
            manifest_path=manifest,
            run_directory=layout.root,
            image="zion-eval:test",
            grader_provider="codex",
            grader_model="grade-v2",
        )
    )
    assert json.loads(
        (regrade / "regrade_result.json").read_text(encoding="utf-8")
    )["status"] == "completed"
    assert launched_images and set(launched_images) == {image_id}
    assert len(cache_ensures) == 2

    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'truth_address_space = "rva"', 'truth_address_space = "va"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(OrchestrationError, match="truth address space"):
        regrade_evaluation(
            RegradeConfig(
                manifest_path=manifest,
                run_directory=layout.root,
                image="zion-eval:test",
                grader_provider="codex",
                grader_model="grade-v3",
            )
        )

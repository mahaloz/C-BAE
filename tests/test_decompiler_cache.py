from __future__ import annotations

import json
from pathlib import Path

import pytest

from zion_eval.artifacts import atomic_write_json, sha256_file
from zion_eval.decompiler_cache import (
    DecompilerCacheError,
    ensure_project_cache,
    project_cache_key,
)
from zion_eval.docker_runner import ContainerResult


IMAGE_A = "sha256:" + "1" * 64
IMAGE_B = "sha256:" + "2" * 64


def _fake_analysis_container(calls: list[object]):
    def run(spec: object) -> ContainerResult:
        calls.append(spec)
        by_destination = {
            mount.destination: mount for mount in spec.mounts  # type: ignore[attr-defined]
        }
        output = by_destination["/output"].source
        backend = spec.command[  # type: ignore[attr-defined]
            spec.command.index("--backend") + 1  # type: ignore[attr-defined]
        ]
        if backend == "ida":
            project = output / "project" / "ida"
            project.mkdir(parents=True)
            (project / "target.i64").write_bytes(b"analyzed-project")
        else:
            project = output / "project" / "target_ghidra"
            repository = project / "target_ghidra.rep"
            repository.mkdir(parents=True)
            (project / "target_ghidra.gpr").write_bytes(b"gpr")
            (repository / "project.prp").write_bytes(b"analyzed-project")
        binary_digest = sha256_file(by_destination["/input/target"].source)
        atomic_write_json(
            output / "analysis.json",
            {
                "schema_version": 1,
                "backend": backend,
                "binary_sha256": binary_digest,
                "binary_base": "0x0",
                "function_count": 1,
                "function_catalog_sha256": "f" * 64,
            },
        )
        atomic_write_json(output / "stage_result.json", {"status": "completed"})
        return ContainerResult(tuple(spec.command), 0, "", "")  # type: ignore[attr-defined]

    return run


def test_project_cache_key_commits_to_binary_image_backend_and_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    first, context = project_cache_key(
        binary_sha256=digest, runtime_image_id=IMAGE_A, backend="ghidra"
    )
    again, _ = project_cache_key(
        binary_sha256=digest, runtime_image_id=IMAGE_A, backend="GHIDRA"
    )
    different_binary, _ = project_cache_key(
        binary_sha256="b" * 64, runtime_image_id=IMAGE_A, backend="ghidra"
    )
    different_image, _ = project_cache_key(
        binary_sha256=digest, runtime_image_id=IMAGE_B, backend="ghidra"
    )
    monkeypatch.setattr(
        "zion_eval.decompiler_cache.ANALYSIS_RECIPE_VERSION", 2
    )
    different_recipe, _ = project_cache_key(
        binary_sha256=digest, runtime_image_id=IMAGE_A, backend="ghidra"
    )
    ida, ida_context = project_cache_key(
        binary_sha256=digest, runtime_image_id=IMAGE_A, backend="IDA"
    )

    assert first == again
    assert len(
        {first, different_binary, different_image, different_recipe, ida}
    ) == 5
    assert context["binary_name"] == "target"
    assert context["project_name"] == "target_ghidra"
    assert ida_context["project_name"] == "ida/target.i64"
    with pytest.raises(DecompilerCacheError, match="immutable"):
        project_cache_key(
            binary_sha256=digest,
            runtime_image_id="zion-function-eval:latest",
            backend="ghidra",
        )
    with pytest.raises(DecompilerCacheError, match="requires the 'ida' or 'ghidra'"):
        project_cache_key(
            binary_sha256=digest, runtime_image_id=IMAGE_A, backend="angr"
        )


def test_ida_cache_accepts_a_saved_i64_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    calls: list[object] = []
    monkeypatch.setattr(
        "zion_eval.decompiler_cache.run_container", _fake_analysis_container(calls)
    )

    entry = ensure_project_cache(
        binary_path=binary,
        binary_sha256=sha256_file(binary),
        runtime_image_id=IMAGE_A,
        backend="ida",
        cache_root=tmp_path / "cache",
        decompiler_timeout_seconds=30,
        container_user="123:456",
    )

    assert len(calls) == 1
    assert entry.state_seed.joinpath(
        "decompiler-project", "ida", "target.i64"
    ).read_bytes() == b"analyzed-project"


def test_cache_miss_builds_without_credentials_and_hit_skips_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "identity-bearing-binary-name"
    binary.write_bytes(b"fixture")
    calls: list[object] = []
    monkeypatch.setattr(
        "zion_eval.decompiler_cache.run_container", _fake_analysis_container(calls)
    )

    arguments = {
        "binary_path": binary,
        "binary_sha256": sha256_file(binary),
        "runtime_image_id": IMAGE_A,
        "backend": "ghidra",
        "cache_root": tmp_path / "cache",
        "decompiler_timeout_seconds": 30,
        "container_user": "123:456",
    }
    first = ensure_project_cache(**arguments)
    second = ensure_project_cache(**arguments)

    assert first.root == second.root
    assert len(calls) == 1
    spec = calls[0]
    assert spec.environment_names == ()  # type: ignore[attr-defined]
    assert spec.environment == {}  # type: ignore[attr-defined]
    assert spec.command[0] == "stage-analyze"  # type: ignore[attr-defined]
    command_text = "\0".join(spec.command)  # type: ignore[attr-defined]
    assert "--provider" not in command_text
    assert "--model" not in command_text
    assert "grading_packet" not in command_text
    assert str(binary.resolve()) not in command_text
    assert {mount.destination for mount in spec.mounts} == {  # type: ignore[attr-defined]
        "/input/target",
        "/output",
        "/state",
    }
    assert first.state_seed.joinpath("decompiler-project").is_dir()
    assert first.state_seed.joinpath("decompiler-analysis.json").is_file()


def test_corrupt_cache_is_not_seeded_and_is_rebuilt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    calls: list[object] = []
    monkeypatch.setattr(
        "zion_eval.decompiler_cache.run_container", _fake_analysis_container(calls)
    )
    arguments = {
        "binary_path": binary,
        "binary_sha256": sha256_file(binary),
        "runtime_image_id": IMAGE_A,
        "backend": "ghidra",
        "cache_root": tmp_path / "cache",
        "decompiler_timeout_seconds": 30,
        "container_user": "123:456",
    }
    first = ensure_project_cache(**arguments)
    poisoned = (
        first.state_seed
        / "decompiler-project"
        / "target_ghidra"
        / "target_ghidra.rep"
        / "project.prp"
    )
    poisoned.write_bytes(b"post-agent-poison")

    rebuilt = ensure_project_cache(**arguments)

    assert len(calls) == 2
    assert rebuilt.root == first.root
    assert poisoned.read_bytes() == b"analyzed-project"
    assert json.loads((rebuilt.root / "manifest.json").read_text())["kind"] == (
        "pristine-decompiler-project"
    )


def test_unexpected_seed_entry_forces_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    calls: list[object] = []
    monkeypatch.setattr(
        "zion_eval.decompiler_cache.run_container", _fake_analysis_container(calls)
    )
    arguments = {
        "binary_path": binary,
        "binary_sha256": sha256_file(binary),
        "runtime_image_id": IMAGE_A,
        "backend": "ghidra",
        "cache_root": tmp_path / "cache",
        "decompiler_timeout_seconds": 30,
        "container_user": "123:456",
    }
    first = ensure_project_cache(**arguments)
    (first.state_seed / "authoritative_names.txt").write_text(
        "must never reach an agent", encoding="utf-8"
    )

    rebuilt = ensure_project_cache(**arguments)

    assert len(calls) == 2
    assert not (rebuilt.state_seed / "authoritative_names.txt").exists()

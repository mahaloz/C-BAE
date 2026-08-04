from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from zion_eval.docker_runner import (
    BindMount,
    ContainerSpec,
    DockerRunError,
    NeutralStagingError,
    build_docker_command,
    neutral_agent_staging,
    run_container,
)


def test_docker_command_uses_read_only_root_and_exact_mount(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()

    with neutral_agent_staging(
        binary_path=binary, output_dir=output, state_dir=state
    ) as staging:
        spec = ContainerSpec(
            image="zion-eval:test",
            command=["stage-reverse"],
            mounts=[BindMount(staging.binary, "/input/target")],
            environment_names=[],
            user="1234:5678",
            mount_source_root=staging.root,
        )

        command = build_docker_command(spec, "zion-agent-0123456789ab")

        assert "--read-only" in command
        assert command[command.index("--user") + 1] == "1234:5678"
        assert (
            f"type=bind,src={staging.binary},dst=/input/target,readonly" in command
        )
        assert str(binary.resolve()) not in "\0".join(command)
        assert command[-2:] == ["zion-eval:test", "stage-reverse"]


def test_direct_bind_source_is_rejected(tmp_path: Path) -> None:
    binary = tmp_path / "identity-bearing-target"
    binary.write_bytes(b"fixture")
    spec = ContainerSpec(
        image="zion-eval:test",
        command=["stage-reverse"],
        mounts=[BindMount(binary, "/input/target")],
        environment_names=[],
    )

    with pytest.raises(DockerRunError, match="neutral mount_source_root"):
        build_docker_command(spec, "zion-agent-0123456789ab")

    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()
    with neutral_agent_staging(
        binary_path=binary, output_dir=output, state_dir=state
    ) as staging:
        escaping = ContainerSpec(
            image="zion-eval:test",
            command=["stage-reverse"],
            mounts=[BindMount(binary, "/input/target")],
            environment_names=[],
            mount_source_root=staging.root,
        )
        with pytest.raises(DockerRunError, match="escapes neutral staging root"):
            build_docker_command(escaping, "zion-agent-0123456789ab")


def test_staging_copies_input_recovers_outputs_discards_state_and_skips_links(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "original-target"
    binary.write_bytes(b"fixture")
    output = tmp_path / "real-output"
    state = tmp_path / "real-state"
    output.mkdir()
    state.mkdir()

    staged_root: Path
    with neutral_agent_staging(
        binary_path=binary, output_dir=output, state_dir=state
    ) as staging:
        staged_root = staging.root
        assert staging.binary.read_bytes() == b"fixture"
        assert staging.binary.stat().st_ino != binary.stat().st_ino
        assert staging.binary.stat().st_mode & 0o777 == 0o600
        (staging.output / "partial.json").write_text("{}", encoding="utf-8")
        (staging.state / "cache").mkdir()
        (staging.state / "cache" / "entry").write_text("saved", encoding="utf-8")
        (staging.output / "unsafe-link").symlink_to(binary)

    assert (output / "partial.json").read_text(encoding="utf-8") == "{}"
    assert not (state / "cache").exists()
    assert not (output / "unsafe-link").exists()
    assert not staged_root.exists()


def test_state_recovery_requires_explicit_opt_in(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()

    with neutral_agent_staging(
        binary_path=binary,
        output_dir=output,
        state_dir=state,
        recover_state=True,
    ) as staging:
        (staging.state / "diagnostic").write_text("saved", encoding="utf-8")

    assert (state / "diagnostic").read_text(encoding="utf-8") == "saved"


def test_pristine_state_seed_is_copied_to_independent_writable_inodes(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    output = tmp_path / "output"
    state = tmp_path / "state"
    seed = tmp_path / "cache" / "state-seed"
    project = seed / "decompiler-project" / "target_ghidra"
    project.mkdir(parents=True)
    cached_file = project / "database"
    cached_file.write_bytes(b"pristine")
    cached_file.chmod(0o400)
    project.chmod(0o500)
    output.mkdir()
    state.mkdir()
    original_file_mode = cached_file.stat().st_mode & 0o777
    original_dir_mode = project.stat().st_mode & 0o777

    with neutral_agent_staging(
        binary_path=binary,
        output_dir=output,
        state_dir=state,
        state_seed=seed,
    ) as staging:
        clone = (
            staging.state / "decompiler-project" / "target_ghidra" / "database"
        )
        source_stat = cached_file.stat()
        clone_stat = clone.stat()
        assert (source_stat.st_dev, source_stat.st_ino) != (
            clone_stat.st_dev,
            clone_stat.st_ino,
        )
        assert clone_stat.st_mode & 0o777 == 0o600
        clone.write_bytes(b"agent mutation")
        assert cached_file.read_bytes() == b"pristine"

    assert cached_file.stat().st_mode & 0o777 == original_file_mode
    assert project.stat().st_mode & 0o777 == original_dir_mode


def test_state_seed_rejects_links_before_agent_launch(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"fixture")
    output = tmp_path / "output"
    state = tmp_path / "state"
    seed = tmp_path / "state-seed"
    outside = tmp_path / "private-truth"
    output.mkdir()
    state.mkdir()
    seed.mkdir()
    outside.write_text("secret", encoding="utf-8")
    (seed / "unsafe").symlink_to(outside)

    with pytest.raises(NeutralStagingError, match="link or special"):
        with neutral_agent_staging(
            binary_path=binary,
            output_dir=output,
            state_dir=state,
            state_seed=seed,
        ):
            pytest.fail("staging must fail before yielding to a container launch")

    assert outside.read_text(encoding="utf-8") == "secret"


def test_non_neutral_container_name_is_rejected() -> None:
    spec = ContainerSpec(
        image="zion-eval:test", command=[], mounts=[], environment_names=[]
    )

    with pytest.raises(DockerRunError, match="target-neutral"):
        build_docker_command(spec, "zion-reverse-secret-target")


def test_interruption_forcibly_removes_only_randomized_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        if command[:2] == ["docker", "run"]:
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("zion_eval.docker_runner.subprocess.run", fake_run)
    spec = ContainerSpec(
        image="zion-eval:test", command=[], mounts=[], environment_names=[]
    )

    with pytest.raises(KeyboardInterrupt):
        run_container(spec)

    launched_name = calls[0][calls[0].index("--name") + 1]
    assert launched_name.startswith("zion-agent-")
    assert calls[1] == ("docker", "rm", "--force", launched_name)


def test_missing_secret_fails_before_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    spec = ContainerSpec(
        image="zion-eval:test",
        command=[],
        mounts=[],
        environment_names=["ANTHROPIC_API_KEY"],
    )

    with pytest.raises(DockerRunError, match="ANTHROPIC_API_KEY"):
        build_docker_command(spec, "zion-agent-0123456789ab")

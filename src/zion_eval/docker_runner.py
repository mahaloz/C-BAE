"""Minimal Docker CLI adapter used by the trusted host orchestrator."""

from __future__ import annotations

from contextlib import contextmanager
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Iterator, Mapping, Sequence


class DockerRunError(RuntimeError):
    """Raised when an evaluation stage container cannot be completed."""


class NeutralStagingError(DockerRunError):
    """A neutral bind-mount staging area could not be prepared or recovered."""


_STAGING_PARENT = Path("/tmp")
_STAGING_PREFIX = "zion-agent-"
_STAGING_NAME_RE = re.compile(r"^zion-agent-[a-z0-9_]{8}$")
_CONTAINER_NAME_RE = re.compile(r"^zion-agent-[0-9a-f]{12}$")


@dataclass(frozen=True)
class BindMount:
    source: Path
    destination: str
    read_only: bool = True

    def argument(self) -> str:
        resolved = self.source.resolve(strict=True)
        fields = ["type=bind", f"src={resolved}", f"dst={self.destination}"]
        if self.read_only:
            fields.append("readonly")
        return ",".join(fields)


@dataclass(frozen=True)
class ContainerResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass
class ContainerSpec:
    image: str
    command: Sequence[str]
    mounts: Sequence[BindMount]
    environment_names: Sequence[str]
    environment: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: int = 6 * 60 * 60
    platform: str = "linux/amd64"
    tmpfs_size: str = "4g"
    raise_on_failure: bool = True
    user: str | None = None
    mount_source_root: Path | None = None


@dataclass(frozen=True, slots=True)
class NeutralStagePaths:
    """Identity-free host paths used as the only agent bind sources."""

    root: Path
    binary: Path
    output: Path
    state: Path
    packet: Path | None = None


def _container_name() -> str:
    """Return a randomized name that cannot contain a target or user run id."""

    return f"zion-agent-{uuid.uuid4().hex[:12]}"


@contextmanager
def neutral_agent_staging(
    *,
    binary_path: Path,
    output_dir: Path,
    state_dir: Path,
    packet_path: Path | None = None,
    state_seed: Path | None = None,
    recover_state: bool = False,
) -> Iterator[NeutralStagePaths]:
    """Stage every bind source under a fresh neutral root and recover writes.

    The binary and grading packet are copied so the neutral tree owns
    independent private snapshots with predictable permissions. This also
    avoids Docker Desktop bind-mount inconsistencies observed for hard-linked
    large binaries under ``/tmp``. Output is copied back after the container
    has stopped, including
    when the caller raises due to timeout, interruption, or launch failure.
    State is ephemeral by default because completed/failed stages never resume
    it and Ghidra projects can be many gigabytes; callers may explicitly request
    recovery for diagnostics. A trusted state seed (for example, a closed
    pre-agent Ghidra project) is copied into the neutral state with independent
    inodes before launch. Container-created links and special files are never
    followed.
    """

    real_output = _existing_directory(output_dir, "output_dir")
    real_state = _existing_directory(state_dir, "state_dir")
    root = Path(
        tempfile.mkdtemp(prefix=_STAGING_PREFIX, dir=str(_STAGING_PARENT))
    ).resolve(strict=True)
    os.chmod(root, 0o700)
    try:
        input_dir = _new_private_directory(root / "input")
        staged_output = _new_private_directory(root / "output")
        staged_state = _new_private_directory(root / "state")
        if state_seed is not None:
            _copy_seed_tree(state_seed, staged_state)
        staged_binary = input_dir / "target"
        _stage_regular_file(binary_path, staged_binary)
        staged_packet: Path | None = None
        if packet_path is not None:
            staged_packet = input_dir / "grading_packet.json"
            _stage_regular_file(packet_path, staged_packet)
        paths = NeutralStagePaths(
            root=root,
            binary=staged_binary,
            output=staged_output,
            state=staged_state,
            packet=staged_packet,
        )
    except BaseException:
        _remove_staging_root(root)
        raise

    stage_error: BaseException | None = None
    stage_traceback: TracebackType | None = None
    try:
        yield paths
    except BaseException as error:
        stage_error = error
        stage_traceback = error.__traceback__

    copyback_error: BaseException | None = None
    try:
        _copy_tree_contents(staged_output, real_output)
        if recover_state:
            _copy_tree_contents(staged_state, real_state)
    except BaseException as error:
        copyback_error = NeutralStagingError(
            f"failed to recover neutral stage artifacts from {root}: {error}"
        )

    cleanup_error: BaseException | None = None
    if copyback_error is None:
        try:
            _remove_staging_root(root)
        except BaseException as error:
            cleanup_error = NeutralStagingError(
                f"failed to clean neutral staging directory {root}: {error}"
            )

    if stage_error is not None:
        cause = copyback_error or cleanup_error
        if cause is not None:
            raise stage_error.with_traceback(stage_traceback) from cause
        raise stage_error.with_traceback(stage_traceback)
    if copyback_error is not None:
        # Keep the only complete artifact tree for manual recovery.
        raise copyback_error
    if cleanup_error is not None:
        raise cleanup_error


def _existing_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise NeutralStagingError(f"{label} is unavailable: {path}: {error}") from error
    if not resolved.is_dir():
        raise NeutralStagingError(f"{label} must be a directory: {resolved}")
    return resolved


def _new_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def _regular_file(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise NeutralStagingError(f"{label} is unavailable: {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise NeutralStagingError(f"{label} must be a regular file: {resolved}")
    return resolved


def _stage_regular_file(source: Path, destination: Path) -> None:
    resolved = _regular_file(source, "staged input")
    _copy_regular_file(resolved, destination)


def _copy_regular_file(source: Path, destination: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, flags)
    temporary_fd = -1
    temporary_name: str | None = None
    try:
        source_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(source_metadata.st_mode):
            raise NeutralStagingError(f"refusing to copy non-regular file: {source}")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=".zion-copy-", dir=str(destination.parent)
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
    finally:
        os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _copy_tree_contents(source: Path, destination: Path) -> None:
    """Merge regular files/directories without following untrusted links."""

    source_metadata = source.lstat()
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise NeutralStagingError(f"staged writable root is not a directory: {source}")
    os.chmod(source, 0o700, follow_symlinks=False)
    for entry in os.scandir(source):
        entry_path = Path(entry.path)
        metadata = entry.stat(follow_symlinks=False)
        destination_path = destination / entry.name
        if stat.S_ISDIR(metadata.st_mode):
            os.chmod(entry_path, 0o700, follow_symlinks=False)
            if destination_path.exists():
                target_metadata = destination_path.lstat()
                if not stat.S_ISDIR(target_metadata.st_mode):
                    raise NeutralStagingError(
                        f"copyback directory collides with non-directory: {destination_path}"
                    )
            else:
                destination_path.mkdir(mode=0o700)
            _copy_tree_contents(entry_path, destination_path)
        elif stat.S_ISREG(metadata.st_mode):
            os.chmod(entry_path, 0o600, follow_symlinks=False)
            _copy_regular_file(entry_path, destination_path)
        # Symlinks, sockets, FIFOs, and devices are transient or unsafe and are
        # intentionally not copied into the canonical run directory.


def _copy_seed_tree(source: Path, destination: Path) -> None:
    """Copy a trusted cache seed without links, hard links, or source mutation."""

    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise NeutralStagingError(f"state seed is unavailable: {source}: {error}") from error
    if not stat.S_ISDIR(source_metadata.st_mode) or source.is_symlink():
        raise NeutralStagingError("state seed must be a real directory")

    for entry in os.scandir(source):
        entry_path = Path(entry.path)
        metadata = entry.stat(follow_symlinks=False)
        destination_path = destination / entry.name
        if stat.S_ISDIR(metadata.st_mode):
            destination_path.mkdir(mode=0o700)
            _copy_seed_tree(entry_path, destination_path)
        elif stat.S_ISREG(metadata.st_mode):
            _copy_regular_file(entry_path, destination_path)
            # A mutable stage must never share an inode with the pristine seed.
            source_stat = entry_path.stat()
            destination_stat = destination_path.stat()
            if (
                source_stat.st_dev == destination_stat.st_dev
                and source_stat.st_ino == destination_stat.st_ino
            ):
                raise NeutralStagingError(
                    f"state seed copy unexpectedly shares an inode: {entry_path}"
                )
        else:
            raise NeutralStagingError(
                f"state seed contains a link or special file: {entry_path}"
            )


def _validated_staging_root(path: Path) -> Path:
    if path.is_symlink():
        raise NeutralStagingError("neutral staging root cannot be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise NeutralStagingError("neutral staging root must be a directory")
    expected_parent = _STAGING_PARENT.resolve(strict=True)
    if resolved.parent != expected_parent or not _STAGING_NAME_RE.fullmatch(resolved.name):
        raise NeutralStagingError(
            f"bind source root is not a randomized neutral /tmp directory: {resolved}"
        )
    return resolved


def _remove_staging_root(root: Path) -> None:
    resolved = _validated_staging_root(root)

    def repair_permissions(function: object, path: str, _error: object) -> None:
        candidate = Path(path)
        if not candidate.is_symlink():
            os.chmod(candidate, 0o700)
        function(path)  # type: ignore[operator]

    shutil.rmtree(resolved, onerror=repair_permissions)


def build_docker_command(spec: ContainerSpec, name: str) -> list[str]:
    missing = [key for key in spec.environment_names if not os.environ.get(key)]
    if missing:
        raise DockerRunError(
            "missing required provider environment variable(s): " + ", ".join(missing)
        )

    if not _CONTAINER_NAME_RE.fullmatch(name):
        raise DockerRunError("container name must be randomized and target-neutral")

    if spec.mounts:
        if spec.mount_source_root is None:
            raise DockerRunError("bind mounts require a neutral mount_source_root")
        mount_root = _validated_staging_root(spec.mount_source_root)
        for mount in spec.mounts:
            source = mount.source.resolve(strict=True)
            try:
                source.relative_to(mount_root)
            except ValueError as error:
                raise DockerRunError(
                    f"bind source escapes neutral staging root: {source}"
                ) from error

    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--platform",
        spec.platform,
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,size={spec.tmpfs_size}",
        "--security-opt",
        "no-new-privileges:true",
    ]
    if spec.user:
        command.extend(("--user", spec.user))
    for mount in spec.mounts:
        command.extend(("--mount", mount.argument()))
    for key in spec.environment_names:
        command.extend(("--env", key))
    for key, value in sorted(spec.environment.items()):
        command.extend(("--env", f"{key}={value}"))
    command.append(spec.image)
    command.extend(spec.command)
    return command


def run_container(spec: ContainerSpec) -> ContainerResult:
    """Run one agent and remove its randomized container before propagating errors."""

    name = _container_name()
    command = build_docker_command(spec, name)
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=spec.timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise DockerRunError("docker CLI was not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        try:
            _force_remove_container(name)
        except DockerRunError as cleanup_error:
            raise DockerRunError(
                f"container {name} exceeded {spec.timeout_seconds} seconds and "
                "could not be confirmed stopped"
            ) from cleanup_error
        raise DockerRunError(
            f"container {name} exceeded {spec.timeout_seconds} seconds"
        ) from exc
    except BaseException as exc:
        try:
            _force_remove_container(name)
        except DockerRunError as cleanup_error:
            raise exc from cleanup_error
        raise

    result = ContainerResult(
        command=tuple(command),
        returncode=process.returncode,
        stdout=process.stdout,
        stderr=process.stderr,
    )
    if result.returncode and spec.raise_on_failure:
        raise DockerRunError(
            f"container {name} exited with {result.returncode}: "
            f"{result.stderr.strip()[-2000:]}"
        )
    return result


def _force_remove_container(name: str) -> None:
    try:
        removal = subprocess.run(
            ["docker", "rm", "--force", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DockerRunError(
            f"could not remove interrupted container {name}: {error}"
        ) from error
    if removal.returncode == 0:
        return

    try:
        inspection = subprocess.run(
            ["docker", "container", "inspect", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DockerRunError(
            f"could not confirm interrupted container {name} was removed: {error}"
        ) from error
    if inspection.returncode == 0:
        raise DockerRunError(
            f"interrupted container {name} is still running after forced removal"
        )
    absent_markers = ("no such object", "no such container")
    if not any(marker in inspection.stderr.lower() for marker in absent_markers):
        raise DockerRunError(
            f"could not confirm interrupted container {name} is absent: "
            f"{inspection.stderr.strip()[-500:]}"
        )

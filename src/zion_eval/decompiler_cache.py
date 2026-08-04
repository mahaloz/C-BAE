"""Trusted, content-addressed caches for pristine decompiler projects.

The cache is built before either model is started.  Agent containers receive a
private byte-for-byte copy of the cached project through neutral staging; the
canonical cache is never mounted into an agent container and agent state is
never promoted back into it.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Any, Iterator, Mapping

from .artifacts import (
    atomic_write_json,
    atomic_write_text,
    canonical_json_sha256,
    read_json,
    secure_directory,
    sha256_file,
)
from .docker_runner import (
    BindMount,
    ContainerSpec,
    neutral_agent_staging,
    run_container,
)


CACHE_SCHEMA_VERSION = 1
ANALYSIS_RECIPE_VERSION = 1
_CACHE_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_PERSISTENT_BACKENDS = frozenset({"ida", "ghidra"})


class DecompilerCacheError(RuntimeError):
    """A pristine project cache could not be built or verified."""


@dataclass(frozen=True, slots=True)
class ProjectCacheEntry:
    key: str
    root: Path
    state_seed: Path
    manifest: Mapping[str, Any]

    def configuration(self) -> dict[str, Any]:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "key": self.key,
            "analysis_recipe_version": ANALYSIS_RECIPE_VERSION,
            "manifest_sha256": sha256_file(self.root / "manifest.json"),
        }


def project_cache_key(
    *, binary_sha256: str, runtime_image_id: str, backend: str
) -> tuple[str, dict[str, Any]]:
    """Return the cache key and the exact context it commits to."""

    normalized_backend = backend.strip().lower()
    if normalized_backend not in _PERSISTENT_BACKENDS:
        raise DecompilerCacheError(
            "persistent project caching requires the 'ida' or 'ghidra' backend"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", binary_sha256):
        raise DecompilerCacheError(
            "binary_sha256 must be 64 lowercase hexadecimal digits"
        )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", runtime_image_id):
        raise DecompilerCacheError(
            "runtime_image_id must be an immutable sha256 image ID"
        )
    context = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "analysis_recipe_version": ANALYSIS_RECIPE_VERSION,
        "binary_sha256": binary_sha256,
        "runtime_image_id": runtime_image_id,
        "backend": normalized_backend,
        # These neutral names are part of the decompiler project identity.
        "binary_name": "target",
        "project_name": (
            "ida/target.i64" if normalized_backend == "ida" else "target_ghidra"
        ),
    }
    return canonical_json_sha256(context), context


def ensure_project_cache(
    *,
    binary_path: Path,
    binary_sha256: str,
    runtime_image_id: str,
    backend: str,
    cache_root: Path,
    decompiler_timeout_seconds: int,
    container_user: str,
) -> ProjectCacheEntry:
    """Return a verified pristine project, building it once on a cache miss."""

    if decompiler_timeout_seconds <= 0:
        raise DecompilerCacheError("decompiler timeout must be positive")
    key, context = project_cache_key(
        binary_sha256=binary_sha256,
        runtime_image_id=runtime_image_id,
        backend=backend,
    )
    version_root = secure_directory(
        cache_root.resolve() / f"v{CACHE_SCHEMA_VERSION}"
    )
    locks = secure_directory(version_root / ".locks")
    entry_path = version_root / key
    with _cache_lock(locks / f"{key}.lock"):
        if entry_path.exists():
            try:
                return _validate_entry(entry_path, key=key, context=context)
            except DecompilerCacheError:
                _remove_invalid_entry(entry_path, version_root=version_root, key=key)

        temporary: Path | None = Path(
            tempfile.mkdtemp(prefix=f".{key}.build-", dir=str(version_root))
        )
        os.chmod(temporary, 0o700)
        try:
            _build_entry(
                temporary,
                binary_path=binary_path,
                binary_sha256=binary_sha256,
                runtime_image_id=runtime_image_id,
                backend=backend,
                context=context,
                decompiler_timeout_seconds=decompiler_timeout_seconds,
                container_user=container_user,
            )
            built = _validate_entry(temporary, key=key, context=context)
            os.replace(temporary, entry_path)
            temporary = None
            return ProjectCacheEntry(
                key=built.key,
                root=entry_path,
                state_seed=entry_path / "state-seed",
                manifest=built.manifest,
            )
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary)


@contextmanager
def _cache_lock(path: Path) -> Iterator[None]:
    secure_directory(path.parent)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _build_entry(
    root: Path,
    *,
    binary_path: Path,
    binary_sha256: str,
    runtime_image_id: str,
    backend: str,
    context: Mapping[str, Any],
    decompiler_timeout_seconds: int,
    container_user: str,
) -> None:
    container_output = secure_directory(root / "container-output")
    container_state = secure_directory(root / "container-state")
    command = (
        "stage-analyze",
        "--binary",
        "/input/target",
        "--output-dir",
        "/output",
        "--state-dir",
        "/state",
        "--backend",
        backend,
        "--decompiler-timeout-seconds",
        str(decompiler_timeout_seconds),
    )
    with neutral_agent_staging(
        binary_path=binary_path,
        output_dir=container_output,
        state_dir=container_state,
    ) as staging:
        result = run_container(
            ContainerSpec(
                image=runtime_image_id,
                command=command,
                mounts=(
                    BindMount(staging.binary, "/input/target", read_only=True),
                    BindMount(staging.output, "/output", read_only=False),
                    BindMount(staging.state, "/state", read_only=False),
                ),
                environment_names=(),
                timeout_seconds=2 * decompiler_timeout_seconds + 180,
                raise_on_failure=False,
                user=container_user,
                mount_source_root=staging.root,
            )
        )
    atomic_write_text(container_output / "container.stdout.log", result.stdout)
    atomic_write_text(container_output / "container.stderr.log", result.stderr)
    stage_result_path = container_output / "stage_result.json"
    stage_result = _read_object(stage_result_path, "analysis stage result")
    if result.returncode != 0 or stage_result.get("status") != "completed":
        error = stage_result.get("error", {})
        raise DecompilerCacheError(
            "pristine analysis container failed with "
            f"exit {result.returncode}: {json.dumps(error, sort_keys=True)}"
        )

    analysis_path = container_output / "analysis.json"
    analysis = _read_object(analysis_path, "analysis metadata")
    _validate_analysis_metadata(
        analysis,
        binary_sha256=binary_sha256,
        backend=backend,
    )
    project_source = container_output / "project"
    _validate_project_shape(project_source, backend=backend)

    state_seed = secure_directory(root / "state-seed")
    os.replace(project_source, state_seed / "decompiler-project")
    os.replace(analysis_path, state_seed / "decompiler-analysis.json")
    os.replace(stage_result_path, root / "build-stage-result.json")
    shutil.rmtree(container_output)
    shutil.rmtree(container_state)

    project_files = _attest_project_tree(state_seed / "decompiler-project")
    analysis_file = state_seed / "decompiler-analysis.json"
    manifest = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "kind": "pristine-decompiler-project",
        "context": dict(context),
        "analysis": {
            "size": analysis_file.stat().st_size,
            "sha256": sha256_file(analysis_file),
        },
        "project_files": project_files,
    }
    atomic_write_json(root / "manifest.json", manifest)


def _validate_entry(
    root: Path, *, key: str, context: Mapping[str, Any]
) -> ProjectCacheEntry:
    if not _CACHE_KEY_RE.fullmatch(key):
        raise DecompilerCacheError("invalid decompiler cache key")
    try:
        metadata = root.lstat()
    except OSError as error:
        raise DecompilerCacheError(f"cannot stat decompiler cache entry: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise DecompilerCacheError("decompiler cache entry is not a real directory")
    manifest = _read_object(root / "manifest.json", "decompiler cache manifest")
    if manifest.get("schema_version") != CACHE_SCHEMA_VERSION:
        raise DecompilerCacheError("decompiler cache schema version differs")
    if manifest.get("kind") != "pristine-decompiler-project":
        raise DecompilerCacheError("decompiler cache kind differs")
    if manifest.get("context") != dict(context):
        raise DecompilerCacheError("decompiler cache context differs")

    state_seed = root / "state-seed"
    project = state_seed / "decompiler-project"
    analysis_path = state_seed / "decompiler-analysis.json"
    try:
        seed_metadata = state_seed.lstat()
    except OSError as error:
        raise DecompilerCacheError(f"cached state seed is unavailable: {error}") from error
    if not stat.S_ISDIR(seed_metadata.st_mode) or state_seed.is_symlink():
        raise DecompilerCacheError("cached state seed must be a real directory")
    if {entry.name for entry in os.scandir(state_seed)} != {
        "decompiler-project",
        "decompiler-analysis.json",
    }:
        raise DecompilerCacheError("cached state seed contains unexpected entries")
    _require_regular_file(root / "manifest.json", "decompiler cache manifest")
    _require_regular_file(analysis_path, "cached analysis metadata")
    _validate_project_shape(project, backend=str(context["backend"]))
    analysis_attestation = manifest.get("analysis")
    if not isinstance(analysis_attestation, dict) or analysis_attestation != {
        "size": analysis_path.stat().st_size,
        "sha256": sha256_file(analysis_path),
    }:
        raise DecompilerCacheError("cached analysis metadata differs from its attestation")
    analysis = _read_object(analysis_path, "cached analysis metadata")
    _validate_analysis_metadata(
        analysis,
        binary_sha256=str(context["binary_sha256"]),
        backend=str(context["backend"]),
    )

    expected_files = manifest.get("project_files")
    actual_files = _attest_project_tree(project)
    if expected_files != actual_files:
        raise DecompilerCacheError("cached decompiler project differs from its attestation")
    return ProjectCacheEntry(
        key=key,
        root=root,
        state_seed=state_seed,
        manifest=manifest,
    )


def _validate_analysis_metadata(
    value: Mapping[str, Any], *, binary_sha256: str, backend: str
) -> None:
    expected_keys = {
        "schema_version",
        "backend",
        "binary_sha256",
        "binary_base",
        "function_count",
        "function_catalog_sha256",
    }
    if set(value) != expected_keys or value.get("schema_version") != 1:
        raise DecompilerCacheError("analysis metadata has an invalid contract")
    if value.get("backend") != backend or value.get("binary_sha256") != binary_sha256:
        raise DecompilerCacheError(
            "analysis metadata does not match the requested binary/backend"
        )
    binary_base = value.get("binary_base")
    fingerprint = value.get("function_catalog_sha256")
    count = value.get("function_count")
    if not isinstance(binary_base, str) or not re.fullmatch(
        r"0x[0-9a-f]+", binary_base
    ):
        raise DecompilerCacheError("analysis metadata has an invalid binary base")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise DecompilerCacheError("analysis metadata has an invalid function count")
    if not isinstance(fingerprint, str) or not re.fullmatch(
        r"[0-9a-f]{64}", fingerprint
    ):
        raise DecompilerCacheError("analysis metadata has an invalid function fingerprint")


def _validate_project_shape(project: Path, *, backend: str) -> None:
    try:
        metadata = project.lstat()
    except OSError as error:
        raise DecompilerCacheError(
            f"cached decompiler project is unavailable: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or project.is_symlink():
        raise DecompilerCacheError(
            "cached decompiler project must be a real directory"
        )
    if backend == "ida":
        database = project / "ida" / "target.i64"
        if not database.is_file() or database.is_symlink():
            raise DecompilerCacheError("cached IDA project has an unexpected layout")
        return
    if backend == "ghidra":
        inner = project / "target_ghidra"
        gpr = inner / "target_ghidra.gpr"
        repository = inner / "target_ghidra.rep"
        if (
            not gpr.is_file()
            or gpr.is_symlink()
            or not repository.is_dir()
            or repository.is_symlink()
        ):
            raise DecompilerCacheError("cached Ghidra project has an unexpected layout")
        return
    raise DecompilerCacheError(f"unsupported persistent backend {backend!r}")


def _attest_project_tree(project: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            relative = path.relative_to(project).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                records.append({"path": relative, "type": "directory"})
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                if path.name.endswith(".lock") or path.name.endswith(".lock~"):
                    raise DecompilerCacheError(
                        "cached decompiler project contains an active lock artifact: "
                        f"{relative}"
                    )
                records.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": metadata.st_size,
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise DecompilerCacheError(
                    "cached decompiler project contains a link or special file: "
                    f"{relative}"
                )

    visit(project)
    if not records:
        raise DecompilerCacheError("cached decompiler project is empty")
    return records


def _require_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DecompilerCacheError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise DecompilerCacheError(f"{label} must be a regular non-symlink file")


def _read_object(path: Path, label: str) -> dict[str, Any]:
    _require_regular_file(path, label)
    try:
        value = read_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DecompilerCacheError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise DecompilerCacheError(f"{label} must be a JSON object")
    return value


def _remove_invalid_entry(entry: Path, *, version_root: Path, key: str) -> None:
    if not _CACHE_KEY_RE.fullmatch(key):
        raise DecompilerCacheError("refusing to remove an invalid cache key")
    resolved_parent = entry.parent.resolve(strict=True)
    if resolved_parent != version_root.resolve(strict=True) or entry.name != key:
        raise DecompilerCacheError("refusing to remove a cache path outside its version root")
    if entry.is_symlink() or not entry.is_dir():
        entry.unlink(missing_ok=True)
    else:
        shutil.rmtree(entry)

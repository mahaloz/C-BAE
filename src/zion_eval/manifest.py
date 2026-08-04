"""Versioned target-manifest loading and artifact verification."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .errors import HashMismatchError, ManifestError

SUPPORTED_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class ManifestDefaults:
    """Defaults inherited by targets that do not override them."""

    function_count: int
    decompiler_backend: str


@dataclass(frozen=True, slots=True)
class TargetManifest:
    """One fully resolved evaluation target."""

    id: str
    binary_path: Path
    truth_path: Path
    binary_sha256: str
    truth_sha256: str
    format: str
    architecture: str
    truth_address_space: str
    image_base: int
    default_backend: str
    default_count: int

    @property
    def binary(self) -> Path:
        """Compatibility alias for the resolved stripped binary path."""

        return self.binary_path

    @property
    def truth(self) -> Path:
        """Compatibility alias for the resolved private truth path."""

        return self.truth_path


@dataclass(frozen=True, slots=True)
class EvaluationManifest:
    """A validated manifest and its targets."""

    path: Path
    schema_version: int
    defaults: ManifestDefaults
    targets: tuple[TargetManifest, ...]

    def get_target(self, target_id: str) -> TargetManifest:
        for target in self.targets:
            if target.id == target_id:
                return target
        available = ", ".join(target.id for target in self.targets)
        raise ManifestError(
            f"unknown target {target_id!r}; available targets: {available or '(none)'}"
        )


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return the lowercase SHA-256 of *path* without loading it into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be a TOML table")
    return value


def _string(table: dict[str, Any], field: str, context: str) -> str:
    value = table.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{context}.{field} must be a nonempty string")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ManifestError(f"{field} must be a positive integer")
    return value


def _artifact_path(root: Path, value: str, field: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise ManifestError(f"{field} must be relative to the manifest directory")
    resolved = (root / relative).resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"{field} escapes the manifest directory: {value!r}") from exc
    return resolved


def _checksum(table: dict[str, Any], field: str, context: str) -> str:
    value = _string(table, field, context)
    if not _SHA256_RE.fullmatch(value):
        raise ManifestError(f"{context}.{field} must contain 64 hexadecimal digits")
    return value.lower()


def load_manifest(
    path: str | Path = "mapping.toml", *, verify_hashes: bool = False
) -> EvaluationManifest:
    """Load a version-1 manifest and resolve artifact paths against its directory.

    Hash verification is opt-in because loading the two current targets otherwise
    reads hundreds of megabytes. Production validation and runs should pass
    ``verify_hashes=True`` (or call :func:`verify_target_files`).
    """

    manifest_path = Path(path).resolve(strict=False)
    try:
        with manifest_path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError("manifest root must be a TOML table")

    version = document.get("schema_version")
    if isinstance(version, bool) or version != SUPPORTED_SCHEMA_VERSION:
        raise ManifestError(
            f"unsupported schema_version {version!r}; expected {SUPPORTED_SCHEMA_VERSION}"
        )

    defaults_table = _mapping(document.get("defaults"), "defaults")
    defaults = ManifestDefaults(
        function_count=_positive_int(
            defaults_table.get("function_count"), "defaults.function_count"
        ),
        decompiler_backend=_string(
            defaults_table, "decompiler_backend", "defaults"
        ).lower(),
    )

    raw_targets = document.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ManifestError("targets must be a nonempty TOML array of tables")

    root = manifest_path.parent.resolve()
    targets: list[TargetManifest] = []
    seen_ids: set[str] = set()
    for position, raw_target in enumerate(raw_targets):
        context = f"targets[{position}]"
        table = _mapping(raw_target, context)
        target_id = _string(table, "id", context)
        if not _ID_RE.fullmatch(target_id):
            raise ManifestError(
                f"{context}.id may contain only letters, digits, '.', '_', and '-'"
            )
        if target_id in seen_ids:
            raise ManifestError(f"duplicate target id {target_id!r}")
        seen_ids.add(target_id)

        binary_format = _string(table, "format", context).lower()
        if binary_format not in {"elf", "pe"}:
            raise ManifestError(f"{context}.format must be 'elf' or 'pe'")
        architecture = _string(table, "architecture", context).lower()
        address_space = _string(table, "truth_address_space", context).lower()
        if address_space not in {"rva", "va"}:
            raise ManifestError(
                f"{context}.truth_address_space must be 'rva' or 'va'"
            )
        image_base = table.get("image_base")
        if isinstance(image_base, bool) or not isinstance(image_base, int):
            raise ManifestError(f"{context}.image_base must be an integer")
        if not 0 <= image_base <= (1 << 64) - 1:
            raise ManifestError(f"{context}.image_base must be an unsigned 64-bit value")

        backend = table.get("decompiler_backend", defaults.decompiler_backend)
        if not isinstance(backend, str) or not backend.strip():
            raise ManifestError(f"{context}.decompiler_backend must be nonempty")
        count = _positive_int(
            table.get("function_count", defaults.function_count),
            f"{context}.function_count",
        )
        binary = _artifact_path(
            root, _string(table, "binary", context), f"{context}.binary"
        )
        truth = _artifact_path(
            root, _string(table, "truth", context), f"{context}.truth"
        )
        target = TargetManifest(
            id=target_id,
            binary_path=binary,
            truth_path=truth,
            binary_sha256=_checksum(table, "binary_sha256", context),
            truth_sha256=_checksum(table, "truth_sha256", context),
            format=binary_format,
            architecture=architecture,
            truth_address_space=address_space,
            image_base=image_base,
            default_backend=backend.lower(),
            default_count=count,
        )
        if verify_hashes:
            verify_target_files(target)
        targets.append(target)

    return EvaluationManifest(
        path=manifest_path,
        schema_version=version,
        defaults=defaults,
        targets=tuple(targets),
    )


def verify_file(path: Path, expected_sha256: str, label: str) -> None:
    if not path.is_file():
        raise ManifestError(f"{label} does not exist or is not a regular file: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise HashMismatchError(
            f"{label} SHA-256 mismatch: expected {expected_sha256}, got {actual}"
        )


def verify_target_files(target: TargetManifest) -> None:
    """Verify both the stripped binary and private truth for one target."""

    verify_file(target.binary_path, target.binary_sha256, f"{target.id} binary")
    verify_file(target.truth_path, target.truth_sha256, f"{target.id} truth")

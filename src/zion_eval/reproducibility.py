"""Docker runtime identity and immutable-artifact attestations."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping

from .artifacts import atomic_write_json, read_json, sha256_file


class ReproducibilityError(RuntimeError):
    """A runtime or frozen artifact no longer matches its recorded identity."""


def inspect_docker_image(image: str) -> dict[str, Any]:
    """Resolve a mutable Docker reference to an exact local image identity."""

    if not isinstance(image, str) or not image.strip():
        raise ReproducibilityError("Docker image reference must be nonempty")
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError as error:
        raise ReproducibilityError("docker CLI was not found on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise ReproducibilityError("Docker image inspection exceeded 60 seconds") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip()[-1000:]
        raise ReproducibilityError(
            f"cannot inspect Docker image {image!r}: {detail or 'docker inspect failed'}"
        )
    try:
        documents = json.loads(completed.stdout)
        if not isinstance(documents, list) or len(documents) != 1:
            raise ValueError("expected one image document")
        document = documents[0]
        if not isinstance(document, dict):
            raise ValueError("image document is not an object")
        image_id = document["Id"]
        architecture = document["Architecture"]
        operating_system = document["Os"]
        if not all(
            isinstance(value, str) and value
            for value in (image_id, architecture, operating_system)
        ):
            raise ValueError("image identity fields are missing")
        raw_digests = document.get("RepoDigests") or []
        if not isinstance(raw_digests, list) or not all(
            isinstance(value, str) for value in raw_digests
        ):
            raise ValueError("RepoDigests is malformed")
        config = document.get("Config") or {}
        raw_labels = (config.get("Labels") or {}) if isinstance(config, dict) else {}
        if not isinstance(raw_labels, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_labels.items()
        ):
            raise ValueError("image labels are malformed")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReproducibilityError(
            f"Docker returned an invalid image inspection document: {error}"
        ) from error

    version_labels = {
        key: value
        for key, value in sorted(raw_labels.items())
        if key.startswith("io.zion-eval.")
    }
    return {
        "requested_reference": image,
        "image_id": image_id,
        "repo_digests": sorted(set(raw_digests)),
        "platform": f"{operating_system}/{architecture}",
        "runtime_version_labels": version_labels,
    }


def file_attestation(path: Path) -> dict[str, Any]:
    """Hash one regular, non-symlink artifact and record its exact size."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReproducibilityError(f"cannot stat frozen artifact {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ReproducibilityError(f"frozen artifact is not a regular file: {path}")
    return {
        "name": path.name,
        "size": metadata.st_size,
        "sha256": sha256_file(path),
    }


def write_or_verify_attestation(
    path: Path,
    *,
    kind: str,
    files: Mapping[str, Path],
    context: Mapping[str, Any],
    allow_create: bool,
) -> dict[str, Any]:
    """Create an artifact lock once, or verify every byte against the lock."""

    if not kind.strip() or not files:
        raise ValueError("attestation kind and files must be nonempty")
    document = {
        "schema_version": 1,
        "kind": kind,
        "context": dict(context),
        "files": {
            label: file_attestation(file_path)
            for label, file_path in sorted(files.items())
        },
    }
    if path.exists():
        existing = read_json(path)
        if existing != document:
            raise ReproducibilityError(
                f"frozen {kind} artifacts differ from {path.name}"
            )
        return document
    if not allow_create:
        raise ReproducibilityError(
            f"frozen {kind} attestation is missing: {path}"
        )
    atomic_write_json(path, document, mode=0o400)
    return document

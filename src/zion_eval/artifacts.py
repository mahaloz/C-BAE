"""Small, dependency-free helpers for reproducible run artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def secure_directory(path: Path, mode: int = 0o700) -> Path:
    """Create *path* and make its permissions no broader than ``mode``."""

    path.mkdir(parents=True, exist_ok=True)
    current = path.stat().st_mode & 0o777
    if current & ~mode:
        path.chmod(mode)
    return path


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Atomically replace *path* with UTF-8 text in the same directory."""

    secure_directory(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    """Write stable, human-readable JSON with an atomic rename."""

    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    atomic_write_text(path, payload + "\n", mode=mode)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def new_run_id(_target_id: str | None = None) -> str:
    """Return a target-neutral, collision-resistant run identifier."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-eval-{secrets.token_hex(6)}"

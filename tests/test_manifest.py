from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from zion_eval.errors import HashMismatchError, ManifestError
from zion_eval.manifest import load_manifest, verify_target_files


REPOSITORY = Path(__file__).resolve().parents[1]


def test_seed_manifest_resolves_and_verifies_current_targets() -> None:
    manifest = load_manifest(REPOSITORY / "mapping.toml")

    assert manifest.schema_version == 1
    assert manifest.defaults.function_count == 100
    assert [target.id for target in manifest.targets] == [
        "bedrock-server-linux-1.21.0.03",
        "minecraft-china-client-windows-1.16.201",
    ]
    linux, windows = manifest.targets
    assert linux.binary_path == (REPOSITORY / "stripped/binary1").resolve()
    assert linux.truth_address_space == "va"
    assert linux.image_base == 0
    assert windows.format == "pe"
    assert windows.image_base == 0x140000000
    assert windows.default_count == 100
    assert windows.default_backend == "ida"

    # These scans ensure mapping.toml remains pinned to the checked-in samples.
    for target in manifest.targets:
        verify_target_files(target)


def _write_fixture_manifest(tmp_path: Path, *, target_extra: str = "") -> Path:
    binary = tmp_path / "target.bin"
    truth = tmp_path / "truth.json"
    binary.write_bytes(b"binary")
    truth.write_text("{}", encoding="utf-8")
    checksum = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    path = tmp_path / "mapping.toml"
    path.write_text(
        f"""schema_version = 1
[defaults]
function_count = 7
decompiler_backend = "angr"

[[targets]]
id = "fixture"
binary = "target.bin"
truth = "truth.json"
binary_sha256 = "{checksum(binary)}"
truth_sha256 = "{checksum(truth)}"
format = "elf"
architecture = "x86_64"
truth_address_space = "rva"
image_base = 0x0
{target_extra}
""",
        encoding="utf-8",
    )
    return path


def test_target_can_override_defaults(tmp_path: Path) -> None:
    path = _write_fixture_manifest(
        tmp_path, target_extra='function_count = 3\ndecompiler_backend = "ghidra"'
    )
    target = load_manifest(path, verify_hashes=True).get_target("fixture")

    assert target.default_count == 3
    assert target.default_backend == "ghidra"


def test_hash_mismatch_is_fatal(tmp_path: Path) -> None:
    path = _write_fixture_manifest(tmp_path)
    (tmp_path / "target.bin").write_bytes(b"changed")

    with pytest.raises(HashMismatchError, match="SHA-256 mismatch"):
        load_manifest(path, verify_hashes=True)


def test_artifact_paths_cannot_escape_manifest_root(tmp_path: Path) -> None:
    path = _write_fixture_manifest(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        'binary = "target.bin"', 'binary = "../outside.bin"'
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ManifestError, match="escapes"):
        load_manifest(path)


@pytest.mark.parametrize(
    "replacement, message",
    [
        ("schema_version = 99", "unsupported schema_version"),
        ('truth_address_space = "file"', "truth_address_space"),
        ("function_count = 0", "positive integer"),
    ],
)
def test_manifest_rejects_unsupported_values(
    tmp_path: Path, replacement: str, message: str
) -> None:
    path = _write_fixture_manifest(tmp_path)
    text = path.read_text(encoding="utf-8")
    if replacement.startswith("schema"):
        text = text.replace("schema_version = 1", replacement)
    elif replacement.startswith("truth"):
        text = text.replace('truth_address_space = "rva"', replacement)
    else:
        text = text.replace("function_count = 7", replacement)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ManifestError, match=message):
        load_manifest(path)

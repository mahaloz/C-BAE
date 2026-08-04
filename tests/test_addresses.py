from __future__ import annotations

import json
from pathlib import Path

import pytest

from zion_eval.addresses import (
    FunctionSnapshot,
    canonical_rva,
    load_function_snapshot,
    parse_address,
    parse_prediction_json,
    to_rva,
)
from zion_eval.errors import (
    AddressError,
    AddressNotFoundError,
    AmbiguousAddressError,
    DuplicateAddressError,
    DuplicateJSONKeyError,
)


def test_canonical_rva_and_declared_address_spaces() -> None:
    assert canonical_rva("0X0000AbC") == "0xabc"
    assert canonical_rva(0) == "0x0"
    assert to_rva("0x140001000", address_space="va", image_base=0x140000000) == "0x1000"
    assert to_rva("0x1000", address_space="rva", image_base=0x140000000) == "0x1000"


@pytest.mark.parametrize("value", [True, -1, 1 << 64, "1000", "0x", "-0x1"])
def test_parse_address_rejects_noncanonical_or_out_of_range_values(value: object) -> None:
    with pytest.raises(AddressError):
        parse_address(value)  # type: ignore[arg-type]


def test_snapshot_resolves_unique_rva_and_va() -> None:
    snapshot = FunctionSnapshot.from_addresses(
        ["0x1000", "0x2000"], image_base=0x140000000
    )

    assert snapshot.resolve("0x1000") == "0x1000"
    assert snapshot.resolve("0x140002000") == "0x2000"
    with pytest.raises(AddressNotFoundError):
        snapshot.resolve("0x140003000")


def test_snapshot_rejects_ambiguous_interpretation() -> None:
    snapshot = FunctionSnapshot.from_addresses(
        ["0x1000", "0x140001000"], image_base=0x140000000
    )

    with pytest.raises(AmbiguousAddressError, match="ambiguously"):
        snapshot.resolve("0x140001000")


def test_prediction_parser_detects_raw_json_duplicate_keys() -> None:
    snapshot = FunctionSnapshot.from_addresses(["0x1000"], image_base=0)
    payload = '{"0x1000":{"name":"one"},"0x1000":{"name":"two"}}'

    with pytest.raises(DuplicateJSONKeyError):
        parse_prediction_json(payload, snapshot)


def test_prediction_parser_detects_post_normalization_duplicates() -> None:
    snapshot = FunctionSnapshot.from_addresses(["0x1000"], image_base=0x140000000)
    payload = (
        '{"0x1000":{"name":"one"},'
        '"0x140001000":{"name":"two"}}'
    )

    with pytest.raises(DuplicateAddressError, match="both normalize"):
        parse_prediction_json(payload, snapshot, expected_count=2)


def test_prediction_parser_enforces_exact_schema_and_count() -> None:
    snapshot = FunctionSnapshot.from_addresses(["0x1000"], image_base=0)

    with pytest.raises(AddressError, match="exactly 2"):
        parse_prediction_json('{"0x1000":{"name":"ok"}}', snapshot, expected_count=2)
    with pytest.raises(AddressError, match="only the 'name'"):
        parse_prediction_json(
            '{"0x1000":{"name":"ok","rationale":"no"}}', snapshot
        )
    with pytest.raises(AddressError, match="nonempty"):
        parse_prediction_json('{"0x1000":{"name":"  "}}', snapshot)


def test_prediction_names_support_long_authoritative_symbols() -> None:
    snapshot = FunctionSnapshot.from_addresses(["0x1000"], image_base=0)
    name = "A" * 10191
    payload = json.dumps({"0x1000": {"name": name}})

    prediction = parse_prediction_json(payload, snapshot, expected_count=1)[0]
    assert prediction.name == name


def test_load_snapshot_understands_embedded_va_metadata_and_explicit_rva(
    tmp_path: Path,
) -> None:
    path = tmp_path / "functions.json"
    path.write_text(
        json.dumps(
            {
                "image_base": "0x140000000",
                "address_space": "va",
                "functions": [
                    {"address": "0x140001000"},
                    {"rva": "0x2000"},
                ],
            }
        ),
        encoding="utf-8",
    )

    snapshot = load_function_snapshot(path, image_base=0, address_space="rva")
    assert snapshot.rvas == frozenset({"0x1000", "0x2000"})
    assert snapshot.image_base == 0x140000000

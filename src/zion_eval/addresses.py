"""Address parsing and unambiguous VA/RVA normalization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import (
    AddressError,
    AddressNotFoundError,
    AmbiguousAddressError,
    DuplicateAddressError,
    DuplicateJSONKeyError,
)

MAX_ADDRESS = (1 << 64) - 1
_HEX_ADDRESS_RE = re.compile(r"^0[xX]([0-9a-fA-F]+)$")


def parse_address(value: int | str) -> int:
    """Parse an unsigned 64-bit integer or ``0x``-prefixed hexadecimal string."""

    if isinstance(value, bool):
        raise AddressError("boolean values are not addresses")
    if isinstance(value, int):
        address = value
    elif isinstance(value, str):
        match = _HEX_ADDRESS_RE.fullmatch(value)
        if not match:
            raise AddressError(
                f"address {value!r} must be a 0x-prefixed hexadecimal value"
            )
        address = int(match.group(1), 16)
    else:
        raise AddressError(f"address must be an integer or hex string, got {type(value).__name__}")
    if not 0 <= address <= MAX_ADDRESS:
        raise AddressError(f"address {address!r} is outside the unsigned 64-bit range")
    return address


def canonical_rva(value: int | str) -> str:
    """Return the canonical lowercase, minimally padded lifted-RVA spelling."""

    return f"0x{parse_address(value):x}"


def to_rva(value: int | str, *, address_space: str, image_base: int) -> str:
    """Normalize an address from a declared address space (not a guess)."""

    address = parse_address(value)
    if address_space == "rva":
        return canonical_rva(address)
    if address_space != "va":
        raise AddressError("address_space must be 'rva' or 'va'")
    base = parse_address(image_base)
    if address < base:
        raise AddressError(
            f"VA {canonical_rva(address)} is below image base {canonical_rva(base)}"
        )
    return canonical_rva(address - base)


@dataclass(frozen=True, slots=True)
class FunctionSnapshot:
    """The immutable set of functions DecLib discovered before agent execution."""

    rvas: frozenset[str]
    image_base: int

    @classmethod
    def from_addresses(
        cls,
        addresses: Iterable[int | str],
        *,
        image_base: int,
        address_space: str = "rva",
    ) -> "FunctionSnapshot":
        base = parse_address(image_base)
        normalized = frozenset(
            to_rva(value, address_space=address_space, image_base=base)
            for value in addresses
        )
        if not normalized:
            raise AddressError("function snapshot is empty")
        return cls(rvas=normalized, image_base=base)

    def resolve(self, submitted_address: int | str) -> str:
        """Resolve a submission as RVA or VA only when exactly one function fits.

        The same candidate produced by both interpretations (notably image base
        zero) is unambiguous. Two different candidates are rejected instead of
        guessing which address convention the model intended.
        """

        raw = parse_address(submitted_address)
        candidates: set[str] = set()
        direct = canonical_rva(raw)
        if direct in self.rvas:
            candidates.add(direct)
        if raw >= self.image_base:
            rebased = canonical_rva(raw - self.image_base)
            if rebased in self.rvas:
                candidates.add(rebased)

        if not candidates:
            raise AddressNotFoundError(
                f"submitted address {canonical_rva(raw)} is not in the pre-agent "
                "function snapshot as either an RVA or VA"
            )
        if len(candidates) > 1:
            choices = ", ".join(sorted(candidates, key=parse_address))
            raise AmbiguousAddressError(
                f"submitted address {canonical_rva(raw)} ambiguously identifies {choices}"
            )
        return next(iter(candidates))


@dataclass(frozen=True, slots=True)
class Prediction:
    """One validated model prediction keyed by canonical lifted RVA."""

    rva: str
    name: str
    submitted_address: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rva": self.rva,
            "name": self.name,
            "submitted_address": self.submitted_address,
        }


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate raw JSON key {key!r}")
        result[key] = value
    return result


def decode_json_without_duplicates(payload: str) -> Any:
    """Decode JSON while rejecting duplicate keys at every object depth."""

    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
    except DuplicateJSONKeyError:
        raise
    except json.JSONDecodeError as exc:
        raise AddressError(f"prediction output is not valid JSON: {exc}") from exc


def normalize_predictions(
    document: Mapping[str, Any],
    snapshot: FunctionSnapshot,
    *,
    expected_count: int | None = None,
) -> tuple[Prediction, ...]:
    """Validate and normalize an already-decoded address-keyed prediction object."""

    if not isinstance(document, Mapping):
        raise AddressError("prediction output must be a JSON object keyed by address")
    if expected_count is not None:
        if (
            isinstance(expected_count, bool)
            or not isinstance(expected_count, int)
            or expected_count <= 0
        ):
            raise AddressError("expected_count must be a positive integer")
        if len(document) != expected_count:
            raise AddressError(
                f"prediction output has {len(document)} entries; expected exactly {expected_count}"
            )

    predictions: list[Prediction] = []
    normalized_seen: dict[str, str] = {}
    for raw_address, body in document.items():
        if not isinstance(raw_address, str):
            # JSON keys are strings, but this keeps direct Python callers honest.
            raise AddressError("prediction object keys must be address strings")
        rva = snapshot.resolve(raw_address)
        if rva in normalized_seen:
            raise DuplicateAddressError(
                f"submitted addresses {normalized_seen[rva]!r} and {raw_address!r} "
                f"both normalize to {rva}"
            )
        normalized_seen[rva] = raw_address

        if not isinstance(body, Mapping):
            raise AddressError(f"prediction {raw_address!r} must be an object")
        if set(body) != {"name"}:
            raise AddressError(
                f"prediction {raw_address!r} must contain only the 'name' field"
            )
        name = body.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AddressError(f"prediction {raw_address!r}.name must be nonempty")
        if len(name) > 32768 or any(ord(character) < 0x20 for character in name):
            raise AddressError(
                f"prediction {raw_address!r}.name contains control characters or is too long"
            )
        predictions.append(
            Prediction(
                rva=rva,
                name=name,
                submitted_address=canonical_rva(raw_address),
            )
        )
    return tuple(predictions)


def parse_prediction_json(
    payload: str,
    snapshot: FunctionSnapshot,
    *,
    expected_count: int | None = None,
) -> tuple[Prediction, ...]:
    """Decode, reject raw duplicate keys, and normalize prediction JSON."""

    document = decode_json_without_duplicates(payload)
    return normalize_predictions(document, snapshot, expected_count=expected_count)


def load_predictions(
    path: str | Path,
    snapshot: FunctionSnapshot,
    *,
    expected_count: int | None = None,
) -> tuple[Prediction, ...]:
    try:
        payload = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AddressError(f"cannot read predictions from {path}: {exc}") from exc
    return parse_prediction_json(payload, snapshot, expected_count=expected_count)


def _snapshot_entries(document: Any) -> tuple[list[tuple[int | str, str | None]], str | None, int | None]:
    """Extract addresses plus optional per-entry spaces from common snapshots."""

    declared_space: str | None = None
    declared_base: int | None = None
    body = document
    if isinstance(document, Mapping) and "functions" in document:
        body = document["functions"]
        if "address_space" in document:
            declared_space = document["address_space"]
        if "image_base" in document:
            declared_base = parse_address(document["image_base"])

    entries: list[tuple[int | str, str | None]] = []
    if isinstance(body, list):
        for position, item in enumerate(body):
            if isinstance(item, (str, int)) and not isinstance(item, bool):
                entries.append((item, None))
                continue
            if not isinstance(item, Mapping):
                raise AddressError(f"functions[{position}] has no usable address")
            for field in ("rva", "address", "entry", "entry_point", "start"):
                if field in item:
                    entries.append((item[field], "rva" if field == "rva" else None))
                    break
            else:
                raise AddressError(f"functions[{position}] has no usable address")
    elif isinstance(body, Mapping):
        for key in body:
            try:
                parse_address(key)
            except AddressError:
                continue
            entries.append((key, None))
    else:
        raise AddressError("function snapshot must be a list or address-keyed object")
    if not entries:
        raise AddressError("function snapshot contains no addresses")
    return entries, declared_space, declared_base


def load_function_snapshot(
    path: str | Path,
    *,
    image_base: int,
    address_space: str = "rva",
) -> FunctionSnapshot:
    """Load common DecLib snapshot shapes into canonical lifted RVAs."""

    try:
        payload = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AddressError(f"cannot read function snapshot from {path}: {exc}") from exc
    document = decode_json_without_duplicates(payload)
    entries, embedded_space, embedded_base = _snapshot_entries(document)
    effective_base = parse_address(embedded_base if embedded_base is not None else image_base)
    effective_space = embedded_space or address_space
    if effective_space not in {"rva", "va"}:
        raise AddressError("function snapshot address_space must be 'rva' or 'va'")
    normalized = [
        to_rva(value, address_space=item_space or effective_space, image_base=effective_base)
        for value, item_space in entries
    ]
    return FunctionSnapshot.from_addresses(
        normalized, image_base=effective_base, address_space="rva"
    )

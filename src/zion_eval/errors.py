"""Domain errors raised by the evaluation data layer."""

from __future__ import annotations


class EvaluationDataError(ValueError):
    """Base class for invalid manifests, artifacts, and evaluation data."""


class ManifestError(EvaluationDataError):
    """The target manifest is missing, malformed, or internally inconsistent."""


class HashMismatchError(ManifestError):
    """A target artifact does not match the hash pinned by its manifest."""


class TruthIndexError(EvaluationDataError):
    """Ground-truth data could not be validated or indexed."""


class AddressError(EvaluationDataError):
    """An address is malformed or cannot be normalized safely."""


class AddressNotFoundError(AddressError):
    """Neither interpretation of an address occurs in the function snapshot."""


class AmbiguousAddressError(AddressError):
    """Both VA and RVA interpretations resolve to different functions."""


class DuplicateAddressError(AddressError):
    """Two input addresses identify the same normalized function."""


class DuplicateJSONKeyError(AddressError):
    """A JSON object contains a repeated raw key."""


class ScoringError(EvaluationDataError):
    """An evaluation result cannot be scored deterministically."""

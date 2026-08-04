"""Deterministic fixed-N and gradeable-only evaluation scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .addresses import Prediction, canonical_rva
from .errors import ScoringError
from .truth import TruthRecord, classify_names, is_placeholder_name

GRADER_VERDICTS = frozenset(
    {"exact", "equivalent", "partial", "incorrect", "ungradable"}
)


@dataclass(frozen=True, slots=True)
class ScoredItem:
    rva: str
    predicted_name: str
    truth_name: str | None
    mangled_name: str | None
    grader_verdict: str | None
    category: str
    deterministic_exact: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "rva": self.rva,
            "predicted_name": self.predicted_name,
            "truth_name": self.truth_name,
            "mangled_name": self.mangled_name,
            "grader_verdict": self.grader_verdict,
            "category": self.category,
            "deterministic_exact": self.deterministic_exact,
        }


@dataclass(frozen=True, slots=True)
class ScoreCounts:
    exact: int
    equivalent: int
    partial: int
    incorrect: int
    ungradable: int
    infrastructure_failure: int

    @property
    def gradeable(self) -> int:
        return self.exact + self.equivalent + self.partial + self.incorrect

    def to_dict(self) -> dict[str, int]:
        return {
            "exact": self.exact,
            "equivalent": self.equivalent,
            "partial": self.partial,
            "incorrect": self.incorrect,
            "ungradable": self.ungradable,
            "infrastructure_failure": self.infrastructure_failure,
            "gradeable": self.gradeable,
        }


@dataclass(frozen=True, slots=True)
class ScoreReport:
    requested_count: int
    submitted_count: int
    counts: ScoreCounts
    exact_accuracy: float
    semantic_accuracy: float
    gradeable_exact_accuracy: float | None
    gradeable_semantic_accuracy: float | None
    items: tuple[ScoredItem, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "requested_count": self.requested_count,
            "submitted_count": self.submitted_count,
            "counts": self.counts.to_dict(),
            "exact_accuracy": self.exact_accuracy,
            "semantic_accuracy": self.semantic_accuracy,
            "gradeable_exact_accuracy": self.gradeable_exact_accuracy,
            "gradeable_semantic_accuracy": self.gradeable_semantic_accuracy,
            "items": [item.to_dict() for item in self.items],
        }


def _prediction_fields(prediction: Prediction | Mapping[str, Any]) -> tuple[str, str]:
    if isinstance(prediction, Mapping):
        rva = prediction.get("rva")
        name = prediction.get("name", prediction.get("predicted_name"))
    else:
        rva = prediction.rva
        name = prediction.name
    if not isinstance(rva, (str, int)) or isinstance(rva, bool):
        raise ScoringError("each prediction must have an RVA")
    if not isinstance(name, str) or not name:
        raise ScoringError(f"prediction at {rva!r} has no name")
    return canonical_rva(rva), name


def _truth_fields(
    record: TruthRecord | Mapping[str, Any] | None,
) -> tuple[str | None, str | None, bool]:
    if record is None:
        return None, None, False
    if isinstance(record, Mapping):
        name = record.get("name", record.get("truth_name"))
        mangled = record.get("mangled_name")
        explicit_gradeable = record.get("gradeable")
    else:
        name = record.name
        mangled = record.mangled_name
        explicit_gradeable = record.gradeable
    if name is not None and not isinstance(name, str):
        raise ScoringError("truth name must be a string or null")
    if mangled is not None and not isinstance(mangled, str):
        raise ScoringError("truth mangled_name must be a string or null")
    derived_gradeable, _ = classify_names(name, mangled)
    if explicit_gradeable is None:
        gradeable = derived_gradeable
    elif not isinstance(explicit_gradeable, bool):
        raise ScoringError("truth gradeable must be boolean")
    else:
        # A caller cannot accidentally override missing/generated truth into a
        # credit-bearing record.
        gradeable = explicit_gradeable and derived_gradeable
    return name, mangled, gradeable


def _verdict_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        verdict = value
    elif isinstance(value, Mapping):
        verdict = value.get("verdict")
    else:
        verdict = getattr(value, "verdict", None)
    if hasattr(verdict, "value"):
        verdict = verdict.value
    if not isinstance(verdict, str):
        raise ScoringError("grader verdict must be a string or contain a verdict field")
    verdict = verdict.lower()
    if verdict not in GRADER_VERDICTS:
        choices = ", ".join(sorted(GRADER_VERDICTS))
        raise ScoringError(f"unknown grader verdict {verdict!r}; expected one of {choices}")
    return verdict


def _canonical_mapping(mapping: Mapping[str, Any], label: str) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    origins: dict[str, str] = {}
    for raw_key, value in mapping.items():
        key = canonical_rva(raw_key)
        if key in normalized:
            raise ScoringError(
                f"duplicate normalized {label} keys {origins[key]!r} and {raw_key!r}"
            )
        normalized[key] = value
        origins[key] = str(raw_key)
    return normalized


def score_predictions(
    predictions: Sequence[Prediction | Mapping[str, Any]],
    truth_by_rva: Mapping[str, TruthRecord | Mapping[str, Any] | None],
    verdicts_by_rva: Mapping[str, Any],
    *,
    requested_count: int,
) -> ScoreReport:
    """Score selected predictions with fixed-N primary denominators.

    Literal equality with either usable authoritative spelling is deterministic.
    It overrides a conflicting grader verdict. A non-literal grader ``exact`` is
    treated as semantically equivalent, never as literal exact credit.
    """

    if (
        isinstance(requested_count, bool)
        or not isinstance(requested_count, int)
        or requested_count <= 0
    ):
        raise ScoringError("requested_count must be a positive integer")
    if len(predictions) > requested_count:
        raise ScoringError(
            f"received {len(predictions)} predictions for requested_count={requested_count}"
        )

    truth = _canonical_mapping(truth_by_rva, "truth")
    verdicts = _canonical_mapping(verdicts_by_rva, "verdict")
    seen_predictions: set[str] = set()
    items: list[ScoredItem] = []
    category_counts = {
        "exact": 0,
        "equivalent": 0,
        "partial": 0,
        "incorrect": 0,
        "ungradable": 0,
        "infrastructure_failure": requested_count - len(predictions),
    }

    for prediction in predictions:
        rva, predicted_name = _prediction_fields(prediction)
        if rva in seen_predictions:
            raise ScoringError(f"duplicate prediction for {rva}")
        seen_predictions.add(rva)
        truth_name, mangled_name, gradeable = _truth_fields(truth.get(rva))
        verdict = _verdict_value(verdicts.get(rva))
        exact_names = {
            value
            for value in (truth_name, mangled_name)
            if value and not is_placeholder_name(value)
        }
        deterministic_exact = gradeable and predicted_name in exact_names

        if deterministic_exact:
            category = "exact"
        elif not gradeable or verdict == "ungradable":
            category = "ungradable"
        elif verdict is None:
            category = "infrastructure_failure"
        elif verdict in {"exact", "equivalent"}:
            category = "equivalent"
        else:
            category = verdict
        category_counts[category] += 1
        items.append(
            ScoredItem(
                rva=rva,
                predicted_name=predicted_name,
                truth_name=truth_name,
                mangled_name=mangled_name,
                grader_verdict=verdict,
                category=category,
                deterministic_exact=deterministic_exact,
            )
        )

    counts = ScoreCounts(
        exact=category_counts["exact"],
        equivalent=category_counts["equivalent"],
        partial=category_counts["partial"],
        incorrect=category_counts["incorrect"],
        ungradable=category_counts["ungradable"],
        infrastructure_failure=category_counts["infrastructure_failure"],
    )
    gradeable = counts.gradeable
    return ScoreReport(
        requested_count=requested_count,
        submitted_count=len(predictions),
        counts=counts,
        exact_accuracy=counts.exact / requested_count,
        semantic_accuracy=(counts.exact + counts.equivalent) / requested_count,
        gradeable_exact_accuracy=counts.exact / gradeable if gradeable else None,
        gradeable_semantic_accuracy=(counts.exact + counts.equivalent) / gradeable
        if gradeable
        else None,
        items=tuple(items),
    )

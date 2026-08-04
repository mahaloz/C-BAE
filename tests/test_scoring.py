from __future__ import annotations

import pytest

from zion_eval.addresses import Prediction
from zion_eval.errors import ScoringError
from zion_eval.scoring import score_predictions
from zion_eval.truth import TruthRecord


def _prediction(rva: str, name: str) -> Prediction:
    return Prediction(rva=rva, name=name, submitted_address=rva)


def _truth(
    rva: str,
    name: str | None,
    mangled: str | None,
    *,
    gradeable: bool = True,
) -> TruthRecord:
    return TruthRecord(
        rva=rva,
        name=name,
        mangled_name=mangled,
        gradeable=gradeable,
        ungradable_reason=None if gradeable else "fixture",
    )


def test_fixed_n_and_gradeable_only_scores_with_exact_override() -> None:
    predictions = [
        _prediction("0x1", "Thing::run()"),
        _prediction("0x2", "_ZN5Thing4stopEv"),
        _prediction("0x3", "Thing::open()"),
        _prediction("0x4", "parser_helper"),
        _prediction("0x5", "sub_5000"),
    ]
    truth = {
        "0x1": _truth("0x1", "Thing::run()", "_ZN5Thing3runEv"),
        "0x2": _truth("0x2", "Thing::stop()", "_ZN5Thing4stopEv"),
        "0x3": _truth("0x3", "Thing::openFile()", "mangled_open"),
        "0x4": _truth("0x4", "Parser::readHeader()", "mangled_read"),
        "0x5": _truth("0x5", "sub_5000", "sub_5000", gradeable=False),
    }
    verdicts = {
        "0x1": "incorrect",  # deterministic equality overrides this
        "0x2": "partial",  # mangled equality also overrides this
        "0x3": "equivalent",
        "0x4": "partial",
        "0x5": "equivalent",  # unusable truth cannot earn credit
    }

    report = score_predictions(
        predictions, truth, verdicts, requested_count=6
    )

    assert report.counts.exact == 2
    assert report.counts.equivalent == 1
    assert report.counts.partial == 1
    assert report.counts.ungradable == 1
    assert report.counts.infrastructure_failure == 1
    assert report.counts.gradeable == 4
    assert report.exact_accuracy == pytest.approx(2 / 6)
    assert report.semantic_accuracy == pytest.approx(3 / 6)
    assert report.gradeable_exact_accuracy == pytest.approx(2 / 4)
    assert report.gradeable_semantic_accuracy == pytest.approx(3 / 4)


def test_nonliteral_grader_exact_only_earns_semantic_credit() -> None:
    report = score_predictions(
        [_prediction("0x1", "same semantic operation")],
        {"0x1": _truth("0x1", "Real::name()", "mangled")},
        {"0x1": {"verdict": "exact"}},
        requested_count=1,
    )

    assert report.counts.exact == 0
    assert report.counts.equivalent == 1
    assert report.semantic_accuracy == 1.0


def test_missing_truth_is_ungradable_and_missing_verdict_is_infrastructure() -> None:
    report = score_predictions(
        [_prediction("0x1", "guess"), _prediction("0x2", "guess")],
        {"0x2": _truth("0x2", "Truth::name()", "mangled")},
        {},
        requested_count=2,
    )

    assert report.counts.ungradable == 1
    assert report.counts.infrastructure_failure == 1
    assert report.gradeable_semantic_accuracy is None


def test_exact_matching_is_case_sensitive() -> None:
    report = score_predictions(
        [_prediction("0x1", "thing::run()")],
        {"0x1": _truth("0x1", "Thing::run()", None)},
        {"0x1": "incorrect"},
        requested_count=1,
    )
    assert report.counts.exact == 0
    assert report.counts.incorrect == 1


def test_scoring_rejects_duplicate_or_excess_predictions() -> None:
    duplicate = [_prediction("0x1", "one"), _prediction("0X01", "two")]
    with pytest.raises(ScoringError, match="duplicate prediction"):
        score_predictions(duplicate, {}, {}, requested_count=2)
    with pytest.raises(ScoringError, match="received 2"):
        score_predictions(duplicate, {}, {}, requested_count=1)


def test_score_report_is_json_serializable_shape() -> None:
    report = score_predictions([], {}, {}, requested_count=1).to_dict()
    assert report["counts"]["infrastructure_failure"] == 1  # type: ignore[index]
    assert report["items"] == []

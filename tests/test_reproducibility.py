from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zion_eval.reproducibility import (
    ReproducibilityError,
    inspect_docker_image,
    write_or_verify_attestation,
)


def test_docker_image_reference_resolves_to_id_and_version_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = [
        {
            "Id": "sha256:exact",
            "RepoDigests": ["example@sha256:digest"],
            "Architecture": "amd64",
            "Os": "linux",
            "Config": {
                "Labels": {
                    "io.zion-eval.declib.version": "4.4.1",
                    "unrelated": "ignored",
                }
            },
        }
    ]
    monkeypatch.setattr(
        "zion_eval.reproducibility.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(response), stderr=""
        ),
    )

    identity = inspect_docker_image("example:mutable")

    assert identity == {
        "requested_reference": "example:mutable",
        "image_id": "sha256:exact",
        "repo_digests": ["example@sha256:digest"],
        "platform": "linux/amd64",
        "runtime_version_labels": {"io.zion-eval.declib.version": "4.4.1"},
    }


def test_attestation_detects_edited_frozen_prediction(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.json"
    snapshot = tmp_path / "function_snapshot.json"
    predictions.write_text('{"0x10":{"name":"first"}}', encoding="utf-8")
    snapshot.write_text('{"functions":[{"rva":"0x10"}]}', encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    files = {"predictions": predictions, "function_snapshot": snapshot}

    write_or_verify_attestation(
        attestation,
        kind="reverse",
        files=files,
        context={"binary_sha256": "a" * 64},
        allow_create=True,
    )
    write_or_verify_attestation(
        attestation,
        kind="reverse",
        files=files,
        context={"binary_sha256": "a" * 64},
        allow_create=False,
    )

    predictions.write_text('{"0x10":{"name":"edited"}}', encoding="utf-8")
    with pytest.raises(ReproducibilityError, match="differ"):
        write_or_verify_attestation(
            attestation,
            kind="reverse",
            files=files,
            context={"binary_sha256": "a" * 64},
            allow_create=False,
        )


def test_missing_attestation_cannot_be_adopted_during_resume(tmp_path: Path) -> None:
    artifact = tmp_path / "predictions.json"
    artifact.write_text("{}", encoding="utf-8")

    with pytest.raises(ReproducibilityError, match="missing"):
        write_or_verify_attestation(
            tmp_path / "attestation.json",
            kind="reverse",
            files={"predictions": artifact},
            context={},
            allow_create=False,
        )

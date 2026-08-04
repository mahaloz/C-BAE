"""Trusted host orchestration and reverse/grader filesystem separation."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .addresses import Prediction, load_function_snapshot, load_predictions
from .artifacts import (
    atomic_write_json,
    atomic_write_text,
    canonical_json_sha256,
    new_run_id,
    read_json,
    secure_directory,
    sha256_file,
)
from .docker_runner import (
    BindMount,
    ContainerSpec,
    NeutralStagePaths,
    neutral_agent_staging,
    run_container,
)
from .decompiler_cache import ProjectCacheEntry, ensure_project_cache
from .manifest import load_manifest, verify_file
from .providers import decode_strict_json
from .reproducibility import (
    inspect_docker_image,
    write_or_verify_attestation,
)
from .scoring import ScoreReport, score_predictions
from .truth import TruthRecord, build_truth_index


class OrchestrationError(RuntimeError):
    """A run cannot be prepared or advanced safely."""


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVERSE_CONTAINER_TIMEOUT_SECONDS = 5 * 60 * 60


def _validated_run_id(value: str) -> str:
    if value in {".", ".."} or not _RUN_ID_RE.fullmatch(value):
        raise OrchestrationError(
            "run id must be 1-128 letters, digits, '.', '_', or '-' with no path separators"
        )
    return value


@dataclass(frozen=True, slots=True)
class RunLayout:
    root: Path
    reverse_output: Path
    reverse_state: Path
    private: Path
    grade_output: Path
    grade_state: Path

    @classmethod
    def create(
        cls,
        runs_directory: Path,
        target_id: str,
        run_id: str | None = None,
    ) -> "RunLayout":
        base = runs_directory.resolve()
        selected_id = _validated_run_id(run_id or new_run_id(target_id))
        root = (base / selected_id).resolve()
        try:
            root.relative_to(base)
        except ValueError as error:
            raise OrchestrationError("run directory escapes the configured runs root") from error
        if root.exists() and any(root.iterdir()):
            raise OrchestrationError(f"run directory already exists and is not empty: {root}")
        secure_directory(root)
        layout = cls(
            root=root,
            reverse_output=root / "reverse",
            reverse_state=root / "state" / "reverse",
            private=root / "private",
            grade_output=root / "private" / "grade",
            grade_state=root / "private" / "state" / "grade",
        )
        for directory in (
            layout.reverse_output,
            layout.reverse_state,
            layout.private,
            layout.grade_output,
            layout.grade_state,
        ):
            secure_directory(directory)
        return layout

    @classmethod
    def open(cls, root: Path) -> "RunLayout":
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            raise OrchestrationError(f"run path is not a directory: {resolved}")
        return cls(
            root=resolved,
            reverse_output=resolved / "reverse",
            reverse_state=resolved / "state" / "reverse",
            private=resolved / "private",
            grade_output=resolved / "private" / "grade",
            grade_state=resolved / "private" / "state" / "grade",
        )


@dataclass(frozen=True, slots=True)
class EvaluationRunConfig:
    manifest_path: Path
    target_id: str
    image: str
    reverser_provider: str
    reverser_model: str
    grader_provider: str
    grader_model: str
    runs_directory: Path = Path("runs")
    count: int | None = None
    backend: str | None = None
    timeout_seconds: int = 21_600
    decompiler_timeout_seconds: int = 21_600
    reverser_max_budget_usd: float | None = None
    grader_max_budget_usd: float | None = None
    reverser_reasoning_effort: str | None = None
    grader_reasoning_effort: str | None = None
    run_id: str | None = None
    resume: bool = False


@dataclass(frozen=True, slots=True)
class RegradeConfig:
    manifest_path: Path
    run_directory: Path
    image: str
    grader_provider: str
    grader_model: str
    backend: str | None = None
    timeout_seconds: int = 21_600
    decompiler_timeout_seconds: int = 21_600
    grader_max_budget_usd: float | None = None
    grader_reasoning_effort: str | None = None


def provider_credential_name(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized == "codex":
        return "CODEX_API_KEY"
    if normalized in {"claude", "claude-code", "claudecode"}:
        return "ANTHROPIC_API_KEY"
    raise OrchestrationError(
        f"unsupported provider {provider!r}; expected 'codex' or 'claude'"
    )


def provider_environment_names(provider: str) -> list[str]:
    normalized = provider.strip().lower()
    if normalized == "codex" and os.environ.get("CODEX_AUTH_JSON"):
        return ["CODEX_AUTH_JSON"]
    return [provider_credential_name(provider)]


def host_container_user() -> str:
    """Use the invoking non-root UID/GID so 0700 bind mounts remain writable."""

    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        raise OrchestrationError("host orchestration requires a POSIX user model")
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        raise OrchestrationError(
            "refusing to run evaluation agents as root; invoke zion-eval as a non-root user"
        )
    return f"{uid}:{gid}"


def reverse_mounts(staging: NeutralStagePaths) -> tuple[BindMount, ...]:
    """Return the complete reverser mount set from one neutral staging root."""

    mounts = (
        BindMount(staging.binary, "/input/target", read_only=True),
        BindMount(staging.output, "/output", read_only=False),
        BindMount(staging.state, "/state", read_only=False),
    )
    neutral_root = staging.root.resolve(strict=True)
    for mount in mounts:
        source = mount.source.resolve(strict=True)
        try:
            source.relative_to(neutral_root)
        except ValueError as error:
            raise OrchestrationError(
                "reverser bind source escapes its neutral staging root"
            ) from error
    return mounts


def build_grading_packet(
    predictions: Sequence[Prediction],
    truth_by_rva: Mapping[str, TruthRecord | None],
) -> dict[str, Any]:
    """Join only selected predictions to truth for the private grader input."""

    entries: list[dict[str, Any]] = []
    for prediction in predictions:
        truth = truth_by_rva.get(prediction.rva)
        if truth is None:
            entries.append(
                {
                    "address": prediction.rva,
                    "predicted_name": prediction.name,
                    "authoritative_names": [],
                    "gradable": False,
                    "ungradable_reason": "missing_truth",
                }
            )
            continue
        authoritative_names = list(
            dict.fromkeys(
                name
                for name in (truth.name, truth.mangled_name)
                if isinstance(name, str) and name in truth.exact_names
            )
        )
        entry: dict[str, Any] = {
            "address": prediction.rva,
            "predicted_name": prediction.name,
            "authoritative_names": authoritative_names,
            "gradable": truth.gradeable,
        }
        if not truth.gradeable:
            entry["ungradable_reason"] = truth.ungradable_reason or "unusable_truth"
        entries.append(entry)
    return {"schema_version": 1, "entries": entries}


def public_score_document(report: ScoreReport) -> dict[str, Any]:
    """Return aggregate scores without authoritative names or item-level truth."""

    full = report.to_dict()
    full.pop("items", None)
    return {"schema_version": 1, **full}


def write_run_configuration(layout: RunLayout, document: Mapping[str, Any]) -> Path:
    path = layout.root / "config.json"
    atomic_write_json(path, dict(document))
    return path


def run_evaluation(config: EvaluationRunConfig) -> RunLayout:
    """Run or resume one complete two-container evaluation."""

    manifest = load_manifest(config.manifest_path)
    target = manifest.get_target(config.target_id)
    count = config.count if config.count is not None else target.default_count
    backend = (config.backend or target.default_backend).lower()
    _validate_run_options(config, count=count, backend=backend)

    layout: RunLayout | None = None
    reverse_status: str | None = None
    grade_status: str | None = None
    frozen_project_cache_config: Any = None
    if config.resume:
        if not config.run_id:
            raise OrchestrationError("--resume requires --run-id")
        layout = RunLayout.open(
            config.runs_directory / _validated_run_id(config.run_id)
        )
        reverse_status = _stage_status(layout.reverse_output / "stage_result.json")
        grade_status = _stage_status(layout.grade_output / "stage_result.json")
        if reverse_status not in {None, "completed"}:
            raise OrchestrationError(
                "a failed reverse stage is immutable; start a new run instead"
            )
        if grade_status not in {None, "completed"}:
            raise OrchestrationError(
                "a failed grade stage is immutable; start a new run or regrade instead"
            )
        frozen_configuration = read_json(layout.root / "config.json")
        if not isinstance(frozen_configuration, dict):
            raise OrchestrationError("frozen run config.json must be an object")
        frozen_project_cache_config = frozen_configuration.get(
            "decompiler_project_cache"
        )
        required_providers: list[str] = []
        if reverse_status is None:
            required_providers.append(config.reverser_provider)
        if reverse_status in {None, "completed"} and grade_status is None:
            required_providers.append(config.grader_provider)
        _require_provider_credentials(*required_providers)
    else:
        _require_provider_credentials(
            config.reverser_provider, config.grader_provider
        )

    runtime_image = inspect_docker_image(config.image)
    truth_cache = _shared_truth_cache(manifest.path, target.id)
    verify_file(target.binary_path, target.binary_sha256, f"{target.id} binary")
    # A verified immutable cache avoids rereading a multi-hundred-MB truth file
    # on every batch entry; a missing/invalid cache verifies before any API spend.
    with build_truth_index(target, truth_cache):
        pass

    project_cache: ProjectCacheEntry | None = None
    needs_decompiler = not (
        config.resume
        and reverse_status == "completed"
        and grade_status == "completed"
    )
    if backend in {"ida", "ghidra"} and needs_decompiler:
        project_cache = ensure_project_cache(
            binary_path=target.binary_path,
            binary_sha256=target.binary_sha256,
            runtime_image_id=runtime_image["image_id"],
            backend=backend,
            cache_root=_shared_decompiler_cache(manifest.path),
            decompiler_timeout_seconds=config.decompiler_timeout_seconds,
            container_user=host_container_user(),
        )

    if layout is None:
        layout = RunLayout.create(
            config.runs_directory,
            target.id,
            run_id=config.run_id,
        )

    project_cache_configuration = None
    if project_cache is not None:
        project_cache_configuration = project_cache.configuration()
    elif config.resume and not needs_decompiler:
        project_cache_configuration = frozen_project_cache_config

    configuration = {
        "schema_version": 1,
        "target_id": target.id,
        "manifest_sha256": sha256_file(manifest.path),
        "binary_sha256": target.binary_sha256,
        "truth_sha256": target.truth_sha256,
        "image_base": f"0x{target.image_base:x}",
        "truth_address_space": target.truth_address_space,
        "binary_format": target.format,
        "architecture": target.architecture,
        "count": count,
        "backend": backend,
        "image": config.image,
        "runtime_image": runtime_image,
        "decompiler_project_cache": project_cache_configuration,
        "reverser": {
            "provider": provider_display_name(config.reverser_provider),
            "model": config.reverser_model,
            "max_budget_usd": config.reverser_max_budget_usd,
            "reasoning_effort": config.reverser_reasoning_effort,
        },
        "grader": {
            "provider": provider_display_name(config.grader_provider),
            "model": config.grader_model,
            "max_budget_usd": config.grader_max_budget_usd,
            "reasoning_effort": config.grader_reasoning_effort,
        },
        "timeout_seconds": config.timeout_seconds,
        "decompiler_timeout_seconds": config.decompiler_timeout_seconds,
    }
    _write_or_check_configuration(layout, configuration, resume=config.resume)
    configuration_sha256 = canonical_json_sha256(configuration)
    # Launch by immutable content ID, not by the mutable tag inspected above.
    runtime_config = replace(config, image=runtime_image["image_id"])

    try:
        reverse_launched = _run_reverse_container(
            runtime_config,
            target.binary_path,
            target.image_base,
            count,
            backend,
            layout,
            project_seed=project_cache.state_seed if project_cache else None,
        )
        reverse_attestation_path = layout.reverse_output / "attestation.json"
        write_or_verify_attestation(
            reverse_attestation_path,
            kind="reverse",
            files={
                "function_snapshot": layout.reverse_output / "function_snapshot.json",
                "predictions": layout.reverse_output / "predictions.json",
                "submitted_addresses": layout.reverse_output / "submitted_addresses.json",
            },
            context={
                "configuration_sha256": configuration_sha256,
                "binary_sha256": target.binary_sha256,
                "runtime_image_id": runtime_image["image_id"],
            },
            allow_create=reverse_launched,
        )
        snapshot = load_function_snapshot(
            layout.reverse_output / "function_snapshot.json",
            image_base=target.image_base,
            address_space="rva",
        )
        predictions = load_predictions(
            layout.reverse_output / "predictions.json",
            snapshot,
            expected_count=count,
        )

        with build_truth_index(target, truth_cache) as truth_index:
            truth_by_rva = truth_index.lookup_many(
                [prediction.rva for prediction in predictions]
            )
            packet = build_grading_packet(predictions, truth_by_rva)
            packet_path = layout.private / "grading_packet.json"
            atomic_write_json(packet_path, packet)
            grade_launched = _run_grade_container(
                runtime_config,
                target.binary_path,
                target.image_base,
                backend,
                packet_path,
                layout,
                project_seed=project_cache.state_seed if project_cache else None,
            )
            grade_attestation_path = layout.grade_output / "attestation.json"
            write_or_verify_attestation(
                grade_attestation_path,
                kind="grade",
                files={
                    "function_snapshot": layout.grade_output / "function_snapshot.json",
                    "grading_packet": packet_path,
                    "verdicts": layout.grade_output / "verdicts.json",
                },
                context={
                    "configuration_sha256": configuration_sha256,
                    "binary_sha256": target.binary_sha256,
                    "truth_sha256": target.truth_sha256,
                    "reverse_attestation_sha256": sha256_file(
                        reverse_attestation_path
                    ),
                    "runtime_image_id": runtime_image["image_id"],
                },
                allow_create=grade_launched,
            )
            verdicts = _strict_json_object(layout.grade_output / "verdicts.json")
            report = score_predictions(
                predictions,
                truth_by_rva,
                verdicts,
                requested_count=count,
            )

        atomic_write_json(layout.private / "scores-with-truth.json", report.to_dict())
        public_scores = public_score_document(report)
        atomic_write_json(layout.root / "scores.json", public_scores)
        atomic_write_json(
            layout.root / "run_result.json",
            {
                "schema_version": 1,
                "status": "completed",
                "run_id": layout.root.name,
                "configuration_sha256": configuration_sha256,
                "reverse_attestation_sha256": sha256_file(
                    reverse_attestation_path
                ),
                "grade_attestation_sha256": sha256_file(grade_attestation_path),
                "scores": public_scores,
            },
        )
        return layout
    except Exception as error:
        atomic_write_json(
            layout.root / "run_result.json",
            {
                "schema_version": 1,
                "status": "failed",
                "run_id": layout.root.name,
                "configuration_sha256": configuration_sha256,
                "error": {"type": type(error).__name__, "message": str(error)},
            },
        )
        raise


def regrade_evaluation(config: RegradeConfig) -> Path:
    """Grade frozen predictions in a fresh private sub-run."""

    layout = RunLayout.open(config.run_directory)
    original = read_json(layout.root / "config.json")
    if not isinstance(original, dict) or not isinstance(original.get("target_id"), str):
        raise OrchestrationError("run config.json has no target_id")
    manifest = load_manifest(config.manifest_path)
    target = manifest.get_target(original["target_id"])
    if original.get("binary_sha256") != target.binary_sha256:
        raise OrchestrationError("frozen run binary hash no longer matches the manifest")
    if original.get("truth_sha256") != target.truth_sha256:
        raise OrchestrationError("frozen run truth hash no longer matches the manifest")
    if original.get("image_base") != f"0x{target.image_base:x}":
        raise OrchestrationError("frozen run image base no longer matches the manifest")
    if original.get("truth_address_space") != target.truth_address_space:
        raise OrchestrationError(
            "frozen run truth address space no longer matches the manifest"
        )
    count = original.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise OrchestrationError("frozen run has an invalid function count")
    backend = (config.backend or original.get("backend") or target.default_backend).lower()
    original_runtime = original.get("runtime_image")
    if not isinstance(original_runtime, dict) or not isinstance(
        original_runtime.get("image_id"), str
    ):
        raise OrchestrationError("frozen run has no exact runtime image identity")
    _require_provider_credentials(config.grader_provider)
    runtime_image = inspect_docker_image(config.image)
    truth_cache = _shared_truth_cache(manifest.path, target.id)
    verify_file(target.binary_path, target.binary_sha256, f"{target.id} binary")
    with build_truth_index(target, truth_cache):
        pass
    project_cache: ProjectCacheEntry | None = None
    if backend in {"ida", "ghidra"}:
        project_cache = ensure_project_cache(
            binary_path=target.binary_path,
            binary_sha256=target.binary_sha256,
            runtime_image_id=runtime_image["image_id"],
            backend=backend,
            cache_root=_shared_decompiler_cache(manifest.path),
            decompiler_timeout_seconds=config.decompiler_timeout_seconds,
            container_user=host_container_user(),
        )
    original_configuration_sha256 = canonical_json_sha256(original)
    reverse_attestation_path = layout.reverse_output / "attestation.json"
    write_or_verify_attestation(
        reverse_attestation_path,
        kind="reverse",
        files={
            "function_snapshot": layout.reverse_output / "function_snapshot.json",
            "predictions": layout.reverse_output / "predictions.json",
            "submitted_addresses": layout.reverse_output / "submitted_addresses.json",
        },
        context={
            "configuration_sha256": original_configuration_sha256,
            "binary_sha256": target.binary_sha256,
            "runtime_image_id": original_runtime["image_id"],
        },
        allow_create=False,
    )

    snapshot = load_function_snapshot(
        layout.reverse_output / "function_snapshot.json",
        image_base=target.image_base,
        address_space="rva",
    )
    predictions = load_predictions(
        layout.reverse_output / "predictions.json",
        snapshot,
        expected_count=count,
    )
    suffix = new_run_id("regrade")
    regrade_root = secure_directory(layout.private / "regrades" / suffix)
    grade_output = secure_directory(regrade_root / "grade")
    grade_state = secure_directory(regrade_root / "state")
    regrade_configuration = {
        "schema_version": 1,
        "source_run_id": layout.root.name,
        "source_configuration_sha256": original_configuration_sha256,
        "source_reverse_attestation_sha256": sha256_file(reverse_attestation_path),
        "binary_sha256": target.binary_sha256,
        "truth_sha256": target.truth_sha256,
        "backend": backend,
        "image": config.image,
        "runtime_image": runtime_image,
        "decompiler_project_cache": (
            project_cache.configuration() if project_cache is not None else None
        ),
        "grader": {
            "provider": provider_display_name(config.grader_provider),
            "model": config.grader_model,
            "max_budget_usd": config.grader_max_budget_usd,
            "reasoning_effort": config.grader_reasoning_effort,
        },
        "timeout_seconds": config.timeout_seconds,
        "decompiler_timeout_seconds": config.decompiler_timeout_seconds,
    }
    atomic_write_json(regrade_root / "config.json", regrade_configuration)
    with build_truth_index(target, truth_cache) as truth_index:
        truth_by_rva = truth_index.lookup_many([item.rva for item in predictions])
        packet_path = regrade_root / "grading_packet.json"
        atomic_write_json(packet_path, build_grading_packet(predictions, truth_by_rva))
        _invoke_grade_container(
            image=runtime_image["image_id"],
            binary_path=target.binary_path,
            image_base=target.image_base,
            backend=backend,
            packet_path=packet_path,
            output_dir=grade_output,
            state_dir=grade_state,
            provider=config.grader_provider,
            model=config.grader_model,
            timeout_seconds=config.timeout_seconds,
            decompiler_timeout_seconds=config.decompiler_timeout_seconds,
            max_budget_usd=config.grader_max_budget_usd,
            reasoning_effort=config.grader_reasoning_effort,
            project_seed=project_cache.state_seed if project_cache else None,
        )
        grade_attestation_path = grade_output / "attestation.json"
        write_or_verify_attestation(
            grade_attestation_path,
            kind="regrade",
            files={
                "function_snapshot": grade_output / "function_snapshot.json",
                "grading_packet": packet_path,
                "verdicts": grade_output / "verdicts.json",
            },
            context={
                "configuration_sha256": canonical_json_sha256(
                    regrade_configuration
                ),
                "binary_sha256": target.binary_sha256,
                "truth_sha256": target.truth_sha256,
                "reverse_attestation_sha256": sha256_file(
                    reverse_attestation_path
                ),
                "runtime_image_id": runtime_image["image_id"],
            },
            allow_create=True,
        )
        verdicts = _strict_json_object(grade_output / "verdicts.json")
        report = score_predictions(
            predictions, truth_by_rva, verdicts, requested_count=count
        )
    atomic_write_json(regrade_root / "scores-with-truth.json", report.to_dict())
    atomic_write_json(regrade_root / "scores.json", public_score_document(report))
    atomic_write_json(
        regrade_root / "regrade_result.json",
        {
            "schema_version": 1,
            "status": "completed",
            "configuration_sha256": canonical_json_sha256(regrade_configuration),
            "grade_attestation_sha256": sha256_file(grade_attestation_path),
        },
    )
    return regrade_root


def provider_display_name(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized == "codex":
        return "codex"
    if normalized in {"claude", "claude-code", "claudecode"}:
        return "claude"
    raise OrchestrationError(f"unsupported provider {provider!r}")


def _shared_truth_cache(manifest_path: Path, target_id: str) -> Path:
    """Reuse immutable checksum-keyed indexes across runs and batch entries."""

    return manifest_path.resolve().parent / ".zion-eval" / "truth-cache" / target_id


def _shared_decompiler_cache(manifest_path: Path) -> Path:
    """Content-addressed projects shared without exposing identity-bearing paths."""

    return manifest_path.resolve().parent / ".zion-eval" / "decompiler-cache"


def _require_provider_credentials(*providers: str) -> None:
    missing: set[str] = set()
    for provider in providers:
        normalized = provider.strip().lower()
        if normalized == "codex" and (
            os.environ.get("CODEX_AUTH_JSON")
            or os.environ.get(provider_credential_name(provider))
        ):
            continue
        credential = provider_credential_name(provider)
        if not os.environ.get(credential):
            missing.add(credential)
    if missing:
        raise OrchestrationError(
            "missing required provider environment variable(s): "
            + ", ".join(sorted(missing))
        )


def _validate_run_options(
    config: EvaluationRunConfig, *, count: int, backend: str
) -> None:
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise OrchestrationError("function count must be a positive integer")
    if backend not in {"ida", "ghidra", "angr"}:
        raise OrchestrationError("backend must be 'ida', 'ghidra', or 'angr'")
    for label, value in (
        ("reverser model", config.reverser_model),
        ("grader model", config.grader_model),
        ("image", config.image),
    ):
        if not value.strip():
            raise OrchestrationError(f"{label} must be explicit")
    provider_display_name(config.reverser_provider)
    provider_display_name(config.grader_provider)
    for label, effort in (
        ("reverser reasoning effort", config.reverser_reasoning_effort),
        ("grader reasoning effort", config.grader_reasoning_effort),
    ):
        if effort not in {None, "low", "medium", "high", "xhigh"}:
            raise OrchestrationError(
                f"{label} must be low, medium, high, or xhigh"
            )
    if config.timeout_seconds <= 0 or config.decompiler_timeout_seconds <= 0:
        raise OrchestrationError("timeouts must be positive")


def _write_or_check_configuration(
    layout: RunLayout, configuration: Mapping[str, Any], *, resume: bool
) -> None:
    path = layout.root / "config.json"
    if resume:
        existing = read_json(path)
        if existing != dict(configuration):
            raise OrchestrationError(
                "resume configuration differs from the frozen run configuration"
            )
        return
    write_run_configuration(layout, configuration)


def _stage_status(path: Path) -> str | None:
    if not path.is_file():
        return None
    document = read_json(path)
    return document.get("status") if isinstance(document, dict) else None


def _run_reverse_container(
    config: EvaluationRunConfig,
    binary_path: Path,
    image_base: int,
    count: int,
    backend: str,
    layout: RunLayout,
    project_seed: Path | None = None,
) -> bool:
    result_path = layout.reverse_output / "stage_result.json"
    status = _stage_status(result_path)
    if status == "completed":
        if not config.resume:
            raise OrchestrationError("reverse stage already exists without --resume")
        return False
    if status is not None:
        raise OrchestrationError(
            "a failed reverse stage is immutable; start a new run instead of repairing it"
        )
    command = [
        "stage-reverse",
        "--binary",
        "/input/target",
        "--output-dir",
        "/output",
        "--state-dir",
        "/state",
        "--provider",
        provider_display_name(config.reverser_provider),
        "--model",
        config.reverser_model,
        "--backend",
        backend,
        "--count",
        str(count),
        "--image-base",
        f"0x{image_base:x}",
        "--timeout-seconds",
        str(config.timeout_seconds),
        "--decompiler-timeout-seconds",
        str(config.decompiler_timeout_seconds),
    ]
    if config.reverser_reasoning_effort is not None:
        command.extend(("--reasoning-effort", config.reverser_reasoning_effort))
    if config.reverser_max_budget_usd is not None:
        command.extend(("--max-budget-usd", str(config.reverser_max_budget_usd)))
    with neutral_agent_staging(
        binary_path=binary_path,
        output_dir=layout.reverse_output,
        state_dir=layout.reverse_state,
        state_seed=project_seed,
    ) as staging:
        result = run_container(
            ContainerSpec(
                image=config.image,
                command=command,
                mounts=reverse_mounts(staging),
                environment_names=provider_environment_names(
                    config.reverser_provider
                ),
                timeout_seconds=min(
                    _REVERSE_CONTAINER_TIMEOUT_SECONDS,
                    config.timeout_seconds
                    + 2 * config.decompiler_timeout_seconds
                    + 180,
                ),
                raise_on_failure=False,
                user=host_container_user(),
                mount_source_root=staging.root,
            )
        )
    _persist_container_result(layout.reverse_output, result)
    _require_completed_stage(result_path, result.returncode, "reverse")
    return True


def _run_grade_container(
    config: EvaluationRunConfig,
    binary_path: Path,
    image_base: int,
    backend: str,
    packet_path: Path,
    layout: RunLayout,
    project_seed: Path | None = None,
) -> bool:
    result_path = layout.grade_output / "stage_result.json"
    status = _stage_status(result_path)
    if status == "completed":
        if not config.resume:
            raise OrchestrationError("grade stage already exists without --resume")
        return False
    if status is not None:
        raise OrchestrationError(
            "a failed grade stage is immutable; start a new run or regrade instead"
        )
    _invoke_grade_container(
        image=config.image,
        binary_path=binary_path,
        image_base=image_base,
        backend=backend,
        packet_path=packet_path,
        output_dir=layout.grade_output,
        state_dir=layout.grade_state,
        provider=config.grader_provider,
        model=config.grader_model,
        timeout_seconds=config.timeout_seconds,
        decompiler_timeout_seconds=config.decompiler_timeout_seconds,
        max_budget_usd=config.grader_max_budget_usd,
        reasoning_effort=config.grader_reasoning_effort,
        project_seed=project_seed,
    )
    return True


def _invoke_grade_container(
    *,
    image: str,
    binary_path: Path,
    image_base: int,
    backend: str,
    packet_path: Path,
    output_dir: Path,
    state_dir: Path,
    provider: str,
    model: str,
    timeout_seconds: int,
    decompiler_timeout_seconds: int,
    max_budget_usd: float | None,
    reasoning_effort: str | None = None,
    project_seed: Path | None = None,
) -> None:
    command = [
        "stage-grade",
        "--binary",
        "/input/target",
        "--packet",
        "/input/grading_packet.json",
        "--output-dir",
        "/output",
        "--state-dir",
        "/state",
        "--provider",
        provider_display_name(provider),
        "--model",
        model,
        "--backend",
        backend,
        "--image-base",
        f"0x{image_base:x}",
        "--timeout-seconds",
        str(timeout_seconds),
        "--decompiler-timeout-seconds",
        str(decompiler_timeout_seconds),
    ]
    if reasoning_effort is not None:
        command.extend(("--reasoning-effort", reasoning_effort))
    if max_budget_usd is not None:
        command.extend(("--max-budget-usd", str(max_budget_usd)))
    with neutral_agent_staging(
        binary_path=binary_path,
        packet_path=packet_path,
        output_dir=output_dir,
        state_dir=state_dir,
        state_seed=project_seed,
    ) as staging:
        if staging.packet is None:  # Defensive: packet_path was supplied above.
            raise OrchestrationError("grader packet was not staged")
        mounts = (
            BindMount(staging.binary, "/input/target", read_only=True),
            BindMount(
                staging.packet, "/input/grading_packet.json", read_only=True
            ),
            BindMount(staging.output, "/output", read_only=False),
            BindMount(staging.state, "/state", read_only=False),
        )
        result = run_container(
            ContainerSpec(
                image=image,
                command=command,
                mounts=mounts,
                environment_names=provider_environment_names(provider),
                timeout_seconds=(
                    timeout_seconds + 2 * decompiler_timeout_seconds + 180
                ),
                raise_on_failure=False,
                user=host_container_user(),
                mount_source_root=staging.root,
            )
        )
    _persist_container_result(output_dir, result)
    _require_completed_stage(output_dir / "stage_result.json", result.returncode, "grade")


def _persist_container_result(output_dir: Path, result: Any) -> None:
    atomic_write_text(output_dir / "container.stdout.log", result.stdout)
    atomic_write_text(output_dir / "container.stderr.log", result.stderr)
    atomic_write_json(
        output_dir / "container.json",
        {
            "returncode": result.returncode,
            "command": [_redact_bind_source(item) for item in result.command],
        },
    )


def _redact_bind_source(argument: str) -> str:
    if not argument.startswith("type=bind,"):
        return argument
    fields = argument.split(",")
    return ",".join(
        "src=<neutral-staging>" if field.startswith("src=") else field
        for field in fields
    )


def _require_completed_stage(path: Path, returncode: int, label: str) -> None:
    status = _stage_status(path)
    if returncode != 0 or status != "completed":
        detail = "stage_result.json is missing"
        if path.is_file():
            document = read_json(path)
            if isinstance(document, dict):
                detail = json.dumps(document.get("error", {}), sort_keys=True)
        raise OrchestrationError(
            f"{label} container exited with {returncode} and stage status {status!r}: {detail}"
        )


def _strict_json_object(path: Path) -> dict[str, Any]:
    try:
        value = decode_strict_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise OrchestrationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise OrchestrationError(f"{path} must contain a JSON object")
    return value

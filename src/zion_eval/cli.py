"""Command-line interface for host orchestration and isolated container stages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .artifacts import atomic_write_json, new_run_id
from .manifest import load_manifest, verify_file
from .orchestrator import (
    EvaluationRunConfig,
    RegradeConfig,
    regrade_evaluation,
    run_evaluation,
)
from .stages import (
    AnalysisStageConfig,
    GradeStageConfig,
    ReverseStageConfig,
    run_analysis_stage,
    run_grade_stage,
    run_reverse_stage,
)
from .truth import build_truth_index


DEFAULT_IMAGE = "zion-function-eval:local"
DEFAULT_TIMEOUT_SECONDS = 21_600


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _address(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer or 0x-prefixed hex") from error
    if not 0 <= parsed < 1 << 64:
        raise argparse.ArgumentTypeError("must be an unsigned 64-bit value")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zion-eval",
        description="Blind function-name recovery evaluation harness",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    targets_parser = subparsers.add_parser("targets", help="list registered targets")
    targets_parser.add_argument("--manifest", type=Path, default=Path("mapping.toml"))
    targets_parser.set_defaults(handler=_targets)

    validate = subparsers.add_parser(
        "validate", help="verify manifests, hashes, and private truth indexes"
    )
    validate.add_argument("--manifest", type=Path, default=Path("mapping.toml"))
    validate.add_argument("--target", action="append", dest="targets")
    validate.add_argument(
        "--cache-dir", type=Path, default=Path(".zion-eval/truth-cache")
    )
    validate.add_argument(
        "--quick",
        action="store_true",
        help="validate manifest structure only; skip hashes and truth parsing",
    )
    validate.set_defaults(handler=_validate)

    stage_reverse = subparsers.add_parser(
        "stage-reverse", help="internal reverser stage used by the container runtime"
    )
    _add_stage_arguments(stage_reverse)
    stage_reverse.add_argument("--count", type=_positive_int, default=100)
    stage_reverse.set_defaults(handler=_stage_reverse)

    stage_grade = subparsers.add_parser(
        "stage-grade", help="internal grader stage used by the container runtime"
    )
    _add_stage_arguments(stage_grade)
    stage_grade.add_argument("--packet", type=Path, required=True)
    stage_grade.set_defaults(handler=_stage_grade)

    stage_analyze = subparsers.add_parser(
        "stage-analyze",
        help="internal provider-free pristine analysis stage used by the host cache",
    )
    stage_analyze.add_argument("--binary", type=Path, required=True)
    stage_analyze.add_argument("--output-dir", type=Path, required=True)
    stage_analyze.add_argument("--state-dir", type=Path)
    stage_analyze.add_argument(
        "--backend", choices=("ida", "ghidra"), default="ida"
    )
    stage_analyze.add_argument(
        "--decompiler-timeout-seconds",
        type=_positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    stage_analyze.add_argument("--decompiler-executable", default="decompiler")
    stage_analyze.set_defaults(handler=_stage_analyze)

    run = subparsers.add_parser("run", help="run one reverse-and-grade evaluation")
    _add_host_run_arguments(run)
    run.add_argument("--target", required=True)
    run.add_argument("--count", type=_positive_int)
    run.add_argument("--run-id")
    run.add_argument("--resume", action="store_true")
    run.set_defaults(handler=_run)

    regrade = subparsers.add_parser(
        "regrade", help="grade a frozen prediction set with a new grader"
    )
    regrade.add_argument("--manifest", type=Path, default=Path("mapping.toml"))
    regrade.add_argument("--run-dir", type=Path, required=True)
    regrade.add_argument("--image", default=DEFAULT_IMAGE)
    regrade.add_argument("--grader-provider", choices=("codex", "claude"), required=True)
    regrade.add_argument("--grader-model", required=True)
    regrade.add_argument("--backend", choices=("ida", "ghidra", "angr"))
    regrade.add_argument(
        "--timeout-seconds", type=_positive_int, default=DEFAULT_TIMEOUT_SECONDS
    )
    regrade.add_argument(
        "--decompiler-timeout-seconds",
        type=_positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    regrade.add_argument("--grader-max-budget-usd", type=_positive_float)
    regrade.set_defaults(handler=_regrade)

    batch = subparsers.add_parser("batch", help="run a JSON evaluation matrix")
    batch.add_argument("--matrix", type=Path, required=True)
    batch.add_argument("--manifest", type=Path, default=Path("mapping.toml"))
    batch.add_argument("--image", default=DEFAULT_IMAGE)
    batch.add_argument("--runs-dir", type=Path, default=Path("runs"))
    batch.add_argument("--continue-on-error", action="store_true")
    batch.set_defaults(handler=_batch)
    return parser


def _add_stage_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--provider", choices=("codex", "claude"), required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--backend", choices=("ida", "ghidra", "angr"), default="ida"
    )
    parser.add_argument("--image-base", type=_address, default=0)
    parser.add_argument(
        "--timeout-seconds", type=_positive_int, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--decompiler-timeout-seconds",
        type=_positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument("--provider-executable")
    parser.add_argument("--decompiler-executable", default="decompiler")
    parser.add_argument("--max-budget-usd", type=_positive_float)


def _add_host_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=Path, default=Path("mapping.toml"))
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument("--backend", choices=("ida", "ghidra", "angr"))
    parser.add_argument("--reverser-provider", choices=("codex", "claude"), required=True)
    parser.add_argument("--reverser-model", required=True)
    parser.add_argument("--grader-provider", choices=("codex", "claude"), required=True)
    parser.add_argument("--grader-model", required=True)
    parser.add_argument(
        "--timeout-seconds", type=_positive_int, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--decompiler-timeout-seconds",
        type=_positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument("--reverser-max-budget-usd", type=_positive_float)
    parser.add_argument("--grader-max-budget-usd", type=_positive_float)


def _targets(arguments: argparse.Namespace) -> int:
    manifest = load_manifest(arguments.manifest)
    document = {
        "schema_version": manifest.schema_version,
        "targets": [
            {
                "id": target.id,
                "format": target.format,
                "architecture": target.architecture,
                "default_count": target.default_count,
                "default_backend": target.default_backend,
            }
            for target in manifest.targets
        ],
    }
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def _validate(arguments: argparse.Namespace) -> int:
    manifest = load_manifest(arguments.manifest)
    if arguments.targets:
        targets = [manifest.get_target(target_id) for target_id in arguments.targets]
    else:
        targets = list(manifest.targets)
    results: list[dict[str, Any]] = []
    for target in targets:
        result: dict[str, Any] = {"id": target.id, "status": "valid"}
        if not arguments.quick:
            verify_file(
                target.binary_path,
                target.binary_sha256,
                f"{target.id} binary",
            )
            cache = arguments.cache_dir / target.id
            with build_truth_index(target, cache) as index:
                result.update(
                    {
                        "truth_records": index.count,
                        "gradeable_records": index.gradeable_count,
                        "truth_index": str(index.path),
                    }
                )
        results.append(result)
    print(json.dumps({"schema_version": 1, "targets": results}, indent=2, sort_keys=True))
    return 0


def _stage_reverse(arguments: argparse.Namespace) -> int:
    result = run_reverse_stage(
        ReverseStageConfig(
            binary_path=arguments.binary,
            output_dir=arguments.output_dir,
            provider_name=arguments.provider,
            model=arguments.model,
            state_dir=arguments.state_dir,
            backend=arguments.backend,
            count=arguments.count,
            image_base=arguments.image_base,
            timeout_seconds=arguments.timeout_seconds,
            decompiler_timeout_seconds=arguments.decompiler_timeout_seconds,
            provider_executable=arguments.provider_executable,
            decompiler_executable=arguments.decompiler_executable,
            max_budget_usd=arguments.max_budget_usd,
        )
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.succeeded else 1


def _stage_grade(arguments: argparse.Namespace) -> int:
    result = run_grade_stage(
        GradeStageConfig(
            binary_path=arguments.binary,
            packet_path=arguments.packet,
            output_dir=arguments.output_dir,
            provider_name=arguments.provider,
            model=arguments.model,
            state_dir=arguments.state_dir,
            backend=arguments.backend,
            image_base=arguments.image_base,
            timeout_seconds=arguments.timeout_seconds,
            decompiler_timeout_seconds=arguments.decompiler_timeout_seconds,
            provider_executable=arguments.provider_executable,
            decompiler_executable=arguments.decompiler_executable,
            max_budget_usd=arguments.max_budget_usd,
        )
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.succeeded else 1


def _stage_analyze(arguments: argparse.Namespace) -> int:
    result = run_analysis_stage(
        AnalysisStageConfig(
            binary_path=arguments.binary,
            output_dir=arguments.output_dir,
            state_dir=arguments.state_dir,
            backend=arguments.backend,
            decompiler_timeout_seconds=arguments.decompiler_timeout_seconds,
            decompiler_executable=arguments.decompiler_executable,
        )
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.succeeded else 1


def _run(arguments: argparse.Namespace) -> int:
    layout = run_evaluation(
        EvaluationRunConfig(
            manifest_path=arguments.manifest,
            target_id=arguments.target,
            image=arguments.image,
            reverser_provider=arguments.reverser_provider,
            reverser_model=arguments.reverser_model,
            grader_provider=arguments.grader_provider,
            grader_model=arguments.grader_model,
            runs_directory=arguments.runs_dir,
            count=arguments.count,
            backend=arguments.backend,
            timeout_seconds=arguments.timeout_seconds,
            decompiler_timeout_seconds=arguments.decompiler_timeout_seconds,
            reverser_max_budget_usd=arguments.reverser_max_budget_usd,
            grader_max_budget_usd=arguments.grader_max_budget_usd,
            run_id=arguments.run_id,
            resume=arguments.resume,
        )
    )
    print(json.dumps({"status": "completed", "run_directory": str(layout.root)}))
    return 0


def _regrade(arguments: argparse.Namespace) -> int:
    root = regrade_evaluation(
        RegradeConfig(
            manifest_path=arguments.manifest,
            run_directory=arguments.run_dir,
            image=arguments.image,
            grader_provider=arguments.grader_provider,
            grader_model=arguments.grader_model,
            backend=arguments.backend,
            timeout_seconds=arguments.timeout_seconds,
            decompiler_timeout_seconds=arguments.decompiler_timeout_seconds,
            grader_max_budget_usd=arguments.grader_max_budget_usd,
        )
    )
    print(json.dumps({"status": "completed", "regrade_directory": str(root)}))
    return 0


def _batch(arguments: argparse.Namespace) -> int:
    try:
        matrix = json.loads(arguments.matrix.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read batch matrix: {error}") from error
    if not isinstance(matrix, dict) or matrix.get("schema_version") != 1:
        raise ValueError("batch matrix must be a schema_version=1 JSON object")
    defaults = matrix.get("defaults", {})
    runs = matrix.get("runs")
    if not isinstance(defaults, dict) or not isinstance(runs, list) or not runs:
        raise ValueError("batch matrix requires object defaults and a nonempty runs array")

    results: list[dict[str, Any]] = []
    for position, raw in enumerate(runs):
        if not isinstance(raw, dict):
            raise ValueError(f"batch runs[{position}] must be an object")
        entry = {**defaults, **raw}
        required = (
            "target",
            "reverser_provider",
            "reverser_model",
            "grader_provider",
            "grader_model",
        )
        missing = [key for key in required if not entry.get(key)]
        if missing:
            raise ValueError(f"batch runs[{position}] is missing {', '.join(missing)}")
        try:
            layout = run_evaluation(
                EvaluationRunConfig(
                    manifest_path=arguments.manifest,
                    target_id=str(entry["target"]),
                    image=str(entry.get("image", arguments.image)),
                    reverser_provider=str(entry["reverser_provider"]),
                    reverser_model=str(entry["reverser_model"]),
                    grader_provider=str(entry["grader_provider"]),
                    grader_model=str(entry["grader_model"]),
                    runs_directory=arguments.runs_dir,
                    count=entry.get("count"),
                    backend=entry.get("backend"),
                    timeout_seconds=int(entry.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                    decompiler_timeout_seconds=int(
                        entry.get("decompiler_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
                    ),
                    reverser_max_budget_usd=entry.get("reverser_max_budget_usd"),
                    grader_max_budget_usd=entry.get("grader_max_budget_usd"),
                    run_id=entry.get("run_id"),
                )
            )
            results.append(
                {"position": position, "status": "completed", "run_directory": str(layout.root)}
            )
        except Exception as error:
            results.append(
                {
                    "position": position,
                    "status": "failed",
                    "error": {"type": type(error).__name__, "message": str(error)},
                }
            )
            if not arguments.continue_on_error:
                break
    document = {"schema_version": 1, "runs": results}
    arguments.runs_dir.mkdir(parents=True, exist_ok=True)
    output = arguments.runs_dir / f"batch-{new_run_id()}.json"
    atomic_write_json(output, document)
    print(json.dumps({**document, "result_path": str(output)}, indent=2, sort_keys=True))
    return 0 if all(item["status"] == "completed" for item in results) else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except KeyboardInterrupt:
        print("zion-eval: interrupted", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"zion-eval: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

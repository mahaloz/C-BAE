#!/usr/bin/env python3
"""Export zion-eval run artifacts into the static dashboard data bundle."""

from __future__ import annotations

import argparse
import json
import re
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility for the project venv.
    import tomli as tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENERIC_NAME = re.compile(
    r"^(?:sub_|nullsub_|j_|loc_|unk_|off_|byte_|word_|dword_|qword_)", re.I
)
DECOMPILE_COMMAND = re.compile(r"\bdecompiler\s+decompile\b", re.I)
DISASSEMBLE_COMMAND = re.compile(r"\bdecompiler\s+disassemble\b", re.I)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with path.open() as handle:
            for line in handle:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return events


def clean_display_name(target_id: str) -> str:
    known = {
        "bedrock-server-linux-1.21.0.03": "Bedrock Server 1.21.0.03",
        "minecraft-china-client-windows-1.16.201": "Minecraft China Client 1.16.201",
    }
    if target_id in known:
        return known[target_id]
    return " ".join(part.capitalize() for part in target_id.split("-"))


def os_for_format(binary_format: str, target_id: str) -> str:
    value = f"{binary_format} {target_id}".lower()
    if "windows" in value or binary_format.lower() == "pe":
        return "Windows"
    if "linux" in value or binary_format.lower() == "elf":
        return "Linux"
    if "mac" in value or "mach" in value:
        return "macOS"
    return "Unknown"


def human_stage(stage: str) -> str:
    return stage.replace("_", " ").strip().title()


def usage_from_events(events: list[dict[str, Any]]) -> dict[str, int]:
    for event in reversed(events):
        if event.get("type") == "turn.completed" and isinstance(event.get("usage"), dict):
            return {
                key: int(event["usage"].get(key, 0) or 0)
                for key in (
                    "input_tokens",
                    "cached_input_tokens",
                    "output_tokens",
                    "reasoning_output_tokens",
                )
            }
    return {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }


def usage_key(usage: dict[str, Any]) -> tuple[int, int, int]:
    return (
        int(usage.get("input_tokens", 0) or 0),
        int(usage.get("cached_input_tokens", 0) or 0),
        int(usage.get("output_tokens", 0) or 0),
    )


def cost_index(runs_dir: Path) -> dict[tuple[int, int, int], dict[str, float]]:
    index: dict[tuple[int, int, int], dict[str, float]] = {}
    for path in runs_dir.glob("*cost-summary.json"):
        summary = read_json(path, {})
        for stage in summary.get("stages", {}).values():
            key = usage_key(stage)
            if not any(key):
                continue
            index[key] = {
                "standard": float(stage.get("standard_rate_usd", 0) or 0),
                "upperBound": float(stage.get("long_context_upper_bound_usd", 0) or 0),
            }
    return index


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + "\n… output truncated by dashboard export …"


def excerpt_around(value: str, needle: str, radius: int = 1400) -> str:
    position = value.lower().find(needle.lower())
    if position < 0:
        return truncate(value, radius * 2)
    start = max(0, position - radius)
    end = min(len(value), position + len(needle) + radius)
    prefix = "…\n" if start else ""
    suffix = "\n…" if end < len(value) else ""
    return prefix + value[start:end].strip() + suffix


def command_records(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for event in events:
        item = event.get("item", {})
        if event.get("type") != "item.completed" or item.get("type") != "command_execution":
            continue
        records.append(
            {
                "id": str(item.get("id", "")),
                "command": str(item.get("command", "")),
                "output": str(item.get("aggregated_output", "")),
                "status": str(item.get("status", "")),
            }
        )
    return records


def evidence_for(address: str, records: list[dict[str, str]]) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    address_lower = address.lower()
    for record in records:
        command = record["command"]
        output = record["output"]
        command_has = address_lower in command.lower()
        output_has = address_lower in output.lower()
        if not command_has and not output_has:
            continue
        if command_has and DECOMPILE_COMMAND.search(command):
            kind = "decompilation"
            label = "Direct decompilation"
            excerpt = truncate(output, 9000)
        elif command_has and DISASSEMBLE_COMMAND.search(command):
            kind = "disassembly"
            label = "Direct disassembly"
            excerpt = truncate(output, 7000)
        elif command_has:
            kind = "command"
            label = "Address-targeted command"
            excerpt = truncate(output, 4500)
        else:
            kind = "trace"
            label = "Mentioned in command output"
            excerpt = excerpt_around(output, address)
        signature = (kind, excerpt[:600])
        if signature in seen:
            continue
        seen.add(signature)
        evidence.append(
            {
                "kind": kind,
                "label": label,
                "eventId": record["id"],
                "command": truncate(command, 1200),
                "output": excerpt or "(command produced no captured output)",
            }
        )
        if len(evidence) >= 6:
            break
    return evidence


def tool_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [
        event.get("item", {})
        for event in events
        if event.get("type") == "item.completed"
    ]
    counts = Counter(str(item.get("type", "unknown")) for item in completed)
    commands = [item for item in completed if item.get("type") == "command_execution"]
    collaborations = [item for item in completed if item.get("type") == "collab_tool_call"]
    web_calls = [
        item
        for item in completed
        if "web" in str(item.get("type", "")).lower()
        or "search" in str(item.get("type", "")).lower()
    ]
    return {
        "total": len(commands) + len(collaborations) + len(web_calls),
        "shell": len(commands),
        "collaboration": len(collaborations),
        "web": len(web_calls),
        "decompilations": sum(
            1 for item in commands if DECOMPILE_COMMAND.search(str(item.get("command", "")))
        ),
        "disassemblies": sum(
            1 for item in commands if DISASSEMBLE_COMMAND.search(str(item.get("command", "")))
        ),
        "eventTypes": dict(sorted(counts.items())),
    }


def load_manifest(root: Path) -> dict[str, dict[str, Any]]:
    with (root / "mapping.toml").open("rb") as handle:
        mapping = tomllib.load(handle)
    return {target["id"]: target for target in mapping.get("targets", [])}


def stage_data(
    stage_result_path: Path,
    events_path: Path,
    costs: dict[tuple[int, int, int], dict[str, float]],
) -> dict[str, Any]:
    result = read_json(stage_result_path, {})
    events = read_events(events_path)
    usage = usage_from_events(events)
    cost = costs.get(usage_key(usage))
    return {
        "durationSeconds": float(result.get("duration_seconds", 0) or 0),
        "startedAt": result.get("started_at"),
        "finishedAt": result.get("finished_at"),
        "status": result.get("status", "unknown"),
        "usage": usage,
        "cost": cost,
    }


def export_run(
    root: Path,
    run_dir: Path,
    manifest: dict[str, dict[str, Any]],
    costs: dict[tuple[int, int, int], dict[str, float]],
    decompilations: dict[str, Any],
) -> dict[str, Any] | None:
    config = read_json(run_dir / "config.json", {})
    result = read_json(run_dir / "run_result.json", {})
    scores = read_json(run_dir / "private" / "scores-with-truth.json")
    raw_predictions = read_json(run_dir / "reverse" / "predictions.json", {})
    if isinstance(raw_predictions, dict) and "predictions" in raw_predictions:
        predictions = raw_predictions.get("predictions", [])
    elif isinstance(raw_predictions, dict):
        predictions = [
            {
                "address": address,
                "name": value.get("name", "") if isinstance(value, dict) else value,
            }
            for address, value in raw_predictions.items()
        ]
    else:
        predictions = raw_predictions or []
    snapshot = read_json(run_dir / "reverse" / "function_snapshot.json", {})
    if not config or not scores or not predictions or not snapshot:
        return None

    target_id = str(config.get("target_id", run_dir.name))
    run_id = str(result.get("run_id", run_dir.name))
    target = manifest.get(target_id, {})
    binary_path = root / str(target.get("binary", ""))
    binary_size = binary_path.stat().st_size if binary_path.is_file() else None
    snapshot_functions = snapshot.get("functions", [])
    by_address = {item.get("rva"): item for item in snapshot_functions}
    score_by_address = {item.get("rva"): item for item in scores.get("items", [])}

    reverse_events = read_events(run_dir / "reverse" / "provider" / "events.jsonl")
    records = command_records(reverse_events)
    selections: list[dict[str, Any]] = []
    for index, prediction in enumerate(predictions, start=1):
        address = str(prediction.get("address", ""))
        score = score_by_address.get(address, {})
        function = by_address.get(address, {})
        visible_name = function.get("discovered_name")
        evidence = evidence_for(address, records)
        selections.append(
            {
                "index": index,
                "address": address,
                "predictedName": prediction.get("name", ""),
                "truthName": score.get("truth_name"),
                "mangledName": score.get("mangled_name"),
                "category": score.get("category", "ungradable"),
                "graderVerdict": score.get("grader_verdict"),
                "discoveredName": visible_name,
                "size": function.get("size"),
                "wasPreNamed": bool(visible_name and not GENERIC_NAME.search(str(visible_name))),
                "directDecompilationCaptured": any(
                    item["kind"] == "decompilation" for item in evidence
                ),
                "decompilation": decompilations.get("runs", {})
                .get(run_id, {})
                .get(address),
                "evidence": evidence,
            }
        )

    reverse = stage_data(
        run_dir / "reverse" / "stage_result.json",
        run_dir / "reverse" / "provider" / "events.jsonl",
        costs,
    )
    grade = stage_data(
        run_dir / "private" / "grade" / "stage_result.json",
        run_dir / "private" / "grade" / "provider" / "events.jsonl",
        costs,
    )
    stage_costs = [stage.get("cost") for stage in (reverse, grade)]
    known_costs = [cost for cost in stage_costs if cost]
    total_cost = (
        {
            "standard": sum(cost["standard"] for cost in known_costs),
            "upperBound": sum(cost["upperBound"] for cost in known_costs),
            "kind": "API list-price equivalent",
        }
        if len(known_costs) == 2
        else None
    )
    score_counts = scores.get("counts", {})
    return {
        "id": run_id,
        "targetId": target_id,
        "displayName": clean_display_name(target_id),
        "status": result.get("status", "unknown"),
        "model": config.get("reverser", {}).get("model", "unknown"),
        "reasoningEffort": config.get("reverser", {}).get("reasoning_effort"),
        "backend": config.get("backend"),
        "binary": {
            "sizeBytes": binary_size,
            "architecture": config.get("architecture", target.get("architecture")),
            "format": config.get("binary_format", target.get("format")),
            "os": os_for_format(
                str(config.get("binary_format", target.get("format", ""))), target_id
            ),
            "functionCount": len(snapshot_functions),
            "sha256": config.get("binary_sha256"),
        },
        "scores": {
            "exactAccuracy": float(scores.get("exact_accuracy", 0) or 0),
            "semanticAccuracy": float(scores.get("semantic_accuracy", 0) or 0),
            "counts": score_counts,
            "submitted": int(scores.get("submitted_count", 0) or 0),
        },
        "reverse": reverse,
        "grade": grade,
        "totalDurationSeconds": reverse["durationSeconds"] + grade["durationSeconds"],
        "cost": total_cost,
        "tools": tool_summary(reverse_events),
        "audit": {
            "preNamedSelections": sum(1 for item in selections if item["wasPreNamed"]),
            "directDecompilationsCaptured": sum(
                1 for item in selections if item["directDecompilationCaptured"]
            ),
            "decompilationsAvailable": sum(
                1
                for item in selections
                if (item.get("decompilation") or {}).get("status") == "ok"
            ),
            "selectionsWithTraceEvidence": sum(
                1 for item in selections if item["evidence"]
            ),
            "traceAvailable": bool(reverse_events),
        },
        "selections": selections,
    }


def build_dashboard(root: Path, runs_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(root)
    costs = cost_index(runs_dir)
    decompilations = read_json(root / "web" / "data" / "decompilations.json", {})
    runs = []
    for run_dir in sorted(runs_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        exported = export_run(root, run_dir, manifest, costs, decompilations)
        if exported:
            runs.append(exported)

    total_predictions = sum(run["scores"]["submitted"] for run in runs)
    total_exact = sum(run["scores"]["counts"].get("exact", 0) for run in runs)
    total_semantic = sum(
        run["scores"]["counts"].get("exact", 0)
        + run["scores"]["counts"].get("equivalent", 0)
        for run in runs
    )
    known_costs = [run["cost"] for run in runs if run["cost"]]
    total_standard = sum(cost["standard"] for cost in known_costs)
    total_upper = sum(cost["upperBound"] for cost in known_costs)
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "overview": {
            "binaryCount": len(runs),
            "predictionCount": total_predictions,
            "exactAccuracy": total_exact / total_predictions if total_predictions else 0,
            "semanticAccuracy": total_semantic / total_predictions if total_predictions else 0,
            "averageDurationSeconds": (
                sum(run["totalDurationSeconds"] for run in runs) / len(runs)
                if runs
                else 0
            ),
            "totalCost": total_standard if len(known_costs) == len(runs) else None,
            "averageCost": total_standard / len(runs) if len(known_costs) == len(runs) and runs else None,
            "totalCostUpperBound": total_upper if len(known_costs) == len(runs) else None,
            "costKind": "API list-price equivalent" if known_costs else None,
        },
        "runs": runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--runs-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    runs_dir = (args.runs_dir or root / "runs").resolve()
    output = (args.output or root / "web" / "data" / "dashboard.json").resolve()
    dashboard = build_dashboard(root, runs_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dashboard, indent=2) + "\n")
    print(
        f"Exported {len(dashboard['runs'])} runs and "
        f"{dashboard['overview']['predictionCount']} predictions to {output}"
    )


if __name__ == "__main__":
    main()

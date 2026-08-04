#!/usr/bin/env python3
"""Populate a reusable IDA pseudocode cache for dashboard selections."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w") as temporary:
            json.dump(cache, temporary, indent=2)
            temporary.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def parse_server(value: str) -> tuple[str, str]:
    try:
        run_id, server_id = value.split("=", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected RUN_ID=SERVER_ID") from error
    if not run_id or not server_id:
        raise argparse.ArgumentTypeError("expected non-empty RUN_ID=SERVER_ID")
    return run_id, server_id


def error_record(message: str) -> dict[str, Any]:
    return {
        "status": "error",
        "text": None,
        "backend": "ida",
        "error": message,
    }


def decompile_batch(
    server_id: str, addresses: list[str], timeout: int
) -> dict[str, dict[str, Any]]:
    """Decompile a chunk without the CLI's full-catalog address validation."""
    from declib.api.decompiler_client import DecompilerClient

    records: dict[str, dict[str, Any]] = {}
    try:
        with DecompilerClient.discover_from_registry(
            server_id=server_id, timeout=timeout
        ) as client:
            for address in addresses:
                try:
                    decompilation = client.decompile(int(address, 0))
                    text = getattr(decompilation, "text", None)
                    if not text:
                        records[address] = error_record(
                            "IDA returned no pseudocode"
                        )
                        continue
                    records[address] = {
                        "status": "ok",
                        "text": text,
                        "backend": str(
                            getattr(decompilation, "decompiler", "ida") or "ida"
                        ),
                        "error": None,
                    }
                except Exception as error:  # Continue across unsupported functions.
                    records[address] = error_record(f"{type(error).__name__}: {error}")
    except Exception as error:
        message = f"{type(error).__name__}: {error}"
        return {address: error_record(message) for address in addresses}
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dashboard", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--server", action="append", type=parse_server, default=[])
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--retry-errors", action="store_true")
    args = parser.parse_args()

    dashboard = read_json(args.dashboard, {})
    servers = dict(args.server)
    cache = read_json(
        args.cache,
        {"schemaVersion": 1, "generatedAt": None, "runs": {}},
    )
    cached_runs = cache.setdefault("runs", {})

    targets: list[tuple[str, str]] = []
    for run in dashboard.get("runs", []):
        run_id = run.get("id")
        if run_id not in servers:
            continue
        for selection in run.get("selections", []):
            targets.append((run_id, selection.get("address")))

    completed = 0
    skipped = 0
    failures = 0
    total = len(targets)
    pending_by_run: dict[str, list[str]] = {}
    for run_id, address in targets:
        run_cache = cached_runs.setdefault(run_id, {})
        existing = run_cache.get(address)
        if existing and (
            existing.get("status") == "ok"
            or (existing.get("status") == "error" and not args.retry_errors)
        ):
            skipped += 1
            continue
        pending_by_run.setdefault(run_id, []).append(address)

    for run_id, addresses in pending_by_run.items():
        for start in range(0, len(addresses), args.batch_size):
            chunk = addresses[start : start + args.batch_size]
            records = decompile_batch(servers[run_id], chunk, args.timeout_seconds)
            for address in chunk:
                record = records[address]
                record["capturedAt"] = datetime.now(timezone.utc).isoformat()
                cached_runs[run_id][address] = record
                completed += 1
                failures += int(record["status"] != "ok")
                cache["generatedAt"] = record["capturedAt"]
                write_cache(args.cache, cache)
            print(
                f"[{completed + skipped}/{total}] generated={completed} "
                f"skipped={skipped} failures={failures}",
                flush=True,
            )

    print(
        f"Finished {total} selections: generated={completed}, "
        f"skipped={skipped}, failures={failures}",
        flush=True,
    )


if __name__ == "__main__":
    main()

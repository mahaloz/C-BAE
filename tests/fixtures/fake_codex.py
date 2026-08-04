#!/usr/bin/env python3
"""Offline Codex CLI stand-in for container-stage integration canaries.

It implements only the arguments consumed by ``CodexProvider``.  Reverse
responses enumerate the already-running DecLib server; grade responses cover
every schema key.  This file is never copied into the runtime image.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def option(name: str) -> str:
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError) as error:
        raise SystemExit(f"missing fake Codex option: {name}") from error


def main() -> int:
    prompt = sys.stdin.read()
    schema = json.loads(Path(option("--output-schema")).read_text(encoding="utf-8"))
    final_path = Path(option("--output-last-message"))

    if "predictions" in schema.get("properties", {}):
        match = re.search(r"server id is\s+`([^`]+)`", prompt)
        if match is None:
            raise SystemExit("fake Codex could not find the DecLib server id")
        completed = subprocess.run(
            ["decompiler", "list_functions", "--id", match.group(1), "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        functions = json.loads(completed.stdout)
        count = schema["properties"]["predictions"]["minItems"]
        usable = [entry for entry in functions if int(entry.get("size") or 0) > 0]
        if len(usable) < count:
            raise SystemExit("fake Codex found too few functions")
        output = {
            "predictions": [
                {
                    "address": (
                        hex(entry["addr"])
                        if isinstance(entry["addr"], int)
                        else entry["addr"]
                    ),
                    "name": f"offline_canary_function_{position}",
                }
                for position, entry in enumerate(usable[:count], start=1)
            ]
        }
    else:
        output = {
            address: {
                "verdict": "incorrect",
                "justification": "Offline integration canary verdict.",
                "confidence": 1.0,
            }
            for address in schema["required"]
        }

    final_path.write_text(json.dumps(output), encoding="utf-8")
    print(json.dumps({"type": "fake_codex_completed"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

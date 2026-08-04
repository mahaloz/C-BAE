#!/usr/bin/env bash
set -euo pipefail

quick=false
if (($# > 1)); then
    echo "usage: zion-runtime-smoke [--quick]" >&2
    exit 2
elif (($# == 1)); then
    if [[ $1 != "--quick" ]]; then
        echo "usage: zion-runtime-smoke [--quick]" >&2
        exit 2
    fi
    quick=true
fi

require_command() {
    if ! command -v "$1" >/dev/null; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

require_output_version() {
    local command_name=$1
    local expected=$2
    shift 2
    local output
    output=$("$command_name" "$@" 2>&1)
    if [[ $output != *"$expected"* ]]; then
        echo "$command_name reported an unexpected version: $output" >&2
        exit 1
    fi
    printf '%s: %s\n' "$command_name" "$output"
}

if [[ $(uname -m) != "x86_64" ]]; then
    echo "unsupported architecture: $(uname -m); expected x86_64" >&2
    exit 1
fi

for tool in java node codex claude declib decompiler zion-eval gcc readelf objdump file jq rg; do
    require_command "$tool"
done

require_output_version node "v${ZION_EVAL_NODE_VERSION}" --version
require_output_version codex "${ZION_EVAL_CODEX_VERSION}" --version
require_output_version claude "${ZION_EVAL_CLAUDE_VERSION}" --version
require_output_version java 'version "21' -version

if [[ ! -x ${GHIDRA_INSTALL_DIR}/support/analyzeHeadless ]]; then
    echo "Ghidra analyzeHeadless is missing or not executable" >&2
    exit 1
fi
if ! grep -Eq "^application\\.version=${ZION_EVAL_GHIDRA_VERSION//./\\.}$" \
    "${GHIDRA_INSTALL_DIR}/Ghidra/application.properties"; then
    echo "Ghidra version metadata does not match ${ZION_EVAL_GHIDRA_VERSION}" >&2
    exit 1
fi

if [[ ! -x ${IDA_INSTALL_DIR}/idat ]]; then
    echo "IDA headless executable is missing or not executable" >&2
    exit 1
fi
if [[ ! -f ${IDA_INSTALL_DIR}/libidalib.so ]]; then
    echo "IDA library is missing" >&2
    exit 1
fi
if [[ ! -f ${IDA_INSTALL_DIR}/idapro.hexlic ]]; then
    echo "IDA license is missing" >&2
    exit 1
fi

smoke_idausr=$(mktemp -d /tmp/zion-ida-smoke.XXXXXX)
trap 'rm -r -- "$smoke_idausr"' EXIT
printf '{"Paths":{"ida-install-dir":"%s"}}\n' "${IDA_INSTALL_DIR}" \
    >"${smoke_idausr}/ida-config.json"
export IDAUSR=$smoke_idausr

python - <<'PY'
from importlib.metadata import version

expected = {
    "declib": "4.4.1",
    "pyghidra": "3.1.0",
    "angr": "9.2.213",
    "jsonschema": "4.26.0",
}
for distribution, wanted in expected.items():
    actual = version(distribution)
    if actual != wanted:
        raise SystemExit(f"{distribution}: expected {wanted}, got {actual}")
    print(f"{distribution}: {actual}")

import idapro
import angr  # noqa: F401
import declib  # noqa: F401
import pyghidra  # noqa: F401

ida_version = idapro.get_library_version()
if ida_version is None or ida_version[:2] != (9, 2):
    raise SystemExit(f"IDA: expected 9.2, got {ida_version}")
print(f"IDA: {ida_version[0]}.{ida_version[1]}.{ida_version[2]}")

import json
import os
from pathlib import Path

contracts = Path(os.environ["ZION_EVAL_CONTRACTS_DIR"])
schema_paths = [
    contracts / "schemas" / name
    for name in (
        "grading-packet.schema.json",
        "predictions.schema.json",
        "verdicts.schema.json",
    )
]
prompt_paths = [
    contracts / "prompts" / name
    for name in ("grader.md", "reverser.md")
]
for schema in schema_paths:
    json.loads(schema.read_text(encoding="utf-8"))
for prompt in prompt_paths:
    if not prompt.read_text(encoding="utf-8").strip():
        raise SystemExit(f"empty prompt contract: {prompt}")
PY

if [[ $quick == true ]]; then
    echo "zion runtime quick smoke test passed"
    exit 0
fi

smoke_dir=$(mktemp -d /tmp/zion-runtime-smoke.XXXXXX)
printf '%s\n' \
    '__attribute__((noinline)) int helper(int x) { return x * 7 + 3; }' \
    'int main(void) { return helper(4) == 31 ? 0 : 1; }' \
    | gcc -O0 -fno-inline -x c - -o "${smoke_dir}/fixture"

SMOKE_DIR=$smoke_dir python - <<'PY'
import os
from pathlib import Path

import idapro  # noqa: F401
import ida_registry

ida_registry.reg_write_bool("EULA 90", True)

from declib.api.decompiler_interface import DecompilerInterface

root = Path(os.environ["SMOKE_DIR"])
binary = root / "fixture"

for backend in ("ida", "ghidra", "angr"):
    project_dir = root / f"{backend}-project"
    project_dir.mkdir()
    interface = DecompilerInterface.discover(
        force_decompiler=backend,
        binary_path=binary,
        headless=True,
        project_dir=project_dir,
    )
    if interface is None:
        raise SystemExit(f"{backend}: DecLib did not create an interface")
    try:
        functions = list(interface.functions.items())
        if not functions:
            raise SystemExit(f"{backend}: no functions discovered")

        preferred = [
            (address, function)
            for address, function in functions
            if function.name == "helper"
        ]
        candidates = preferred or [
            (address, function)
            for address, function in functions
            if function.size and function.size > 0
        ]
        decompilation = None
        for address, _function in candidates[:10]:
            decompilation = interface.decompile(address)
            if decompilation is not None and decompilation.text:
                break
        if decompilation is None or not decompilation.text:
            raise SystemExit(f"{backend}: could not decompile a discovered function")
        print(
            f"{backend}: {len(functions)} functions; "
            f"decompiled {hex(decompilation.addr)}"
        )
    finally:
        interface.shutdown()

print("DecLib IDA, Ghidra, and angr backend smoke tests passed")
PY

echo "zion runtime full smoke test passed"

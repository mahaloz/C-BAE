"""Prompts and strict JSON Schemas shared by the evaluation stages."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence


VERDICTS = ("exact", "equivalent", "partial", "incorrect", "ungradable")


_REVERSE_TEMPLATE = """\
You are the reverser in a blind function-name recovery evaluation.

You have at most five hours of wall-clock time for this evaluation. The
container will be forcibly cut off five hours after it starts, so manage your
time and return your final predictions before the cutoff.

The stripped target is already loaded in the {backend} backend through DecLib.
The target's identity and original symbols are intentionally unavailable. Do not
try to identify the product, search the Internet, use a web browser, query online
services, inspect package/repository history, or locate symbol files. Work only
from the binary evidence available through DecLib.

The complete pre-agent function catalog is already saved as
`function_catalog.json` in your working directory. Large targets can contain
hundreds of thousands of functions, so never print the whole catalog or an
unfiltered full string listing into your context. Inspect counts, bounded
slices, and filters locally, for example:

  jq '.functions | length' function_catalog.json
  jq '.functions[:200]' function_catalog.json
  jq '[limit(200; .functions[] | select(.size >= 64))]' function_catalog.json
  decompiler list_strings --min-length 8 --id {server_id} --json > strings.json
  jq 'length' strings.json
  jq '.[0:200]' strings.json

The DecLib server id is `{server_id}`. Use focused commands such as:

  decompiler decompile 0xADDRESS --id {server_id} --json
  decompiler disassemble 0xADDRESS --id {server_id} --json

You may inspect callers, callees, cross-references, data, strings, and supporting
functions with other `decompiler --help` commands. Do not rename functions in the
decompiler: your only submitted names are in the final answer.

Choose exactly {count} substantive functions yourself. Prefer functions whose
semantics you can support from evidence; avoid pure thunks, import stubs, and
obvious compiler scaffolding where practical. For each chosen function, infer the
most likely original function name. Include a namespace/class qualification and
signature details only when the evidence supports them; do not fabricate a known
library identity.

Return only the schema-constrained JSON object. Its only field is `predictions`,
an array of exactly {count} objects containing only `address` and `name`. Copy
the `address` string exactly from `function_catalog.json` (the lifted DecLib
address beginning with `0x`); do not calculate or submit a VA/RVA yourself.
Every address must be distinct. Do not include confidence, rationale, markdown,
or commentary.
"""


_CHOOSER_TEMPLATE = """\
You are the chooser in a blind function-name recovery evaluation.

Select exactly {count} functions that a separate reverser will later have to
name. You do not name them. The chooser and reverser have isolated workspaces;
the reverser receives only your frozen address set, not your reasoning.

The stripped target is already loaded in the {backend} backend through DecLib.
The target's identity and original symbols are intentionally unavailable. Do not
try to identify the product, search the Internet, use a web browser, query online
services, inspect package/repository history, or locate symbol files. Work only
from binary evidence available inside this container.

The complete pre-agent catalog is `function_catalog.json`. Large targets can
contain hundreds of thousands of functions, so use bounded local filters rather
than printing the full catalog or string list into context. The DecLib server id
is `{server_id}`. Inspect candidates and their context with focused commands such
as:

  decompiler decompile 0xADDRESS --id {server_id} --json
  decompiler disassemble 0xADDRESS --id {server_id} --json
  decompiler get_callers 0xADDRESS --id {server_id} --json
  decompiler get_callees 0xADDRESS --id {server_id} --json
  decompiler list_strings --min-length 8 --id {server_id} --json

Every selected function must satisfy all of these requirements:

1. Its decompilation contains more than five meaningful code lines. Function
   headers, braces, blank lines, and comments do not count. The harness will
   decompile every selected function and reject the complete selection if any
   function fails this objective minimum.
2. It is substantive, not a thunk, PLT/import stub, trivial accessor, compiler
   scaffold, or other tiny wrapper.
3. It is not merely a generic library/runtime function copied from unrelated
   code (for example allocator, container, compression, crypto, or libc
   implementation code with no target-specific role).
4. Its behavior is comparatively distinctive to this binary: prefer functions
   tied to the target's own concepts, formats, protocols, state machines,
   gameplay/domain behavior, or product-specific subsystems. Use strings,
   callers/callees, data references, and neighboring functions as evidence.

Favor a diverse set across target-specific subsystems rather than many nearly
identical siblings. Do not optimize for functions that are easiest to name; your
job is to construct a representative, distinctive challenge set.

Return only the schema-constrained JSON object. Its only field is `selections`,
an array of exactly {count} objects containing only `address`. Copy each address
exactly from `function_catalog.json` (the lifted DecLib `0x` address). Every
address must be distinct. Do not include names, confidence, rationale, markdown,
or commentary.
"""


_GRADER_TEMPLATE = """\
You are the grader in a blind function-name recovery evaluation.

Read `{packet_name}`. It contains only the selected lifted function address, the
proposed name, authoritative name(s), and whether usable truth exists. The
reverser's provider, model, confidence, transcript, and rationale are deliberately
hidden and must not influence grading.

The stripped target is already loaded in the {backend} backend through DecLib at
server id `{server_id}`. First compare names. When a name comparison is genuinely
ambiguous, inspect the function and relevant context with commands such as:

  decompiler decompile 0xADDRESS --id {server_id} --json
  decompiler disassemble 0xADDRESS --id {server_id} --json
  decompiler get_callers 0xADDRESS --id {server_id} --json
  decompiler xref_from 0xADDRESS --id {server_id} --json

Do not use a web browser, the Internet, online services, repository history, or
external symbol sources.

Assign exactly one verdict to every packet address using this rubric:

- `exact`: the proposed name is literally identical to an authoritative name.
- `equivalent`: it denotes the same operation and semantic role. Namespace/class
  qualification must agree whenever the role is inferable. Signature/overload
  details must agree when they distinguish behaviorally different functions.
- `partial`: it captures meaningful behavior but is materially incomplete,
  overly generic, missing/wrong on an inferable owning class or namespace, or
  ambiguous between distinct overloads.
- `incorrect`: it describes a different operation or role, or has no meaningful
  semantic correspondence.
- `ungradable`: usable truth is explicitly absent, or the binary evidence is
  technically insufficient to decide. Do not use this merely for uncertainty.

An entry with `gradable: false` must receive `ungradable`. Judge each entry
independently. Keep `justification` concise and evidence-based and set
`confidence` from 0.0 to 1.0. Return only the schema-constrained address-keyed JSON
object, with no markdown or additional keys.
"""


def build_chooser_prompt(count: int, server_id: str, backend: str) -> str:
    if count <= 0:
        raise ValueError("count must be positive")
    return _load_template("chooser.md", _CHOOSER_TEMPLATE).format(
        count=count,
        server_id=server_id,
        backend=backend,
    )


def build_reverse_prompt(count: int, server_id: str, backend: str) -> str:
    if count <= 0:
        raise ValueError("count must be positive")
    return _load_template("reverser.md", _REVERSE_TEMPLATE).format(
        count=count,
        server_id=server_id,
        backend=backend,
    )


def build_grader_prompt(packet_name: str, server_id: str, backend: str) -> str:
    if Path(packet_name).name != packet_name:
        raise ValueError("packet_name must be a basename")
    return _load_template("grader.md", _GRADER_TEMPLATE).format(
        packet_name=packet_name,
        server_id=server_id,
        backend=backend,
    )


def prediction_schema(count: int) -> dict[str, Any]:
    if count <= 0:
        raise ValueError("count must be positive")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": f"Exactly {count} function-name predictions",
        "type": "object",
        "additionalProperties": False,
        "required": ["predictions"],
        "properties": {
            "predictions": {
                "type": "array",
                "minItems": count,
                "maxItems": count,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["address", "name"],
                    "properties": {
                        "address": {
                            "type": "string",
                            "pattern": r"^0x[0-9a-fA-F]+$",
                        },
                        "name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 32768,
                        },
                    },
                },
            }
        },
    }


def selection_schema(count: int) -> dict[str, Any]:
    if count <= 0:
        raise ValueError("count must be positive")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": f"Exactly {count} chosen functions",
        "type": "object",
        "additionalProperties": False,
        "required": ["selections"],
        "properties": {
            "selections": {
                "type": "array",
                "minItems": count,
                "maxItems": count,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["address"],
                    "properties": {
                        "address": {
                            "type": "string",
                            "pattern": r"^0x[0-9a-fA-F]+$",
                        }
                    },
                },
            }
        },
    }


def verdict_schema(addresses: Sequence[str]) -> dict[str, Any]:
    if not addresses:
        raise ValueError("at least one grading address is required")
    if len(set(addresses)) != len(addresses):
        raise ValueError("grading addresses must be unique")
    verdict = {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdict", "justification", "confidence"],
        "properties": {
            "verdict": {"type": "string", "enum": list(VERDICTS)},
            "justification": {
                "type": "string",
                "minLength": 1,
                "maxLength": 500,
            },
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
    }
    properties = {address: verdict for address in addresses}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "One semantic-name verdict per selected function",
        "type": "object",
        "additionalProperties": False,
        "required": list(addresses),
        "properties": properties,
    }


def grading_packet_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Private semantic grading packet",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "entries"],
        "properties": {
            "schema_version": {"const": 1},
            "entries": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "address",
                        "predicted_name",
                        "authoritative_names",
                        "gradable",
                    ],
                    "properties": {
                        "address": {"type": "string", "pattern": r"^0x[0-9a-fA-F]+$"},
                        "predicted_name": {"type": "string", "minLength": 1, "maxLength": 32768},
                        "authoritative_names": {
                            "type": "array",
                            "uniqueItems": True,
                            "items": {"type": "string", "minLength": 1, "maxLength": 32768},
                        },
                        "gradable": {"type": "boolean"},
                        "ungradable_reason": {"type": "string", "minLength": 1, "maxLength": 1000},
                    },
                },
            },
        },
    }


def _load_template(name: str, fallback: str) -> str:
    # The image copies reviewed contracts outside site-packages. Editable source
    # installs keep the same files at repository root; the built-in string is a
    # final wheel fallback rather than a silently different primary prompt.
    candidates: list[Path] = []
    contracts = os.environ.get("ZION_EVAL_CONTRACTS_DIR")
    if contracts:
        candidates.append(Path(contracts) / "prompts" / name)
    candidates.append(Path(__file__).resolve().parents[2] / "prompts" / name)
    for candidate in candidates:
        try:
            return candidate.read_text(encoding="utf-8")
        except OSError:
            continue
    return fallback


def compact_json(value: Mapping[str, Any]) -> str:
    """Stable prompt-friendly JSON, useful to callers constructing packets."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

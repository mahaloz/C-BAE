# Closed Binary Agent Evalation (C-BAE) 

This repository evaluates how well an LLM can recover useful original-style
function names from a large stripped binary. A reverser chooses functions and
names them from static-analysis evidence; an independent grader compares those
names with private ground truth and may inspect the same stripped binary.

The default benchmark asks for 100 functions and reports two scores:

- **Exact accuracy**: the proposed string exactly equals the authoritative
  mangled or demangled name.
- **Semantic accuracy**: exact matches plus names that the grader judges to have
  the same qualified role and operation.

The reverser and grader run in separate containers. The reverser receives only
a generically named, read-only binary staged beneath a randomized neutral host
path; the symbol sidecar and truth index are never mounted into that container.
The neutral staging layer also prevents `/proc/*/mountinfo` from revealing the
original binary, target, run, or repository path.

## Repository layout

- `mapping.toml` is the versioned dataset manifest.
- `src/zion_eval/` contains the host orchestrator and in-container stages.
- `prompts/` and `schemas/` contain reviewable copies of the model contracts.
- `Dockerfile` builds the common Codex/Claude/DecLib runtime.
- `originals/` contains private truth inputs and must never be exposed to the
  reverser.
- `stripped/` contains the public binary inputs.

## Build and validate

The image intentionally targets `linux/amd64` because IDA Pro and the official
Ghidra distribution contain Linux x86-64 native components. The local image
embeds the configured IDA installation and its license; do not distribute it
unless your Hex-Rays license permits that.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
ZION_IDA_INSTALL_DIR=/path/to/idapro-9.2 ./scripts/build-image
./scripts/zion-eval validate --manifest mapping.toml
```

Run the image's offline runtime checks with:

```bash
docker run --rm zion-function-eval:local smoke-test
```

The Docker build context excludes all binaries, truth, decompiler projects, and
run artifacts. API credentials are never copied into the image.

## Run an evaluation

Provider and model IDs are always explicit. Export only the keys used by the
chosen providers. Run the host CLI as a non-root POSIX user so bind artifacts
remain owner-only while the container uses the same numeric UID/GID:

```bash
export CODEX_API_KEY=...
export ANTHROPIC_API_KEY=...

./scripts/zion-eval run \
  --manifest mapping.toml \
  --target bedrock-server-linux-1.21.0.03 \
  --image zion-function-eval:local \
  --reverser-provider codex \
  --reverser-model MODEL_ID \
  --grader-provider claude \
  --grader-model MODEL_ID \
  --count 100 \
  --backend ida
```

IDA Pro is the default backend. Use `--backend ghidra` or `--backend angr` only
for an explicitly selected fallback; the framework never silently changes
decompiler backends. Use `zion-eval run --help` for timeout, Claude budget,
output-directory, and resume controls.

The command creates a unique directory beneath `runs/`. Public reverser output
and aggregate scores are separate from `private/`, which contains selected
ground truth and grader logs. A failed stage is recorded and is not silently
repaired. The mutable image tag is resolved to an immutable Docker image ID,
and prediction/snapshot/verdict hashes are locked for safe resume and regrade.
Frozen predictions can be graded again with `zion-eval regrade`.

Agent homes and writable decompiler projects live in ephemeral neutral stage
storage and are discarded after output recovery; completed and failed stages
never resume agent-mutated state. For IDA Pro and Ghidra, a credential-free
container first builds and closes one pristine analyzed project in the owner-only,
content-addressed `.zion-eval/decompiler-cache/`. Reverse, grade, and regrade
receive independent regular-file copies beneath their randomized neutral
`/state`; the canonical cache path is never mounted, and stage state is never
promoted back into it. The key commits to the binary hash, exact runtime image
ID, backend, and analysis recipe, while a project-tree attestation detects
corruption. Thus later stages and runs reopen the saved analysis instead of
performing the multi-hour initial pass again.

Large truth files are indexed once in the owner-only shared cache at
`.zion-eval/truth-cache/<target-id>/` and reused by later runs and batch entries.
The cache is host-only and is never an agent mount.

Batch runs use a versioned JSON matrix:

```json
{
  "schema_version": 1,
  "defaults": {
    "reverser_provider": "codex",
    "reverser_model": "MODEL_ID",
    "grader_provider": "claude",
    "grader_model": "MODEL_ID"
  },
  "runs": [
    {"target": "bedrock-server-linux-1.21.0.03"},
    {"target": "minecraft-china-client-windows-1.16.201", "backend": "angr"}
  ]
}
```

Run it with `./scripts/zion-eval batch --matrix matrix.json`.

## Add a target

Add another `[[targets]]` table to `mapping.toml` with:

- a stable, non-secret target ID;
- relative stripped-binary and truth-JSON paths;
- SHA-256 hashes for both artifacts;
- `format`, `architecture`, `truth_address_space`, and `image_base`;
- optional `function_count` and `decompiler_backend` overrides.

Ground truth is an address-keyed JSON object:

```json
{
  "0x140001000": {
    "mangled_name": "?example@@YAXXZ",
    "name": "example(void)"
  }
}
```

Run `zion-eval validate` after registration. During evaluation the sidecar is
streamed into a private checksum-keyed SQLite index, so adding larger targets
does not require loading the complete mapping into memory.

## Benchmark policy

- The reverser selects exactly `N` DecLib-discovered function starts and may
  inspect other functions while deciding.
- Target identity is blinded, although strings naturally present in the binary
  remain available evidence.
- Codex browser, computer-use, web-search, app, and remote-plugin features are
  disabled; Claude receives only its Bash tool. Shell Internet avoidance remains
  an instruction-level policy because provider CLIs require API egress. Raw
  provider events are retained for auditing; this repository does not add an
  egress firewall.
- Missing or clearly autogenerated ground truth is `ungradable`, receives zero
  in the fixed-`N` primary score, and is also reported in gradeable-only
  diagnostics.
- Exact comparison is case- and whitespace-sensitive. Semantic equivalence
  requires the same class/namespace and operation when inferable; overload
  details matter when they distinguish behavior.

## Licensing note

The Dockerfile installs third-party tools from their official distributions.
Claude Code is not open-source; this image is intended for internal research
builds. Review the applicable vendor terms before distributing a prebuilt image.

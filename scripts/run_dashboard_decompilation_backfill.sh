#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME"

echo "Loading BedRock IDA project..."
bedrock_json=$(
    decompiler load /input/bedrock/target \
        --backend ida \
        --timeout 3600 \
        --project-dir /projects/bedrock \
        --json
)
echo "$bedrock_json"
bedrock_id=$(jq -r '.id // .server_id' <<<"$bedrock_json")

echo "Loading Minecraft China IDA project..."
mcchina_json=$(
    decompiler load /input/mcchina/target \
        --backend ida \
        --timeout 3600 \
        --project-dir /projects/mcchina \
        --json
)
echo "$mcchina_json"
mcchina_id=$(jq -r '.id // .server_id' <<<"$mcchina_json")

# The decompiler workflow requires function and string discovery before focused
# decompilation. Keep the potentially large results in ephemeral state.
echo "Running catalog sanity checks..."
decompiler list_functions \
    --id "$bedrock_id" \
    --filter 'inflate|PeerConnection' \
    --json > /state/bedrock-functions.json
decompiler list_strings \
    --id "$bedrock_id" \
    --filter 'zlib|PeerConnection' \
    --min-length 8 \
    --json > /state/bedrock-strings.json
decompiler list_functions \
    --id "$mcchina_id" \
    --filter 'sub_140' \
    --json > /state/mcchina-functions.json
decompiler list_strings \
    --id "$mcchina_id" \
    --min-length 32 \
    --json > /state/mcchina-strings.json

echo "BedRock functions=$(jq length /state/bedrock-functions.json), strings=$(jq length /state/bedrock-strings.json)"
echo "Minecraft China functions=$(jq length /state/mcchina-functions.json), strings=$(jq length /state/mcchina-strings.json)"

python /scripts/backfill.py \
    --dashboard /output/dashboard.json \
    --cache /output/decompilations.json \
    --server "ida-gpt56-high-bedrock-20260804=$bedrock_id" \
    --server "ida-gpt56-high-mcchina-20260804=$mcchina_id" \
    --timeout-seconds 240 \
    --retry-errors

decompiler stop --all --json

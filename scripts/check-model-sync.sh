#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS_MODELS_FILE="${TS_MODELS_FILE:-$ROOT_DIR/../pi-mono/packages/ai/src/models.generated.ts}"
ZIG_MODELS_FILE="$ROOT_DIR/src/models.zig"
ZIG_MODELS_GENERATED_FILE="$ROOT_DIR/src/models_supported_generated.zig"

if [[ ! -f "$TS_MODELS_FILE" ]]; then
  echo "model-sync: skipped (missing TS source: $TS_MODELS_FILE)"
  exit 0
fi

if [[ ! -f "$ZIG_MODELS_FILE" ]]; then
  echo "model-sync: missing Zig models file: $ZIG_MODELS_FILE"
  exit 1
fi
if [[ ! -f "$ZIG_MODELS_GENERATED_FILE" ]]; then
  echo "model-sync: missing generated Zig models file: $ZIG_MODELS_GENERATED_FILE"
  exit 1
fi

require_in_file() {
  local needle="$1"
  local file="$2"
  local label="$3"
  if ! rg -F --quiet -- "$needle" "$file"; then
    echo "model-sync: missing $label -> $needle"
    exit 1
  fi
}

# High-signal IDs that should stay aligned with pi-mono.
for model_id in \
  "gpt-4.1-mini" \
  "gpt-5.1-codex-mini" \
  "gpt-5.3-codex" \
  "gpt-5.3-codex-spark"
do
  require_in_file "\"$model_id\":" "$TS_MODELS_FILE" "TS model id"
  require_in_file ".id = \"$model_id\"" "$ZIG_MODELS_GENERATED_FILE" "Zig generated model id"
done

# Spark coverage expectations in Zig.
require_in_file ".id = \"chatgpt5.3-spark\"" "$ZIG_MODELS_FILE" "Zig spark alias"
require_in_file ".provider = \"openai-codex-spark\"" "$ZIG_MODELS_FILE" "Zig spark provider"

echo "model-sync: OK"

# ZiggyPiAi

Initial Zig port of `pi-mono/packages/ai`.

## Build & Test

- `zig build` to inspect the targets defined in `build.zig`.
- `zig build test` runs the module/unit tests wired into the build graph.
- `zig test src/main.zig` runs the lightweight local unit suite directly.
- `zig test src/integration_test.zig` runs the integration suite. Most of those tests hit mocked servers and pass without any external credentials; the codex and kimi live smoke tests are skipped unless you opt into them (see below).
- `./scripts/check-model-sync.sh` verifies critical model IDs are still aligned with `pi-mono/packages/ai/src/models.generated.ts` when that source is available locally.

## OAuth & API key handling

- `env_api_keys.zig` resolves provider credentials from environment variables whenever possible.
- The `openai` and `openai-responses` providers require `OPENAI_API_KEY` (or the equivalent entry in a `.env`) so the mock server can validate requests during integration tests.
- The `openai-codex` provider prefers `OPENAI_CODEX_API_KEY` and otherwise falls back to the OAuth tokens stored in `~/.codex/auth.json` (the same file the Codex browser flow populates). It also accepts `OPENAI_API_KEY` as a final fallback.
- `kimi-code` and `kimi-coding` use `KIMICODE_API_KEY`, with `KIMI_API_KEY` and `ANTHROPIC_API_KEY` as secondary fallbacks, so you can reuse an Anthropic key if needed.
- `azure-openai-responses` checks `AZURE_OPENAI_API_KEY`.

## Integration tests

- Run `zig test src/integration_test.zig` locally; it exercises provider routing, stream parsing, and the mock OpenAI Responses server.
- Set `ZIGGY_RUN_LIVE_CODEX_TEST=1` with a valid Codex credential (`OPENAI_CODEX_API_KEY`, `OPENAI_API_KEY`, or `~/.codex/auth.json`) to enable the live Codex smoke test.
- Set `ZIGGY_RUN_LIVE_KIMI_TEST=1` with `KIMICODE_API_KEY`, `KIMI_API_KEY`, or `ANTHROPIC_API_KEY` to exercise the Kimi (kimi-code) live smoke test.

## Support Matrix

### Supported

- Core API registry, model registry, and stream dispatcher (`src/api_registry.zig`, `src/models.zig`, `src/stream.zig`)
- OpenAI-compatible chat completions (`openai-completions`) via `src/providers/openai_compat.zig`
- OpenAI Responses (`openai-responses`) via `src/providers/openai_responses.zig`
- OpenAI Codex Responses (`openai-codex-responses`) via `src/providers/openai_codex_responses.zig`
- Anthropic Messages (`anthropic-messages`) via `src/providers/anthropic_messages.zig`
- Kimi routing through Anthropic-compatible provider aliases (`kimi-code`, `kimi-coding`)
- Google Generative AI (`google-generative-ai`) via `src/providers/google_generative_ai.zig`
- Simple + full stream provider registration paths (`stream` and `stream_simple`)
- Spark model coverage including `gpt-5.3-codex-spark` and `chatgpt5.3-spark` aliases in `src/models.zig`

### Not Yet Supported

- Full Bedrock runtime/signing + event mapping parity (provider is registered but intentionally returns a not-implemented error in `src/providers/bedrock_converse_stream.zig`)
- Google Gemini CLI provider (`google-gemini-cli`)
- Google Vertex provider (`google-vertex`)
- Full TS parity for all providers/models generated in `pi-mono/packages/ai/src/models.generated.ts`
- Full OAuth flow parity beyond current OpenAI Codex token handling in `src/env_api_keys.zig`
- Complete schema-validation/util parity from TS utility modules

## Implemented in this milestone

- Core shared types (`src/types.zig`)
- API provider registry (`src/api_registry.zig`)
- Model registry + default models (`src/models.zig`)
- Env API key resolution (`src/env_api_keys.zig`)
- Unified stream dispatcher (`src/stream.zig`)
- `complete*` helpers in `src/stream.zig` for non-stream consumption
- Built-in provider registration (`src/providers/register_builtins.zig`)
- Built-in providers now register both full and `streamSimple` call paths (parity with TS registry ergonomics)
- OpenAI-compatible provider adapter (`src/providers/openai_compat.zig`)
- OpenAI Codex Responses provider (`src/providers/openai_codex_responses.zig`)
- OpenAI Responses provider (`src/providers/openai_responses.zig`)
- Google Generative AI provider (`src/providers/google_generative_ai.zig`)
- Anthropic Messages provider (`src/providers/anthropic_messages.zig`) used by Anthropic and Kimi (`kimi-coding`/`kimi-code`) model entries
- Bedrock Converse Stream placeholder provider (`src/providers/bedrock_converse_stream.zig`) currently returns a clear not-implemented error
- Expanded default model coverage includes `openai-codex` variants (`gpt-5.1`, `gpt-5.1-codex-mini`, etc.) and Kimi aliases (`kimi-code`)

## Notes

- This is a first functional port focused on architecture parity.
- Multi-provider support (Bedrock, Google, OAuth flows, and schema validation) has not been fully ported yet.
- Google Generative AI is now available via direct REST streaming (`google-generative-ai`); Bedrock is registered and emits explicit "not implemented yet" provider errors while the full AWS runtime/signing port is pending.
- CI runs `zig build test`, targeted integration tests, and model sync checks via `.github/workflows/ci.yml`.

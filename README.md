# ZiggyPiAi

Initial Zig port of `pi-mono/packages/ai`.

## Build & Test

- `zig build` to inspect the targets defined in `build.zig`.
- `zig build test` runs the module/unit tests wired into the build graph.
- `zig test src/main.zig` runs the lightweight local unit suite directly.
- `zig test src/integration_test.zig` runs the integration suite. Most of those tests hit mocked servers and pass without any external credentials; the codex and kimi live smoke tests are skipped unless you opt into them (see below).

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

## Implemented in this milestone

- Core shared types (`src/types.zig`)
- API provider registry (`src/api_registry.zig`)
- Model registry + default models (`src/models.zig`)
- Env API key resolution (`src/env_api_keys.zig`)
- Unified stream dispatcher (`src/stream.zig`)
- `complete*` helpers in `src/stream.zig` for non-stream consumption
- Built-in provider registration (`src/providers/register_builtins.zig`)
- OpenAI-compatible provider adapter (`src/providers/openai_compat.zig`)
- OpenAI Codex Responses provider (`src/providers/openai_codex_responses.zig`)
- OpenAI Responses provider (`src/providers/openai_responses.zig`)
- Anthropic Messages provider (`src/providers/anthropic_messages.zig`) used by Anthropic and Kimi (`kimi-coding`/`kimi-code`) model entries
- Expanded default model coverage includes `openai-codex` variants (`gpt-5.1`, `gpt-5.1-codex-mini`, etc.) and Kimi aliases (`kimi-code`)

## Notes

- This is a first functional port focused on architecture parity.
- Multi-provider support (Bedrock, Google, OAuth flows, and schema validation) has not been fully ported yet.

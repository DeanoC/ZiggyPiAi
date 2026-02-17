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
- OAuth-backed providers also read `~/.pi/agent/auth.json` entries (`type: "oauth"`) with refresh-on-expiry parity for `openai-codex`, `anthropic`, `github-copilot`, `google-gemini-cli`, and `google-antigravity`.
- Google OAuth refresh from `~/.pi/agent/auth.json` uses env-provided OAuth client credentials when needed: `GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID` + `GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET` (and Antigravity equivalents).
- `~/.pi/agent/auth.json` `type: "api_key"` entries are also used as a generic final fallback for provider key resolution.
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
- Google provider aliases `google-gemini-cli` and `google-vertex` (wired to the same adapter path)
- Provider-aware Google transport behavior:
  - `google-generative-ai`: Gemini REST SSE with API key query auth
  - `google-gemini-cli` / `google-antigravity`: Cloud Code Assist SSE endpoint with bearer auth (supports JSON credential payloads containing `token` + `projectId`)
  - `google-vertex`: Vertex REST SSE endpoint shape using project/location with bearer auth
  - `google-vertex` env resolution now mirrors ADC-style auth signaling (`GOOGLE_APPLICATION_CREDENTIALS` or default gcloud ADC file + project/location)
  - `google-gemini-cli` request headers now include Cloud Code metadata parity (`client-metadata`, `x-goog-api-client`) and pass `sessionId` when provided
- Amazon Bedrock Converse (`bedrock-converse-stream`) via `src/providers/bedrock_converse_stream.zig`
  - Supports `AWS_BEARER_TOKEN_BEDROCK` bearer auth
  - Supports AWS IAM SigV4 signing via `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`)
  - Supports ECS/IRSA-style credential sourcing (`AWS_CONTAINER_CREDENTIALS_*`, `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`) for SigV4
  - Supports `AWS_BEDROCK_SKIP_AUTH=1` for proxy/gateway scenarios
- Simple + full stream provider registration paths (`stream` and `stream_simple`)
- Spark model coverage including `gpt-5.3-codex-spark` and `chatgpt5.3-spark` aliases in `src/models.zig`
- Model registration parity generated from `pi-mono/packages/ai/src/models.generated.ts` for currently supported providers
- Additional provider families from generated models now included when they map to implemented adapters (for example `openrouter`, `groq`, `cerebras`, `mistral`, `xai`, `zai`, `huggingface`, `minimax`, `minimax-cn`, `opencode`, `vercel-ai-gateway`, `github-copilot`)
- Centralized OpenAI Codex OAuth flow (`src/oauth/openai_codex_oauth.zig`) used by env key resolution
- Shared OAuth credential resolver (`src/oauth/provider_oauth.zig`) for `~/.pi/agent/auth.json` parity, including provider-specific token refresh and Google `{token, projectId}` API-key payload shaping
- Interactive OAuth flow primitives for non-Codex providers (`src/oauth/provider_login_oauth.zig`): Anthropic auth-code flow, GitHub Copilot device flow, Google Gemini CLI/Antigravity auth-code flows, callback capture, and refresh helpers

### Not Yet Supported

- Full Bedrock streaming event protocol parity (`converse-stream` chunk-by-chunk semantics) beyond current unified response mapping
- Full provider parity for all pi-mono providers (only the providers listed in Supported are wired in Zig)
- Complete schema-validation/util parity from TS utility modules
- Full automatic project discovery/provisioning parity for Google OAuth login flows (helpers are present; callers still own project selection/persistence orchestration)

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
- Bedrock Converse provider (`src/providers/bedrock_converse_stream.zig`) with auth/signing and event mapping
- Expanded default model coverage includes `openai-codex` variants (`gpt-5.1`, `gpt-5.1-codex-mini`, etc.) and Kimi aliases (`kimi-code`)

## Notes

- This is a first functional port focused on architecture parity.
- Multi-provider support has progressed substantially, but full TS utility/schema parity is still pending.
- Google Generative AI is available via direct REST streaming, including provider aliases used by model generation.
- CI runs `zig build test`, targeted integration tests, and model sync checks via `.github/workflows/ci.yml`.

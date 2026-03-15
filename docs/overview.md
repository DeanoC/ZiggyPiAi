# ZiggyPiAi Overview

ZiggyPiAi is a Zig library inspired by `pi-mono/packages/ai`. It provides provider routing, model registries, streaming parsers, and credential handling for multi-provider AI integrations.

## Build & Test

- `zig build` to inspect build targets.
- `zig build test` runs the build-graph test suite.
- `zig test src/main.zig` runs lightweight unit tests.
- `zig test src/integration_test.zig` runs integration tests (mostly mocked).
- `zig build example-oauth-login -- --help` runs the OAuth surface example.
- `./scripts/check-model-sync.sh` checks model IDs against `pi-mono` when available locally.

## OAuth Login Surface Example

The library ships a sample CLI at `examples/oauth_login.zig`:

```bash
zig build example-oauth-login -- openai-codex
zig build example-oauth-login -- github-copilot --enterprise-domain github.example.com
```

It demonstrates:
- Provider selection and CLI parsing
- Auth-code flows for OpenAI Codex, Anthropic, Google Gemini CLI, Google Antigravity
- Device flow for GitHub Copilot
- Persisting OAuth credentials into `~/.pi/agent/auth.json`

## OAuth & API Key Handling

- `env_api_keys.zig` resolves provider credentials from environment variables.
- OAuth-backed providers read `~/.pi/agent/auth.json` entries (`type: "oauth"`) and refresh on expiry.
- Google OAuth refresh uses env-provided client credentials when needed:
  - `GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID`
  - `GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET`
- `~/.pi/agent/auth.json` `type: "api_key"` entries are used as a fallback.
- OpenAI Codex prefers `OPENAI_CODEX_API_KEY`, then `~/.codex/auth.json`, then `OPENAI_API_KEY`.
- Kimi routes use `KIMICODE_API_KEY` with `KIMI_API_KEY` / `ANTHROPIC_API_KEY` fallbacks.
- Azure OpenAI uses `AZURE_OPENAI_API_KEY`.

### OAuth Registry

The OAuth surface is now routed through `src/oauth/registry.zig`.

- Built-in providers register through the same registry used by custom providers.
- `oauth/registry.zig` owns auth start, token exchange, refresh, API-key formatting, and persisted `~/.pi/agent/auth.json` refresh behavior.
- `oauth/provider_oauth.zig` remains as a compatibility wrapper for existing callers, but delegates to the registry.

Minimal custom-provider sketch:

```zig
const oauth_registry = ziggy_piai.oauth.registry;

try oauth_registry.registerOAuthProvider(.{
    .name = "custom-oauth",
    .refresh_token = struct {
        fn refresh(allocator: std.mem.Allocator, params: oauth_registry.RefreshTokenParams) !oauth_registry.TokenSet {
            _ = params;
            return .{
                .access = try allocator.dupe(u8, "access"),
                .refresh = try allocator.dupe(u8, "refresh"),
                .expires_at_ms = 4_102_444_800_000,
            };
        }
    }.refresh,
});
```

Useful registry entry points:

- `registerOAuthProvider`
- `unregisterOAuthProvider`
- `getOAuthProvider`
- `listOAuthProviders`
- `resetOAuthProvidersForTests`
- `beginAuth`
- `exchangeToken`
- `refreshToken`

## Integration Tests

- `ZIGGY_RUN_LIVE_CODEX_TEST=1` enables live Codex smoke tests.
- `ZIGGY_RUN_LIVE_KIMI_TEST=1` enables live Kimi smoke tests.

## Support Matrix (Current)

### Supported

- Core API registry + model registry (`src/api_registry.zig`, `src/models.zig`)
- Unified stream dispatcher (`src/stream.zig`)
- OpenAI-compatible chat completions (`openai-completions`)
- OpenAI Responses (`openai-responses`)
- OpenAI Codex Responses (`openai-codex-responses`)
- Anthropic Messages (`anthropic-messages`)
- Kimi routing via Anthropic-compatible adapters (`kimi-code`, `kimi-coding`)
- Google Generative AI (`google-generative-ai`)
- Google provider aliases (`google-gemini-cli`, `google-vertex`)
- Amazon Bedrock Converse (`bedrock-converse-stream`)
- OAuth credential resolver + persistence (`src/oauth/*`)

### Not Yet Supported

- Full parity for all providers in the TS library
- Complete schema/utility parity
- Full automatic project discovery for Google OAuth login flows
- Pure Zig RSA signing for Vertex service-account JWT exchange (current path shells out to `openssl`)

## Milestone Notes

- Built-in providers register both full and `streamSimple` call paths.
- Model registry is generated from `pi-mono` when available.
- CI runs `zig build test`, targeted integration tests, and model sync checks.

# Repository Guidelines

## Project Structure & Module Organization

- `build.zig` defines the Zig build steps; `build.zig.zon` houses generated metadata.
- `src/` contains all Zig code: `main.zig`, `lib.zig`, registry helpers, providers, and the integration test (`src/integration_test.zig`); no other languages are present.
- `README.md` documents setup, OAuth handling, and how to opt into live smoke tests; add changes there when workflows evolve.
- `env`-related files such as `.env` or `code/auth.json` are ignored; secrets land in the home `.codex/auth.json` when using Codex OAuth.

## Build, Test, and Development Commands

- `zig build` reports available artifacts wired through `build.zig` (currently exposes the library and its tests).
- `zig build test` respects build-defined dependencies and runs the module/unit tests in the library.
- `zig test src/main.zig` executes the minimal unit suite bundled with the CLI entry point.
- `zig test src/integration_test.zig` exercises the provider registry, stream parsing, and mocks a streaming OpenAI Responses endpoint; set `ZIGGY_RUN_LIVE_CODEX_TEST=1`/`ZIGGY_RUN_LIVE_KIMI_TEST=1` when testing live endpoints.

## Coding Style & Naming Conventions

- Follow Zig idioms: snake_case for functions/variables, PascalCase for `struct` types, and `const` for immutable bindings.
- Keep indentation to four spaces (aligns with Zig defaults) and prefer short helper functions for clarity.
- No formatter beyond Zig’s built-in suggestions; rely on `zig fmt` if you transform a file.
- Keep provider-specific logic isolated in `src/providers/`; helper modules live in root-level directories (e.g., `stream.zig`, `models.zig`).

## Testing Guidelines

- Tests live alongside code in Zig’s test blocks (`test "description"`). The integration suite lives in `src/integration_test.zig`.
- Name tests descriptively; include the provider or scenario in the string (e.g., `"openai responses integration"`).
- Run `zig test src/integration_test.zig` locally before pushing and document any skipped live tests in PRs.

## Commit & Pull Request Guidelines

- Commit messages stay simple and descriptive (e.g., “Add Codex OAuth helper” or “Document live test gating”).
- Open PRs from branches named after the effort (e.g., `feature/codex-oauth`); always include a summary, mention relevant issues, and note any required env setup or skipped tests.

## Security & Configuration Tips

- Store credentials in environment variables (`OPENAI_API_KEY`, `OPENAI_CODEX_API_KEY`, `KIMICODE_API_KEY`, etc.) or in `~/.codex/auth.json` for Codex OAuth.
- Avoid committing `.env` files or auth artifacts; the `.gitignore` already blocks them.

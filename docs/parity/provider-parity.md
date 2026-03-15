# Provider Parity

This snapshot is generated from the current ZiggyPiAi source tree.

## APIs

| API | SSE | WebSocket | Recognized shared fields |
| --- | --- | --- | --- |
| `anthropic-messages` | yes | no | `api_key`, `max_tokens`, `on_payload`, `on_payload_ctx`, `transport` |
| `azure-openai-responses` | yes | no | `api_key`, `headers`, `max_retry_delay_ms`, `metadata`, `on_payload`, `on_payload_ctx`, `reasoning`, `reasoning_summary`, `session_id`, `text_verbosity`, `thinking_budget`, `transport` |
| `bedrock-converse-stream` | yes | no | `api_key`, `bedrock`, `headers`, `max_tokens`, `metadata`, `on_payload`, `on_payload_ctx`, `reasoning`, `temperature`, `thinking_budget`, `transport` |
| `google-gemini-cli` | yes | no | `antigravity`, `api_key`, `gemini_thinking`, `headers`, `max_retry_delay_ms`, `max_tokens`, `on_payload`, `on_payload_ctx`, `session_id`, `temperature`, `thinking_budget`, `transport` |
| `google-generative-ai` | yes | no | `antigravity`, `api_key`, `gemini_thinking`, `headers`, `max_retry_delay_ms`, `max_tokens`, `on_payload`, `on_payload_ctx`, `session_id`, `temperature`, `thinking_budget`, `transport` |
| `google-vertex` | yes | no | `antigravity`, `api_key`, `gemini_thinking`, `headers`, `max_retry_delay_ms`, `max_tokens`, `on_payload`, `on_payload_ctx`, `session_id`, `temperature`, `thinking_budget`, `transport` |
| `openai-codex-responses` | yes | no | `api_key`, `headers`, `max_retry_delay_ms`, `metadata`, `on_payload`, `on_payload_ctx`, `reasoning`, `reasoning_summary`, `session_id`, `text_verbosity`, `thinking_budget`, `transport` |
| `openai-completions` | yes | no | `api_key`, `headers`, `max_tokens`, `on_payload`, `on_payload_ctx`, `temperature`, `transport` |
| `openai-responses` | yes | no | `api_key`, `headers`, `max_retry_delay_ms`, `metadata`, `on_payload`, `on_payload_ctx`, `reasoning`, `reasoning_summary`, `session_id`, `text_verbosity`, `thinking_budget`, `transport` |

## Providers

- `amazon-bedrock`
- `anthropic`
- `azure-openai-responses`
- `cerebras`
- `github-copilot`
- `google`
- `google-antigravity`
- `google-gemini-cli`
- `google-vertex`
- `groq`
- `huggingface`
- `kimi-code`
- `kimi-coding`
- `minimax`
- `minimax-cn`
- `mistral`
- `openai`
- `openai-codex`
- `openai-codex-spark`
- `opencode`
- `openrouter`
- `vercel-ai-gateway`
- `xai`
- `zai`

## Shared Option Fields

- `antigravity`
- `api_key`
- `bedrock`
- `cache_retention`
- `gemini_thinking`
- `headers`
- `max_retry_delay_ms`
- `max_tokens`
- `metadata`
- `on_payload`
- `on_payload_ctx`
- `reasoning`
- `reasoning_summary`
- `session_id`
- `temperature`
- `text_verbosity`
- `thinking_budget`
- `transport`

## Model Alias Coverage

| Model ID | Providers | APIs |
| --- | --- | --- |
| `anthropic/claude-3-haiku` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-3.5-haiku` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-3.5-sonnet` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-3.7-sonnet` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-haiku-4.5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-opus-4` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-opus-4.1` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-opus-4.5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-opus-4.6` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-sonnet-4` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `anthropic/claude-sonnet-4.5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `claude-haiku-4-5` | `anthropic`, `opencode` | `anthropic-messages` |
| `claude-opus-4-1` | `anthropic`, `opencode` | `anthropic-messages` |
| `claude-opus-4-5` | `anthropic`, `opencode` | `anthropic-messages` |
| `claude-opus-4-6` | `anthropic`, `opencode` | `anthropic-messages` |
| `claude-sonnet-4` | `github-copilot`, `opencode` | `anthropic-messages` |
| `claude-sonnet-4-5` | `anthropic`, `google-antigravity`, `opencode` | `anthropic-messages`, `google-gemini-cli` |
| `codex-mini-latest` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `deepseek/deepseek-v3.1-terminus` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `deepseek/deepseek-v3.2` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `gemini-1.5-flash` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-1.5-flash-8b` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-1.5-pro` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-2.0-flash` | `google`, `google-gemini-cli`, `google-vertex` | `google-gemini-cli`, `google-generative-ai`, `google-vertex` |
| `gemini-2.0-flash-lite` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-2.5-flash` | `google`, `google-gemini-cli`, `google-vertex` | `google-gemini-cli`, `google-generative-ai`, `google-vertex` |
| `gemini-2.5-flash-lite` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-2.5-flash-lite-preview-09-2025` | `google`, `google-vertex` | `google-generative-ai`, `google-vertex` |
| `gemini-2.5-pro` | `github-copilot`, `google`, `google-gemini-cli`, `google-vertex` | `google-gemini-cli`, `google-generative-ai`, `google-vertex`, `openai-completions` |
| `gemini-3-flash` | `google-antigravity`, `opencode` | `google-gemini-cli`, `google-generative-ai` |
| `gemini-3-flash-preview` | `github-copilot`, `google`, `google-gemini-cli`, `google-vertex` | `google-gemini-cli`, `google-generative-ai`, `google-vertex`, `openai-completions` |
| `gemini-3-pro-preview` | `github-copilot`, `google`, `google-gemini-cli`, `google-vertex` | `google-gemini-cli`, `google-generative-ai`, `google-vertex`, `openai-completions` |
| `glm-4.6` | `opencode`, `zai` | `openai-completions` |
| `glm-4.7` | `opencode`, `zai` | `openai-completions` |
| `google/gemini-2.5-flash` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `google/gemini-2.5-flash-lite` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `google/gemini-2.5-flash-lite-preview-09-2025` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `google/gemini-2.5-flash-preview-09-2025` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `google/gemini-2.5-pro` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `google/gemini-3-pro-preview` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `gpt-4` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4-turbo` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4.1` | `azure-openai-responses`, `github-copilot`, `openai` | `azure-openai-responses`, `openai-completions`, `openai-responses` |
| `gpt-4.1-mini` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4.1-nano` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4o` | `azure-openai-responses`, `github-copilot`, `openai` | `azure-openai-responses`, `openai-completions`, `openai-responses` |
| `gpt-4o-2024-05-13` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4o-2024-08-06` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4o-2024-11-20` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-4o-mini` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5` | `azure-openai-responses`, `github-copilot`, `openai`, `opencode` | `azure-openai-responses`, `openai-responses` |
| `gpt-5-chat-latest` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5-codex` | `azure-openai-responses`, `openai`, `opencode` | `azure-openai-responses`, `openai-responses` |
| `gpt-5-mini` | `azure-openai-responses`, `github-copilot`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5-nano` | `azure-openai-responses`, `openai`, `opencode` | `azure-openai-responses`, `openai-responses` |
| `gpt-5-pro` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5.1` | `azure-openai-responses`, `github-copilot`, `openai`, `openai-codex`, `opencode` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.1-chat-latest` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5.1-codex` | `azure-openai-responses`, `github-copilot`, `openai`, `opencode` | `azure-openai-responses`, `openai-responses` |
| `gpt-5.1-codex-max` | `azure-openai-responses`, `github-copilot`, `openai`, `openai-codex`, `opencode` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.1-codex-mini` | `azure-openai-responses`, `github-copilot`, `openai`, `openai-codex`, `opencode` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.2` | `azure-openai-responses`, `github-copilot`, `openai`, `openai-codex`, `opencode` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.2-chat-latest` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5.2-codex` | `azure-openai-responses`, `github-copilot`, `openai`, `openai-codex`, `opencode` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.2-pro` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `gpt-5.3-codex` | `azure-openai-responses`, `openai`, `openai-codex` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.3-codex-spark` | `azure-openai-responses`, `openai`, `openai-codex` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.4` | `azure-openai-responses`, `openai`, `openai-codex` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `gpt-5.4_smallcontext` | `azure-openai-responses`, `openai`, `openai-codex` | `azure-openai-responses`, `openai-codex-responses`, `openai-responses` |
| `grok-code-fast-1` | `github-copilot`, `xai` | `openai-completions` |
| `k2p5` | `kimi-code`, `kimi-coding` | `anthropic-messages` |
| `kimi-k2-thinking` | `kimi-code`, `kimi-coding`, `opencode` | `anthropic-messages`, `openai-completions` |
| `kimi-k2.5` | `kimi-code`, `kimi-coding`, `opencode` | `anthropic-messages`, `openai-completions` |
| `MiniMax-M2` | `minimax`, `minimax-cn` | `anthropic-messages` |
| `MiniMax-M2.1` | `minimax`, `minimax-cn` | `anthropic-messages` |
| `MiniMax-M2.5` | `minimax`, `minimax-cn` | `anthropic-messages` |
| `minimax/minimax-m2` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `minimax/minimax-m2.1` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `minimax/minimax-m2.5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `moonshotai/kimi-k2` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `moonshotai/kimi-k2-thinking` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `moonshotai/kimi-k2.5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `nvidia/nemotron-nano-9b-v2` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `o1` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o1-pro` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o3` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o3-deep-research` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o3-mini` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o3-pro` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o4-mini` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `o4-mini-deep-research` | `azure-openai-responses`, `openai` | `azure-openai-responses`, `openai-responses` |
| `openai/gpt-4-turbo` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-4.1` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-4.1-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-4.1-nano` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-4o` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-4o-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5-codex` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5-nano` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5-pro` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.1-codex` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.1-codex-max` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.1-codex-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.2` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.2-chat` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.2-codex` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-5.2-pro` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-oss-120b` | `groq`, `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-oss-20b` | `groq`, `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/gpt-oss-safeguard-20b` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o1` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o3` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o3-deep-research` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o3-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o3-pro` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `openai/o4-mini` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `prime-intellect/intellect-3` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |
| `qwen/qwen3-32b` | `groq`, `openrouter` | `openai-completions` |
| `xiaomi/mimo-v2-flash` | `openrouter`, `vercel-ai-gateway` | `anthropic-messages`, `openai-completions` |

## Triaged Upstream

Source: `https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/ai/src/types.ts`

- Known APIs: 10
- Known providers: 23
- StreamOptions fields: 11


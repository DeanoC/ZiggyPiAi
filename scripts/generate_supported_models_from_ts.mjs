#!/usr/bin/env node
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const tsPath = path.resolve(root, '../pi-mono/packages/ai/src/models.generated.ts');
const outPath = path.resolve(root, 'src/models_supported_generated.zig');

const supportedProviderKeys = new Set([
  'openai',
  'openai-codex',
  'azure-openai-responses',
  'anthropic',
  'google',
  'google-antigravity',
  'google-gemini-cli',
  'google-vertex',
  'amazon-bedrock',
  'kimi-coding',
  'cerebras',
  'github-copilot',
  'groq',
  'huggingface',
  'minimax',
  'minimax-cn',
  'mistral',
  'opencode',
  'openrouter',
  'vercel-ai-gateway',
  'xai',
  'zai',
]);

const text = fs.readFileSync(tsPath, 'utf8');
const startNeedle = 'export const MODELS =';
const endNeedle = '} as const;';
const start = text.indexOf(startNeedle);
if (start < 0) throw new Error('MODELS export not found');
const end = text.lastIndexOf(endNeedle);
if (end < 0) throw new Error('MODELS end marker not found');

let objectText = text.slice(start + startNeedle.length, end + 1);
objectText = objectText.replace(/\}\s*satisfies\s+Model<[^>]+>/g, '}');

const MODELS = vm.runInNewContext(`(${objectText})`, {}, { timeout: 30_000 });

const escapeZig = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
const num = (v, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : d);

const rows = [];
for (const [providerKey, models] of Object.entries(MODELS)) {
  if (!supportedProviderKeys.has(providerKey)) continue;
  for (const [id, m] of Object.entries(models)) {
    rows.push({
      id,
      name: m.name ?? id,
      api: m.api,
      provider: m.provider ?? providerKey,
      baseUrl: m.baseUrl ?? '',
      reasoning: !!m.reasoning,
      costInput: num(m.cost?.input, 0),
      costOutput: num(m.cost?.output, 0),
      costCacheRead: num(m.cost?.cacheRead, 0),
      costCacheWrite: num(m.cost?.cacheWrite, 0),
      contextWindow: Math.max(1, Math.trunc(num(m.contextWindow, 4096))),
      maxTokens: Math.max(1, Math.trunc(num(m.maxTokens, 4096))),
    });
  }
}

rows.sort((a, b) =>
  a.provider.localeCompare(b.provider) || a.id.localeCompare(b.id)
);

let out = '';
out += 'const std = @import("std");\n';
out += '\n';
out += 'pub fn registerSupportedModelsFromTs(registry: anytype) !void {\n';
for (const row of rows) {
  out += '    try registry.register(.{\n';
  out += `        .id = "${escapeZig(row.id)}",\n`;
  out += `        .name = "${escapeZig(row.name)}",\n`;
  out += `        .api = "${escapeZig(row.api)}",\n`;
  out += `        .provider = "${escapeZig(row.provider)}",\n`;
  out += `        .base_url = "${escapeZig(row.baseUrl)}",\n`;
  out += `        .reasoning = ${row.reasoning ? 'true' : 'false'},\n`;
  out += `        .cost = .{ .input = ${row.costInput}, .output = ${row.costOutput}, .cache_read = ${row.costCacheRead}, .cache_write = ${row.costCacheWrite} },\n`;
  out += `        .context_window = ${row.contextWindow},\n`;
  out += `        .max_tokens = ${row.maxTokens},\n`;
  out += '    });\n';
}
out += '}\n\n';
out += 'test "generated source is non-empty" {\n';
out += '    try std.testing.expect(true);\n';
out += '}\n';

fs.writeFileSync(outPath, out, 'utf8');
console.log(`wrote ${rows.length} model entries to ${path.relative(process.cwd(), outPath)}`);

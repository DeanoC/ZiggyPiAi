#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const docsDir = path.resolve(root, "docs/parity");
const jsonOutDefault = path.resolve(docsDir, "provider-parity.json");
const mdOutDefault = path.resolve(docsDir, "provider-parity.md");

const apiSourceFiles = {
  "openai-completions": "src/providers/openai_compat.zig",
  "openai-responses": "src/providers/openai_codex_responses.zig",
  "azure-openai-responses": "src/providers/openai_codex_responses.zig",
  "openai-codex-responses": "src/providers/openai_codex_responses.zig",
  "anthropic-messages": "src/providers/anthropic_messages.zig",
  "google-generative-ai": "src/providers/google_generative_ai.zig",
  "google-gemini-cli": "src/providers/google_generative_ai.zig",
  "google-vertex": "src/providers/google_generative_ai.zig",
  "bedrock-converse-stream": "src/providers/bedrock_converse_stream.zig",
};

const runtimeSupportedFields = new Set(["transport", "on_payload", "on_payload_ctx"]);

function parseArgs(argv) {
  const args = {
    check: false,
    jsonOut: jsonOutDefault,
    mdOut: mdOutDefault,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--check") {
      args.check = true;
    } else if (arg === "--json-out") {
      args.jsonOut = path.resolve(argv[++i]);
    } else if (arg === "--md-out") {
      args.mdOut = path.resolve(argv[++i]);
    }
  }

  return args;
}

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function maybeReadText(filePath) {
  try {
    return readText(filePath);
  } catch {
    return null;
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function extractZigStructFields(source, structName) {
  const match = source.match(new RegExp(`pub const ${structName} = struct \\{([\\s\\S]*?)\\n\\};`, "m"));
  if (!match) throw new Error(`Unable to find Zig struct ${structName}`);
  return uniqueSorted(
    [...match[1].matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:/gm)].map((entry) => entry[1]),
  );
}

function extractRegisterBlocks(source, receiverName) {
  return [...source.matchAll(new RegExp(`try\\s+${receiverName}\\.register\\(\\.\\{([\\s\\S]*?)\\}\\);`, "g"))].map(
    (match) => match[1],
  );
}

function extractStringField(block, fieldName) {
  const match = block.match(new RegExp(`\\.${fieldName}\\s*=\\s*"([^"]*)"`, "m"));
  return match ? match[1] : null;
}

function extractBoolField(block, fieldName, defaultValue) {
  const match = block.match(new RegExp(`\\.${fieldName}\\s*=\\s*(true|false)`, "m"));
  return match ? match[1] === "true" : defaultValue;
}

function extractApiProviders(source) {
  return extractRegisterBlocks(source, "api_registry")
    .map((block) => {
      const api = extractStringField(block, "api");
      if (!api) return null;
      return {
        api,
        supports_sse: extractBoolField(block, "supports_sse", true),
        supports_websocket: extractBoolField(block, "supports_websocket", false),
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.api.localeCompare(b.api));
}

function extractModelEntries(source) {
  return extractRegisterBlocks(source, "registry")
    .map((block) => {
      const id = extractStringField(block, "id");
      const provider = extractStringField(block, "provider");
      const api = extractStringField(block, "api");
      if (!id || !provider || !api) return null;
      return { id, provider, api };
    })
    .filter(Boolean);
}

function buildRecognizedOptionFields(api, streamOptionFields) {
  const relativeFile = apiSourceFiles[api];
  if (!relativeFile) throw new Error(`Missing provider source mapping for API ${api}`);
  const source = readText(path.resolve(root, relativeFile));
  const recognized = new Set();
  for (const field of runtimeSupportedFields) recognized.add(field);
  for (const field of streamOptionFields) {
    if (source.includes(`options.${field}`)) recognized.add(field);
  }
  return uniqueSorted([...recognized]);
}

function buildModelAliases(modelEntries) {
  const aliasMap = new Map();
  for (const entry of modelEntries) {
    const existing = aliasMap.get(entry.id) ?? {
      model_id: entry.id,
      providers: new Set(),
      apis: new Set(),
    };
    existing.providers.add(entry.provider);
    existing.apis.add(entry.api);
    aliasMap.set(entry.id, existing);
  }

  return [...aliasMap.values()]
    .filter((entry) => entry.providers.size > 1 || entry.apis.size > 1)
    .map((entry) => ({
      model_id: entry.model_id,
      providers: uniqueSorted([...entry.providers]),
      apis: uniqueSorted([...entry.apis]),
    }))
    .sort((a, b) => a.model_id.localeCompare(b.model_id));
}

function tryCurl(url) {
  try {
    return execFileSync("curl", ["-L", "--silent", "--fail", url], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

function loadUpstreamText(localPathEnv, fallbackLocalPath, remoteUrl) {
  const explicitPath = process.env[localPathEnv];
  const candidates = [explicitPath, fallbackLocalPath].filter(Boolean);
  for (const candidate of candidates) {
    if (!candidate) continue;
    const text = maybeReadText(candidate);
    if (text != null) {
      return { source: candidate, text };
    }
  }

  const remote = tryCurl(remoteUrl);
  if (remote != null) {
    return { source: remoteUrl, text: remote };
  }

  return null;
}

function extractTypeScriptInterfaceFields(source, interfaceName) {
  const match = source.match(new RegExp(`export interface ${interfaceName} \\{([\\s\\S]*?)\\n\\}`, "m"));
  if (!match) return [];
  return uniqueSorted(
    [...match[1].matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:/gm)].map((entry) => entry[1]),
  );
}

function extractTypeScriptStringUnion(source, typeName) {
  const match = source.match(new RegExp(`export type ${typeName} =([\\s\\S]*?);`, "m"));
  if (!match) return [];
  return uniqueSorted([...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]));
}

function buildTriagedUpstreamSnapshot() {
  const upstreamTypes = loadUpstreamText(
    "PI_MONO_TYPES_FILE",
    path.resolve(root, "../pi-mono/packages/ai/src/types.ts"),
    "https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/ai/src/types.ts",
  );

  if (!upstreamTypes) return null;

  return {
    source: upstreamTypes.source,
    known_api_ids: extractTypeScriptStringUnion(upstreamTypes.text, "KnownApi"),
    known_provider_ids: extractTypeScriptStringUnion(upstreamTypes.text, "KnownProvider"),
    stream_option_fields: extractTypeScriptInterfaceFields(upstreamTypes.text, "StreamOptions"),
  };
}

function buildLocalSnapshot() {
  const typesSource = readText(path.resolve(root, "src/types.zig"));
  const registerSource = readText(path.resolve(root, "src/providers/register_builtins.zig"));
  const modelsSource = readText(path.resolve(root, "src/models.zig"));
  const generatedModelsSource = readText(path.resolve(root, "src/models_supported_generated.zig"));

  const sharedOptionFields = extractZigStructFields(typesSource, "StreamOptions");
  const apis = extractApiProviders(registerSource).map((entry) => ({
    ...entry,
    source_file: apiSourceFiles[entry.api],
    recognized_option_fields: buildRecognizedOptionFields(entry.api, sharedOptionFields),
  }));

  const modelEntries = [
    ...extractModelEntries(generatedModelsSource),
    ...extractModelEntries(modelsSource),
  ];

  return {
    shared_option_fields: sharedOptionFields,
    apis,
    providers: uniqueSorted(modelEntries.map((entry) => entry.provider)),
    model_aliases: buildModelAliases(modelEntries),
  };
}

function buildReport() {
  const local = buildLocalSnapshot();
  return {
    ...local,
    triaged_upstream: buildTriagedUpstreamSnapshot(),
  };
}

function generateMarkdown(report) {
  const lines = [];
  lines.push("# Provider Parity");
  lines.push("");
  lines.push("This snapshot is generated from the current ZiggyPiAi source tree.");
  lines.push("");
  lines.push("## APIs");
  lines.push("");
  lines.push("| API | SSE | WebSocket | Recognized shared fields |");
  lines.push("| --- | --- | --- | --- |");
  for (const api of report.apis) {
    lines.push(
      `| \`${api.api}\` | ${api.supports_sse ? "yes" : "no"} | ${api.supports_websocket ? "yes" : "no"} | ${api.recognized_option_fields.map((field) => `\`${field}\``).join(", ")} |`,
    );
  }
  lines.push("");
  lines.push("## Providers");
  lines.push("");
  lines.push(report.providers.map((provider) => `- \`${provider}\``).join("\n"));
  lines.push("");
  lines.push("## Shared Option Fields");
  lines.push("");
  lines.push(report.shared_option_fields.map((field) => `- \`${field}\``).join("\n"));
  lines.push("");
  lines.push("## Model Alias Coverage");
  lines.push("");
  if (report.model_aliases.length === 0) {
    lines.push("No multi-provider aliases detected.");
  } else {
    lines.push("| Model ID | Providers | APIs |");
    lines.push("| --- | --- | --- |");
    for (const alias of report.model_aliases) {
      lines.push(
        `| \`${alias.model_id}\` | ${alias.providers.map((value) => `\`${value}\``).join(", ")} | ${alias.apis.map((value) => `\`${value}\``).join(", ")} |`,
      );
    }
  }
  lines.push("");
  lines.push("## Triaged Upstream");
  lines.push("");
  if (!report.triaged_upstream) {
    lines.push("Upstream pi-mono snapshot unavailable when this report was generated.");
  } else {
    lines.push(`Source: \`${report.triaged_upstream.source}\``);
    lines.push("");
    lines.push(`- Known APIs: ${report.triaged_upstream.known_api_ids.length}`);
    lines.push(`- Known providers: ${report.triaged_upstream.known_provider_ids.length}`);
    lines.push(`- StreamOptions fields: ${report.triaged_upstream.stream_option_fields.length}`);
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function summarizeArrayDiff(label, expected, actual) {
  const missing = expected.filter((value) => !actual.includes(value));
  const added = actual.filter((value) => !expected.includes(value));
  const lines = [];
  if (missing.length > 0) lines.push(`missing ${label}: ${missing.join(", ")}`);
  if (added.length > 0) lines.push(`added ${label}: ${added.join(", ")}`);
  return lines;
}

function checkLocalSnapshot(expectedReport, actualReport) {
  const expected = {
    shared_option_fields: expectedReport.shared_option_fields,
    apis: expectedReport.apis,
    providers: expectedReport.providers,
    model_aliases: expectedReport.model_aliases,
  };
  const actual = {
    shared_option_fields: actualReport.shared_option_fields,
    apis: actualReport.apis,
    providers: actualReport.providers,
    model_aliases: actualReport.model_aliases,
  };

  if (JSON.stringify(expected) === JSON.stringify(actual)) return true;

  const diagnostics = [];
  diagnostics.push(...summarizeArrayDiff("shared option fields", expected.shared_option_fields, actual.shared_option_fields));
  diagnostics.push(...summarizeArrayDiff("provider ids", expected.providers, actual.providers));
  diagnostics.push(...summarizeArrayDiff("api ids", expected.apis.map((entry) => entry.api), actual.apis.map((entry) => entry.api)));

  const expectedApis = new Map(expected.apis.map((entry) => [entry.api, entry]));
  const actualApis = new Map(actual.apis.map((entry) => [entry.api, entry]));
  for (const [api, expectedApi] of expectedApis) {
    const actualApi = actualApis.get(api);
    if (!actualApi) continue;
    if (expectedApi.supports_sse !== actualApi.supports_sse || expectedApi.supports_websocket !== actualApi.supports_websocket) {
      diagnostics.push(`transport capability changed for ${api}`);
    }
    if (JSON.stringify(expectedApi.recognized_option_fields) !== JSON.stringify(actualApi.recognized_option_fields)) {
      diagnostics.push(`recognized shared fields changed for ${api}`);
    }
  }

  if (JSON.stringify(expected.model_aliases) !== JSON.stringify(actual.model_aliases)) {
    diagnostics.push("model alias coverage changed");
  }

  console.error("provider-parity: tracked local snapshot is stale");
  for (const diagnostic of diagnostics) {
    console.error(`provider-parity: ${diagnostic}`);
  }
  console.error("provider-parity: run `node scripts/generate-provider-parity.mjs` and commit the updated docs/parity report");
  return false;
}

function warnOnUpstreamAdditions(expectedUpstream) {
  if (!expectedUpstream) return;
  const liveUpstream = buildTriagedUpstreamSnapshot();
  if (!liveUpstream) {
    console.warn("provider-parity: warning: upstream pi-mono snapshot unavailable; skipping upstream drift warning check");
    return;
  }

  const warnings = [];
  warnings.push(...summarizeArrayDiff("upstream known APIs", expectedUpstream.known_api_ids, liveUpstream.known_api_ids).filter((line) => line.startsWith("added ")));
  warnings.push(...summarizeArrayDiff("upstream known providers", expectedUpstream.known_provider_ids, liveUpstream.known_provider_ids).filter((line) => line.startsWith("added ")));
  warnings.push(...summarizeArrayDiff("upstream StreamOptions fields", expectedUpstream.stream_option_fields, liveUpstream.stream_option_fields).filter((line) => line.startsWith("added ")));

  for (const warning of warnings) {
    console.warn(`provider-parity: warning: ${warning}`);
  }
}

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = buildReport();

  if (args.check) {
    const expectedRaw = maybeReadText(args.jsonOut);
    if (expectedRaw == null) {
      console.error(`provider-parity: missing tracked snapshot: ${args.jsonOut}`);
      process.exit(1);
    }
    const expectedReport = JSON.parse(expectedRaw);
    const ok = checkLocalSnapshot(expectedReport, report);
    warnOnUpstreamAdditions(expectedReport.triaged_upstream ?? null);
    process.exit(ok ? 0 : 1);
  }

  ensureParentDir(args.jsonOut);
  ensureParentDir(args.mdOut);
  fs.writeFileSync(args.jsonOut, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  fs.writeFileSync(args.mdOut, generateMarkdown(report), "utf8");
  console.log(`wrote ${path.relative(root, args.jsonOut)}`);
  console.log(`wrote ${path.relative(root, args.mdOut)}`);
}

main();

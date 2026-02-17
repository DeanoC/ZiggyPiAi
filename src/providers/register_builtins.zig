const std = @import("std");
const registry = @import("../api_registry.zig");
const types = @import("../types.zig");
const anthropic = @import("anthropic_messages.zig");
const bedrock = @import("bedrock_converse_stream.zig");
const google = @import("google_generative_ai.zig");
const openai = @import("openai_compat.zig");
const codex = @import("openai_codex_responses.zig");
const openai_responses = @import("openai_responses.zig");

fn asStreamOptions(options: types.SimpleStreamOptions) types.StreamOptions {
    return .{
        .temperature = options.temperature,
        .max_tokens = options.max_tokens,
        .api_key = options.api_key,
        .reasoning = options.reasoning,
        .reasoning_summary = options.reasoning_summary,
        .session_id = options.session_id,
        .text_verbosity = options.text_verbosity,
        .headers = options.headers,
    };
}

fn streamSimpleOpenAICompat(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try openai.streamOpenAICompat(allocator, client, model, context, asStreamOptions(options), events);
}

fn streamSimpleOpenAIResponses(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try openai_responses.streamOpenAIResponses(allocator, client, model, context, asStreamOptions(options), events);
}

fn streamSimpleOpenAICodexResponses(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try codex.streamOpenAICodexResponses(allocator, client, model, context, asStreamOptions(options), events);
}

fn streamSimpleAnthropicMessages(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try anthropic.streamAnthropicMessages(allocator, client, model, context, asStreamOptions(options), events);
}

fn streamSimpleGoogleGenerativeAI(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try google.streamGoogleGenerativeAI(allocator, client, model, context, asStreamOptions(options), events);
}

fn streamSimpleBedrockConverseStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.SimpleStreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    try bedrock.streamBedrockConverseStream(allocator, client, model, context, asStreamOptions(options), events);
}

pub fn registerBuiltInApiProviders(api_registry: *registry.ApiRegistry) !void {
    try api_registry.register(.{
        .api = "openai-completions",
        .stream = openai.streamOpenAICompat,
        .stream_simple = streamSimpleOpenAICompat,
    });
    try api_registry.register(.{
        .api = "openai-responses",
        .stream = openai_responses.streamOpenAIResponses,
        .stream_simple = streamSimpleOpenAIResponses,
    });
    try api_registry.register(.{
        .api = "azure-openai-responses",
        .stream = openai_responses.streamOpenAIResponses,
        .stream_simple = streamSimpleOpenAIResponses,
    });
    try api_registry.register(.{
        .api = "openai-codex-responses",
        .stream = codex.streamOpenAICodexResponses,
        .stream_simple = streamSimpleOpenAICodexResponses,
    });
    try api_registry.register(.{
        .api = "anthropic-messages",
        .stream = anthropic.streamAnthropicMessages,
        .stream_simple = streamSimpleAnthropicMessages,
    });
    try api_registry.register(.{
        .api = "google-generative-ai",
        .stream = google.streamGoogleGenerativeAI,
        .stream_simple = streamSimpleGoogleGenerativeAI,
    });
    try api_registry.register(.{
        .api = "google-gemini-cli",
        .stream = google.streamGoogleGenerativeAI,
        .stream_simple = streamSimpleGoogleGenerativeAI,
    });
    try api_registry.register(.{
        .api = "google-vertex",
        .stream = google.streamGoogleGenerativeAI,
        .stream_simple = streamSimpleGoogleGenerativeAI,
    });
    try api_registry.register(.{
        .api = "bedrock-converse-stream",
        .stream = bedrock.streamBedrockConverseStream,
        .stream_simple = streamSimpleBedrockConverseStream,
    });
}

test "registerBuiltInApiProviders includes expected apis" {
    const allocator = std.testing.allocator;
    var api_registry = registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try registerBuiltInApiProviders(&api_registry);

    try std.testing.expect(api_registry.get("openai-completions") != null);
    try std.testing.expect(api_registry.get("openai-responses") != null);
    try std.testing.expect(api_registry.get("azure-openai-responses") != null);
    try std.testing.expect(api_registry.get("openai-codex-responses") != null);
    try std.testing.expect(api_registry.get("anthropic-messages") != null);
    try std.testing.expect(api_registry.get("google-generative-ai") != null);
    try std.testing.expect(api_registry.get("google-gemini-cli") != null);
    try std.testing.expect(api_registry.get("google-vertex") != null);
    try std.testing.expect(api_registry.get("bedrock-converse-stream") != null);
    try std.testing.expect(api_registry.get("openai-completions").?.stream_simple != null);
    try std.testing.expect(api_registry.get("openai-responses").?.stream_simple != null);
    try std.testing.expect(api_registry.get("azure-openai-responses").?.stream_simple != null);
    try std.testing.expect(api_registry.get("openai-codex-responses").?.stream_simple != null);
    try std.testing.expect(api_registry.get("anthropic-messages").?.stream_simple != null);
    try std.testing.expect(api_registry.get("google-generative-ai").?.stream_simple != null);
    try std.testing.expect(api_registry.get("google-gemini-cli").?.stream_simple != null);
    try std.testing.expect(api_registry.get("google-vertex").?.stream_simple != null);
    try std.testing.expect(api_registry.get("bedrock-converse-stream").?.stream_simple != null);
}

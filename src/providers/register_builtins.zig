const std = @import("std");
const registry = @import("../api_registry.zig");
const anthropic = @import("anthropic_messages.zig");
const openai = @import("openai_compat.zig");
const codex = @import("openai_codex_responses.zig");
const openai_responses = @import("openai_responses.zig");

pub fn registerBuiltInApiProviders(api_registry: *registry.ApiRegistry) !void {
    try api_registry.register(.{
        .api = "openai-completions",
        .stream = openai.streamOpenAICompat,
    });
    try api_registry.register(.{
        .api = "openai-responses",
        .stream = openai_responses.streamOpenAIResponses,
    });
    try api_registry.register(.{
        .api = "azure-openai-responses",
        .stream = openai_responses.streamOpenAIResponses,
    });
    try api_registry.register(.{
        .api = "openai-codex-responses",
        .stream = codex.streamOpenAICodexResponses,
    });
    try api_registry.register(.{
        .api = "anthropic-messages",
        .stream = anthropic.streamAnthropicMessages,
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
}

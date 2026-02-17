const std = @import("std");
const types = @import("../types.zig");

pub fn streamBedrockConverseStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    _ = client;
    _ = model;
    _ = context;
    _ = options;
    try events.append(.{ .err = try allocator.dupe(u8, "bedrock-converse-stream is not implemented in ZiggyPiAi yet") });
}

test "bedrock provider returns explicit not-implemented error" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |event| {
            if (event == .err) allocator.free(event.err);
        }
        events.deinit();
    }
    const model: types.Model = .{
        .id = "anthropic.claude-3-7-sonnet-20250219-v1:0",
        .name = "Claude Sonnet 3.7",
        .api = "bedrock-converse-stream",
        .provider = "bedrock",
        .base_url = "https://bedrock-runtime.us-east-1.amazonaws.com",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 200_000,
        .max_tokens = 32_000,
    };
    try streamBedrockConverseStream(allocator, &client, model, .{ .messages = &.{} }, .{}, &events);
    try std.testing.expect(events.items.len == 1);
    try std.testing.expect(events.items[0] == .err);
}

const std = @import("std");
const types = @import("types.zig");

pub fn dispatchPayload(options: types.StreamOptions, payload: types.ProviderPayload) !void {
    const callback = options.on_payload orelse return;
    try callback(options.on_payload_ctx, payload);
}

pub fn dispatchRawJson(options: types.StreamOptions, raw_json: []const u8) !void {
    try dispatchPayload(options, .{ .raw_json = raw_json });
}

pub fn dispatchUsage(options: types.StreamOptions, usage: types.Usage) !void {
    try dispatchPayload(options, .{ .usage = usage });
}

pub fn dispatchDone(options: types.StreamOptions) !void {
    try dispatchPayload(options, .done);
}

pub fn appendTextDelta(
    allocator: std.mem.Allocator,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
    options: types.StreamOptions,
    content_index: usize,
    delta: []const u8,
) !void {
    try dispatchPayload(options, .{ .text_delta = .{
        .content_index = content_index,
        .delta = delta,
    } });
    try events.append(.{ .text_delta = .{
        .content_index = content_index,
        .delta = try allocator.dupe(u8, delta),
    } });
}

pub fn appendThinkingDelta(
    allocator: std.mem.Allocator,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
    options: types.StreamOptions,
    content_index: usize,
    delta: []const u8,
) !void {
    try dispatchPayload(options, .{ .thinking_delta = .{
        .content_index = content_index,
        .delta = delta,
    } });
    try events.append(.{ .thinking_delta = .{
        .content_index = content_index,
        .delta = try allocator.dupe(u8, delta),
    } });
}

pub fn appendToolCallDelta(
    allocator: std.mem.Allocator,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
    options: types.StreamOptions,
    content_index: usize,
    delta: []const u8,
) !void {
    try dispatchPayload(options, .{ .tool_call_delta = .{
        .content_index = content_index,
        .delta = delta,
    } });
    try events.append(.{ .toolcall_delta = .{
        .content_index = content_index,
        .delta = try allocator.dupe(u8, delta),
    } });
}

pub fn appendDone(
    events: *std.array_list.Managed(types.AssistantMessageEvent),
    options: types.StreamOptions,
    message: types.AssistantMessage,
) !void {
    try events.append(.{ .done = message });
    try dispatchDone(options);
}

fn freeTestEventPayloads(allocator: std.mem.Allocator, events: *std.array_list.Managed(types.AssistantMessageEvent)) void {
    for (events.items) |*event| {
        switch (event.*) {
            .done => |*done| {
                allocator.free(done.text);
                allocator.free(done.thinking);
                if (done.content_blocks) |blocks| types.freeMessageContents(allocator, blocks);
                if (done.error_message) |err| allocator.free(err);
                if (done.tool_calls.len > 0) allocator.free(done.tool_calls);
            },
            else => {},
        }
    }
    events.deinit();
}

test "appendDone records done event before invoking callback" {
    const Capture = struct {
        fn failOnDone(_: ?*anyopaque, payload: types.ProviderPayload) !void {
            if (payload == .done) return error.DoneHookFailed;
        }
    };

    const allocator = std.testing.allocator;
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer freeTestEventPayloads(allocator, &events);

    const message: types.AssistantMessage = .{
        .text = try allocator.dupe(u8, "done"),
        .thinking = try allocator.dupe(u8, ""),
        .content_blocks = null,
        .tool_calls = &.{},
        .api = "api",
        .provider = "provider",
        .model = "model",
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    };

    try std.testing.expectError(error.DoneHookFailed, appendDone(&events, .{
        .on_payload = Capture.failOnDone,
    }, message));
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0] == .done);
}

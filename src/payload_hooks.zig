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
    try dispatchDone(options);
    try events.append(.{ .done = message });
}

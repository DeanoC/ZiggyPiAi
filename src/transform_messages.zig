const std = @import("std");
const types = @import("types.zig");

pub const PreparedMessages = std.array_list.Managed(types.Message);

fn insertSyntheticToolResult(
    pending_tool_calls: []const types.ToolCall,
    tool_results: *std.StringHashMap(bool),
    out: *PreparedMessages,
) !void {
    for (pending_tool_calls) |tc| {
        if (tool_results.get(tc.id) != null) continue;
        try out.append(.{
            .role = .tool,
            .content = "No result provided",
            .tool_call_id = tc.id,
            .tool_name = tc.name,
            .is_error = true,
        });
    }
    tool_results.clearRetainingCapacity();
}

pub fn prepareMessagesForApi(
    allocator: std.mem.Allocator,
    context_messages: []const types.Message,
) !PreparedMessages {
    var transformed = PreparedMessages.init(allocator);
    var pending_tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer pending_tool_calls.deinit();

    var tool_results = std.StringHashMap(bool).init(allocator);
    defer tool_results.deinit();

    for (context_messages) |msg| {
        switch (msg.role) {
            .assistant => {
                if (msg.stop_reason == .err or msg.stop_reason == .aborted) {
                    pending_tool_calls.clearRetainingCapacity();
                    continue;
                }
                if (pending_tool_calls.items.len > 0) {
                    try insertSyntheticToolResult(pending_tool_calls.items, &tool_results, &transformed);
                    pending_tool_calls.clearRetainingCapacity();
                }

                try transformed.append(msg);
                pending_tool_calls.clearRetainingCapacity();
                if (msg.tool_calls) |tool_calls| {
                    try pending_tool_calls.appendSlice(tool_calls);
                }
            },
            .tool, .tool_result => {
                if (msg.tool_call_id) |tool_call_id| {
                    tool_results.put(tool_call_id, true) catch {};
                }
                try transformed.append(msg);
            },
            .user, .system => {
                if (pending_tool_calls.items.len > 0) {
                    try insertSyntheticToolResult(pending_tool_calls.items, &tool_results, &transformed);
                    pending_tool_calls.clearRetainingCapacity();
                }
                try transformed.append(msg);
            },
        }
    }

    // Keep behavior stable: do not auto-append synthetic tool results at end of history.
    return transformed;
}

fn appendBlocksTextToWriter(
    blocks: []const types.MessageContent,
    writer: anytype,
) !void {
    var wrote_any = false;
    for (blocks) |block| {
        switch (block) {
            .text => |text| {
                if (wrote_any) try writer.writeByte('\n');
                try writer.writeAll(text.text);
                wrote_any = true;
            },
            .thinking => {},
            .image => {},
        }
    }
}

pub fn appendMessageTextToWriter(
    msg: types.Message,
    writer: anytype,
) !void {
    if (msg.content_blocks) |blocks| {
        if (blocks.len > 0) {
            try appendBlocksTextToWriter(blocks, writer);
            return;
        }
    }
    try writer.writeAll(msg.content);
}

test "prepareMessagesForApi skips errored and aborted assistant turns" {
    const msgs: []const types.Message = &.{
        .{ .role = .user, .content = "hello" },
        .{
            .role = .assistant,
            .content = "ignore",
            .tool_calls = &[_]types.ToolCall{},
            .stop_reason = .err,
        },
        .{
            .role = .assistant,
            .content = "discard",
            .tool_calls = &[_]types.ToolCall{},
            .stop_reason = .aborted,
        },
        .{ .role = .user, .content = "retry me" },
    };

    const prepared = try prepareMessagesForApi(std.testing.allocator, msgs);
    defer prepared.deinit();

    try std.testing.expect(prepared.items.len == 2);
    try std.testing.expect(prepared.items[0].role == .user);
    try std.testing.expect(prepared.items[1].role == .user);
    try std.testing.expect(prepared.items[0].stop_reason == .stop);
}

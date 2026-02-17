const std = @import("std");
const types = @import("../types.zig");
const transform = @import("../transform_messages.zig");

fn writeJson(writer: anytype, value: anytype) !void {
    try std.fmt.format(writer, "{f}", .{std.json.fmt(value, .{})});
}

fn readAllResponseBody(reader: *std.Io.Reader, out: *std.array_list.Managed(u8)) !void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&tmp);
        if (n == 0) return;
        try out.appendSlice(tmp[0..n]);
    }
}

const CurrentKind = enum { none, text, thinking, tool };

const CurrentTool = struct {
    id: std.array_list.Managed(u8),
    name: std.array_list.Managed(u8),
    partial_args: std.array_list.Managed(u8),
};

fn roleString(role: types.MessageRole) []const u8 {
    return switch (role) {
        .system => "system",
        .user => "user",
        .assistant => "assistant",
        .tool, .tool_result => "tool",
    };
}

fn mapStopReason(s: []const u8) types.StopReason {
    if (std.mem.eql(u8, s, "stop")) return .stop;
    if (std.mem.eql(u8, s, "length")) return .length;
    if (std.mem.eql(u8, s, "tool_calls") or std.mem.eql(u8, s, "function_call")) return .tool_use;
    return .err;
}

fn appendList(dst: *std.array_list.Managed(u8), src: []const u8) !void {
    if (src.len == 0) return;
    try dst.appendSlice(src);
}

fn normalizeToolCallId(allocator: std.mem.Allocator, id: []const u8) ![]const u8 {
    const sep = std.mem.indexOfScalar(u8, id, '|');
    const raw_id = if (sep) |idx| id[0..idx] else id;
    var normalized = std.array_list.Managed(u8).init(allocator);
    defer normalized.deinit();

    for (raw_id) |ch| {
        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-') {
            try normalized.append(ch);
        } else {
            try normalized.append('_');
        }
    }

    if (normalized.items.len > 40) {
        normalized.items.len = 40;
    }

    return try normalized.toOwnedSlice();
}

fn cachedNormalizedToolCallId(
    allocator: std.mem.Allocator,
    raw_id: []const u8,
    tool_call_ids: *std.StringHashMap([]const u8),
) ![]const u8 {
    if (tool_call_ids.get(raw_id)) |cached| {
        return cached;
    }

    const normalized = try normalizeToolCallId(allocator, raw_id);
    try tool_call_ids.put(raw_id, normalized);
    return normalized;
}

fn hasToolHistory(messages: []const types.Message) bool {
    for (messages) |msg| {
        switch (msg.role) {
            .assistant => {
                if (msg.tool_calls) |tool_calls| {
                    if (tool_calls.len > 0) return true;
                }
            },
            .tool, .tool_result => return true,
            else => {},
        }
    }
    return false;
}

fn appendMessageContentText(
    allocator: std.mem.Allocator,
    msg: types.Message,
    writer: anytype,
) !void {
    var text = std.array_list.Managed(u8).init(allocator);
    defer text.deinit();
    try transform.appendMessageTextToWriter(msg, text.writer());
    try writeJson(writer, text.items);
}

fn appendToolCallInput(
    allocator: std.mem.Allocator,
    writer: anytype,
    tool_call: types.ToolCall,
) !void {
    const normalized_id = try normalizeToolCallId(allocator, tool_call.id);
    defer allocator.free(normalized_id);

    try writer.writeAll("{\"id\":");
    try writeJson(writer, normalized_id);
    try writer.writeAll(",\"type\":\"function\",\"function\":{\"name\":");
    try writeJson(writer, tool_call.name);
    try writer.writeAll(",\"arguments\":");
    try writeJson(writer, tool_call.arguments_json);
    try writer.writeAll("}}");
}

fn appendMessageTools(
    allocator: std.mem.Allocator,
    tool_calls: []const types.ToolCall,
    tool_call_ids: *std.StringHashMap([]const u8),
    writer: anytype,
) !void {
    try writer.writeAll(",\"tool_calls\":[");
    for (tool_calls, 0..) |tc, i| {
        if (i > 0) try writer.writeByte(',');
        const normalized_id = try cachedNormalizedToolCallId(allocator, tc.id, tool_call_ids);
        try writer.writeAll("{\"id\":");
        try writeJson(writer, normalized_id);
        try writer.writeAll(",\"type\":\"function\",\"function\":{\"name\":");
        try writeJson(writer, tc.name);
        try writer.writeAll(",\"arguments\":");
        try writeJson(writer, tc.arguments_json);
        try writer.writeAll("}}");
    }
    try writer.writeAll("]");
}

fn appendToolResultText(
    allocator: std.mem.Allocator,
    msg: types.Message,
    tool_call_ids: *std.StringHashMap([]const u8),
    writer: anytype,
) !void {
    if (msg.tool_call_id) |tool_call_id| {
        try writer.writeAll(",\"tool_call_id\":");
        const normalized_tool_call_id = try cachedNormalizedToolCallId(allocator, tool_call_id, tool_call_ids);
        try writeJson(writer, normalized_tool_call_id);
    } else {
        return;
    }
    if (msg.tool_name) |tool_name| {
        try writer.writeAll(",\"name\":");
        try writeJson(writer, tool_name);
    }
    try writer.writeAll(",\"content\":");
    try appendMessageContentText(allocator, msg, writer);
}

fn finishCurrentBlock(
    allocator: std.mem.Allocator,
    current_kind: *CurrentKind,
    current_index: usize,
    current_text: *std.array_list.Managed(u8),
    current_tool: *CurrentTool,
    tool_calls: *std.array_list.Managed(types.ToolCall),
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    switch (current_kind.*) {
        .none => {},
        .text => {
            const content = try allocator.dupe(u8, current_text.items);
            try events.append(.{
                .text_end = .{
                    .content_index = current_index,
                    .content = content,
                },
            });
            current_text.clearRetainingCapacity();
        },
        .thinking => {
            const content = try allocator.dupe(u8, current_text.items);
            try events.append(.{
                .thinking_end = .{
                    .content_index = current_index,
                    .content = content,
                },
            });
            current_text.clearRetainingCapacity();
        },
        .tool => {
            const tool = types.ToolCall{
                .id = try allocator.dupe(u8, current_tool.id.items),
                .name = try allocator.dupe(u8, current_tool.name.items),
                .arguments_json = try allocator.dupe(u8, current_tool.partial_args.items),
            };
            try tool_calls.append(tool);
            try events.append(.{
                .toolcall_end = .{
                    .content_index = current_index,
                    .tool_call = tool,
                },
            });
            current_tool.id.clearRetainingCapacity();
            current_tool.name.clearRetainingCapacity();
            current_tool.partial_args.clearRetainingCapacity();
        },
    }
    current_kind.* = .none;
}

fn parseSSEFrames(
    allocator: std.mem.Allocator,
    payload: []const u8,
    model: types.Model,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    var text_builder = std.array_list.Managed(u8).init(allocator);
    defer text_builder.deinit();
    var full_text_builder = std.array_list.Managed(u8).init(allocator);
    defer full_text_builder.deinit();
    var thinking_builder = std.array_list.Managed(u8).init(allocator);
    defer thinking_builder.deinit();
    var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer tool_calls.deinit();
    var frame_data = std.array_list.Managed(u8).init(allocator);
    defer frame_data.deinit();

    var current_tool = CurrentTool{
        .id = std.array_list.Managed(u8).init(allocator),
        .name = std.array_list.Managed(u8).init(allocator),
        .partial_args = std.array_list.Managed(u8).init(allocator),
    };
    defer {
        current_tool.id.deinit();
        current_tool.name.deinit();
        current_tool.partial_args.deinit();
    }

    var usage: types.Usage = .{};
    var current_kind: CurrentKind = .none;
    var current_index: usize = 0;
    var block_count: usize = 0;
    var stop_reason: types.StopReason = .stop;

    var out_msg: types.AssistantMessage = .{
        .text = "",
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = usage,
        .stop_reason = .stop,
    };
    try events.append(.{ .start = out_msg });

    var it = std.mem.splitScalar(u8, payload, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) {
            if (frame_data.items.len == 0) continue;
            const frame = std.mem.trim(u8, frame_data.items, " ");
            frame_data.clearRetainingCapacity();
            if (std.mem.eql(u8, frame, "[DONE]")) break;

            var parsed = std.json.parseFromSlice(std.json.Value, allocator, frame, .{}) catch continue;
            defer parsed.deinit();
            const root = parsed.value;
            if (root != .object) continue;

            if (root.object.get("usage")) |usage_v| {
                if (usage_v == .object) {
                    if (usage_v.object.get("prompt_tokens")) |v| {
                        if (v == .integer) usage.input = @intCast(v.integer);
                    }
                    if (usage_v.object.get("completion_tokens")) |v| {
                        if (v == .integer) usage.output = @intCast(v.integer);
                    }
                    if (usage_v.object.get("total_tokens")) |v| {
                        if (v == .integer) usage.total_tokens = @intCast(v.integer);
                    }
                    types.calculateCost(model, &usage);
                }
            }

            const choices_v = root.object.get("choices") orelse continue;
            if (choices_v != .array or choices_v.array.items.len == 0) continue;
            const c0 = choices_v.array.items[0];
            if (c0 != .object) continue;

            if (c0.object.get("finish_reason")) |fr| {
                if (fr == .string and fr.string.len > 0) stop_reason = mapStopReason(fr.string);
            }

            const delta_v = c0.object.get("delta") orelse continue;
            if (delta_v != .object) continue;

            if (delta_v.object.get("content")) |content_v| {
                if (content_v == .string and content_v.string.len > 0) {
                    if (current_kind != .text) {
                        if (current_kind != .none) {
                            try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
                        }
                        current_kind = .text;
                        current_index = block_count;
                        block_count += 1;
                        try events.append(.{ .text_start = current_index });
                    }
                    try appendList(&text_builder, content_v.string);
                    try appendList(&full_text_builder, content_v.string);
                    try events.append(.{
                        .text_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, content_v.string),
                        },
                    });
                }
            }

            if (delta_v.object.get("reasoning_content")) |think_v| {
                if (think_v == .string and think_v.string.len > 0) {
                    if (current_kind != .thinking) {
                        if (current_kind != .none) {
                            try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
                        }
                        current_kind = .thinking;
                        current_index = block_count;
                        block_count += 1;
                        try events.append(.{ .thinking_start = current_index });
                    }
                    try appendList(&text_builder, think_v.string);
                    try appendList(&thinking_builder, think_v.string);
                    try events.append(.{
                        .thinking_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, think_v.string),
                        },
                    });
                }
            } else if (delta_v.object.get("reasoning")) |think_v| {
                if (think_v == .string and think_v.string.len > 0) {
                    if (current_kind != .thinking) {
                        if (current_kind != .none) {
                            try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
                        }
                        current_kind = .thinking;
                        current_index = block_count;
                        block_count += 1;
                        try events.append(.{ .thinking_start = current_index });
                    }
                    try appendList(&text_builder, think_v.string);
                    try appendList(&thinking_builder, think_v.string);
                    try events.append(.{
                        .thinking_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, think_v.string),
                        },
                    });
                }
            } else if (delta_v.object.get("reasoning_text")) |think_v| {
                if (think_v == .string and think_v.string.len > 0) {
                    if (current_kind != .thinking) {
                        if (current_kind != .none) {
                            try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
                        }
                        current_kind = .thinking;
                        current_index = block_count;
                        block_count += 1;
                        try events.append(.{ .thinking_start = current_index });
                    }
                    try appendList(&text_builder, think_v.string);
                    try appendList(&thinking_builder, think_v.string);
                    try events.append(.{
                        .thinking_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, think_v.string),
                        },
                    });
                }
            }

            if (delta_v.object.get("tool_calls")) |tc_v| {
                if (tc_v == .array) {
                    for (tc_v.array.items) |tc_item| {
                        if (tc_item != .object) continue;
                        var tc_id: []const u8 = "";
                        var tc_name: []const u8 = "";
                        var tc_args_delta: []const u8 = "";

                        if (tc_item.object.get("id")) |id_v| {
                            if (id_v == .string) tc_id = id_v.string;
                        }
                        if (tc_item.object.get("function")) |f_v| {
                            if (f_v == .object) {
                                if (f_v.object.get("name")) |n_v| {
                                    if (n_v == .string) tc_name = n_v.string;
                                }
                                if (f_v.object.get("arguments")) |a_v| {
                                    if (a_v == .string) tc_args_delta = a_v.string;
                                }
                            }
                        }

                        const id_changed = tc_id.len > 0 and !std.mem.eql(u8, tc_id, current_tool.id.items);
                        if (current_kind != .tool or id_changed) {
                            if (current_kind != .none) {
                                try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
                            }
                            current_kind = .tool;
                            current_index = block_count;
                            block_count += 1;
                            current_tool.id.clearRetainingCapacity();
                            current_tool.name.clearRetainingCapacity();
                            current_tool.partial_args.clearRetainingCapacity();
                            if (tc_id.len > 0) try current_tool.id.appendSlice(tc_id);
                            if (tc_name.len > 0) try current_tool.name.appendSlice(tc_name);
                            try events.append(.{ .toolcall_start = current_index });
                        }

                        if (tc_id.len > 0) {
                            current_tool.id.clearRetainingCapacity();
                            try current_tool.id.appendSlice(tc_id);
                        }
                        if (tc_name.len > 0) {
                            current_tool.name.clearRetainingCapacity();
                            try current_tool.name.appendSlice(tc_name);
                        }
                        if (tc_args_delta.len > 0) {
                            try current_tool.partial_args.appendSlice(tc_args_delta);
                        }
                        try events.append(.{
                            .toolcall_delta = .{
                                .content_index = current_index,
                                .delta = try allocator.dupe(u8, tc_args_delta),
                            },
                        });
                    }
                }
            }
            continue;
        }

        if (std.mem.startsWith(u8, line, "data:")) {
            const chunk = std.mem.trimLeft(u8, line["data:".len..], " ");
            try frame_data.appendSlice(chunk);
        }
    }

    if (current_kind != .none) {
        try finishCurrentBlock(allocator, &current_kind, current_index, &text_builder, &current_tool, &tool_calls, events);
    }

    out_msg.text = try allocator.dupe(u8, full_text_builder.items);
    out_msg.thinking = try allocator.dupe(u8, thinking_builder.items);
    out_msg.tool_calls = try tool_calls.toOwnedSlice();
    out_msg.usage = usage;
    out_msg.stop_reason = stop_reason;
    try events.append(.{ .done = out_msg });
}

pub fn streamOpenAICompat(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const api_key = options.api_key orelse return error.MissingApiKey;

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();

    try body.writer().writeAll("{\"model\":");
    try writeJson(body.writer(), model.id);
    try body.writer().writeAll(",\"stream\":true,\"stream_options\":{\"include_usage\":true},\"messages\":[");

    var first = true;
    const prepared_messages = try transform.prepareMessagesForApi(allocator, context.messages);
    defer prepared_messages.deinit();
    var tool_call_ids = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = tool_call_ids.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        tool_call_ids.deinit();
    }

    for (prepared_messages.items) |msg| {
        if (msg.role == .assistant) {
            if (msg.tool_calls) |tool_calls| {
                for (tool_calls) |tc| {
                    _ = try cachedNormalizedToolCallId(allocator, tc.id, &tool_call_ids);
                }
            }
        }
    }

    if (context.system_prompt) |system_prompt| {
        try body.writer().writeAll("{\"role\":\"system\",\"content\":");
        try writeJson(body.writer(), system_prompt);
        try body.writer().writeAll("}");
        first = false;
    }

    for (prepared_messages.items) |msg| {
        if (!first) try body.writer().writeByte(',');
        first = false;
        try body.writer().writeAll("{\"role\":");
        try writeJson(body.writer(), roleString(msg.role));
        try body.writer().writeAll(",\"content\":");
        try appendMessageContentText(allocator, msg, body.writer());
        if (msg.tool_calls) |tool_calls| {
            try appendMessageTools(allocator, tool_calls, &tool_call_ids, body.writer());
        }
        if (msg.role == .tool or msg.role == .tool_result) {
            try appendToolResultText(allocator, msg, &tool_call_ids, body.writer());
        }
        try body.writer().writeAll("}");
    }
    try body.writer().writeAll("]");
    if (context.tools) |tools| {
        try body.writer().writeAll(",\"tools\":[");
        for (tools, 0..) |tool, i| {
            if (i > 0) try body.writer().writeByte(',');
            try body.writer().writeAll("{\"type\":\"function\",\"function\":{\"name\":");
            try writeJson(body.writer(), tool.name);
            try body.writer().writeAll(",\"description\":");
            try writeJson(body.writer(), tool.description);
            try body.writer().writeAll(",\"parameters\":");
            try body.writer().writeAll(tool.parameters_json);
            try body.writer().writeAll("}}");
        }
        try body.writer().writeAll("],\"tool_choice\":\"auto\"");
    } else if (hasToolHistory(prepared_messages.items)) {
        try body.writer().writeAll(",\"tools\":[]");
    }

    if (options.temperature) |temperature| {
        try body.writer().writeAll(",\"temperature\":");
        try body.writer().print("{d}", .{temperature});
    }
    if (options.max_tokens) |max_tokens| {
        try body.writer().writeAll(",\"max_tokens\":");
        try body.writer().print("{d}", .{max_tokens});
    }
    try body.writer().writeAll("}");

    const endpoint = try std.fmt.allocPrint(allocator, "{s}/chat/completions", .{model.base_url});
    defer allocator.free(endpoint);

    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
    defer allocator.free(auth_header);

    var req = try client.request(.POST, try std.Uri.parse(endpoint), .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "text/event-stream" },
        },
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    });
    defer req.deinit();

    try req.sendBodyComplete(body.items);
    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok) {
        var err_body = std.array_list.Managed(u8).init(allocator);
        defer err_body.deinit();
        var transfer_buffer: [8192]u8 = undefined;
        const err_reader = response.reader(&transfer_buffer);
        try readAllResponseBody(err_reader, &err_body);
        try events.append(.{ .err = try allocator.dupe(u8, err_body.items) });
        return;
    }

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &response_buf);
    try parseSSEFrames(allocator, response_buf.items, model, events);
}

fn freeTestEvents(allocator: std.mem.Allocator, events: *std.array_list.Managed(types.AssistantMessageEvent)) void {
    for (events.items) |ev| {
        switch (ev) {
            .text_delta => |v| allocator.free(v.delta),
            .text_end => |v| allocator.free(v.content),
            .thinking_delta => |v| allocator.free(v.delta),
            .thinking_end => |v| allocator.free(v.content),
            .toolcall_delta => |v| allocator.free(v.delta),
            .done => |v| {
                allocator.free(v.text);
                allocator.free(v.thinking);
                for (v.tool_calls) |tc| {
                    allocator.free(tc.id);
                    allocator.free(tc.name);
                    allocator.free(tc.arguments_json);
                }
                allocator.free(v.tool_calls);
            },
            .err => |v| allocator.free(v),
            else => {},
        }
    }
    events.deinit();
}

test "parseSSEFrames emits text and toolcall events" {
    const allocator = std.testing.allocator;
    const model: types.Model = .{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };
    const sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" ++
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call_1\",\"function\":{\"name\":\"sum\",\"arguments\":\"{\\\"a\\\":1\"}}]}}]}\n\n" ++
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\",\\\"b\\\":2}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n" ++
        "data: [DONE]\n\n";

    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer freeTestEvents(allocator, &events);
    try parseSSEFrames(allocator, sse, model, &events);
    try std.testing.expect(events.items.len >= 7);
}

test "cached tool-call ID normalization memoizes" {
    const allocator = std.testing.allocator;
    var map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    const first = try cachedNormalizedToolCallId(allocator, "weird|id with spaces!", &map);
    const second = try cachedNormalizedToolCallId(allocator, "weird|id with spaces!", &map);
    try std.testing.expect(std.mem.eql(u8, first, second));
}

test "parseSSEFrames handles interleaved thinking and text deltas" {
    const allocator = std.testing.allocator;
    const model: types.Model = .{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = true,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };
    const sse =
        "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking-1\"}}]}\n\n" ++
        "data: {\"choices\":[{\"delta\":{\"content\":\"answer-1\"}}]}\n\n" ++
        "data: {\"choices\":[{\"delta\":{\"reasoning_text\":\"thinking-2\"}}]}\n\n" ++
        "data: {\"choices\":[{\"delta\":{\"content\":\"answer-2\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n\n" ++
        "data: [DONE]\n\n";

    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer freeTestEvents(allocator, &events);
    try parseSSEFrames(allocator, sse, model, &events);

    var saw_thinking = false;
    var saw_text = false;
    var saw_done = false;
    for (events.items) |event| {
        switch (event) {
            .thinking_delta => saw_thinking = true,
            .text_delta => saw_text = true,
            .done => |done| {
                saw_done = true;
                try std.testing.expectEqualStrings("answer-1answer-2", done.text);
                try std.testing.expectEqualStrings("thinking-1thinking-2", done.thinking);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_thinking);
    try std.testing.expect(saw_text);
    try std.testing.expect(saw_done);
}

test "parseSSEFrames handles empty stream payload" {
    const allocator = std.testing.allocator;
    const model: types.Model = .{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };
    const sse = "data: [DONE]\n\n";

    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer freeTestEvents(allocator, &events);
    try parseSSEFrames(allocator, sse, model, &events);
    try std.testing.expect(events.items.len == 2);
    switch (events.items[1]) {
        .done => |done| {
            try std.testing.expectEqualStrings("", done.text);
            try std.testing.expectEqualStrings("", done.thinking);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSSEFrames preserves unicode content" {
    const allocator = std.testing.allocator;
    const model: types.Model = .{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };
    const sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \\uD83D\\uDE00\"},\"finish_reason\":\"stop\"}]}\n\n" ++
        "data: [DONE]\n\n";

    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer freeTestEvents(allocator, &events);
    try parseSSEFrames(allocator, sse, model, &events);

    switch (events.items[1]) {
        .text_start => {},
        else => {},
    }
    switch (events.items[events.items.len - 1]) {
        .done => |done| try std.testing.expect(std.mem.indexOf(u8, done.text, "Hello ") != null),
        else => return error.TestUnexpectedResult,
    }
}

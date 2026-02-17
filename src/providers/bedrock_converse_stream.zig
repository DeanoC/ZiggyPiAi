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

fn appendHeader(headers: *std.array_list.Managed(std.http.Header), name: []const u8, value: []const u8) !void {
    try headers.append(.{ .name = name, .value = value });
}

fn mapStopReason(reason: []const u8) types.StopReason {
    if (std.mem.eql(u8, reason, "end_turn") or std.mem.eql(u8, reason, "stop")) return .stop;
    if (std.mem.eql(u8, reason, "max_tokens") or std.mem.eql(u8, reason, "length")) return .length;
    if (std.mem.eql(u8, reason, "tool_use") or std.mem.eql(u8, reason, "tool_calls")) return .tool_use;
    if (std.mem.eql(u8, reason, "guardrail_intervened")) return .err;
    return .stop;
}

fn appendMessageText(allocator: std.mem.Allocator, msg: types.Message, writer: anytype) !bool {
    var text = std.array_list.Managed(u8).init(allocator);
    defer text.deinit();
    try transform.appendMessageTextToWriter(msg, text.writer());
    if (text.items.len == 0) return false;
    try writeJson(writer, text.items);
    return true;
}

fn appendAssistantToolCalls(writer: anytype, msg: types.Message) !bool {
    const tool_calls = msg.tool_calls orelse return false;
    if (tool_calls.len == 0) return false;
    for (tool_calls, 0..) |tc, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"toolUse\":{\"toolUseId\":");
        try writeJson(writer, tc.id);
        try writer.writeAll(",\"name\":");
        try writeJson(writer, tc.name);
        try writer.writeAll(",\"input\":");
        try writer.writeAll(tc.arguments_json);
        try writer.writeAll("}}");
    }
    return true;
}

fn buildConverseBody(
    allocator: std.mem.Allocator,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
) ![]const u8 {
    var body = std.array_list.Managed(u8).init(allocator);
    errdefer body.deinit();

    try body.writer().writeAll("{\"messages\":[");

    const prepared_messages = try transform.prepareMessagesForApi(allocator, context.messages);
    defer prepared_messages.deinit();

    var first_message = true;
    for (prepared_messages.items) |msg| {
        if (msg.role == .system) continue;
        if (!first_message) try body.writer().writeByte(',');
        first_message = false;

        if (msg.role == .tool or msg.role == .tool_result) {
            try body.writer().writeAll("{\"role\":\"user\",\"content\":[{\"toolResult\":{\"toolUseId\":");
            try writeJson(body.writer(), msg.tool_call_id orelse "");
            try body.writer().writeAll(",\"content\":[{\"text\":");
            _ = try appendMessageText(allocator, msg, body.writer());
            try body.writer().writeAll("}],\"status\":");
            try writeJson(body.writer(), if (msg.is_error) "error" else "success");
            try body.writer().writeAll("}}]}");
            continue;
        }

        try body.writer().writeAll("{\"role\":");
        try writeJson(body.writer(), if (msg.role == .assistant) "assistant" else "user");
        try body.writer().writeAll(",\"content\":[");

        var wrote_any = false;
        if (msg.role == .assistant) {
            wrote_any = try appendAssistantToolCalls(body.writer(), msg);
            if (wrote_any) try body.writer().writeByte(',');
        }

        try body.writer().writeAll("{\"text\":");
        if (!(try appendMessageText(allocator, msg, body.writer()))) {
            try writeJson(body.writer(), "");
        }
        try body.writer().writeAll("}]}");
    }

    try body.writer().writeAll("]");

    if (context.system_prompt) |system_prompt| {
        try body.writer().writeAll(",\"system\":[{\"text\":");
        try writeJson(body.writer(), system_prompt);
        try body.writer().writeAll("}]");
    }

    if (options.max_tokens != null or options.temperature != null) {
        try body.writer().writeAll(",\"inferenceConfig\":{");
        var wrote = false;
        if (options.max_tokens) |max_tokens| {
            try body.writer().writeAll("\"maxTokens\":");
            try body.writer().print("{d}", .{max_tokens});
            wrote = true;
        }
        if (options.temperature) |temp| {
            if (wrote) try body.writer().writeByte(',');
            try body.writer().writeAll("\"temperature\":");
            try body.writer().print("{d}", .{temp});
        }
        try body.writer().writeAll("}");
    }

    if (context.tools) |tools| {
        try body.writer().writeAll(",\"toolConfig\":{\"tools\":[");
        for (tools, 0..) |tool, i| {
            if (i > 0) try body.writer().writeByte(',');
            try body.writer().writeAll("{\"toolSpec\":{\"name\":");
            try writeJson(body.writer(), tool.name);
            try body.writer().writeAll(",\"description\":");
            try writeJson(body.writer(), tool.description);
            try body.writer().writeAll(",\"inputSchema\":{\"json\":");
            try body.writer().writeAll(tool.parameters_json);
            try body.writer().writeAll("}}}");
        }
        try body.writer().writeAll("]}");
    }

    _ = model;
    try body.writer().writeAll("}");
    return body.toOwnedSlice();
}

fn appendTextEvent(
    allocator: std.mem.Allocator,
    text: []const u8,
    block_index: usize,
    full_text: *std.array_list.Managed(u8),
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    if (text.len == 0) return;
    try events.append(.{ .text_start = block_index });
    try full_text.appendSlice(text);
    try events.append(.{ .text_delta = .{ .content_index = block_index, .delta = try allocator.dupe(u8, text) } });
    try events.append(.{ .text_end = .{ .content_index = block_index, .content = try allocator.dupe(u8, text) } });
}

fn appendThinkingEvent(
    allocator: std.mem.Allocator,
    text: []const u8,
    block_index: usize,
    full_thinking: *std.array_list.Managed(u8),
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    if (text.len == 0) return;
    try events.append(.{ .thinking_start = block_index });
    try full_thinking.appendSlice(text);
    try events.append(.{ .thinking_delta = .{ .content_index = block_index, .delta = try allocator.dupe(u8, text) } });
    try events.append(.{ .thinking_end = .{ .content_index = block_index, .content = try allocator.dupe(u8, text) } });
}

fn parseConverseResponse(
    allocator: std.mem.Allocator,
    payload: []const u8,
    model: types.Model,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch {
        try events.append(.{ .err = try allocator.dupe(u8, "Invalid Bedrock JSON response") });
        return;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        try events.append(.{ .err = try allocator.dupe(u8, "Invalid Bedrock JSON root") });
        return;
    }

    var usage: types.Usage = .{};
    var stop_reason: types.StopReason = .stop;

    var out = types.AssistantMessage{
        .text = "",
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = usage,
    };
    try events.append(.{ .start = out });

    if (parsed.value.object.get("stopReason")) |sr| {
        if (sr == .string) stop_reason = mapStopReason(sr.string);
    }

    if (parsed.value.object.get("usage")) |usage_v| {
        if (usage_v == .object) {
            if (usage_v.object.get("inputTokens")) |v| {
                if (v == .integer) usage.input = @intCast(v.integer);
            }
            if (usage_v.object.get("outputTokens")) |v| {
                if (v == .integer) usage.output = @intCast(v.integer);
            }
            if (usage_v.object.get("totalTokens")) |v| {
                if (v == .integer) usage.total_tokens = @intCast(v.integer);
            }
            if (usage_v.object.get("cacheReadInputTokens")) |v| {
                if (v == .integer) usage.cache_read = @intCast(v.integer);
            }
            if (usage_v.object.get("cacheWriteInputTokens")) |v| {
                if (v == .integer) usage.cache_write = @intCast(v.integer);
            }
            types.calculateCost(model, &usage);
        }
    }

    var full_text = std.array_list.Managed(u8).init(allocator);
    defer full_text.deinit();
    var full_thinking = std.array_list.Managed(u8).init(allocator);
    defer full_thinking.deinit();
    var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer tool_calls.deinit();

    var block_index: usize = 0;
    if (parsed.value.object.get("output")) |output_v| {
        if (output_v == .object) {
            if (output_v.object.get("message")) |message_v| {
                if (message_v == .object) {
                    if (message_v.object.get("content")) |content_v| {
                        if (content_v == .array) {
                            for (content_v.array.items) |item| {
                                if (item != .object) continue;

                                if (item.object.get("text")) |text_v| {
                                    if (text_v == .string) {
                                        try appendTextEvent(allocator, text_v.string, block_index, &full_text, events);
                                        block_index += 1;
                                    }
                                }

                                if (item.object.get("reasoningContent")) |reasoning_v| {
                                    if (reasoning_v == .object) {
                                        if (reasoning_v.object.get("reasoningText")) |rt_v| {
                                            if (rt_v == .object) {
                                                if (rt_v.object.get("text")) |t_v| {
                                                    if (t_v == .string) {
                                                        try appendThinkingEvent(allocator, t_v.string, block_index, &full_thinking, events);
                                                        block_index += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if (item.object.get("toolUse")) |tool_use_v| {
                                    if (tool_use_v == .object) {
                                        const id_v = tool_use_v.object.get("toolUseId") orelse continue;
                                        const name_v = tool_use_v.object.get("name") orelse continue;
                                        if (id_v != .string or name_v != .string) continue;
                                        const args = if (tool_use_v.object.get("input")) |input_v|
                                            try std.json.Stringify.valueAlloc(allocator, input_v, .{})
                                        else
                                            try allocator.dupe(u8, "{}");
                                        defer allocator.free(args);

                                        try events.append(.{ .toolcall_start = block_index });
                                        try events.append(.{ .toolcall_delta = .{ .content_index = block_index, .delta = try allocator.dupe(u8, args) } });

                                        const tool_call_for_done = types.ToolCall{
                                            .id = try allocator.dupe(u8, id_v.string),
                                            .name = try allocator.dupe(u8, name_v.string),
                                            .arguments_json = try allocator.dupe(u8, args),
                                        };
                                        try tool_calls.append(tool_call_for_done);

                                        const tool_call_for_event = types.ToolCall{
                                            .id = try allocator.dupe(u8, id_v.string),
                                            .name = try allocator.dupe(u8, name_v.string),
                                            .arguments_json = try allocator.dupe(u8, args),
                                        };
                                        try events.append(.{ .toolcall_end = .{ .content_index = block_index, .tool_call = tool_call_for_event } });
                                        block_index += 1;
                                        stop_reason = .tool_use;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    out.text = try allocator.dupe(u8, full_text.items);
    out.thinking = try allocator.dupe(u8, full_thinking.items);
    out.tool_calls = try tool_calls.toOwnedSlice();
    out.usage = usage;
    out.stop_reason = stop_reason;
    try events.append(.{ .done = out });
}

pub fn streamBedrockConverseStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const api_key = options.api_key orelse return error.MissingApiKey;

    const endpoint = try std.fmt.allocPrint(
        allocator,
        "{s}/model/{s}/converse",
        .{ std.mem.trimRight(u8, model.base_url, "/"), model.id },
    );
    defer allocator.free(endpoint);

    const body = try buildConverseBody(allocator, model, context, options);
    defer allocator.free(body);

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
    defer allocator.free(auth);
    try appendHeader(&headers, "Authorization", auth);
    try appendHeader(&headers, "content-type", "application/json");
    try appendHeader(&headers, "accept", "application/json");

    if (options.headers) |custom_headers| {
        for (custom_headers) |header| try appendHeader(&headers, header.name, header.value);
    }

    var req = try client.request(.POST, try std.Uri.parse(endpoint), .{ .extra_headers = headers.items });
    defer req.deinit();

    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();

    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &response_buf);

    if (response.head.status != .ok) {
        try events.append(.{ .err = try allocator.dupe(u8, response_buf.items) });
        return;
    }

    try parseConverseResponse(allocator, response_buf.items, model, events);
}

test "bedrock stop reason mapping" {
    try std.testing.expect(mapStopReason("end_turn") == .stop);
    try std.testing.expect(mapStopReason("max_tokens") == .length);
    try std.testing.expect(mapStopReason("tool_use") == .tool_use);
}

test "bedrock response parser emits text and tool events" {
    const allocator = std.testing.allocator;
    const model: types.Model = .{
        .id = "anthropic.claude-3-7-sonnet-20250219-v1:0",
        .name = "Claude Sonnet 3.7",
        .api = "bedrock-converse-stream",
        .provider = "amazon-bedrock",
        .base_url = "https://bedrock-runtime.us-east-1.amazonaws.com",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 200_000,
        .max_tokens = 32_000,
    };

    const payload =
        "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[" ++
        "{\"text\":\"hello\"}," ++
        "{\"toolUse\":{\"toolUseId\":\"tu_1\",\"name\":\"sum\",\"input\":{\"a\":1,\"b\":2}}}" ++
        "]}},\"stopReason\":\"tool_use\",\"usage\":{\"inputTokens\":3,\"outputTokens\":4,\"totalTokens\":7}}";

    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |event| {
            switch (event) {
                .text_delta => |v| allocator.free(v.delta),
                .text_end => |v| allocator.free(v.content),
                .thinking_delta => |v| allocator.free(v.delta),
                .thinking_end => |v| allocator.free(v.content),
                .toolcall_delta => |v| allocator.free(v.delta),
                .toolcall_end => |v| {
                    allocator.free(v.tool_call.id);
                    allocator.free(v.tool_call.name);
                    allocator.free(v.tool_call.arguments_json);
                },
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

    try parseConverseResponse(allocator, payload, model, &events);
    try std.testing.expect(events.items.len >= 5);
}

const std = @import("std");
const types = @import("../types.zig");
const transform = @import("../transform_messages.zig");

fn writeJson(writer: anytype, value: anytype) !void {
    try std.fmt.format(writer, "{f}", .{std.json.fmt(value, .{})});
}

fn appendHeader(headers: *std.array_list.Managed(std.http.Header), name: []const u8, value: []const u8) !void {
    try headers.append(.{ .name = name, .value = value });
}

fn readAllResponseBody(reader: *std.Io.Reader, out: *std.array_list.Managed(u8)) !void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&tmp);
        if (n == 0) return;
        try out.appendSlice(tmp[0..n]);
    }
}

fn mapGoogleStopReason(reason: []const u8) types.StopReason {
    if (std.mem.eql(u8, reason, "STOP")) return .stop;
    if (std.mem.eql(u8, reason, "MAX_TOKENS")) return .length;
    if (std.mem.eql(u8, reason, "TOOL_CALL")) return .tool_use;
    if (std.mem.eql(u8, reason, "MALFORMED_FUNCTION_CALL")) return .err;
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

fn generateToolId(allocator: std.mem.Allocator, name: []const u8, index: usize) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}_{d}", .{ name, index });
}

pub fn streamGoogleGenerativeAI(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const api_key = options.api_key orelse return error.MissingApiKey;
    const base = std.mem.trimRight(u8, model.base_url, "/");
    const endpoint = try std.fmt.allocPrint(
        allocator,
        "{s}/models/{s}:streamGenerateContent?alt=sse&key={s}",
        .{ base, model.id, api_key },
    );
    defer allocator.free(endpoint);

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();

    try body.writer().writeAll("{\"contents\":[");
    var first = true;
    if (context.system_prompt) |sys| {
        try body.writer().writeAll("{\"role\":\"user\",\"parts\":[{\"text\":");
        try writeJson(body.writer(), sys);
        try body.writer().writeAll("}]}");
        first = false;
    }

    for (context.messages) |msg| {
        if (msg.role != .user and msg.role != .assistant) continue;
        var has_text = false;
        if (!first) try body.writer().writeByte(',');
        first = false;
        try body.writer().writeAll("{\"role\":");
        try writeJson(body.writer(), if (msg.role == .assistant) "model" else "user");
        try body.writer().writeAll(",\"parts\":[{\"text\":");
        has_text = try appendMessageText(allocator, msg, body.writer());
        if (!has_text) {
            try writeJson(body.writer(), "");
        }
        try body.writer().writeAll("}]}");
    }
    try body.writer().writeAll("]");

    if (context.tools) |tools| {
        try body.writer().writeAll(",\"tools\":[{\"functionDeclarations\":[");
        for (tools, 0..) |tool, i| {
            if (i > 0) try body.writer().writeByte(',');
            try body.writer().writeAll("{\"name\":");
            try writeJson(body.writer(), tool.name);
            try body.writer().writeAll(",\"description\":");
            try writeJson(body.writer(), tool.description);
            try body.writer().writeAll(",\"parameters\":");
            try body.writer().writeAll(tool.parameters_json);
            try body.writer().writeAll("}");
        }
        try body.writer().writeAll("]}]");
    }

    if (options.temperature != null or options.max_tokens != null) {
        try body.writer().writeAll(",\"generationConfig\":{");
        var wrote = false;
        if (options.temperature) |temp| {
            try body.writer().writeAll("\"temperature\":");
            try body.writer().print("{d}", .{temp});
            wrote = true;
        }
        if (options.max_tokens) |max_tokens| {
            if (wrote) try body.writer().writeByte(',');
            try body.writer().writeAll("\"maxOutputTokens\":");
            try body.writer().print("{d}", .{max_tokens});
        }
        try body.writer().writeAll("}");
    }
    try body.writer().writeAll("}");

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try appendHeader(&headers, "content-type", "application/json");
    try appendHeader(&headers, "accept", "text/event-stream");
    if (options.headers) |custom_headers| {
        for (custom_headers) |h| try appendHeader(&headers, h.name, h.value);
    }

    var req = try client.request(.POST, try std.Uri.parse(endpoint), .{
        .extra_headers = headers.items,
    });
    defer req.deinit();
    try req.sendBodyComplete(body.items);

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) {
        var err_buf = std.array_list.Managed(u8).init(allocator);
        defer err_buf.deinit();
        var transfer_buffer: [8192]u8 = undefined;
        const err_reader = response.reader(&transfer_buffer);
        try readAllResponseBody(err_reader, &err_buf);
        try events.append(.{ .err = try allocator.dupe(u8, err_buf.items) });
        return;
    }

    var sse = std.array_list.Managed(u8).init(allocator);
    defer sse.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &sse);

    var usage: types.Usage = .{};
    var stop_reason: types.StopReason = .stop;
    var output = types.AssistantMessage{
        .text = "",
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = usage,
    };
    try events.append(.{ .start = output });

    var full_text = std.array_list.Managed(u8).init(allocator);
    defer full_text.deinit();
    var thinking = std.array_list.Managed(u8).init(allocator);
    defer thinking.deinit();
    var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer tool_calls.deinit();

    var frame = std.array_list.Managed(u8).init(allocator);
    defer frame.deinit();
    const block_index: usize = 0;
    var saw_text = false;
    var saw_thinking = false;
    var tool_index: usize = 0;

    var lines = std.mem.splitScalar(u8, sse.items, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0) {
            if (frame.items.len == 0) continue;
            const payload = std.mem.trim(u8, frame.items, " ");
            frame.clearRetainingCapacity();
            if (!std.mem.startsWith(u8, payload, "{")) continue;

            var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const root = parsed.value.object;

            if (root.get("usageMetadata")) |usage_v| {
                if (usage_v == .object) {
                    if (usage_v.object.get("promptTokenCount")) |v| {
                        if (v == .integer) usage.input = @intCast(v.integer);
                    }
                    if (usage_v.object.get("candidatesTokenCount")) |v| {
                        if (v == .integer) usage.output = @intCast(v.integer);
                    }
                    if (usage_v.object.get("totalTokenCount")) |v| {
                        if (v == .integer) usage.total_tokens = @intCast(v.integer);
                    }
                    types.calculateCost(model, &usage);
                }
            }

            const candidates_v = root.get("candidates") orelse continue;
            if (candidates_v != .array or candidates_v.array.items.len == 0) continue;
            const candidate = candidates_v.array.items[0];
            if (candidate != .object) continue;

            if (candidate.object.get("finishReason")) |fr| {
                if (fr == .string) stop_reason = mapGoogleStopReason(fr.string);
            }

            if (candidate.object.get("content")) |content_v| {
                if (content_v == .object) {
                    if (content_v.object.get("parts")) |parts_v| {
                        if (parts_v == .array) {
                            for (parts_v.array.items) |part| {
                                if (part != .object) continue;
                                if (part.object.get("text")) |text_v| {
                                    if (text_v == .string and text_v.string.len > 0) {
                                        if (part.object.get("thought")) |thought_v| {
                                            if (thought_v == .bool and thought_v.bool) {
                                                if (!saw_thinking) {
                                                    saw_thinking = true;
                                                    try events.append(.{ .thinking_start = block_index });
                                                }
                                                try thinking.appendSlice(text_v.string);
                                                try events.append(.{ .thinking_delta = .{
                                                    .content_index = block_index,
                                                    .delta = try allocator.dupe(u8, text_v.string),
                                                } });
                                                continue;
                                            }
                                        }

                                        if (!saw_text) {
                                            saw_text = true;
                                            try events.append(.{ .text_start = block_index });
                                        }
                                        try full_text.appendSlice(text_v.string);
                                        try events.append(.{ .text_delta = .{
                                            .content_index = block_index,
                                            .delta = try allocator.dupe(u8, text_v.string),
                                        } });
                                    }
                                }

                                if (part.object.get("functionCall")) |fc_v| {
                                    if (fc_v != .object) continue;
                                    const name_v = fc_v.object.get("name") orelse continue;
                                    if (name_v != .string) continue;
                                    const args_v = fc_v.object.get("args") orelse continue;
                                    const args_json = try std.json.Stringify.valueAlloc(allocator, args_v, .{});
                                    defer allocator.free(args_json);
                                    const tool_id = try generateToolId(allocator, name_v.string, tool_index);
                                    tool_index += 1;
                                    try events.append(.{ .toolcall_start = block_index + tool_calls.items.len + 1 });
                                    try events.append(.{ .toolcall_delta = .{
                                        .content_index = block_index + tool_calls.items.len + 1,
                                        .delta = try allocator.dupe(u8, args_json),
                                    } });
                                    const tool_call = types.ToolCall{
                                        .id = tool_id,
                                        .name = try allocator.dupe(u8, name_v.string),
                                        .arguments_json = try allocator.dupe(u8, args_json),
                                    };
                                    try tool_calls.append(tool_call);
                                    try events.append(.{ .toolcall_end = .{
                                        .content_index = block_index + tool_calls.items.len,
                                        .tool_call = tool_call,
                                    } });
                                    stop_reason = .tool_use;
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }

        if (std.mem.startsWith(u8, line, "data:")) {
            try frame.appendSlice(std.mem.trimLeft(u8, line["data:".len..], " "));
        }
    }

    if (saw_text) {
        try events.append(.{ .text_end = .{
            .content_index = block_index,
            .content = try allocator.dupe(u8, full_text.items),
        } });
    }
    if (saw_thinking) {
        try events.append(.{ .thinking_end = .{
            .content_index = block_index,
            .content = try allocator.dupe(u8, thinking.items),
        } });
    }

    output.text = try allocator.dupe(u8, full_text.items);
    output.thinking = try allocator.dupe(u8, thinking.items);
    output.tool_calls = try tool_calls.toOwnedSlice();
    output.usage = usage;
    output.stop_reason = stop_reason;
    try events.append(.{ .done = output });
}

test "google stop reason mapping" {
    try std.testing.expect(mapGoogleStopReason("STOP") == .stop);
    try std.testing.expect(mapGoogleStopReason("MAX_TOKENS") == .length);
    try std.testing.expect(mapGoogleStopReason("TOOL_CALL") == .tool_use);
}

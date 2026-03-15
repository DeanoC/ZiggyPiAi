const std = @import("std");
const types = @import("../types.zig");
const transform = @import("../transform_messages.zig");
const payload_hooks = @import("../payload_hooks.zig");

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
    args: std.array_list.Managed(u8),
};

const redacted_thinking_placeholder = "[Reasoning redacted]";

fn stopReasonFromAnthropic(reason: []const u8) types.StopReason {
    if (std.mem.eql(u8, reason, "end_turn")) return .stop;
    if (std.mem.eql(u8, reason, "max_tokens")) return .length;
    if (std.mem.eql(u8, reason, "tool_use")) return .tool_use;
    return .stop;
}

fn finishCurrent(
    allocator: std.mem.Allocator,
    kind: *CurrentKind,
    idx: usize,
    text: *std.array_list.Managed(u8),
    thinking_signature: *std.array_list.Managed(u8),
    thinking_redacted: *bool,
    tool: *CurrentTool,
    content_blocks: *std.array_list.Managed(types.MessageContent),
    tool_calls: *std.array_list.Managed(types.ToolCall),
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    switch (kind.*) {
        .none => {},
        .text => {
            try events.append(.{ .text_end = .{
                .content_index = idx,
                .content = try allocator.dupe(u8, text.items),
            } });
            if (text.items.len > 0) {
                try content_blocks.append(.{ .text = .{
                    .text = try allocator.dupe(u8, text.items),
                } });
            }
            text.clearRetainingCapacity();
        },
        .thinking => {
            try events.append(.{ .thinking_end = .{
                .content_index = idx,
                .content = try allocator.dupe(u8, text.items),
            } });
            if (text.items.len > 0 or thinking_signature.items.len > 0 or thinking_redacted.*) {
                try content_blocks.append(.{ .thinking = .{
                    .thinking = try allocator.dupe(u8, text.items),
                    .signature = if (thinking_signature.items.len > 0)
                        try allocator.dupe(u8, thinking_signature.items)
                    else
                        null,
                    .redacted = thinking_redacted.*,
                } });
            }
            text.clearRetainingCapacity();
            thinking_signature.clearRetainingCapacity();
            thinking_redacted.* = false;
        },
        .tool => {
            const tc: types.ToolCall = .{
                .id = try allocator.dupe(u8, tool.id.items),
                .name = try allocator.dupe(u8, tool.name.items),
                .arguments_json = try allocator.dupe(u8, tool.args.items),
            };
            try tool_calls.append(tc);
            try events.append(.{ .toolcall_end = .{
                .content_index = idx,
                .tool_call = tc,
            } });
            tool.id.clearRetainingCapacity();
            tool.name.clearRetainingCapacity();
            tool.args.clearRetainingCapacity();
        },
    }
    kind.* = .none;
}

fn appendAssistantThinkingContentBlock(
    writer: anytype,
    block: types.ThinkingContent,
) !bool {
    if (block.redacted) {
        if (block.signature) |signature| {
            try writer.writeAll("{\"type\":\"redacted_thinking\",\"data\":");
            try writeJson(writer, signature);
            try writer.writeAll("}");
            return true;
        }
        if (block.thinking.len == 0) return false;
        try appendTextContentBlock(writer, block.thinking);
        return true;
    }

    if (block.thinking.len == 0) return false;
    if (block.signature) |signature| {
        try writer.writeAll("{\"type\":\"thinking\",\"thinking\":");
        try writeJson(writer, block.thinking);
        try writer.writeAll(",\"signature\":");
        try writeJson(writer, signature);
        try writer.writeAll("}");
        return true;
    }

    try appendTextContentBlock(writer, block.thinking);
    return true;
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

    if (normalized.items.len > 64) {
        normalized.items.len = 64;
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

fn appendTextContentBlock(
    writer: anytype,
    text: []const u8,
) !void {
    try writer.writeAll("{\"type\":\"text\",\"text\":");
    try writeJson(writer, text);
    try writer.writeAll("}");
}

fn writeContentFromBlocks(
    msg: types.Message,
    include_images: bool,
    writer: anytype,
) !bool {
    var wrote_any = false;
    if (msg.content_blocks) |blocks| {
        for (blocks) |block| {
            switch (block) {
                .text => |v| {
                    if (v.text.len == 0) continue;
                    if (wrote_any) try writer.writeByte(',');
                    try appendTextContentBlock(writer, v.text);
                    wrote_any = true;
                },
                .thinking => |v| {
                    if (v.thinking.len == 0) continue;
                    if (wrote_any) try writer.writeByte(',');
                    try appendTextContentBlock(writer, v.thinking);
                    wrote_any = true;
                },
                .image => |v| {
                    if (!include_images) continue;
                    if (wrote_any) try writer.writeByte(',');
                    try writer.writeAll("{\"type\":\"image\",\"source\":");
                    try writer.writeAll("{\"type\":\"base64\",\"media_type\":");
                    try writeJson(writer, v.mime_type);
                    try writer.writeAll(",\"data\":");
                    try writeJson(writer, v.data);
                    try writer.writeAll("}}");
                    wrote_any = true;
                },
            }
        }
        return wrote_any;
    }

    if (msg.content.len == 0) return false;
    try appendTextContentBlock(writer, msg.content);
    return true;
}

fn writeToolUseInput(
    allocator: std.mem.Allocator,
    arguments_json: []const u8,
    writer: anytype,
) !void {
    if (arguments_json.len == 0) {
        try writer.writeAll("{}");
        return;
    }

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, arguments_json, .{}) catch {
        try writer.writeAll("{}");
        return;
    };
    defer parsed.deinit();
    try writeJson(writer, parsed.value);
}

fn writeUserMessagesFromToolResults(
    allocator: std.mem.Allocator,
    messages: []const types.Message,
    start: usize,
    first_message: *bool,
    body: *std.array_list.Managed(u8),
    tool_call_ids: *std.StringHashMap([]const u8),
) !usize {
    var i = start;
    if (start >= messages.len) return i;

    if (!first_message.*) try body.writer().writeByte(',');
    first_message.* = false;
    try body.writer().writeAll("{\"role\":\"user\",\"content\":[");

    var first_block = true;
    while (i < messages.len and (messages[i].role == .tool or messages[i].role == .tool_result)) {
        const msg = messages[i];
        if (first_block) {} else try body.writer().writeByte(',');
        try body.writer().writeAll("{\"type\":\"tool_result\",\"tool_use_id\":");

        const tool_call_id = msg.tool_call_id orelse "";
        const normalized_tool_call_id = try cachedNormalizedToolCallId(allocator, tool_call_id, tool_call_ids);
        try writeJson(body.writer(), normalized_tool_call_id);

        try body.writer().writeAll(",\"content\":[");
        var wrote_content = false;
        if (msg.content_blocks) |blocks| {
            for (blocks) |block| {
                switch (block) {
                    .text => |v| {
                        if (v.text.len > 0) {
                            if (wrote_content) try body.writer().writeByte(',');
                            try appendTextContentBlock(body.writer(), v.text);
                            wrote_content = true;
                        }
                    },
                    else => {},
                }
            }
        }

        if (!wrote_content) {
            var fallback = std.array_list.Managed(u8).init(allocator);
            defer fallback.deinit();
            try transform.appendMessageTextToWriter(msg, fallback.writer());
            const fallback_text = if (fallback.items.len > 0) fallback.items else "(see attached image)";
            try appendTextContentBlock(body.writer(), fallback_text);
        }
        try body.writer().writeAll("],\"is_error\":");
        try body.writer().print("{}", .{msg.is_error});
        try body.writer().writeAll("}");
        first_block = false;
        i += 1;
    }
    try body.writer().writeAll("]}");
    return i;
}

fn writeToolCallsForAnthropic(
    allocator: std.mem.Allocator,
    tool_calls: []const types.ToolCall,
    tool_call_ids: *std.StringHashMap([]const u8),
    writer: anytype,
) !void {
    for (tool_calls, 0..) |tc, i| {
        if (i > 0) try writer.writeByte(',');
        const normalized_id = try cachedNormalizedToolCallId(allocator, tc.id, tool_call_ids);
        try writer.writeAll("{\"type\":\"tool_use\",\"id\":");
        try writeJson(writer, normalized_id);
        try writer.writeAll(",\"name\":");
        try writeJson(writer, tc.name);
        try writer.writeAll(",\"input\":");
        try writeToolUseInput(allocator, tc.arguments_json, writer);
        try writer.writeAll("}");
    }
}

pub fn streamAnthropicMessages(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const api_key = options.api_key orelse return error.MissingApiKey;
    const endpoint = try std.fmt.allocPrint(allocator, "{s}/v1/messages", .{std.mem.trimRight(u8, model.base_url, "/")});
    defer allocator.free(endpoint);

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try body.writer().writeAll("{\"model\":");
    try writeJson(body.writer(), model.id);
    try body.writer().print(",\"max_tokens\":{d},\"stream\":true,\"messages\":[", .{options.max_tokens orelse model.max_tokens});

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

    var first = true;
    var i: usize = 0;
    while (i < prepared_messages.items.len) {
        const msg = prepared_messages.items[i];
        if (msg.role == .tool or msg.role == .tool_result) {
            i = try writeUserMessagesFromToolResults(allocator, prepared_messages.items, i, &first, &body, &tool_call_ids);
            continue;
        }

        if (!first) try body.writer().writeByte(',');
        first = false;
        const role: []const u8 = if (msg.role == .assistant) "assistant" else "user";
        try body.writer().writeAll("{\"role\":");
        try writeJson(body.writer(), role);
        try body.writer().writeAll(",\"content\":[");

        if (msg.role == .assistant) {
            var wrote_block = false;
            if (msg.content_blocks) |blocks| {
                for (blocks) |block| {
                    switch (block) {
                        .text => |v| {
                            if (v.text.len > 0) {
                                if (wrote_block) try body.writer().writeByte(',');
                                try appendTextContentBlock(body.writer(), v.text);
                                wrote_block = true;
                            }
                        },
                        .thinking => |v| {
                            if (v.redacted or v.signature != null or v.thinking.len > 0) {
                                if (wrote_block) try body.writer().writeByte(',');
                                if (try appendAssistantThinkingContentBlock(body.writer(), v)) {
                                    wrote_block = true;
                                }
                            }
                        },
                        .image => {},
                    }
                }
            } else if (msg.content.len > 0) {
                try appendTextContentBlock(body.writer(), msg.content);
                wrote_block = true;
            }

            if (msg.tool_calls) |tool_calls| {
                if (tool_calls.len > 0) {
                    if (wrote_block) try body.writer().writeByte(',');
                    try writeToolCallsForAnthropic(allocator, tool_calls, &tool_call_ids, body.writer());
                    wrote_block = true;
                }
            }

            if (!wrote_block) {
                try appendTextContentBlock(body.writer(), "");
            }
        } else {
            if (!try writeContentFromBlocks(msg, true, body.writer())) {
                try appendTextContentBlock(body.writer(), "");
            }
        }
        try body.writer().writeAll("]}");
        i += 1;
    }
    try body.writer().writeAll("]");
    if (context.tools) |tools| {
        try body.writer().writeAll(",\"tools\":[");
        for (tools, 0..) |tool, tool_i| {
            if (tool_i > 0) try body.writer().writeByte(',');
            try body.writer().writeAll("{\"name\":");
            try writeJson(body.writer(), tool.name);
            try body.writer().writeAll(",\"description\":");
            try writeJson(body.writer(), tool.description);
            try body.writer().writeAll(",\"input_schema\":");
            try body.writer().writeAll(tool.parameters_json);
            try body.writer().writeAll("}");
        }
        try body.writer().writeAll("]");
    }
    if (context.system_prompt) |sp| {
        try body.writer().writeAll(",\"system\":");
        try writeJson(body.writer(), sp);
    }
    try body.writer().writeAll("}");

    var req = try client.request(.POST, try std.Uri.parse(endpoint), .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "text/event-stream" },
            .{ .name = "anthropic-version", .value = "2023-06-01" },
            .{ .name = "x-api-key", .value = api_key },
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

    var sse = std.array_list.Managed(u8).init(allocator);
    defer sse.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &sse);

    var usage: types.Usage = .{};
    var stop_reason: types.StopReason = .stop;
    var text_all = std.array_list.Managed(u8).init(allocator);
    defer text_all.deinit();
    var thinking_all = std.array_list.Managed(u8).init(allocator);
    defer thinking_all.deinit();
    var text_current = std.array_list.Managed(u8).init(allocator);
    defer text_current.deinit();
    var current_thinking_signature = std.array_list.Managed(u8).init(allocator);
    defer current_thinking_signature.deinit();
    var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer tool_calls.deinit();
    var content_blocks = std.array_list.Managed(types.MessageContent).init(allocator);
    defer {
        for (content_blocks.items) |block| {
            switch (block) {
                .text => |value| allocator.free(value.text),
                .thinking => |value| {
                    allocator.free(value.thinking);
                    if (value.signature) |signature| allocator.free(signature);
                    if (value.continuation_token) |token| allocator.free(token);
                },
                .image => |value| {
                    allocator.free(value.data);
                    allocator.free(value.mime_type);
                },
            }
        }
        content_blocks.deinit();
    }
    var frame = std.array_list.Managed(u8).init(allocator);
    defer frame.deinit();
    var current_tool = CurrentTool{
        .id = std.array_list.Managed(u8).init(allocator),
        .name = std.array_list.Managed(u8).init(allocator),
        .args = std.array_list.Managed(u8).init(allocator),
    };
    defer {
        current_tool.id.deinit();
        current_tool.name.deinit();
        current_tool.args.deinit();
    }

    var out: types.AssistantMessage = .{
        .text = "",
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = usage,
    };
    try events.append(.{ .start = out });

    var kind: CurrentKind = .none;
    var current_thinking_redacted = false;
    var idx: usize = 0;
    var block_count: usize = 0;

    var lines = std.mem.splitScalar(u8, sse.items, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0) {
            if (frame.items.len == 0) continue;
            const payload = std.mem.trim(u8, frame.items, " ");
            frame.clearRetainingCapacity();
            if (std.mem.eql(u8, payload, "[DONE]")) break;
            try payload_hooks.dispatchRawJson(options, payload);
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch continue;
            defer parsed.deinit();
            const root = parsed.value;
            if (root != .object) continue;
            const type_v = root.object.get("type") orelse continue;
            if (type_v != .string) continue;

            if (std.mem.eql(u8, type_v.string, "message_start")) {
                if (root.object.get("message")) |m| {
                    if (m == .object) {
                        if (m.object.get("usage")) |u| {
                            if (u == .object) {
                                if (u.object.get("input_tokens")) |v| {
                                    if (v == .integer) usage.input = @intCast(v.integer);
                                }
                                usage.total_tokens = usage.input + usage.output;
                                types.calculateCost(model, &usage);
                                try payload_hooks.dispatchUsage(options, usage);
                            }
                        }
                    }
                }
            } else if (std.mem.eql(u8, type_v.string, "content_block_start")) {
                if (kind != .none) try finishCurrent(
                    allocator,
                    &kind,
                    idx,
                    &text_current,
                    &current_thinking_signature,
                    &current_thinking_redacted,
                    &current_tool,
                    &content_blocks,
                    &tool_calls,
                    events,
                );
                idx = block_count;
                block_count += 1;
                const cb = root.object.get("content_block") orelse continue;
                if (cb != .object) continue;
                const cbt = cb.object.get("type") orelse continue;
                if (cbt != .string) continue;
                if (std.mem.eql(u8, cbt.string, "text")) {
                    kind = .text;
                    try events.append(.{ .text_start = idx });
                } else if (std.mem.eql(u8, cbt.string, "thinking")) {
                    kind = .thinking;
                    current_thinking_signature.clearRetainingCapacity();
                    current_thinking_redacted = false;
                    try events.append(.{ .thinking_start = idx });
                } else if (std.mem.eql(u8, cbt.string, "redacted_thinking")) {
                    kind = .thinking;
                    current_thinking_signature.clearRetainingCapacity();
                    current_thinking_redacted = true;
                    text_current.clearRetainingCapacity();
                    try text_current.appendSlice(redacted_thinking_placeholder);
                    try thinking_all.appendSlice(redacted_thinking_placeholder);
                    if (cb.object.get("data")) |value| {
                        if (value == .string and value.string.len > 0) {
                            try current_thinking_signature.appendSlice(value.string);
                        }
                    }
                    try events.append(.{ .thinking_start = idx });
                } else if (std.mem.eql(u8, cbt.string, "tool_use")) {
                    kind = .tool;
                    if (cb.object.get("id")) |v| {
                        if (v == .string) try current_tool.id.appendSlice(v.string);
                    }
                    if (cb.object.get("name")) |v| {
                        if (v == .string) try current_tool.name.appendSlice(v.string);
                    }
                    if (cb.object.get("input")) |v| {
                        if (v == .object) {
                            var tmp = std.array_list.Managed(u8).init(allocator);
                            defer tmp.deinit();
                            try writeJson(tmp.writer(), v);
                            try current_tool.args.appendSlice(tmp.items);
                        }
                    }
                    try events.append(.{ .toolcall_start = idx });
                }
            } else if (std.mem.eql(u8, type_v.string, "content_block_delta")) {
                const delta = root.object.get("delta") orelse continue;
                if (delta != .object) continue;
                if (kind == .text) {
                    if (delta.object.get("text")) |v| {
                        if (v == .string) {
                            try text_current.appendSlice(v.string);
                            try text_all.appendSlice(v.string);
                            try payload_hooks.appendTextDelta(allocator, events, options, idx, v.string);
                        }
                    }
                } else if (kind == .thinking) {
                    if (delta.object.get("thinking")) |v| {
                        if (v == .string) {
                            try text_current.appendSlice(v.string);
                            try thinking_all.appendSlice(v.string);
                            try payload_hooks.appendThinkingDelta(allocator, events, options, idx, v.string);
                        }
                    }
                    if (delta.object.get("signature")) |v| {
                        if (v == .string and v.string.len > 0) {
                            try current_thinking_signature.appendSlice(v.string);
                        }
                    }
                } else if (kind == .tool) {
                    if (delta.object.get("partial_json")) |v| {
                        if (v == .string) {
                            try current_tool.args.appendSlice(v.string);
                            try payload_hooks.appendToolCallDelta(allocator, events, options, idx, v.string);
                        }
                    }
                }
            } else if (std.mem.eql(u8, type_v.string, "content_block_stop")) {
                if (kind != .none) try finishCurrent(
                    allocator,
                    &kind,
                    idx,
                    &text_current,
                    &current_thinking_signature,
                    &current_thinking_redacted,
                    &current_tool,
                    &content_blocks,
                    &tool_calls,
                    events,
                );
            } else if (std.mem.eql(u8, type_v.string, "message_delta")) {
                if (root.object.get("delta")) |d| {
                    if (d == .object) {
                        if (d.object.get("stop_reason")) |sr| {
                            if (sr == .string) stop_reason = stopReasonFromAnthropic(sr.string);
                        }
                    }
                }
                if (root.object.get("usage")) |u| {
                    if (u == .object) {
                        if (u.object.get("output_tokens")) |v| {
                            if (v == .integer) usage.output = @intCast(v.integer);
                        }
                        usage.total_tokens = usage.input + usage.output;
                        types.calculateCost(model, &usage);
                        try payload_hooks.dispatchUsage(options, usage);
                    }
                }
            } else if (std.mem.eql(u8, type_v.string, "message_stop")) {
                break;
            } else if (std.mem.eql(u8, type_v.string, "error")) {
                const msg = blk: {
                    if (root.object.get("error")) |e| {
                        if (e == .object) {
                            if (e.object.get("message")) |mv| {
                                if (mv == .string) break :blk mv.string;
                            }
                        }
                    }
                    break :blk "Anthropic stream error";
                };
                try events.append(.{ .err = try allocator.dupe(u8, msg) });
                return;
            }
            continue;
        }
        if (std.mem.startsWith(u8, line, "data:")) {
            try frame.appendSlice(std.mem.trimLeft(u8, line["data:".len..], " "));
        }
    }
    if (kind != .none) try finishCurrent(
        allocator,
        &kind,
        idx,
        &text_current,
        &current_thinking_signature,
        &current_thinking_redacted,
        &current_tool,
        &content_blocks,
        &tool_calls,
        events,
    );

    out.text = try allocator.dupe(u8, text_all.items);
    out.thinking = try allocator.dupe(u8, thinking_all.items);
    out.content_blocks = if (content_blocks.items.len > 0) try content_blocks.toOwnedSlice() else null;
    out.tool_calls = try tool_calls.toOwnedSlice();
    out.usage = usage;
    out.stop_reason = if (out.tool_calls.len > 0 and stop_reason == .stop) .tool_use else stop_reason;
    try payload_hooks.appendDone(events, options, out);
}

test "anthropic stop reason mapping" {
    try std.testing.expect(stopReasonFromAnthropic("end_turn") == .stop);
    try std.testing.expect(stopReasonFromAnthropic("max_tokens") == .length);
    try std.testing.expect(stopReasonFromAnthropic("tool_use") == .tool_use);
}

test "anthropic assistant thinking blocks serialize signatures and redactions" {
    const allocator = std.testing.allocator;

    var signed = std.array_list.Managed(u8).init(allocator);
    defer signed.deinit();
    _ = try appendAssistantThinkingContentBlock(signed.writer(), .{
        .thinking = "considering options",
        .signature = "sig-123",
    });
    try std.testing.expectEqualStrings(
        "{\"type\":\"thinking\",\"thinking\":\"considering options\",\"signature\":\"sig-123\"}",
        signed.items,
    );

    var redacted = std.array_list.Managed(u8).init(allocator);
    defer redacted.deinit();
    _ = try appendAssistantThinkingContentBlock(redacted.writer(), .{
        .thinking = redacted_thinking_placeholder,
        .signature = "opaque-redacted-payload",
        .redacted = true,
    });
    try std.testing.expectEqualStrings(
        "{\"type\":\"redacted_thinking\",\"data\":\"opaque-redacted-payload\"}",
        redacted.items,
    );
}

test "anthropic finishCurrent preserves thinking metadata in content blocks" {
    const allocator = std.testing.allocator;
    var kind: CurrentKind = .thinking;
    var text = std.array_list.Managed(u8).init(allocator);
    defer text.deinit();
    try text.appendSlice(redacted_thinking_placeholder);
    var signature_buf = std.array_list.Managed(u8).init(allocator);
    defer signature_buf.deinit();
    try signature_buf.appendSlice("opaque-payload");
    var redacted = true;
    var tool = CurrentTool{
        .id = std.array_list.Managed(u8).init(allocator),
        .name = std.array_list.Managed(u8).init(allocator),
        .args = std.array_list.Managed(u8).init(allocator),
    };
    defer {
        tool.id.deinit();
        tool.name.deinit();
        tool.args.deinit();
    }
    var content_blocks = std.array_list.Managed(types.MessageContent).init(allocator);
    defer {
        for (content_blocks.items) |block| {
            switch (block) {
                .text => |value| allocator.free(value.text),
                .thinking => |value| {
                    allocator.free(value.thinking);
                    if (value.signature) |signature| allocator.free(signature);
                    if (value.continuation_token) |token| allocator.free(token);
                },
                .image => |value| {
                    allocator.free(value.data);
                    allocator.free(value.mime_type);
                },
            }
        }
        content_blocks.deinit();
    }
    var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
    defer tool_calls.deinit();
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |event| {
            switch (event) {
                .thinking_end => |value| allocator.free(value.content),
                else => {},
            }
        }
        events.deinit();
    }

    try finishCurrent(
        allocator,
        &kind,
        0,
        &text,
        &signature_buf,
        &redacted,
        &tool,
        &content_blocks,
        &tool_calls,
        &events,
    );

    try std.testing.expectEqual(@as(usize, 1), content_blocks.items.len);
    try std.testing.expect(content_blocks.items[0] == .thinking);
    try std.testing.expectEqualStrings(redacted_thinking_placeholder, content_blocks.items[0].thinking.thinking);
    try std.testing.expect(content_blocks.items[0].thinking.redacted);
    try std.testing.expectEqualStrings("opaque-payload", content_blocks.items[0].thinking.signature.?);
}

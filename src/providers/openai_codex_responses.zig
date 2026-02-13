const std = @import("std");
const types = @import("../types.zig");
const transform = @import("../transform_messages.zig");

const MAX_RETRIES: usize = 3;
const BASE_DELAY_MS: u64 = 1000;
const DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api";
const JWT_CLAIM_PATH = "https://api.openai.com/auth";

const CODEX_RESPONSE_STATUSES = [_][]const u8{
    "completed",
    "incomplete",
    "failed",
    "cancelled",
};

fn shouldDebugCodexErrors() bool {
    const allocator = std.heap.page_allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "ZIGGY_DEBUG_CODEX_ERRORS") catch return false;
    defer allocator.free(enabled);
    return std.mem.eql(u8, enabled, "1") or std.mem.eql(u8, enabled, "true") or std.mem.eql(u8, enabled, "yes");
}

fn writeJson(writer: anytype, value: anytype) !void {
    try std.fmt.format(writer, "{f}", .{std.json.fmt(value, .{})});
}

fn readAllResponseBody(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    content_length: ?u64,
    out: *std.array_list.Managed(u8),
) !void {
    if (content_length) |len_u64| {
        const len = std.math.cast(usize, len_u64) orelse return error.OutOfMemory;
        const body = try reader.readAlloc(allocator, len);
        defer allocator.free(body);
        try out.appendSlice(body);
        return;
    }

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

fn codexEndpoint(allocator: std.mem.Allocator, base_url: []const u8) ![]const u8 {
    const trimmed = std.mem.trimRight(u8, base_url, "/");
    if (std.mem.endsWith(u8, trimmed, "/codex/responses")) return allocator.dupe(u8, trimmed);
    if (std.mem.endsWith(u8, trimmed, "/codex")) return std.fmt.allocPrint(allocator, "{s}/responses", .{trimmed});
    return std.fmt.allocPrint(allocator, "{s}/codex/responses", .{trimmed});
}

fn responseEndpoint(allocator: std.mem.Allocator, base_url: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/responses", .{std.mem.trimRight(u8, base_url, "/")});
}

fn mapStopReason(status: []const u8) types.StopReason {
    if (std.mem.eql(u8, status, "completed")) return .stop;
    if (std.mem.eql(u8, status, "incomplete")) return .length;
    if (std.mem.eql(u8, status, "failed") or std.mem.eql(u8, status, "cancelled")) return .err;
    return .stop;
}

fn isRetryableError(status: std.http.Status, error_text: []const u8) bool {
    if (status == .too_many_requests or status == .internal_server_error or status == .bad_gateway or status == .service_unavailable or status == .gateway_timeout) return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "rate")) |_| return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "limit")) |_| return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "overloaded")) |_| return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "service unavailable")) |_| return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "upstream connect")) |_| return true;
    if (std.ascii.indexOfIgnoreCase(error_text, "connection refused")) |_| return true;
    return false;
}

fn clampReasoningEffort(model_id: []const u8, effort: []const u8) []const u8 {
    const id = if (std.mem.lastIndexOfScalar(u8, model_id, '/')) |idx| model_id[idx + 1 ..] else model_id;
    if ((std.mem.startsWith(u8, id, "gpt-5.2") or std.mem.startsWith(u8, id, "gpt-5.3")) and std.mem.eql(u8, effort, "minimal")) return "low";
    if (std.mem.eql(u8, id, "gpt-5.1") and std.mem.eql(u8, effort, "xhigh")) return "high";
    if (std.mem.eql(u8, id, "gpt-5.1-codex-mini")) {
        if (std.mem.eql(u8, effort, "high") or std.mem.eql(u8, effort, "xhigh")) return "high";
        return "medium";
    }
    return effort;
}

fn decodeBase64Url(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(data) catch return error.InvalidData;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    std.base64.url_safe.Decoder.decode(decoded, data) catch return error.InvalidData;
    return decoded;
}

fn extractCodexAccountId(allocator: std.mem.Allocator, api_key: []const u8) ![]const u8 {
    var it = std.mem.splitScalar(u8, api_key, '.');
    _ = it.next() orelse return error.InvalidCodexApiKey;
    const payload = it.next() orelse return error.InvalidCodexApiKey;
    if (it.next() == null) {
        return error.InvalidCodexApiKey;
    }

    const decoded = try decodeBase64Url(allocator, payload);
    defer allocator.free(decoded);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded, .{}) catch return error.InvalidCodexApiKey;
    defer parsed.deinit();
    const claims_obj = parsed.value;
    if (claims_obj != .object) return error.InvalidCodexApiKey;

    const claim = claims_obj.object.get(JWT_CLAIM_PATH) orelse return error.InvalidCodexApiKey;
    if (claim != .object) return error.InvalidCodexApiKey;
    const account_id = claim.object.get("chatgpt_account_id") orelse return error.InvalidCodexApiKey;
    if (account_id != .string) return error.InvalidCodexApiKey;
    if (account_id.string.len == 0) return error.InvalidCodexApiKey;
    return try allocator.dupe(u8, account_id.string);
}

fn appendHeader(headers: *std.array_list.Managed(std.http.Header), name: []const u8, value: []const u8) !void {
    try headers.append(.{ .name = name, .value = value });
}

fn parseCodexError(allocator: std.mem.Allocator, status: std.http.Status, body: []const u8) ![]const u8 {
    var message = try std.fmt.allocPrint(allocator, "Request failed with status {}", .{@intFromEnum(status)});

    var response = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch null;
    defer if (response) |*parsed| parsed.deinit();
    if (response == null) return message;

    const root = response.?.value;
    if (root != .object) return message;
    const err_json = root.object.get("error") orelse return message;
    if (err_json != .object) return message;

    if (err_json.object.get("message")) |message_v| {
        if (message_v == .string) {
            allocator.free(message);
            message = try allocator.dupe(u8, message_v.string);
        }
    }

    var plan: ?[]const u8 = null;
    if (err_json.object.get("plan_type")) |plan_type| {
        if (plan_type == .string and plan_type.string.len > 0) {
            plan = plan_type.string;
        }
    }

    var resets_at: ?i64 = null;
    if (err_json.object.get("resets_at")) |resets_at_v| {
        if (resets_at_v == .integer) {
            resets_at = @as(i64, @intCast(resets_at_v.integer));
        } else if (resets_at_v == .float) {
            resets_at = @as(i64, @intFromFloat(resets_at_v.float));
        }
    }

    var code: ?[]const u8 = null;
    if (err_json.object.get("code")) |code_v| {
        if (code_v == .string) code = code_v.string;
    } else if (err_json.object.get("type")) |type_v| {
        if (type_v == .string) code = type_v.string;
    }

    const usage_limit = if (status == .too_many_requests) true else blk: {
        if (code) |c| {
            if (std.mem.eql(u8, c, "usage_limit_reached") or std.mem.eql(u8, c, "usage_not_included") or std.mem.eql(u8, c, "rate_limit_exceeded")) break :blk true;
        }
        break :blk false;
    };

    if (usage_limit) {
        const label = if (plan) |p| try std.fmt.allocPrint(allocator, " ({s} plan)", .{p}) else "";
        const wait = if (resets_at) |expires_at| blk: {
            const current = std.time.milliTimestamp();
            const next_ms = if (expires_at > current) expires_at else current;
            const mins = @divTrunc(next_ms - current, 60000);
            break :blk try std.fmt.allocPrint(allocator, " Try again in ~{} min.", .{mins});
        } else "";
        const friendly = try std.fmt.allocPrint(allocator, "You have hit your ChatGPT usage limit{s}.{s}", .{ label, wait });
        allocator.free(message);
        message = friendly;
    }

    return message;
}

fn appendContentTextFromMessage(allocator: std.mem.Allocator, msg: types.Message, writer: anytype) !bool {
    var text = std.array_list.Managed(u8).init(allocator);
    defer text.deinit();
    try transform.appendMessageTextToWriter(msg, text.writer());
    if (text.items.len == 0) {
        return false;
    }
    try writeJson(writer, text.items);
    return true;
}

fn collectMessageText(allocator: std.mem.Allocator, msg: types.Message) ![]const u8 {
    var text = std.array_list.Managed(u8).init(allocator);
    try transform.appendMessageTextToWriter(msg, text.writer());
    return text.toOwnedSlice();
}

fn normalizeToolCallChunk(allocator: std.mem.Allocator, token: []const u8) ![]const u8 {
    var normalized = std.array_list.Managed(u8).init(allocator);
    defer normalized.deinit();

    for (token) |ch| {
        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-') {
            try normalized.append(ch);
        } else {
            try normalized.append('_');
        }
    }

    if (normalized.items.len > 64) {
        normalized.items.len = 64;
    }
    while (normalized.items.len > 0 and normalized.items[normalized.items.len - 1] == '_') {
        normalized.items.len -= 1;
    }

    return try normalized.toOwnedSlice();
}

fn normalizeToolCallId(allocator: std.mem.Allocator, id: []const u8) ![]const u8 {
    const sep = std.mem.indexOfScalar(u8, id, '|');
    const call_raw = if (sep) |idx| id[0..idx] else id;
    const item_raw = if (sep) |idx| id[idx + 1 ..] else "";

    const normalized_call = try normalizeToolCallChunk(allocator, call_raw);
    if (item_raw.len == 0) return normalized_call;
    errdefer allocator.free(normalized_call);

    var normalized_item = try normalizeToolCallChunk(allocator, item_raw);
    if (!std.mem.startsWith(u8, normalized_item, "fc")) {
        const with_prefix = try std.fmt.allocPrint(allocator, "fc_{s}", .{normalized_item});
        allocator.free(normalized_item);
        normalized_item = with_prefix;
    }

    if (normalized_item.len > 64) {
        normalized_item.len = 64;
    }
    while (normalized_item.len > 0 and normalized_item[normalized_item.len - 1] == '_') {
        normalized_item.len -= 1;
    }

    var out = std.array_list.Managed(u8).init(allocator);
    defer out.deinit();
    try out.appendSlice(normalized_call);
    try out.append('|');
    try out.appendSlice(normalized_item);
    allocator.free(normalized_call);
    const normalized = try out.toOwnedSlice();
    allocator.free(normalized_item);
    return normalized;
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

fn appendInputTextItem(writer: anytype, text: []const u8) !void {
    try writer.writeAll("{\"type\":\"input_text\",\"text\":");
    try writeJson(writer, text);
    try writer.writeAll("}");
}

fn appendOutputTextItem(writer: anytype, text: []const u8, item_index: usize) !void {
    try writer.writeAll("{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":");
    try writeJson(writer, text);
    try writer.writeAll("}],\"status\":\"completed\",\"id\":\"msg_");
    var id_buf: [32]u8 = undefined;
    const id_text = try std.fmt.bufPrint(&id_buf, "{}", .{item_index});
    try writer.writeAll(id_text);
    try writer.writeAll("\"}");
}

fn splitToolCallId(tool_call_id: []const u8) struct { call_id: []const u8, item_id: ?[]const u8 } {
    const sep = std.mem.indexOfScalar(u8, tool_call_id, '|');
    if (sep) |idx| {
        return .{ .call_id = tool_call_id[0..idx], .item_id = if (idx + 1 < tool_call_id.len) tool_call_id[idx + 1 ..] else null };
    }
    return .{ .call_id = tool_call_id, .item_id = null };
}

fn appendFunctionCallItem(writer: anytype, normalized_tool_call_id: []const u8, tool_call: types.ToolCall) !void {
    const split = splitToolCallId(normalized_tool_call_id);
    const output_id = split.item_id orelse if (tool_call.id.len > 0) normalized_tool_call_id else "tool";
    try writer.writeAll("{\"type\":\"function_call\",\"call_id\":");
    try writeJson(writer, split.call_id);
    try writer.writeAll(",\"id\":");
    try writeJson(writer, output_id);
    try writer.writeAll(",\"name\":");
    try writeJson(writer, tool_call.name);
    try writer.writeAll(",\"arguments\":");
    try writeJson(writer, tool_call.arguments_json);
}

fn appendToolResultItem(
    allocator: std.mem.Allocator,
    msg: types.Message,
    tool_call_ids: *std.StringHashMap([]const u8),
    writer: anytype,
) !void {
    try writer.writeAll("{\"type\":\"function_call_output\",\"call_id\":");
    const tool_call_id = msg.tool_call_id orelse "";
    const normalized_tool_call_id = try cachedNormalizedToolCallId(allocator, tool_call_id, tool_call_ids);
    const split = splitToolCallId(normalized_tool_call_id);
    try writeJson(writer, split.call_id);
    try writer.writeAll(",\"output\":");

    var text = std.array_list.Managed(u8).init(allocator);
    defer text.deinit();
    try transform.appendMessageTextToWriter(msg, text.writer());
    if (text.items.len == 0) {
        try writeJson(writer, "(see attached image)");
    } else {
        try writeJson(writer, text.items);
    }
    try writer.writeAll("}");
}

fn finishCurrent(
    allocator: std.mem.Allocator,
    current_kind: *CurrentKind,
    current_index: usize,
    text_buf: *std.array_list.Managed(u8),
    current_tool: *CurrentTool,
    tool_calls: *std.array_list.Managed(types.ToolCall),
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    switch (current_kind.*) {
        .none => {},
        .text => {
            try events.append(.{ .text_end = .{
                .content_index = current_index,
                .content = try allocator.dupe(u8, text_buf.items),
            } });
            text_buf.clearRetainingCapacity();
        },
        .thinking => {
            try events.append(.{ .thinking_end = .{
                .content_index = current_index,
                .content = try allocator.dupe(u8, text_buf.items),
            } });
            text_buf.clearRetainingCapacity();
        },
        .tool => {
            const tc: types.ToolCall = .{
                .id = try allocator.dupe(u8, current_tool.id.items),
                .name = try allocator.dupe(u8, current_tool.name.items),
                .arguments_json = try allocator.dupe(u8, current_tool.args.items),
            };
            try tool_calls.append(tc);
            try events.append(.{ .toolcall_end = .{
                .content_index = current_index,
                .tool_call = tc,
            } });
            current_tool.id.clearRetainingCapacity();
            current_tool.name.clearRetainingCapacity();
            current_tool.args.clearRetainingCapacity();
        },
    }
    current_kind.* = .none;
}

fn streamOpenAIResponsesBase(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    endpoint: []const u8,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const api_key = options.api_key orelse return error.MissingApiKey;
    const is_codox_endpoint = std.mem.endsWith(u8, endpoint, "/codex/responses");
    const account_id = if (is_codox_endpoint) try extractCodexAccountId(allocator, api_key) else null;
    defer if (account_id) |aid| allocator.free(aid);

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try body.writer().writeAll("{\"model\":");
    try writeJson(body.writer(), model.id);
    try body.writer().writeAll(",\"stream\":true,\"store\":false");
    const prepared_messages = try transform.prepareMessagesForApi(allocator, context.messages);
    defer prepared_messages.deinit();

    var first = true;
    var system_prompt = context.system_prompt;
    var system_prompt_owned: ?[]const u8 = null;
    defer if (system_prompt_owned) |owned| allocator.free(owned);

    if (system_prompt == null) {
        for (prepared_messages.items) |msg| {
            if (msg.role == .system) {
                const extracted = try collectMessageText(allocator, msg);
                if (extracted.len > 0) {
                    system_prompt = extracted;
                    system_prompt_owned = extracted;
                    break;
                }
                allocator.free(extracted);
            }
        }
    }

    if (system_prompt) |sp| {
        try body.writer().writeAll(",\"instructions\":");
        try writeJson(body.writer(), sp);
    }
    if (options.text_verbosity) |verbosity| {
        try body.writer().writeAll(",\"text\":");
        try body.writer().writeAll("{\"verbosity\":");
        try writeJson(body.writer(), verbosity);
    } else {
        try body.writer().writeAll(",\"text\":{\"verbosity\":\"medium\"");
    }
    try body.writer().writeAll("},\"include\":[\"reasoning.encrypted_content\"]");
    if (options.session_id) |session_id| {
        try body.writer().writeAll(",\"prompt_cache_key\":");
        try writeJson(body.writer(), session_id);
    }
    if (options.reasoning) |reasoning| {
        try body.writer().writeAll(",\"reasoning\":{\"effort\":");
        try writeJson(body.writer(), clampReasoningEffort(model.id, reasoning));
        try body.writer().writeAll(",\"summary\":");
        try writeJson(body.writer(), options.reasoning_summary orelse "auto");
        try body.writer().writeAll("}");
    }
    try body.writer().writeAll(",\"input\":[");
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

    for (prepared_messages.items) |msg| {
        if (msg.role == .system) continue;
        if (!first) try body.writer().writeByte(',');
        first = false;

        if (msg.role == .assistant) {
            var wrote_item = false;
            var item_index: usize = 0;

            const text_output = try collectMessageText(allocator, msg);
            defer allocator.free(text_output);
            if (text_output.len > 0) {
                try appendOutputTextItem(body.writer(), text_output, item_index);
                item_index += 1;
                wrote_item = true;
            }

            if (msg.tool_calls) |tool_calls| {
                for (tool_calls) |tc| {
                    if (wrote_item) try body.writer().writeByte(',');
                    const normalized_tool_call_id = try cachedNormalizedToolCallId(allocator, tc.id, &tool_call_ids);
                    try appendFunctionCallItem(body.writer(), normalized_tool_call_id, tc);
                    wrote_item = true;
                }
            }

            if (!wrote_item) {
                try appendOutputTextItem(body.writer(), "", item_index);
            }
            continue;
        }

        if (msg.role == .tool or msg.role == .tool_result) {
            try appendToolResultItem(allocator, msg, &tool_call_ids, body.writer());
            continue;
        }

        const text_output = try collectMessageText(allocator, msg);
        defer allocator.free(text_output);
        try body.writer().writeAll("{\"role\":\"user\",\"content\":[");
        if (text_output.len > 0) {
            try appendInputTextItem(body.writer(), text_output);
        } else {
            try appendInputTextItem(body.writer(), "");
        }
        try body.writer().writeAll("]}");
    }
    try body.writer().writeAll("]");
    if (context.tools) |tools| {
        try body.writer().writeAll(",\"tools\":[");
        for (tools, 0..) |tool, i| {
            if (i > 0) try body.writer().writeByte(',');
            try body.writer().writeAll("{\"type\":\"function\",\"name\":");
            try writeJson(body.writer(), tool.name);
            try body.writer().writeAll(",\"description\":");
            try writeJson(body.writer(), tool.description);
            try body.writer().writeAll(",\"parameters\":");
            try body.writer().writeAll(tool.parameters_json);
            try body.writer().writeAll("}");
        }
        try body.writer().writeAll("],\"tool_choice\":\"auto\",\"parallel_tool_calls\":true");
    }
    try body.writer().writeAll("}");

    var attempt: usize = 0;
    attempt_loop: while (attempt <= MAX_RETRIES) : (attempt += 1) {
        var request_headers = std.array_list.Managed(std.http.Header).init(allocator);
        defer request_headers.deinit();

        const auth_header_value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
        defer allocator.free(auth_header_value);
        try appendHeader(&request_headers, "Authorization", auth_header_value);
        try appendHeader(&request_headers, "content-type", "application/json");
        try appendHeader(&request_headers, "accept", "text/event-stream");

        if (is_codox_endpoint) {
            if (account_id) |account| {
                try appendHeader(&request_headers, "chatgpt-account-id", account);
            }
            try appendHeader(&request_headers, "OpenAI-Beta", "responses=experimental");
            try appendHeader(&request_headers, "originator", "pi");
            if (options.session_id) |session_id| {
                try appendHeader(&request_headers, "session_id", session_id);
            }
        }

        if (options.headers) |custom_headers| {
            for (custom_headers) |header| {
                try appendHeader(&request_headers, header.name, header.value);
            }
        }

        var req = try client.request(.POST, try std.Uri.parse(endpoint), .{
            .extra_headers = request_headers.items,
        });
        defer req.deinit();

        req.sendBodyComplete(body.items) catch |err| {
            if (attempt < MAX_RETRIES) {
                const delay_ms = BASE_DELAY_MS * (@as(u64, 1) << @intCast(attempt));
                std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                continue :attempt_loop;
            }
            const message = try std.fmt.allocPrint(allocator, "Request failed with error: {s}", .{@errorName(err)});
            defer allocator.free(message);
            try events.append(.{ .err = try allocator.dupe(u8, message) });
            return;
        };

        var redirect_buf: [4096]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            if (attempt < MAX_RETRIES) {
                const delay_ms = BASE_DELAY_MS * (@as(u64, 1) << @intCast(attempt));
                std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                continue :attempt_loop;
            }
            const message = try std.fmt.allocPrint(allocator, "Request failed with error: {s}", .{@errorName(err)});
            defer allocator.free(message);
            try events.append(.{ .err = try allocator.dupe(u8, message) });
            return;
        };

        if (response.head.status != .ok) {
            var err_buf = std.array_list.Managed(u8).init(allocator);
            defer err_buf.deinit();
            var err_transfer: [8192]u8 = undefined;
            const err_reader = response.reader(&err_transfer);
            readAllResponseBody(allocator, err_reader, response.head.content_length, &err_buf) catch {
                if (attempt < MAX_RETRIES and isRetryableError(response.head.status, "")) {
                    const delay_ms = BASE_DELAY_MS * (@as(u64, 1) << @intCast(attempt));
                    std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                    continue :attempt_loop;
                }
                const msg = try std.fmt.allocPrint(allocator, "Request failed with status {}", .{@intFromEnum(response.head.status)});
                defer allocator.free(msg);
                try events.append(.{ .err = try allocator.dupe(u8, msg) });
            };

            if (shouldDebugCodexErrors()) {
                std.debug.print("codex error status={} body={s}\n", .{ @intFromEnum(response.head.status), err_buf.items });
            }

            const friendly = try parseCodexError(allocator, response.head.status, err_buf.items);
            if (attempt < MAX_RETRIES and isRetryableError(response.head.status, friendly)) {
                allocator.free(friendly);
                const delay_ms = BASE_DELAY_MS * (@as(u64, 1) << @intCast(attempt));
                std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                continue :attempt_loop;
            }
            try events.append(.{ .err = friendly });
            return;
        }

        var sse = std.array_list.Managed(u8).init(allocator);
        defer sse.deinit();
        var transfer_buffer: [8192]u8 = undefined;
        const response_reader = response.reader(&transfer_buffer);
        try readAllResponseBody(allocator, response_reader, response.head.content_length, &sse);

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

        var text_buf = std.array_list.Managed(u8).init(allocator);
        defer text_buf.deinit();
        var full_text = std.array_list.Managed(u8).init(allocator);
        defer full_text.deinit();
        var thinking = std.array_list.Managed(u8).init(allocator);
        defer thinking.deinit();
        var tool_calls = std.array_list.Managed(types.ToolCall).init(allocator);
        defer tool_calls.deinit();
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

        var current_kind: CurrentKind = .none;
        var current_index: usize = 0;
        var block_count: usize = 0;

        var lines = std.mem.splitScalar(u8, sse.items, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimRight(u8, raw, "\r");
            if (line.len == 0) {
                if (frame.items.len == 0) continue;
                const payload = std.mem.trim(u8, frame.items, " ");
                frame.clearRetainingCapacity();
                if (std.mem.eql(u8, payload, "[DONE]")) break;

                var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch continue;
                defer parsed.deinit();
                const root = parsed.value;
                if (root != .object) continue;
                const t = root.object.get("type") orelse continue;
                if (t != .string) continue;

                if (std.mem.eql(u8, t.string, "response.output_item.added")) {
                    const item = root.object.get("item") orelse continue;
                    if (item != .object) continue;
                    const it = item.object.get("type") orelse continue;
                    if (it != .string) continue;
                    if (current_kind != .none) try finishCurrent(allocator, &current_kind, current_index, &text_buf, &current_tool, &tool_calls, events);
                    current_index = block_count;
                    block_count += 1;
                    if (std.mem.eql(u8, it.string, "reasoning")) {
                        current_kind = .thinking;
                        try events.append(.{ .thinking_start = current_index });
                    } else if (std.mem.eql(u8, it.string, "message")) {
                        current_kind = .text;
                        try events.append(.{ .text_start = current_index });
                    } else if (std.mem.eql(u8, it.string, "function_call")) {
                        current_kind = .tool;
                        if (item.object.get("call_id")) |v| {
                            if (v == .string) try current_tool.id.appendSlice(v.string);
                        }
                        if (item.object.get("name")) |v| {
                            if (v == .string) try current_tool.name.appendSlice(v.string);
                        }
                        if (item.object.get("arguments")) |v| {
                            if (v == .string) try current_tool.args.appendSlice(v.string);
                        }
                        try events.append(.{ .toolcall_start = current_index });
                    }
                } else if (std.mem.eql(u8, t.string, "response.reasoning_summary_text.delta")) {
                    if (current_kind == .thinking) {
                        const delta_v = root.object.get("delta") orelse continue;
                        if (delta_v != .string) continue;
                        try text_buf.appendSlice(delta_v.string);
                        try thinking.appendSlice(delta_v.string);
                        try events.append(.{ .thinking_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, delta_v.string),
                        } });
                    }
                } else if (std.mem.eql(u8, t.string, "response.output_text.delta") or std.mem.eql(u8, t.string, "response.refusal.delta")) {
                    if (current_kind == .text) {
                        const delta_v = root.object.get("delta") orelse continue;
                        if (delta_v != .string) continue;
                        try text_buf.appendSlice(delta_v.string);
                        try full_text.appendSlice(delta_v.string);
                        try events.append(.{ .text_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, delta_v.string),
                        } });
                    }
                } else if (std.mem.eql(u8, t.string, "response.function_call_arguments.delta")) {
                    if (current_kind == .tool) {
                        const delta_v = root.object.get("delta") orelse continue;
                        if (delta_v != .string) continue;
                        try current_tool.args.appendSlice(delta_v.string);
                        try events.append(.{ .toolcall_delta = .{
                            .content_index = current_index,
                            .delta = try allocator.dupe(u8, delta_v.string),
                        } });
                    }
                } else if (std.mem.eql(u8, t.string, "response.function_call_arguments.done")) {
                    if (current_kind == .tool) {
                        const args_v = root.object.get("arguments") orelse continue;
                        if (args_v == .string) {
                            current_tool.args.clearRetainingCapacity();
                            try current_tool.args.appendSlice(args_v.string);
                        }
                    }
                } else if (std.mem.eql(u8, t.string, "response.output_item.done")) {
                    if (current_kind != .none) {
                        try finishCurrent(allocator, &current_kind, current_index, &text_buf, &current_tool, &tool_calls, events);
                    }
                } else if (std.mem.eql(u8, t.string, "response.completed")) {
                    if (root.object.get("response")) |resp| {
                        if (resp == .object) {
                            if (resp.object.get("status")) |st| {
                                if (st == .string) stop_reason = mapStopReason(st.string);
                            }
                            if (resp.object.get("usage")) |uv| {
                                if (uv == .object) {
                                    if (uv.object.get("input_tokens")) |v| {
                                        if (v == .integer) usage.input = @intCast(v.integer);
                                    }
                                    if (uv.object.get("output_tokens")) |v| {
                                        if (v == .integer) usage.output = @intCast(v.integer);
                                    }
                                    if (uv.object.get("total_tokens")) |v| {
                                        if (v == .integer) usage.total_tokens = @intCast(v.integer);
                                    }
                                    types.calculateCost(model, &usage);
                                }
                            }
                        }
                    }
                } else if (std.mem.eql(u8, t.string, "response.done")) {
                    if (root.object.get("response")) |resp| {
                        if (resp == .object) {
                            if (resp.object.get("status")) |st| {
                                if (st == .string) stop_reason = mapStopReason(st.string);
                            }
                        }
                    }
                } else if (std.mem.eql(u8, t.string, "response.failed")) {
                    const msg = blk: {
                        if (root.object.get("response")) |resp| {
                            if (resp == .object) {
                                if (resp.object.get("error")) |err_v| {
                                    if (err_v == .string) break :blk err_v.string;
                                    if (err_v == .object) {
                                        if (err_v.object.get("message")) |mv| {
                                            if (mv == .string) break :blk mv.string;
                                        }
                                    }
                                }
                            }
                        }
                        if (root.object.get("message")) |mv| {
                            if (mv == .string) break :blk mv.string;
                        }
                        break :blk "Codex stream failed";
                    };
                    try events.append(.{ .err = try allocator.dupe(u8, msg) });
                    return;
                } else if (std.mem.eql(u8, t.string, "error")) {
                    const msg = blk: {
                        if (root.object.get("message")) |mv| {
                            if (mv == .string) break :blk mv.string;
                        }
                        break :blk "Codex stream error";
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

        if (current_kind != .none) try finishCurrent(allocator, &current_kind, current_index, &text_buf, &current_tool, &tool_calls, events);
        out.text = try allocator.dupe(u8, full_text.items);
        out.thinking = try allocator.dupe(u8, thinking.items);
        out.tool_calls = try tool_calls.toOwnedSlice();
        out.usage = usage;
        out.stop_reason = if (out.tool_calls.len > 0 and stop_reason == .stop) .tool_use else stop_reason;
        try events.append(.{ .done = out });
        return;
    }
}
pub fn streamOpenAICodexResponses(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const endpoint = try codexEndpoint(allocator, model.base_url);
    defer allocator.free(endpoint);
    try streamOpenAIResponsesBase(allocator, client, model, context, options, endpoint, events);
}

pub fn streamOpenAIResponses(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const endpoint = try responseEndpoint(allocator, model.base_url);
    defer allocator.free(endpoint);
    try streamOpenAIResponsesBase(allocator, client, model, context, options, endpoint, events);
}

test "codexEndpoint normalization" {
    const allocator = std.testing.allocator;
    const a = try codexEndpoint(allocator, "https://chatgpt.com/backend-api");
    defer allocator.free(a);
    try std.testing.expect(std.mem.eql(u8, a, "https://chatgpt.com/backend-api/codex/responses"));
    const b = try codexEndpoint(allocator, "https://chatgpt.com/backend-api/codex");
    defer allocator.free(b);
    try std.testing.expect(std.mem.eql(u8, b, "https://chatgpt.com/backend-api/codex/responses"));
}

test "responseEndpoint normalization" {
    const allocator = std.testing.allocator;
    const endpoint = try responseEndpoint(allocator, "https://api.openai.com/v1");
    defer allocator.free(endpoint);
    try std.testing.expect(std.mem.eql(u8, endpoint, "https://api.openai.com/v1/responses"));
}

test "codex stop reason mapping" {
    try std.testing.expect(mapStopReason("completed") == .stop);
    try std.testing.expect(mapStopReason("incomplete") == .length);
    try std.testing.expect(mapStopReason("failed") == .err);
}

test "codex tool-call ids are sanitized and mapped" {
    const allocator = std.testing.allocator;
    const normalized = try normalizeToolCallId(allocator, "call with spaces|MyToolId");
    defer allocator.free(normalized);
    try std.testing.expect(std.mem.eql(u8, normalized, "call_with_spaces|fc_MyToolId"));
}

const std = @import("std");
const types = @import("../types.zig");
const transform = @import("../transform_messages.zig");

const service_name = "bedrock";
const authenticated_placeholder = "<authenticated>";

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

fn isAuthenticatedPlaceholder(value: []const u8) bool {
    return std.mem.eql(u8, value, authenticated_placeholder);
}

fn deriveRegionFromBaseUrl(allocator: std.mem.Allocator, base_url: []const u8) ![]const u8 {
    const fallback = "us-east-1";
    const uri = std.Uri.parse(base_url) catch return allocator.dupe(u8, fallback);
    var host_buf: [256]u8 = undefined;
    const host = uri.getHost(&host_buf) catch return allocator.dupe(u8, fallback);

    var it = std.mem.splitScalar(u8, host, '.');
    const first = it.next() orelse return allocator.dupe(u8, fallback);
    const second = it.next() orelse return allocator.dupe(u8, fallback);

    if (!std.mem.startsWith(u8, first, "bedrock-runtime")) return allocator.dupe(u8, fallback);
    if (second.len == 0) return allocator.dupe(u8, fallback);
    return allocator.dupe(u8, second);
}

fn buildAmzDate(timestamp_secs: u64, amz_date: *[16]u8, date_stamp: *[8]u8) !void {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = timestamp_secs };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    _ = try std.fmt.bufPrint(
        amz_date,
        "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
    _ = try std.fmt.bufPrint(
        date_stamp,
        "{d:0>4}{d:0>2}{d:0>2}",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
        },
    );
}

fn sha256Hex(input: []const u8, out: *[64]u8) !void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    _ = try std.fmt.bufPrint(out, "{x}", .{&digest});
}

fn hmacSha256(key: []const u8, message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message, key);
    return out;
}

const SigV4Auth = struct {
    authorization: []const u8,
    amz_date: []const u8,
    payload_sha256: []const u8,
    signed_headers: []const u8,
};

fn buildSigV4Authorization(
    allocator: std.mem.Allocator,
    auth_buf: []u8,
    amz_date_storage: *[16]u8,
    payload_hash_storage: *[64]u8,
    endpoint_uri: std.Uri,
    body: []const u8,
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8,
    region: []const u8,
    timestamp_secs: u64,
) !SigV4Auth {
    var host_buf: [256]u8 = undefined;
    const host = try endpoint_uri.getHost(&host_buf);
    const canonical_uri = switch (endpoint_uri.path) {
        .raw => |v| if (v.len > 0) v else "/",
        .percent_encoded => |v| if (v.len > 0) v else "/",
    };

    var date_stamp_storage: [8]u8 = undefined;
    try buildAmzDate(timestamp_secs, amz_date_storage, &date_stamp_storage);

    try sha256Hex(body, payload_hash_storage);

    const signed_headers = if (session_token != null)
        "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    else
        "host;x-amz-content-sha256;x-amz-date";

    const canonical_headers = if (session_token) |token|
        try std.fmt.allocPrint(
            allocator,
            "host:{s}\nx-amz-content-sha256:{s}\nx-amz-date:{s}\nx-amz-security-token:{s}\n",
            .{ host, payload_hash_storage, amz_date_storage, token },
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "host:{s}\nx-amz-content-sha256:{s}\nx-amz-date:{s}\n",
            .{ host, payload_hash_storage, amz_date_storage },
        );
    defer allocator.free(canonical_headers);

    const canonical_request = try std.fmt.allocPrint(
        allocator,
        "POST\n{s}\n\n{s}\n{s}\n{s}",
        .{ canonical_uri, canonical_headers, signed_headers, payload_hash_storage },
    );
    defer allocator.free(canonical_request);

    var canonical_request_hash: [64]u8 = undefined;
    try sha256Hex(canonical_request, &canonical_request_hash);

    var credential_scope_buf: [96]u8 = undefined;
    const credential_scope = try std.fmt.bufPrint(
        &credential_scope_buf,
        "{s}/{s}/{s}/aws4_request",
        .{ date_stamp_storage, region, service_name },
    );

    const string_to_sign = try std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256\n{s}\n{s}\n{s}",
        .{ amz_date_storage, credential_scope, canonical_request_hash },
    );
    defer allocator.free(string_to_sign);

    const secret_prefix = try std.fmt.allocPrint(allocator, "AWS4{s}", .{secret_access_key});
    defer allocator.free(secret_prefix);
    const k_date = hmacSha256(secret_prefix, &date_stamp_storage);
    const k_region = hmacSha256(&k_date, region);
    const k_service = hmacSha256(&k_region, service_name);
    const k_signing = hmacSha256(&k_service, "aws4_request");
    const signature = hmacSha256(&k_signing, string_to_sign);

    var signature_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&signature_hex, "{x}", .{&signature});

    const authorization = try std.fmt.bufPrint(
        auth_buf,
        "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ access_key_id, credential_scope, signed_headers, signature_hex },
    );

    return .{
        .authorization = authorization,
        .amz_date = amz_date_storage,
        .payload_sha256 = payload_hash_storage,
        .signed_headers = signed_headers,
    };
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

    const api_key = options.api_key;
    const use_bearer = api_key != null and !isAuthenticatedPlaceholder(api_key.?) and api_key.?.len > 0;

    const aws_access_key_id = std.process.getEnvVarOwned(allocator, "AWS_ACCESS_KEY_ID") catch null;
    defer if (aws_access_key_id) |v| allocator.free(v);
    const aws_secret_access_key = std.process.getEnvVarOwned(allocator, "AWS_SECRET_ACCESS_KEY") catch null;
    defer if (aws_secret_access_key) |v| allocator.free(v);
    const aws_session_token = std.process.getEnvVarOwned(allocator, "AWS_SESSION_TOKEN") catch null;
    defer if (aws_session_token) |v| allocator.free(v);
    const aws_region = std.process.getEnvVarOwned(allocator, "AWS_REGION") catch
        std.process.getEnvVarOwned(allocator, "AWS_DEFAULT_REGION") catch null;
    defer if (aws_region) |v| allocator.free(v);

    var sigv4_auth_buf: [1024]u8 = undefined;
    var sigv4_amz_date_buf: [16]u8 = undefined;
    var sigv4_payload_sha_buf: [64]u8 = undefined;
    const endpoint_uri = try std.Uri.parse(endpoint);
    if (use_bearer) {
        const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key.?});
        defer allocator.free(auth);
        try appendHeader(&headers, "Authorization", auth);
    } else if (aws_access_key_id != null and aws_secret_access_key != null) {
        const region_owned = if (aws_region) |region|
            try allocator.dupe(u8, region)
        else
            try deriveRegionFromBaseUrl(allocator, model.base_url);
        defer allocator.free(region_owned);

        const now_ts: u64 = @intCast(std.time.timestamp());
        const sigv4 = try buildSigV4Authorization(
            allocator,
            &sigv4_auth_buf,
            &sigv4_amz_date_buf,
            &sigv4_payload_sha_buf,
            endpoint_uri,
            body,
            aws_access_key_id.?,
            aws_secret_access_key.?,
            aws_session_token,
            region_owned,
            now_ts,
        );
        try appendHeader(&headers, "authorization", sigv4.authorization);
        try appendHeader(&headers, "x-amz-date", sigv4.amz_date);
        try appendHeader(&headers, "x-amz-content-sha256", sigv4.payload_sha256);
        if (aws_session_token) |token| {
            try appendHeader(&headers, "x-amz-security-token", token);
        }
    } else {
        return error.MissingApiKey;
    }

    try appendHeader(&headers, "content-type", "application/json");
    try appendHeader(&headers, "accept", "application/json");

    if (options.headers) |custom_headers| {
        for (custom_headers) |header| try appendHeader(&headers, header.name, header.value);
    }

    var req = try client.request(.POST, endpoint_uri, .{ .extra_headers = headers.items });
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

test "bedrock region derivation from base url" {
    const allocator = std.testing.allocator;
    const derived = try deriveRegionFromBaseUrl(allocator, "https://bedrock-runtime.us-west-2.amazonaws.com");
    defer allocator.free(derived);
    try std.testing.expectEqualStrings("us-west-2", derived);
}

test "bedrock sigv4 authorization shape" {
    const allocator = std.testing.allocator;
    const endpoint_uri = try std.Uri.parse("https://bedrock-runtime.us-east-1.amazonaws.com/model/m/converse");
    var auth_buf: [1024]u8 = undefined;
    var amz_date_buf: [16]u8 = undefined;
    var payload_sha_buf: [64]u8 = undefined;
    const sig = try buildSigV4Authorization(
        allocator,
        &auth_buf,
        &amz_date_buf,
        &payload_sha_buf,
        endpoint_uri,
        "{\"messages\":[]}",
        "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        null,
        "us-east-1",
        1_707_964_800,
    );
    try std.testing.expect(std.mem.startsWith(u8, sig.authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240215/us-east-1/bedrock/aws4_request"));
    try std.testing.expect(std.mem.indexOf(u8, sig.authorization, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") != null);
    try std.testing.expect(sig.amz_date.len == 16);
    try std.testing.expect(std.mem.startsWith(u8, sig.amz_date, "20240215T"));
    try std.testing.expect(sig.amz_date[15] == 'Z');
    try std.testing.expect(sig.payload_sha256.len == 64);
}

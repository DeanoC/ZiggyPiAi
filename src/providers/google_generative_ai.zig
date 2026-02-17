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

const antigravity_instruction =
    "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.";

const GoogleCredentials = struct {
    token: []const u8,
    project_id: ?[]const u8 = null,
};

fn jsonObjectStringField(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    keys: []const []const u8,
) !?[]const u8 {
    for (keys) |key| {
        if (obj.get(key)) |value| {
            if (value == .string and value.string.len > 0) {
                const out = try allocator.dupe(u8, value.string);
                return out;
            }
        }
    }
    return null;
}

fn parseGoogleCredentials(
    allocator: std.mem.Allocator,
    api_key_or_token: []const u8,
) !GoogleCredentials {
    if (api_key_or_token.len == 0) return error.MissingApiKey;
    const trimmed = std.mem.trim(u8, api_key_or_token, " \t\r\n");
    if (trimmed.len == 0) return error.MissingApiKey;
    if (trimmed[0] != '{') {
        return .{
            .token = try allocator.dupe(u8, trimmed),
            .project_id = null,
        };
    }

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return .{
            .token = try allocator.dupe(u8, trimmed),
            .project_id = null,
        };
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidGoogleCredentials;

    const token = (try jsonObjectStringField(allocator, parsed.value.object, &.{ "token", "access_token", "api_key" })) orelse
        return error.InvalidGoogleCredentials;
    errdefer allocator.free(token);
    const project_id = try jsonObjectStringField(allocator, parsed.value.object, &.{ "projectId", "project_id" });

    return .{
        .token = token,
        .project_id = project_id,
    };
}

fn deinitGoogleCredentials(allocator: std.mem.Allocator, creds: *GoogleCredentials) void {
    allocator.free(creds.token);
    if (creds.project_id) |project| allocator.free(project);
}

fn resolveVertexLocation(allocator: std.mem.Allocator) ![]const u8 {
    return std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_LOCATION") catch
        std.process.getEnvVarOwned(allocator, "CLOUD_ML_REGION") catch
        allocator.dupe(u8, "us-central1");
}

fn resolveProjectId(allocator: std.mem.Allocator, creds: GoogleCredentials) !?[]const u8 {
    if (creds.project_id) |project| {
        const copied = try allocator.dupe(u8, project);
        return copied;
    }
    return std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT") catch
        std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT_ID") catch
        std.process.getEnvVarOwned(allocator, "GCLOUD_PROJECT") catch null;
}

fn containsCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn writeGenerateRequestBody(
    allocator: std.mem.Allocator,
    writer: anytype,
    context: types.Context,
    options: types.StreamOptions,
    include_system_prompt_in_contents: bool,
    include_system_instruction: bool,
) !void {
    try writer.writeAll("{\"contents\":[");
    var first = true;
    if (include_system_prompt_in_contents) if (context.system_prompt) |sys| {
        try writer.writeAll("{\"role\":\"user\",\"parts\":[{\"text\":");
        try writeJson(writer, sys);
        try writer.writeAll("}]}");
        first = false;
    };

    for (context.messages) |msg| {
        if (msg.role != .user and msg.role != .assistant) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"role\":");
        try writeJson(writer, if (msg.role == .assistant) "model" else "user");
        try writer.writeAll(",\"parts\":[{\"text\":");
        const has_text = try appendMessageText(allocator, msg, writer);
        if (!has_text) try writeJson(writer, "");
        try writer.writeAll("}]}");
    }
    try writer.writeAll("]");

    if (include_system_instruction) if (context.system_prompt) |sys| {
        try writer.writeAll(",\"systemInstruction\":{\"parts\":[{\"text\":");
        try writeJson(writer, sys);
        try writer.writeAll("}]}");
    };

    if (context.tools) |tools| {
        try writer.writeAll(",\"tools\":[{\"functionDeclarations\":[");
        for (tools, 0..) |tool, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":");
            try writeJson(writer, tool.name);
            try writer.writeAll(",\"description\":");
            try writeJson(writer, tool.description);
            try writer.writeAll(",\"parameters\":");
            try writer.writeAll(tool.parameters_json);
            try writer.writeAll("}");
        }
        try writer.writeAll("]}]");
    }

    if (options.temperature != null or options.max_tokens != null) {
        try writer.writeAll(",\"generationConfig\":{");
        var wrote = false;
        if (options.temperature) |temp| {
            try writer.writeAll("\"temperature\":");
            try writer.print("{d}", .{temp});
            wrote = true;
        }
        if (options.max_tokens) |max_tokens| {
            if (wrote) try writer.writeByte(',');
            try writer.writeAll("\"maxOutputTokens\":");
            try writer.print("{d}", .{max_tokens});
        }
        try writer.writeAll("}");
    }
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

    var endpoint = std.array_list.Managed(u8).init(allocator);
    defer endpoint.deinit();
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try appendHeader(&headers, "content-type", "application/json");
    try appendHeader(&headers, "accept", "text/event-stream");

    const base = std.mem.trimRight(u8, model.base_url, "/");
    if (std.mem.eql(u8, model.api, "google-generative-ai")) {
        const endpoint_owned = try std.fmt.allocPrint(
            allocator,
            "{s}/models/{s}:streamGenerateContent?alt=sse&key={s}",
            .{ base, model.id, api_key },
        );
        defer allocator.free(endpoint_owned);
        try endpoint.appendSlice(endpoint_owned);
        try body.writer().writeByte('{');
        try writeGenerateRequestBody(allocator, body.writer(), context, options, true, false);
        try body.writer().writeByte('}');
    } else if (std.mem.eql(u8, model.api, "google-gemini-cli")) {
        var creds = try parseGoogleCredentials(allocator, api_key);
        defer deinitGoogleCredentials(allocator, &creds);
        const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{creds.token});
        defer allocator.free(auth);
        try appendHeader(&headers, "authorization", auth);
        try appendHeader(&headers, "x-goog-api-client", "google-cloud-sdk vscode_cloudshelleditor/0.1");
        if (std.mem.eql(u8, model.provider, "google-antigravity")) {
            try appendHeader(&headers, "user-agent", "antigravity/1.15.8 darwin/arm64");
            if (containsCaseInsensitive(model.id, "claude") and containsCaseInsensitive(model.id, "thinking")) {
                try appendHeader(&headers, "anthropic-beta", "interleaved-thinking-2025-05-14");
            }
        } else {
            try appendHeader(&headers, "user-agent", "google-cloud-sdk vscode_cloudshelleditor/0.1");
        }

        const endpoint_owned = try std.fmt.allocPrint(allocator, "{s}/v1internal:streamGenerateContent?alt=sse", .{base});
        defer allocator.free(endpoint_owned);
        try endpoint.appendSlice(endpoint_owned);

        const project_id = try resolveProjectId(allocator, creds) orelse return error.MissingProjectId;
        defer allocator.free(project_id);

        const request_id = try std.fmt.allocPrint(allocator, "zig-{d}", .{@as(u64, @intCast(std.time.timestamp()))});
        defer allocator.free(request_id);

        try body.writer().writeAll("{\"project\":");
        try writeJson(body.writer(), project_id);
        try body.writer().writeAll(",\"model\":");
        try writeJson(body.writer(), model.id);
        try body.writer().writeAll(",\"request\":{");
        try writeGenerateRequestBody(allocator, body.writer(), context, options, false, true);
        if (std.mem.eql(u8, model.provider, "google-antigravity")) {
            try body.writer().writeAll(",\"systemInstruction\":{\"role\":\"user\",\"parts\":[{\"text\":");
            try writeJson(body.writer(), antigravity_instruction);
            try body.writer().writeAll("}]}");
        }
        try body.writer().writeByte('}');
        if (std.mem.eql(u8, model.provider, "google-antigravity")) {
            try body.writer().writeAll(",\"requestType\":\"agent\"");
        }
        try body.writer().writeAll(",\"userAgent\":\"ziggypiai\"");
        try body.writer().writeAll(",\"requestId\":");
        try writeJson(body.writer(), request_id);
        try body.writer().writeByte('}');
    } else if (std.mem.eql(u8, model.api, "google-vertex")) {
        var creds = try parseGoogleCredentials(allocator, api_key);
        defer deinitGoogleCredentials(allocator, &creds);
        const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{creds.token});
        defer allocator.free(auth);
        try appendHeader(&headers, "authorization", auth);

        const location = try resolveVertexLocation(allocator);
        defer allocator.free(location);
        const project_id = try resolveProjectId(allocator, creds) orelse return error.MissingProjectId;
        defer allocator.free(project_id);
        const host = if (std.mem.indexOf(u8, model.base_url, "{location}") != null)
            try std.mem.replaceOwned(u8, allocator, model.base_url, "{location}", location)
        else
            try allocator.dupe(u8, model.base_url);
        defer allocator.free(host);
        const host_trimmed = std.mem.trimRight(u8, host, "/");
        const endpoint_owned = try std.fmt.allocPrint(
            allocator,
            "{s}/v1/projects/{s}/locations/{s}/publishers/google/models/{s}:streamGenerateContent?alt=sse",
            .{ host_trimmed, project_id, location, model.id },
        );
        defer allocator.free(endpoint_owned);
        try endpoint.appendSlice(endpoint_owned);
        try body.writer().writeByte('{');
        try writeGenerateRequestBody(allocator, body.writer(), context, options, false, true);
        try body.writer().writeByte('}');
    } else {
        return error.ProviderNotSupported;
    }

    if (options.headers) |custom_headers| {
        for (custom_headers) |h| try appendHeader(&headers, h.name, h.value);
    }

    var req = try client.request(.POST, try std.Uri.parse(endpoint.items), .{
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

test "parse google credentials supports raw token" {
    const allocator = std.testing.allocator;
    var creds = try parseGoogleCredentials(allocator, "ya29.test");
    defer deinitGoogleCredentials(allocator, &creds);
    try std.testing.expectEqualStrings("ya29.test", creds.token);
    try std.testing.expect(creds.project_id == null);
}

test "parse google credentials supports json token payload" {
    const allocator = std.testing.allocator;
    var creds = try parseGoogleCredentials(allocator, "{\"token\":\"ya29.test\",\"projectId\":\"my-project\"}");
    defer deinitGoogleCredentials(allocator, &creds);
    try std.testing.expectEqualStrings("ya29.test", creds.token);
    try std.testing.expect(creds.project_id != null);
    try std.testing.expectEqualStrings("my-project", creds.project_id.?);
}

test "parse google credentials supports oauth style field names" {
    const allocator = std.testing.allocator;
    var creds = try parseGoogleCredentials(allocator, "{\"access_token\":\"ya29.oauth\",\"project_id\":\"proj-123\"}");
    defer deinitGoogleCredentials(allocator, &creds);
    try std.testing.expectEqualStrings("ya29.oauth", creds.token);
    try std.testing.expect(creds.project_id != null);
    try std.testing.expectEqualStrings("proj-123", creds.project_id.?);
}

test "containsCaseInsensitive matches mixed case substrings" {
    try std.testing.expect(containsCaseInsensitive("Claude-Opus-4-5-Thinking", "claude"));
    try std.testing.expect(containsCaseInsensitive("Claude-Opus-4-5-Thinking", "thinking"));
    try std.testing.expect(!containsCaseInsensitive("gemini-2.5-pro", "claude"));
}

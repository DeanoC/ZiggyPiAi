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
    if (std.mem.eql(u8, reason, "BLOCKLIST")) return .err;
    if (std.mem.eql(u8, reason, "PROHIBITED_CONTENT")) return .err;
    if (std.mem.eql(u8, reason, "SPII")) return .err;
    if (std.mem.eql(u8, reason, "SAFETY")) return .err;
    if (std.mem.eql(u8, reason, "IMAGE_SAFETY")) return .err;
    if (std.mem.eql(u8, reason, "IMAGE_PROHIBITED_CONTENT")) return .err;
    if (std.mem.eql(u8, reason, "IMAGE_RECITATION")) return .err;
    if (std.mem.eql(u8, reason, "IMAGE_OTHER")) return .err;
    if (std.mem.eql(u8, reason, "RECITATION")) return .err;
    if (std.mem.eql(u8, reason, "FINISH_REASON_UNSPECIFIED")) return .err;
    if (std.mem.eql(u8, reason, "OTHER")) return .err;
    if (std.mem.eql(u8, reason, "LANGUAGE")) return .err;
    if (std.mem.eql(u8, reason, "MALFORMED_FUNCTION_CALL")) return .err;
    if (std.mem.eql(u8, reason, "UNEXPECTED_TOOL_CALL")) return .err;
    if (std.mem.eql(u8, reason, "NO_IMAGE")) return .err;
    return .err;
}

fn isAuthenticatedPlaceholder(value: []const u8) bool {
    return std.mem.eql(u8, value, "<authenticated>");
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

const AdcAuthorizedUser = struct {
    client_id: []const u8,
    client_secret: []const u8,
    refresh_token: []const u8,
    quota_project_id: ?[]const u8 = null,
};

const AdcServiceAccount = struct {
    client_email: []const u8,
    private_key: []const u8,
    token_uri: []const u8,
    project_id: ?[]const u8 = null,
    quota_project_id: ?[]const u8 = null,
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

fn jsonNestedStringField(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    object_keys: []const []const u8,
    value_keys: []const []const u8,
) !?[]const u8 {
    for (object_keys) |object_key| {
        if (obj.get(object_key)) |nested| {
            if (nested != .object) continue;
            if (try jsonObjectStringField(allocator, nested.object, value_keys)) |value| {
                return value;
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

    const token = (try jsonObjectStringField(allocator, parsed.value.object, &.{ "token", "access_token", "api_key" }) orelse
        try jsonNestedStringField(allocator, parsed.value.object, &.{ "tokens", "oauth", "credentials" }, &.{ "access_token", "token" })) orelse
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

fn deinitAdcAuthorizedUser(allocator: std.mem.Allocator, adc: *AdcAuthorizedUser) void {
    allocator.free(adc.client_id);
    allocator.free(adc.client_secret);
    allocator.free(adc.refresh_token);
    if (adc.quota_project_id) |p| allocator.free(p);
}

fn deinitAdcServiceAccount(allocator: std.mem.Allocator, adc: *AdcServiceAccount) void {
    allocator.free(adc.client_email);
    allocator.free(adc.private_key);
    allocator.free(adc.token_uri);
    if (adc.project_id) |p| allocator.free(p);
    if (adc.quota_project_id) |p| allocator.free(p);
}

fn isUnreservedUriByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    for (input) |c| {
        if (isUnreservedUriByte(c)) {
            try out.append(c);
        } else {
            const encoded = try std.fmt.allocPrint(allocator, "%{X:0>2}", .{c});
            defer allocator.free(encoded);
            for (encoded) |ec| try out.append(std.ascii.toUpper(ec));
        }
    }
    return out.toOwnedSlice();
}

fn parseAuthorizedUserAdc(allocator: std.mem.Allocator, contents: []const u8) !?AdcAuthorizedUser {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const type_v = obj.get("type") orelse return null;
    if (type_v != .string or !std.mem.eql(u8, type_v.string, "authorized_user")) return null;

    const client_id = (try jsonObjectStringField(allocator, obj, &.{"client_id"})) orelse return null;
    errdefer allocator.free(client_id);
    const client_secret = (try jsonObjectStringField(allocator, obj, &.{"client_secret"})) orelse return null;
    errdefer allocator.free(client_secret);
    const refresh_token = (try jsonObjectStringField(allocator, obj, &.{"refresh_token"})) orelse return null;
    errdefer allocator.free(refresh_token);
    const quota_project_id = try jsonObjectStringField(allocator, obj, &.{"quota_project_id"});

    return .{
        .client_id = client_id,
        .client_secret = client_secret,
        .refresh_token = refresh_token,
        .quota_project_id = quota_project_id,
    };
}

fn parseServiceAccountAdc(allocator: std.mem.Allocator, contents: []const u8) !?AdcServiceAccount {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const type_v = obj.get("type") orelse return null;
    if (type_v != .string or !std.mem.eql(u8, type_v.string, "service_account")) return null;

    const client_email = (try jsonObjectStringField(allocator, obj, &.{"client_email"})) orelse return null;
    errdefer allocator.free(client_email);
    const private_key = (try jsonObjectStringField(allocator, obj, &.{"private_key"})) orelse return null;
    errdefer allocator.free(private_key);
    const token_uri = (try jsonObjectStringField(allocator, obj, &.{"token_uri"})) orelse
        try allocator.dupe(u8, "https://oauth2.googleapis.com/token");
    errdefer allocator.free(token_uri);
    const project_id = try jsonObjectStringField(allocator, obj, &.{"project_id"});
    const quota_project_id = try jsonObjectStringField(allocator, obj, &.{"quota_project_id"});

    return .{
        .client_email = client_email,
        .private_key = private_key,
        .token_uri = token_uri,
        .project_id = project_id,
        .quota_project_id = quota_project_id,
    };
}

fn base64UrlEncodeNoPad(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(input.len);
    const out = try allocator.alloc(u8, encoded_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, input);
    return out;
}

fn writeTempFile(allocator: std.mem.Allocator, prefix: []const u8, suffix: []const u8, contents: []const u8) ![]u8 {
    const rand_part = std.crypto.random.int(u64);
    const path = try std.fmt.allocPrint(allocator, "/tmp/ziggypi-{s}-{d}{s}", .{ prefix, rand_part, suffix });
    errdefer allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(contents);
    return path;
}

fn signRs256WithOpenSsl(allocator: std.mem.Allocator, private_key_pem: []const u8, signing_input: []const u8) ![]u8 {
    const key_path = try writeTempFile(allocator, "sa-key", ".pem", private_key_pem);
    defer {
        std.fs.deleteFileAbsolute(key_path) catch {};
        allocator.free(key_path);
    }
    const input_path = try writeTempFile(allocator, "sa-jwt-input", ".txt", signing_input);
    defer {
        std.fs.deleteFileAbsolute(input_path) catch {};
        allocator.free(input_path);
    }

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "openssl", "dgst", "-sha256", "-sign", key_path, "-binary", input_path },
        .max_output_bytes = 1024 * 1024,
    }) catch return error.AdcTokenExchangeFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.AdcTokenExchangeFailed,
        else => return error.AdcTokenExchangeFailed,
    }

    return allocator.dupe(u8, result.stdout);
}

fn exchangeServiceAccountToken(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    adc: AdcServiceAccount,
) !GoogleCredentials {
    const now_ts: i64 = @intCast(std.time.timestamp());
    const header_json = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    const payload_json = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"sub\":\"{s}\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"aud\":\"{s}\",\"iat\":{d},\"exp\":{d}}}",
        .{ adc.client_email, adc.client_email, adc.token_uri, now_ts, now_ts + 3600 },
    );
    defer allocator.free(payload_json);

    const encoded_header = try base64UrlEncodeNoPad(allocator, header_json);
    defer allocator.free(encoded_header);
    const encoded_payload = try base64UrlEncodeNoPad(allocator, payload_json);
    defer allocator.free(encoded_payload);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ encoded_header, encoded_payload });
    defer allocator.free(signing_input);

    const signature = try signRs256WithOpenSsl(allocator, adc.private_key, signing_input);
    defer allocator.free(signature);
    const encoded_signature = try base64UrlEncodeNoPad(allocator, signature);
    defer allocator.free(encoded_signature);
    const assertion = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, encoded_signature });
    defer allocator.free(assertion);

    const encoded_assertion = try urlEncode(allocator, assertion);
    defer allocator.free(encoded_assertion);
    const body = try std.fmt.allocPrint(
        allocator,
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={s}",
        .{encoded_assertion},
    );
    defer allocator.free(body);

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try appendHeader(&headers, "content-type", "application/x-www-form-urlencoded");

    var req = try client.request(.POST, try std.Uri.parse(adc.token_uri), .{ .extra_headers = headers.items });
    defer req.deinit();
    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.AdcTokenExchangeFailed;

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &response_buf);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_buf.items, .{}) catch return error.AdcTokenExchangeFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return error.AdcTokenExchangeFailed;
    const token_v = parsed.value.object.get("access_token") orelse return error.AdcTokenExchangeFailed;
    if (token_v != .string or token_v.string.len == 0) return error.AdcTokenExchangeFailed;

    return .{
        .token = try allocator.dupe(u8, token_v.string),
        .project_id = if (adc.quota_project_id) |p|
            try allocator.dupe(u8, p)
        else if (adc.project_id) |p|
            try allocator.dupe(u8, p)
        else
            null,
    };
}

fn refreshVertexAdcToken(allocator: std.mem.Allocator, client: *std.http.Client, adc: AdcAuthorizedUser) !GoogleCredentials {
    const encoded_client_id = try urlEncode(allocator, adc.client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, adc.client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_refresh_token = try urlEncode(allocator, adc.refresh_token);
    defer allocator.free(encoded_refresh_token);

    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&refresh_token={s}&grant_type=refresh_token",
        .{ encoded_client_id, encoded_client_secret, encoded_refresh_token },
    );
    defer allocator.free(body);

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try appendHeader(&headers, "content-type", "application/x-www-form-urlencoded");

    var req = try client.request(.POST, try std.Uri.parse("https://oauth2.googleapis.com/token"), .{ .extra_headers = headers.items });
    defer req.deinit();
    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.AdcTokenExchangeFailed;

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    try readAllResponseBody(response_reader, &response_buf);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_buf.items, .{}) catch return error.AdcTokenExchangeFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return error.AdcTokenExchangeFailed;
    const token_v = parsed.value.object.get("access_token") orelse return error.AdcTokenExchangeFailed;
    if (token_v != .string or token_v.string.len == 0) return error.AdcTokenExchangeFailed;

    return .{
        .token = try allocator.dupe(u8, token_v.string),
        .project_id = if (adc.quota_project_id) |p| try allocator.dupe(u8, p) else null,
    };
}

fn loadVertexMetadataServerToken(allocator: std.mem.Allocator, client: *std.http.Client) !?GoogleCredentials {
    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try appendHeader(&headers, "metadata-flavor", "Google");

    var req = client.request(
        .GET,
        std.Uri.parse("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token") catch return null,
        .{ .extra_headers = headers.items },
    ) catch return null;
    defer req.deinit();
    req.sendBodiless() catch return null;

    var redirect_buf: [4096]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch return null;
    if (response.head.status != .ok) return null;

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();
    var transfer_buffer: [8192]u8 = undefined;
    const response_reader = response.reader(&transfer_buffer);
    readAllResponseBody(response_reader, &response_buf) catch return null;

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_buf.items, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const token_v = parsed.value.object.get("access_token") orelse return null;
    if (token_v != .string or token_v.string.len == 0) return null;
    return .{
        .token = try allocator.dupe(u8, token_v.string),
        .project_id = null,
    };
}

fn resolveVertexAdcPath(allocator: std.mem.Allocator) !?[]const u8 {
    if (std.process.getEnvVarOwned(allocator, "GOOGLE_APPLICATION_CREDENTIALS")) |path| {
        return path;
    } else |_| {}
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    const out = try std.fmt.allocPrint(allocator, "{s}/.config/gcloud/application_default_credentials.json", .{home});
    return out;
}

fn resolveVertexAdcCredentials(allocator: std.mem.Allocator, client: *std.http.Client) !?GoogleCredentials {
    const adc_path = try resolveVertexAdcPath(allocator);
    defer if (adc_path) |p| allocator.free(p);

    if (adc_path) |path| {
        const file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch null;
        if (file) |f| {
            defer f.close();
            const contents = try f.readToEndAlloc(allocator, 1024 * 1024);
            defer allocator.free(contents);
            if (try parseAuthorizedUserAdc(allocator, contents)) |adc| {
                defer {
                    var a = adc;
                    deinitAdcAuthorizedUser(allocator, &a);
                }
                return try refreshVertexAdcToken(allocator, client, adc);
            }
            if (try parseServiceAccountAdc(allocator, contents)) |adc| {
                defer {
                    var a = adc;
                    deinitAdcServiceAccount(allocator, &a);
                }
                return try exchangeServiceAccountToken(allocator, client, adc);
            }
        }
    }

    return try loadVertexMetadataServerToken(allocator, client);
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
    antigravity_mode: bool,
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

    if (include_system_instruction) {
        if (antigravity_mode) {
            try writer.writeAll(",\"systemInstruction\":{\"role\":\"user\",\"parts\":[{\"text\":");
            try writeJson(writer, antigravity_instruction);
            try writer.writeAll("},{\"text\":");
            const ignored = try std.fmt.allocPrint(allocator, "Please ignore following [ignore]{s}[/ignore]", .{antigravity_instruction});
            defer allocator.free(ignored);
            try writeJson(writer, ignored);
            if (context.system_prompt) |sys| {
                try writer.writeAll("},{\"text\":");
                try writeJson(writer, sys);
            }
            try writer.writeAll("}]}");
        } else if (context.system_prompt) |sys| {
            try writer.writeAll(",\"systemInstruction\":{\"parts\":[{\"text\":");
            try writeJson(writer, sys);
            try writer.writeAll("}]}");
        }
    }

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
        try writeGenerateRequestBody(allocator, body.writer(), context, options, true, false, false);
        try body.writer().writeByte('}');
    } else if (std.mem.eql(u8, model.api, "google-gemini-cli")) {
        var creds = try parseGoogleCredentials(allocator, api_key);
        defer deinitGoogleCredentials(allocator, &creds);
        const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{creds.token});
        defer allocator.free(auth);
        try appendHeader(&headers, "authorization", auth);
        try appendHeader(&headers, "x-goog-api-client", "google-cloud-sdk vscode_cloudshelleditor/0.1");
        try appendHeader(&headers, "client-metadata", "{\"ideType\":\"IDE_UNSPECIFIED\",\"platform\":\"PLATFORM_UNSPECIFIED\",\"pluginType\":\"GEMINI\"}");
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
        try writeGenerateRequestBody(allocator, body.writer(), context, options, false, true, std.mem.eql(u8, model.provider, "google-antigravity"));
        if (options.session_id) |session_id| {
            try body.writer().writeAll(",\"sessionId\":");
            try writeJson(body.writer(), session_id);
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
        var creds = if (isAuthenticatedPlaceholder(api_key))
            (try resolveVertexAdcCredentials(allocator, client) orelse {
                try events.append(.{ .err = try allocator.dupe(u8, "GOOGLE_VERTEX_API_KEY/OAuth token missing and ADC token exchange failed. Ensure GOOGLE_APPLICATION_CREDENTIALS or gcloud ADC authorized_user credentials are configured.") });
                return;
            })
        else
            try parseGoogleCredentials(allocator, api_key);
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
        try writeGenerateRequestBody(allocator, body.writer(), context, options, false, true, false);
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
    try std.testing.expect(mapGoogleStopReason("SAFETY") == .err);
    try std.testing.expect(mapGoogleStopReason("FINISH_REASON_UNSPECIFIED") == .err);
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

test "parse google credentials supports nested oauth token payload" {
    const allocator = std.testing.allocator;
    var creds = try parseGoogleCredentials(allocator, "{\"tokens\":{\"access_token\":\"ya29.nested\"},\"projectId\":\"nested-proj\"}");
    defer deinitGoogleCredentials(allocator, &creds);
    try std.testing.expectEqualStrings("ya29.nested", creds.token);
    try std.testing.expect(creds.project_id != null);
    try std.testing.expectEqualStrings("nested-proj", creds.project_id.?);
}

test "parse authorized_user ADC credentials" {
    const allocator = std.testing.allocator;
    const adc_json =
        \\{"type":"authorized_user","client_id":"cid","client_secret":"csecret","refresh_token":"rtok","quota_project_id":"qproj"}
    ;
    var adc = (try parseAuthorizedUserAdc(allocator, adc_json)) orelse return error.TestExpectedEqual;
    defer deinitAdcAuthorizedUser(allocator, &adc);
    try std.testing.expectEqualStrings("cid", adc.client_id);
    try std.testing.expectEqualStrings("csecret", adc.client_secret);
    try std.testing.expectEqualStrings("rtok", adc.refresh_token);
    try std.testing.expect(adc.quota_project_id != null);
    try std.testing.expectEqualStrings("qproj", adc.quota_project_id.?);
}

test "parse authorized_user ADC rejects non-authorized_user types" {
    const allocator = std.testing.allocator;
    const adc_json = "{\"type\":\"service_account\",\"client_id\":\"cid\"}";
    try std.testing.expect((try parseAuthorizedUserAdc(allocator, adc_json)) == null);
}

test "parse service_account ADC credentials" {
    const allocator = std.testing.allocator;
    const adc_json =
        \\{"type":"service_account","client_email":"svc@example.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token","project_id":"proj","quota_project_id":"quota"}
    ;
    var adc = (try parseServiceAccountAdc(allocator, adc_json)) orelse return error.TestExpectedEqual;
    defer deinitAdcServiceAccount(allocator, &adc);
    try std.testing.expectEqualStrings("svc@example.iam.gserviceaccount.com", adc.client_email);
    try std.testing.expect(std.mem.startsWith(u8, adc.private_key, "-----BEGIN PRIVATE KEY-----"));
    try std.testing.expectEqualStrings("https://oauth2.googleapis.com/token", adc.token_uri);
    try std.testing.expect(adc.project_id != null);
    try std.testing.expectEqualStrings("proj", adc.project_id.?);
    try std.testing.expect(adc.quota_project_id != null);
    try std.testing.expectEqualStrings("quota", adc.quota_project_id.?);
}

test "parse service_account ADC rejects non-service-account types" {
    const allocator = std.testing.allocator;
    const adc_json = "{\"type\":\"authorized_user\",\"client_email\":\"svc@example.com\"}";
    try std.testing.expect((try parseServiceAccountAdc(allocator, adc_json)) == null);
}

test "containsCaseInsensitive matches mixed case substrings" {
    try std.testing.expect(containsCaseInsensitive("Claude-Opus-4-5-Thinking", "claude"));
    try std.testing.expect(containsCaseInsensitive("Claude-Opus-4-5-Thinking", "thinking"));
    try std.testing.expect(!containsCaseInsensitive("gemini-2.5-pro", "claude"));
}

test "antigravity instruction wrapper is formatted" {
    const allocator = std.testing.allocator;
    const wrapped = try std.fmt.allocPrint(allocator, "Please ignore following [ignore]{s}[/ignore]", .{antigravity_instruction});
    defer allocator.free(wrapped);
    try std.testing.expect(std.mem.indexOf(u8, wrapped, "[ignore]") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapped, "[/ignore]") != null);
}

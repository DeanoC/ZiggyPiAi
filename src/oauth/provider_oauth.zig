const std = @import("std");
const codex = @import("openai_codex_oauth.zig");

const anthropic_client_id_b64 = "OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl";

pub const OAuthCredentials = struct {
    access: []const u8,
    refresh: []const u8,
    expires_at_ms: u64,
    project_id: ?[]const u8 = null,
    enterprise_url: ?[]const u8 = null,
};

pub fn freeOAuthCredentials(allocator: std.mem.Allocator, creds: *OAuthCredentials) void {
    allocator.free(creds.access);
    allocator.free(creds.refresh);
    if (creds.project_id) |v| allocator.free(v);
    if (creds.enterprise_url) |v| allocator.free(v);
    creds.* = undefined;
}

fn readAllResponseBody(reader: *std.Io.Reader, out: *std.array_list.Managed(u8)) !void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&tmp);
        if (n == 0) return;
        try out.appendSlice(tmp[0..n]);
    }
}

fn parseExpiresMs(value: std.json.Value) ?u64 {
    const raw: u64 = switch (value) {
        .integer => |v| if (v > 0) @intCast(v) else return null,
        .float => |v| if (v > 0) @intFromFloat(v) else return null,
        else => return null,
    };
    // Handle second-based values defensively.
    if (raw < 10_000_000_000) return raw * 1000;
    return raw;
}

fn duplicateJsonString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string or v.string.len == 0) return null;
    return allocator.dupe(u8, v.string) catch null;
}

pub fn piAuthPathFromHome(allocator: std.mem.Allocator, home: []const u8) ?[]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/.pi/agent/auth.json", .{home}) catch null;
}

fn readOAuthCredentialsFromFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
) ?OAuthCredentials {
    const file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch return null;
    defer file.close();

    const contents = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(contents);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const provider_v = parsed.value.object.get(provider) orelse return null;
    if (provider_v != .object) return null;
    const entry = provider_v.object;

    if (entry.get("type")) |tv| {
        if (tv != .string or !std.mem.eql(u8, tv.string, "oauth")) return null;
    }

    const access = duplicateJsonString(allocator, entry, "access") orelse return null;
    errdefer allocator.free(access);
    const refresh = duplicateJsonString(allocator, entry, "refresh") orelse return null;
    errdefer allocator.free(refresh);

    const expires_v = entry.get("expires") orelse return null;
    const expires = parseExpiresMs(expires_v) orelse return null;

    return .{
        .access = access,
        .refresh = refresh,
        .expires_at_ms = expires,
        .project_id = duplicateJsonString(allocator, entry, "projectId"),
        .enterprise_url = duplicateJsonString(allocator, entry, "enterpriseUrl"),
    };
}

fn decodeBase64String(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, encoded);
    return out;
}

fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    for (input) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(ch);
        } else {
            try out.writer().print("%{X:0>2}", .{ch});
        }
    }
    return out.toOwnedSlice();
}

fn postAndParseJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    content_type: []const u8,
    auth_header: ?[]const u8,
) !std.json.Parsed(std.json.Value) {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try headers.append(.{ .name = "Content-Type", .value = content_type });
    if (auth_header) |auth| try headers.append(.{ .name = "Authorization", .value = auth });

    var req = try client.request(.POST, try std.Uri.parse(url), .{ .extra_headers = headers.items });
    defer req.deinit();

    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenRefreshFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);

    return std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
}

fn getAndParseJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
) !std.json.Parsed(std.json.Value) {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.GET, try std.Uri.parse(url), .{ .extra_headers = extra_headers });
    defer req.deinit();
    try req.sendBodyComplete("");

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenRefreshFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);

    return std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
}

fn refreshOpenAICodex(allocator: std.mem.Allocator, current: OAuthCredentials) !OAuthCredentials {
    var refreshed = try codex.refreshOpenAICodexToken(allocator, current.refresh);
    defer codex.freeCredentials(allocator, &refreshed);
    return .{
        .access = try allocator.dupe(u8, refreshed.access),
        .refresh = try allocator.dupe(u8, refreshed.refresh),
        .expires_at_ms = refreshed.expires_at_ms,
        .project_id = if (current.project_id) |v| try allocator.dupe(u8, v) else null,
        .enterprise_url = if (current.enterprise_url) |v| try allocator.dupe(u8, v) else null,
    };
}

fn refreshAnthropic(allocator: std.mem.Allocator, current: OAuthCredentials) !OAuthCredentials {
    const client_id = try decodeBase64String(allocator, anthropic_client_id_b64);
    defer allocator.free(client_id);
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"grant_type\":\"refresh_token\",\"client_id\":\"{s}\",\"refresh_token\":\"{s}\"}}",
        .{ client_id, current.refresh },
    );
    defer allocator.free(body);

    var parsed = try postAndParseJson(
        allocator,
        "https://console.anthropic.com/v1/oauth/token",
        body,
        "application/json",
        null,
    );
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenRefreshFailed;
    const obj = parsed.value.object;
    const access_v = obj.get("access_token") orelse return error.TokenRefreshFailed;
    const refresh_v = obj.get("refresh_token") orelse return error.TokenRefreshFailed;
    const expires_v = obj.get("expires_in") orelse return error.TokenRefreshFailed;
    if (access_v != .string or refresh_v != .string) return error.TokenRefreshFailed;
    const expires_sec = parseExpiresMs(expires_v) orelse return error.TokenRefreshFailed;
    const now_ms: u64 = @intCast(std.time.milliTimestamp());

    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh_v.string),
        .expires_at_ms = now_ms + expires_sec - 5 * 60 * 1000,
        .project_id = if (current.project_id) |v| try allocator.dupe(u8, v) else null,
        .enterprise_url = if (current.enterprise_url) |v| try allocator.dupe(u8, v) else null,
    };
}

fn refreshGoogleToken(
    allocator: std.mem.Allocator,
    current: OAuthCredentials,
    client_id_env: []const u8,
    client_secret_env: []const u8,
) !OAuthCredentials {
    const client_id = std.process.getEnvVarOwned(allocator, client_id_env) catch return error.MissingOAuthClientConfig;
    defer allocator.free(client_id);
    const client_secret = std.process.getEnvVarOwned(allocator, client_secret_env) catch return error.MissingOAuthClientConfig;
    defer allocator.free(client_secret);
    const encoded_refresh = try urlEncode(allocator, current.refresh);
    defer allocator.free(encoded_refresh);

    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&refresh_token={s}&grant_type=refresh_token",
        .{ client_id, client_secret, encoded_refresh },
    );
    defer allocator.free(body);

    var parsed = try postAndParseJson(
        allocator,
        "https://oauth2.googleapis.com/token",
        body,
        "application/x-www-form-urlencoded",
        null,
    );
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenRefreshFailed;

    const obj = parsed.value.object;
    const access_v = obj.get("access_token") orelse return error.TokenRefreshFailed;
    const expires_v = obj.get("expires_in") orelse return error.TokenRefreshFailed;
    if (access_v != .string) return error.TokenRefreshFailed;
    const expires_sec = parseExpiresMs(expires_v) orelse return error.TokenRefreshFailed;
    const now_ms: u64 = @intCast(std.time.milliTimestamp());
    const refresh = if (obj.get("refresh_token")) |rv|
        if (rv == .string and rv.string.len > 0) rv.string else current.refresh
    else
        current.refresh;

    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh),
        .expires_at_ms = now_ms + expires_sec - 5 * 60 * 1000,
        .project_id = if (current.project_id) |v| try allocator.dupe(u8, v) else null,
        .enterprise_url = if (current.enterprise_url) |v| try allocator.dupe(u8, v) else null,
    };
}

fn refreshGithubCopilot(allocator: std.mem.Allocator, current: OAuthCredentials) !OAuthCredentials {
    const domain = current.enterprise_url orelse "github.com";
    const url = try std.fmt.allocPrint(allocator, "https://api.{s}/copilot_internal/v2/token", .{domain});
    defer allocator.free(url);
    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{current.refresh});
    defer allocator.free(auth);

    const headers = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/json" },
        .{ .name = "Authorization", .value = auth },
        .{ .name = "User-Agent", .value = "GitHubCopilotChat/0.35.0" },
        .{ .name = "Editor-Version", .value = "vscode/1.107.0" },
        .{ .name = "Editor-Plugin-Version", .value = "copilot-chat/0.35.0" },
        .{ .name = "Copilot-Integration-Id", .value = "vscode-chat" },
    };
    var parsed = try getAndParseJson(allocator, url, &headers);
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenRefreshFailed;
    const obj = parsed.value.object;
    const token_v = obj.get("token") orelse return error.TokenRefreshFailed;
    const expires_v = obj.get("expires_at") orelse return error.TokenRefreshFailed;
    if (token_v != .string) return error.TokenRefreshFailed;
    const expires_epoch = parseExpiresMs(expires_v) orelse return error.TokenRefreshFailed;

    return .{
        .access = try allocator.dupe(u8, token_v.string),
        .refresh = try allocator.dupe(u8, current.refresh),
        .expires_at_ms = expires_epoch - 5 * 60 * 1000,
        .project_id = if (current.project_id) |v| try allocator.dupe(u8, v) else null,
        .enterprise_url = if (current.enterprise_url) |v| try allocator.dupe(u8, v) else null,
    };
}

fn refreshOAuthToken(allocator: std.mem.Allocator, provider: []const u8, current: OAuthCredentials) !OAuthCredentials {
    if (std.mem.eql(u8, provider, "openai-codex")) return refreshOpenAICodex(allocator, current);
    if (std.mem.eql(u8, provider, "anthropic")) return refreshAnthropic(allocator, current);
    if (std.mem.eql(u8, provider, "google-gemini-cli")) {
        return refreshGoogleToken(
            allocator,
            current,
            "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID",
            "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET",
        );
    }
    if (std.mem.eql(u8, provider, "google-antigravity")) {
        return refreshGoogleToken(
            allocator,
            current,
            "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_ID",
            "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_SECRET",
        );
    }
    if (std.mem.eql(u8, provider, "github-copilot")) return refreshGithubCopilot(allocator, current);
    return error.UnsupportedOAuthProvider;
}

fn writeOAuthCredentialsToFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
    creds: OAuthCredentials,
) !void {
    var root_value = std.json.Value{ .object = std.json.ObjectMap.init(allocator) };
    var parsed_existing: ?std.json.Parsed(std.json.Value) = null;

    const existing_file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch null;
    if (existing_file) |f| {
        defer f.close();
        const contents = try f.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(contents);
        if (std.json.parseFromSlice(std.json.Value, allocator, contents, .{})) |parsed| {
            if (parsed.value == .object) {
                parsed_existing = parsed;
                root_value = parsed_existing.?.value;
            } else {
                parsed.deinit();
            }
        } else |_| {}
    }
    defer if (parsed_existing) |*p| p.deinit();

    var entry = std.json.ObjectMap.init(allocator);
    try entry.put("type", .{ .string = "oauth" });
    try entry.put("access", .{ .string = creds.access });
    try entry.put("refresh", .{ .string = creds.refresh });
    try entry.put("expires", .{ .integer = @intCast(creds.expires_at_ms) });
    if (creds.project_id) |v| try entry.put("projectId", .{ .string = v });
    if (creds.enterprise_url) |v| try entry.put("enterpriseUrl", .{ .string = v });

    try root_value.object.put(provider, .{ .object = entry });

    const parent = std.fs.path.dirname(auth_path);
    if (parent) |p| std.fs.makeDirAbsolute(p) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const file = try std.fs.createFileAbsolute(auth_path, .{ .truncate = true });
    defer file.close();
    const json_payload = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(root_value, .{})});
    defer allocator.free(json_payload);
    try file.writeAll(json_payload);
    try file.writeAll("\n");
}

fn providerApiKey(allocator: std.mem.Allocator, provider: []const u8, creds: OAuthCredentials) ?[]const u8 {
    if (std.mem.eql(u8, provider, "google-gemini-cli") or std.mem.eql(u8, provider, "google-antigravity")) {
        const project_id = creds.project_id orelse return null;
        return std.fmt.allocPrint(
            allocator,
            "{{\"token\":\"{s}\",\"projectId\":\"{s}\"}}",
            .{ creds.access, project_id },
        ) catch null;
    }
    return allocator.dupe(u8, creds.access) catch null;
}

pub fn getPiOAuthApiKey(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    const auth_path = piAuthPathFromHome(allocator, home) orelse return null;
    defer allocator.free(auth_path);
    return getPiOAuthApiKeyFromPath(allocator, provider, auth_path);
}

pub fn getPiOAuthApiKeyFromPath(
    allocator: std.mem.Allocator,
    provider: []const u8,
    auth_path: []const u8,
) ?[]const u8 {
    var creds = readOAuthCredentialsFromFile(allocator, auth_path, provider) orelse return null;
    defer freeOAuthCredentials(allocator, &creds);

    const now_ms: u64 = @intCast(std.time.milliTimestamp());
    if (now_ms >= creds.expires_at_ms) {
        var refreshed = refreshOAuthToken(allocator, provider, creds) catch return null;
        defer freeOAuthCredentials(allocator, &refreshed);
        writeOAuthCredentialsToFile(allocator, auth_path, provider, refreshed) catch {};
        return providerApiKey(allocator, provider, refreshed);
    }
    return providerApiKey(allocator, provider, creds);
}

test "pi oauth resolves google-gemini-cli key payload" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath(".pi/agent");
    const file = try tmp.dir.createFile(".pi/agent/auth.json", .{});
    defer file.close();
    try file.writeAll(
        \\{"google-gemini-cli":{"type":"oauth","access":"ya29.test","refresh":"refresh","expires":4102444800000,"projectId":"my-proj"}}
    );

    const cwd_realpath = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_realpath);
    const full_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/.pi/agent/auth.json",
        .{ cwd_realpath, tmp.sub_path },
    );
    defer allocator.free(full_path);

    const api_key = getPiOAuthApiKeyFromPath(allocator, "google-gemini-cli", full_path) orelse return error.TestExpectedEqual;
    defer allocator.free(api_key);
    try std.testing.expectEqualStrings("{\"token\":\"ya29.test\",\"projectId\":\"my-proj\"}", api_key);
}

test "pi oauth resolves openai-codex token from auth storage" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath(".pi/agent");
    const file = try tmp.dir.createFile(".pi/agent/auth.json", .{});
    defer file.close();
    try file.writeAll(
        \\{"openai-codex":{"type":"oauth","access":"codex-access","refresh":"refresh","expires":4102444800000}}
    );

    const cwd_realpath = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_realpath);
    const full_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/.pi/agent/auth.json",
        .{ cwd_realpath, tmp.sub_path },
    );
    defer allocator.free(full_path);

    const api_key = getPiOAuthApiKeyFromPath(allocator, "openai-codex", full_path) orelse return error.TestExpectedEqual;
    defer allocator.free(api_key);
    try std.testing.expectEqualStrings("codex-access", api_key);
}

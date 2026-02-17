const std = @import("std");
const codex_oauth = @import("openai_codex_oauth.zig");

pub const OAuthCredentials = struct {
    access: []const u8,
    refresh: []const u8,
    expires_at_ms: u64,
    project_id: ?[]const u8 = null,
    email: ?[]const u8 = null,
    enterprise_url: ?[]const u8 = null,
};

pub fn freeOAuthCredentials(allocator: std.mem.Allocator, creds: *OAuthCredentials) void {
    allocator.free(creds.access);
    allocator.free(creds.refresh);
    if (creds.project_id) |v| allocator.free(v);
    if (creds.email) |v| allocator.free(v);
    if (creds.enterprise_url) |v| allocator.free(v);
    creds.* = undefined;
}

pub const AuthorizationFlow = struct {
    verifier: []const u8,
    state: []const u8,
    url: []const u8,
};

pub fn freeAuthorizationFlow(allocator: std.mem.Allocator, flow: *AuthorizationFlow) void {
    allocator.free(flow.verifier);
    allocator.free(flow.state);
    allocator.free(flow.url);
    flow.* = undefined;
}

pub const DeviceCodeFlow = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: []const u8,
    interval_seconds: u32,
    expires_in_seconds: u32,
};

pub fn freeDeviceCodeFlow(allocator: std.mem.Allocator, flow: *DeviceCodeFlow) void {
    allocator.free(flow.device_code);
    allocator.free(flow.user_code);
    allocator.free(flow.verification_uri);
    flow.* = undefined;
}

fn getRequiredEnv(allocator: std.mem.Allocator, key: []const u8) ![]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch error.MissingOAuthClientConfig;
}

fn randomHex(allocator: std.mem.Allocator, byte_len: usize) ![]const u8 {
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);
    std.crypto.random.bytes(bytes);
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    for (bytes) |b| try out.writer().print("{x:0>2}", .{b});
    return out.toOwnedSlice();
}

fn generatePkceVerifier(allocator: std.mem.Allocator) ![]const u8 {
    var random_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(random_bytes.len);
    const verifier = try allocator.alloc(u8, encoded_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(verifier, &random_bytes);
    return verifier;
}

fn generatePkceChallenge(allocator: std.mem.Allocator, verifier: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(hash.len);
    const challenge = try allocator.alloc(u8, encoded_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(challenge, &hash);
    return challenge;
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

fn readAllResponseBody(reader: *std.Io.Reader, out: *std.array_list.Managed(u8)) !void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&tmp);
        if (n == 0) return;
        try out.appendSlice(tmp[0..n]);
    }
}

fn parseExpiresInMs(expires_v: std.json.Value) !u64 {
    const expires_sec: u64 = switch (expires_v) {
        .integer => |v| if (v > 0) @intCast(v) else return error.TokenExchangeFailed,
        .float => |v| if (v > 0) @intFromFloat(v) else return error.TokenExchangeFailed,
        else => return error.TokenExchangeFailed,
    };
    return @as(u64, @intCast(std.time.milliTimestamp())) + expires_sec * 1000 - 5 * 60 * 1000;
}

fn exchangeGoogleToken(
    allocator: std.mem.Allocator,
    body: []const u8,
    project_id: ?[]const u8,
) !OAuthCredentials {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.POST, try std.Uri.parse("https://oauth2.googleapis.com/token"), .{
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }},
    });
    defer req.deinit();

    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenExchangeFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchangeFailed;

    const access_v = parsed.value.object.get("access_token") orelse return error.TokenExchangeFailed;
    const refresh_v = parsed.value.object.get("refresh_token") orelse return error.TokenExchangeFailed;
    const expires_v = parsed.value.object.get("expires_in") orelse return error.TokenExchangeFailed;
    if (access_v != .string or refresh_v != .string) return error.TokenExchangeFailed;

    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh_v.string),
        .expires_at_ms = try parseExpiresInMs(expires_v),
        .project_id = if (project_id) |p| try allocator.dupe(u8, p) else null,
    };
}

fn getCloudProjectFromEnv(allocator: std.mem.Allocator) ?[]const u8 {
    return std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT") catch
        std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT_ID") catch null;
}

pub fn createGoogleGeminiCliAuthorizationFlow(allocator: std.mem.Allocator) !AuthorizationFlow {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);

    const verifier = try generatePkceVerifier(allocator);
    errdefer allocator.free(verifier);
    const challenge = try generatePkceChallenge(allocator, verifier);
    defer allocator.free(challenge);

    const state = try randomHex(allocator, 16);
    errdefer allocator.free(state);
    const scopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
    const redirect_uri = "http://localhost:8085/oauth2callback";

    const url = try std.fmt.allocPrint(
        allocator,
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={s}&response_type=code&redirect_uri={s}&scope={s}&code_challenge={s}&code_challenge_method=S256&state={s}&access_type=offline&prompt=consent",
        .{ client_id, redirect_uri, scopes, challenge, state },
    );
    return .{ .verifier = verifier, .state = state, .url = url };
}

pub fn createGoogleAntigravityAuthorizationFlow(allocator: std.mem.Allocator) !AuthorizationFlow {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);

    const verifier = try generatePkceVerifier(allocator);
    errdefer allocator.free(verifier);
    const challenge = try generatePkceChallenge(allocator, verifier);
    defer allocator.free(challenge);

    const state = try randomHex(allocator, 16);
    errdefer allocator.free(state);
    const scopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs";
    const redirect_uri = "http://localhost:51121/oauth-callback";

    const url = try std.fmt.allocPrint(
        allocator,
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={s}&response_type=code&redirect_uri={s}&scope={s}&code_challenge={s}&code_challenge_method=S256&state={s}&access_type=offline&prompt=consent",
        .{ client_id, redirect_uri, scopes, challenge, state },
    );
    return .{ .verifier = verifier, .state = state, .url = url };
}

pub fn createAnthropicAuthorizationFlow(allocator: std.mem.Allocator) !AuthorizationFlow {
    const client_id = try getRequiredEnv(allocator, "ANTHROPIC_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);

    const verifier = try generatePkceVerifier(allocator);
    errdefer allocator.free(verifier);
    const challenge = try generatePkceChallenge(allocator, verifier);
    defer allocator.free(challenge);

    const state = try randomHex(allocator, 16);
    errdefer allocator.free(state);
    const redirect_uri = "https://console.anthropic.com/oauth/code/callback";
    const scopes = "org:create_api_key user:profile user:inference";
    const url = try std.fmt.allocPrint(
        allocator,
        "https://claude.ai/oauth/authorize?code=true&client_id={s}&response_type=code&redirect_uri={s}&scope={s}&code_challenge={s}&code_challenge_method=S256&state={s}",
        .{ client_id, redirect_uri, scopes, challenge, state },
    );
    return .{ .verifier = verifier, .state = state, .url = url };
}

pub fn captureAuthorizationCodeViaCallback(
    allocator: std.mem.Allocator,
    port: u16,
    callback_path: []const u8,
    expected_state: []const u8,
) ![]const u8 {
    const address = try std.net.Address.parseIp("127.0.0.1", port);
    var server = try address.listen(.{});
    defer server.deinit();

    const connection = try server.accept();
    defer connection.stream.close();

    var read_buf: [8192]u8 = undefined;
    const n = try connection.stream.read(&read_buf);
    if (n == 0) return error.MissingAuthorizationCode;

    const request = read_buf[0..n];
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return error.MissingAuthorizationCode;
    const request_line = request[0..line_end];
    if (!std.mem.startsWith(u8, request_line, "GET ")) return error.MissingAuthorizationCode;
    const path_start = 4;
    const path_end = std.mem.indexOfScalarPos(u8, request_line, path_start, ' ') orelse return error.MissingAuthorizationCode;
    const path = request_line[path_start..path_end];
    if (!std.mem.startsWith(u8, path, callback_path)) return error.MissingAuthorizationCode;

    const parsed = try codex_oauth.parseAuthorizationInput(allocator, path);
    defer {
        if (parsed.code) |v| allocator.free(v);
        if (parsed.state) |v| allocator.free(v);
    }
    if (parsed.state == null or !std.mem.eql(u8, parsed.state.?, expected_state) or parsed.code == null) {
        return error.StateMismatch;
    }

    const ok_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Connection: close\r\n\r\n" ++
        "<html><body><p>Authentication successful. Return to your terminal.</p></body></html>";
    _ = try connection.stream.write(ok_response);
    return try allocator.dupe(u8, parsed.code.?);
}

pub fn exchangeGoogleGeminiCliAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    verifier: []const u8,
) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);

    const encoded_code = try urlEncode(allocator, code);
    defer allocator.free(encoded_code);
    const encoded_verifier = try urlEncode(allocator, verifier);
    defer allocator.free(encoded_verifier);
    const encoded_client_id = try urlEncode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_redirect_uri = try urlEncode(allocator, "http://localhost:8085/oauth2callback");
    defer allocator.free(encoded_redirect_uri);

    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&code={s}&grant_type=authorization_code&redirect_uri={s}&code_verifier={s}",
        .{ encoded_client_id, encoded_client_secret, encoded_code, encoded_redirect_uri, encoded_verifier },
    );
    defer allocator.free(body);
    const project_id = getCloudProjectFromEnv(allocator);
    defer if (project_id) |p| allocator.free(p);
    return exchangeGoogleToken(allocator, body, project_id);
}

pub fn exchangeGoogleAntigravityAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    verifier: []const u8,
) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);

    const encoded_code = try urlEncode(allocator, code);
    defer allocator.free(encoded_code);
    const encoded_verifier = try urlEncode(allocator, verifier);
    defer allocator.free(encoded_verifier);
    const encoded_client_id = try urlEncode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_redirect_uri = try urlEncode(allocator, "http://localhost:51121/oauth-callback");
    defer allocator.free(encoded_redirect_uri);

    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&code={s}&grant_type=authorization_code&redirect_uri={s}&code_verifier={s}",
        .{ encoded_client_id, encoded_client_secret, encoded_code, encoded_redirect_uri, encoded_verifier },
    );
    defer allocator.free(body);
    const project_id = (getCloudProjectFromEnv(allocator) orelse try allocator.dupe(u8, "rising-fact-p41fc"));
    defer allocator.free(project_id);
    return exchangeGoogleToken(allocator, body, project_id);
}

pub fn refreshGoogleGeminiCliToken(allocator: std.mem.Allocator, refresh_token: []const u8, project_id: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);
    const encoded_client_id = try urlEncode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_refresh = try urlEncode(allocator, refresh_token);
    defer allocator.free(encoded_refresh);
    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&refresh_token={s}&grant_type=refresh_token",
        .{ encoded_client_id, encoded_client_secret, encoded_refresh },
    );
    defer allocator.free(body);
    return exchangeGoogleToken(allocator, body, project_id);
}

pub fn refreshGoogleAntigravityToken(allocator: std.mem.Allocator, refresh_token: []const u8, project_id: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);
    const encoded_client_id = try urlEncode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_refresh = try urlEncode(allocator, refresh_token);
    defer allocator.free(encoded_refresh);
    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&refresh_token={s}&grant_type=refresh_token",
        .{ encoded_client_id, encoded_client_secret, encoded_refresh },
    );
    defer allocator.free(body);
    return exchangeGoogleToken(allocator, body, project_id);
}

pub fn exchangeAnthropicAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    state: []const u8,
    verifier: []const u8,
) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "ANTHROPIC_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const redirect_uri = "https://console.anthropic.com/oauth/code/callback";

    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"grant_type\":\"authorization_code\",\"client_id\":\"{s}\",\"code\":\"{s}\",\"state\":\"{s}\",\"redirect_uri\":\"{s}\",\"code_verifier\":\"{s}\"}}",
        .{ client_id, code, state, redirect_uri, verifier },
    );
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse("https://console.anthropic.com/v1/oauth/token"), .{
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
    defer req.deinit();
    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenExchangeFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchangeFailed;
    const access_v = parsed.value.object.get("access_token") orelse return error.TokenExchangeFailed;
    const refresh_v = parsed.value.object.get("refresh_token") orelse return error.TokenExchangeFailed;
    const expires_v = parsed.value.object.get("expires_in") orelse return error.TokenExchangeFailed;
    if (access_v != .string or refresh_v != .string) return error.TokenExchangeFailed;

    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh_v.string),
        .expires_at_ms = try parseExpiresInMs(expires_v),
    };
}

pub fn refreshAnthropicToken(allocator: std.mem.Allocator, refresh_token: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "ANTHROPIC_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"grant_type\":\"refresh_token\",\"client_id\":\"{s}\",\"refresh_token\":\"{s}\"}}",
        .{ client_id, refresh_token },
    );
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse("https://console.anthropic.com/v1/oauth/token"), .{
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
    defer req.deinit();
    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenExchangeFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchangeFailed;
    const access_v = parsed.value.object.get("access_token") orelse return error.TokenExchangeFailed;
    const refresh_v = parsed.value.object.get("refresh_token") orelse return error.TokenExchangeFailed;
    const expires_v = parsed.value.object.get("expires_in") orelse return error.TokenExchangeFailed;
    if (access_v != .string or refresh_v != .string) return error.TokenExchangeFailed;
    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh_v.string),
        .expires_at_ms = try parseExpiresInMs(expires_v),
    };
}

fn normalizeDomain(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, "github.com");
    if (std.mem.startsWith(u8, trimmed, "http://") or std.mem.startsWith(u8, trimmed, "https://")) {
        const uri = try std.Uri.parse(trimmed);
        var host_buf: [256]u8 = undefined;
        const host = try uri.getHost(&host_buf);
        return allocator.dupe(u8, host);
    }
    return allocator.dupe(u8, trimmed);
}

pub fn startGitHubCopilotDeviceFlow(allocator: std.mem.Allocator, enterprise_domain: ?[]const u8) !DeviceCodeFlow {
    const client_id = std.process.getEnvVarOwned(allocator, "GITHUB_COPILOT_OAUTH_CLIENT_ID") catch try allocator.dupe(u8, "Iv1.b507a08c87ecfe98");
    defer allocator.free(client_id);
    const domain = try normalizeDomain(allocator, enterprise_domain orelse "github.com");
    defer allocator.free(domain);
    const url = try std.fmt.allocPrint(allocator, "https://{s}/login/device/code", .{domain});
    defer allocator.free(url);
    const body = try std.fmt.allocPrint(allocator, "{{\"client_id\":\"{s}\",\"scope\":\"read:user\"}}", .{client_id});
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse(url), .{
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/json" },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "User-Agent", .value = "GitHubCopilotChat/0.35.0" },
        },
    });
    defer req.deinit();
    const body_mut = try allocator.dupe(u8, body);
    defer allocator.free(body_mut);
    try req.sendBodyComplete(body_mut);

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenExchangeFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchangeFailed;

    const device_code_v = parsed.value.object.get("device_code") orelse return error.TokenExchangeFailed;
    const user_code_v = parsed.value.object.get("user_code") orelse return error.TokenExchangeFailed;
    const verify_v = parsed.value.object.get("verification_uri") orelse return error.TokenExchangeFailed;
    const interval_v = parsed.value.object.get("interval") orelse return error.TokenExchangeFailed;
    const expires_v = parsed.value.object.get("expires_in") orelse return error.TokenExchangeFailed;
    if (device_code_v != .string or user_code_v != .string or verify_v != .string) return error.TokenExchangeFailed;
    if (interval_v != .integer or expires_v != .integer) return error.TokenExchangeFailed;

    return .{
        .device_code = try allocator.dupe(u8, device_code_v.string),
        .user_code = try allocator.dupe(u8, user_code_v.string),
        .verification_uri = try allocator.dupe(u8, verify_v.string),
        .interval_seconds = @intCast(interval_v.integer),
        .expires_in_seconds = @intCast(expires_v.integer),
    };
}

pub fn pollGitHubCopilotDeviceAccessToken(
    allocator: std.mem.Allocator,
    device_code: []const u8,
    interval_seconds: u32,
    expires_in_seconds: u32,
    enterprise_domain: ?[]const u8,
) ![]const u8 {
    const client_id = std.process.getEnvVarOwned(allocator, "GITHUB_COPILOT_OAUTH_CLIENT_ID") catch try allocator.dupe(u8, "Iv1.b507a08c87ecfe98");
    defer allocator.free(client_id);
    const domain = try normalizeDomain(allocator, enterprise_domain orelse "github.com");
    defer allocator.free(domain);
    const url = try std.fmt.allocPrint(allocator, "https://{s}/login/oauth/access_token", .{domain});
    defer allocator.free(url);

    const deadline_ms = @as(u64, @intCast(std.time.milliTimestamp())) + @as(u64, expires_in_seconds) * 1000;
    var interval_ms: u64 = @as(u64, interval_seconds) * 1000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline_ms) {
        const body = try std.fmt.allocPrint(
            allocator,
            "{{\"client_id\":\"{s}\",\"device_code\":\"{s}\",\"grant_type\":\"urn:ietf:params:oauth:grant-type:device_code\"}}",
            .{ client_id, device_code },
        );
        defer allocator.free(body);

        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();
        var req = try client.request(.POST, try std.Uri.parse(url), .{
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "User-Agent", .value = "GitHubCopilotChat/0.35.0" },
            },
        });
        defer req.deinit();
        const body_mut = try allocator.dupe(u8, body);
        defer allocator.free(body_mut);
        try req.sendBodyComplete(body_mut);

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        if (response.head.status != .ok) return error.TokenExchangeFailed;

        var transfer_buffer: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        var raw = std.array_list.Managed(u8).init(allocator);
        defer raw.deinit();
        try readAllResponseBody(reader, &raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.TokenExchangeFailed;
        if (parsed.value.object.get("access_token")) |v| {
            if (v == .string and v.string.len > 0) return allocator.dupe(u8, v.string);
        }
        if (parsed.value.object.get("error")) |e| {
            if (e == .string and std.mem.eql(u8, e.string, "slow_down")) interval_ms += 5000;
        }
        std.time.sleep(interval_ms * std.time.ns_per_ms);
    }
    return error.TokenExchangeFailed;
}

pub fn refreshGitHubCopilotToken(allocator: std.mem.Allocator, refresh_token: []const u8, enterprise_domain: ?[]const u8) !OAuthCredentials {
    const domain = try normalizeDomain(allocator, enterprise_domain orelse "github.com");
    defer allocator.free(domain);
    const url = try std.fmt.allocPrint(allocator, "https://api.{s}/copilot_internal/v2/token", .{domain});
    defer allocator.free(url);
    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{refresh_token});
    defer allocator.free(auth);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.GET, try std.Uri.parse(url), .{
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/json" },
            .{ .name = "Authorization", .value = auth },
            .{ .name = "User-Agent", .value = "GitHubCopilotChat/0.35.0" },
            .{ .name = "Editor-Version", .value = "vscode/1.107.0" },
            .{ .name = "Editor-Plugin-Version", .value = "copilot-chat/0.35.0" },
            .{ .name = "Copilot-Integration-Id", .value = "vscode-chat" },
        },
    });
    defer req.deinit();
    try req.sendBodyComplete(&.{});

    var redirect_buf: [1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.TokenExchangeFailed;
    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var raw = std.array_list.Managed(u8).init(allocator);
    defer raw.deinit();
    try readAllResponseBody(reader, &raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw.items, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchangeFailed;
    const token_v = parsed.value.object.get("token") orelse return error.TokenExchangeFailed;
    const expires_v = parsed.value.object.get("expires_at") orelse return error.TokenExchangeFailed;
    if (token_v != .string or expires_v != .integer) return error.TokenExchangeFailed;

    return .{
        .access = try allocator.dupe(u8, token_v.string),
        .refresh = try allocator.dupe(u8, refresh_token),
        .expires_at_ms = @as(u64, @intCast(expires_v.integer)) * 1000 - 5 * 60 * 1000,
        .enterprise_url = try allocator.dupe(u8, domain),
    };
}

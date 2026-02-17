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
    token_url: []const u8,
    body: []const u8,
    project_id: ?[]const u8,
) !OAuthCredentials {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.POST, try std.Uri.parse(token_url), .{
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

fn exchangeGoogleAuthorizationCodeAt(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    code: []const u8,
    verifier: []const u8,
    redirect_uri: []const u8,
    project_id: ?[]const u8,
) !OAuthCredentials {
    const encoded_code = try urlEncode(allocator, code);
    defer allocator.free(encoded_code);
    const encoded_verifier = try urlEncode(allocator, verifier);
    defer allocator.free(encoded_verifier);
    const encoded_client_id = try urlEncode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_client_secret = try urlEncode(allocator, client_secret);
    defer allocator.free(encoded_client_secret);
    const encoded_redirect_uri = try urlEncode(allocator, redirect_uri);
    defer allocator.free(encoded_redirect_uri);

    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&code={s}&grant_type=authorization_code&redirect_uri={s}&code_verifier={s}",
        .{ encoded_client_id, encoded_client_secret, encoded_code, encoded_redirect_uri, encoded_verifier },
    );
    defer allocator.free(body);
    return exchangeGoogleToken(allocator, token_url, body, project_id);
}

fn refreshGoogleTokenAt(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    refresh_token: []const u8,
    project_id: []const u8,
) !OAuthCredentials {
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
    return exchangeGoogleToken(allocator, token_url, body, project_id);
}

fn exchangeAnthropicAuthorizationCodeAt(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    code: []const u8,
    state: []const u8,
    verifier: []const u8,
    redirect_uri: []const u8,
) !OAuthCredentials {
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"grant_type\":\"authorization_code\",\"client_id\":\"{s}\",\"code\":\"{s}\",\"state\":\"{s}\",\"redirect_uri\":\"{s}\",\"code_verifier\":\"{s}\"}}",
        .{ client_id, code, state, redirect_uri, verifier },
    );
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse(token_url), .{
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

fn refreshAnthropicTokenAt(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    refresh_token: []const u8,
) !OAuthCredentials {
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"grant_type\":\"refresh_token\",\"client_id\":\"{s}\",\"refresh_token\":\"{s}\"}}",
        .{ client_id, refresh_token },
    );
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse(token_url), .{
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

pub fn exchangeGoogleGeminiCliAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    verifier: []const u8,
) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);
    const project_id = getCloudProjectFromEnv(allocator);
    defer if (project_id) |p| allocator.free(p);
    return exchangeGoogleAuthorizationCodeAt(
        allocator,
        "https://oauth2.googleapis.com/token",
        client_id,
        client_secret,
        code,
        verifier,
        "http://localhost:8085/oauth2callback",
        project_id,
    );
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

    const project_id = (getCloudProjectFromEnv(allocator) orelse try allocator.dupe(u8, "rising-fact-p41fc"));
    defer allocator.free(project_id);
    return exchangeGoogleAuthorizationCodeAt(
        allocator,
        "https://oauth2.googleapis.com/token",
        client_id,
        client_secret,
        code,
        verifier,
        "http://localhost:51121/oauth-callback",
        project_id,
    );
}

pub fn refreshGoogleGeminiCliToken(allocator: std.mem.Allocator, refresh_token: []const u8, project_id: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_GEMINI_CLI_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);
    return refreshGoogleTokenAt(
        allocator,
        "https://oauth2.googleapis.com/token",
        client_id,
        client_secret,
        refresh_token,
        project_id,
    );
}

pub fn refreshGoogleAntigravityToken(allocator: std.mem.Allocator, refresh_token: []const u8, project_id: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    const client_secret = try getRequiredEnv(allocator, "GOOGLE_ANTIGRAVITY_OAUTH_CLIENT_SECRET");
    defer allocator.free(client_secret);
    return refreshGoogleTokenAt(
        allocator,
        "https://oauth2.googleapis.com/token",
        client_id,
        client_secret,
        refresh_token,
        project_id,
    );
}

pub fn exchangeAnthropicAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    state: []const u8,
    verifier: []const u8,
) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "ANTHROPIC_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    return exchangeAnthropicAuthorizationCodeAt(
        allocator,
        "https://console.anthropic.com/v1/oauth/token",
        client_id,
        code,
        state,
        verifier,
        "https://console.anthropic.com/oauth/code/callback",
    );
}

pub fn refreshAnthropicToken(allocator: std.mem.Allocator, refresh_token: []const u8) !OAuthCredentials {
    const client_id = try getRequiredEnv(allocator, "ANTHROPIC_OAUTH_CLIENT_ID");
    defer allocator.free(client_id);
    return refreshAnthropicTokenAt(
        allocator,
        "https://console.anthropic.com/v1/oauth/token",
        client_id,
        refresh_token,
    );
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

fn startGitHubCopilotDeviceFlowAt(
    allocator: std.mem.Allocator,
    device_code_url: []const u8,
    client_id: []const u8,
) !DeviceCodeFlow {
    const body = try std.fmt.allocPrint(allocator, "{{\"client_id\":\"{s}\",\"scope\":\"read:user\"}}", .{client_id});
    defer allocator.free(body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.POST, try std.Uri.parse(device_code_url), .{
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

pub fn startGitHubCopilotDeviceFlow(allocator: std.mem.Allocator, enterprise_domain: ?[]const u8) !DeviceCodeFlow {
    const client_id = std.process.getEnvVarOwned(allocator, "GITHUB_COPILOT_OAUTH_CLIENT_ID") catch try allocator.dupe(u8, "Iv1.b507a08c87ecfe98");
    defer allocator.free(client_id);
    const domain = try normalizeDomain(allocator, enterprise_domain orelse "github.com");
    defer allocator.free(domain);
    const url = try std.fmt.allocPrint(allocator, "https://{s}/login/device/code", .{domain});
    defer allocator.free(url);
    return startGitHubCopilotDeviceFlowAt(allocator, url, client_id);
}

fn pollGitHubCopilotDeviceAccessTokenAt(
    allocator: std.mem.Allocator,
    access_token_url: []const u8,
    client_id: []const u8,
    device_code: []const u8,
    interval_seconds: u32,
    expires_in_seconds: u32,
) ![]const u8 {
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
        var req = try client.request(.POST, try std.Uri.parse(access_token_url), .{
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
        std.Thread.sleep(interval_ms * std.time.ns_per_ms);
    }
    return error.TokenExchangeFailed;
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
    return pollGitHubCopilotDeviceAccessTokenAt(allocator, url, client_id, device_code, interval_seconds, expires_in_seconds);
}

fn refreshGitHubCopilotTokenAt(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    refresh_token: []const u8,
    domain: []const u8,
) !OAuthCredentials {
    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{refresh_token});
    defer allocator.free(auth);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.GET, try std.Uri.parse(token_url), .{
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
    try req.sendBodiless();

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

pub fn refreshGitHubCopilotToken(allocator: std.mem.Allocator, refresh_token: []const u8, enterprise_domain: ?[]const u8) !OAuthCredentials {
    const domain = try normalizeDomain(allocator, enterprise_domain orelse "github.com");
    defer allocator.free(domain);
    const url = try std.fmt.allocPrint(allocator, "https://api.{s}/copilot_internal/v2/token", .{domain});
    defer allocator.free(url);
    return refreshGitHubCopilotTokenAt(allocator, url, refresh_token, domain);
}

const MockResponse = struct {
    status: []const u8 = "200 OK",
    body: []const u8,
};

const MockServerArgs = struct {
    server: *std.net.Server,
    ready: *std.atomic.Value(bool),
    responses: []const MockResponse,
};

fn mockServerWorker(args: *MockServerArgs) void {
    defer args.server.deinit();
    args.ready.store(true, .seq_cst);

    for (args.responses) |resp| {
        const conn = args.server.accept() catch return;
        defer conn.stream.close();
        var read_buf: [4096]u8 = undefined;
        _ = conn.stream.read(&read_buf) catch {};

        var write_buf: [4096]u8 = undefined;
        var writer = std.net.Stream.writer(conn.stream, &write_buf);
        const w = &writer.interface;
        w.writeAll("HTTP/1.1 ") catch return;
        w.writeAll(resp.status) catch return;
        w.writeAll("\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n") catch return;
        w.writeAll(resp.body) catch return;
        w.flush() catch return;
    }
}

fn startMockServer(
    allocator: std.mem.Allocator,
    responses: []const MockResponse,
) !struct {
    thread: std.Thread,
    url: []u8,
    server_storage: *std.net.Server,
    ready_ptr: *std.atomic.Value(bool),
    args: *MockServerArgs,
} {
    const listen_addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server_value = try std.net.Address.listen(listen_addr, .{});
    const port = server_value.listen_address.getPort();

    const server_storage = try allocator.create(std.net.Server);
    server_storage.* = server_value;

    const ready_ptr = try allocator.create(std.atomic.Value(bool));
    ready_ptr.* = std.atomic.Value(bool).init(false);
    const args = try allocator.create(MockServerArgs);
    args.* = .{
        .server = server_storage,
        .ready = ready_ptr,
        .responses = responses,
    };

    const thread = try std.Thread.spawn(.{}, mockServerWorker, .{args});
    while (!ready_ptr.load(.seq_cst)) {
        _ = std.Thread.yield() catch {};
    }

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{port});
    return .{
        .thread = thread,
        .url = url,
        .server_storage = server_storage,
        .ready_ptr = ready_ptr,
        .args = args,
    };
}

test "oauth login helpers exchange and refresh against mocked endpoints" {
    const allocator = std.testing.allocator;

    const google_exchange_resp = [_]MockResponse{
        .{ .body = "{\"access_token\":\"g-access\",\"refresh_token\":\"g-refresh\",\"expires_in\":3600}" },
    };
    var google_srv = try startMockServer(allocator, &google_exchange_resp);
    defer {
        google_srv.thread.join();
        allocator.free(google_srv.url);
        allocator.destroy(google_srv.server_storage);
        allocator.destroy(google_srv.args);
        allocator.destroy(google_srv.ready_ptr);
    }
    const google_token_url = try std.fmt.allocPrint(allocator, "{s}/token", .{google_srv.url});
    defer allocator.free(google_token_url);
    var g = try exchangeGoogleAuthorizationCodeAt(
        allocator,
        google_token_url,
        "cid",
        "csecret",
        "code",
        "verifier",
        "http://localhost/cb",
        "proj",
    );
    defer freeOAuthCredentials(allocator, &g);
    try std.testing.expectEqualStrings("g-access", g.access);
    try std.testing.expect(g.project_id != null);

    const google_refresh_resp = [_]MockResponse{
        .{ .body = "{\"access_token\":\"g2-access\",\"refresh_token\":\"g2-refresh\",\"expires_in\":3600}" },
    };
    var google_refresh_srv = try startMockServer(allocator, &google_refresh_resp);
    defer {
        google_refresh_srv.thread.join();
        allocator.free(google_refresh_srv.url);
        allocator.destroy(google_refresh_srv.server_storage);
        allocator.destroy(google_refresh_srv.args);
        allocator.destroy(google_refresh_srv.ready_ptr);
    }
    const google_refresh_url = try std.fmt.allocPrint(allocator, "{s}/token", .{google_refresh_srv.url});
    defer allocator.free(google_refresh_url);
    var g2 = try refreshGoogleTokenAt(allocator, google_refresh_url, "cid", "sec", "rt", "proj2");
    defer freeOAuthCredentials(allocator, &g2);
    try std.testing.expectEqualStrings("g2-access", g2.access);

    const anthropic_resp = [_]MockResponse{
        .{ .body = "{\"access_token\":\"a-access\",\"refresh_token\":\"a-refresh\",\"expires_in\":1800}" },
    };
    var a_srv = try startMockServer(allocator, &anthropic_resp);
    defer {
        a_srv.thread.join();
        allocator.free(a_srv.url);
        allocator.destroy(a_srv.server_storage);
        allocator.destroy(a_srv.args);
        allocator.destroy(a_srv.ready_ptr);
    }
    const anthropic_url = try std.fmt.allocPrint(allocator, "{s}/oauth/token", .{a_srv.url});
    defer allocator.free(anthropic_url);
    var a = try exchangeAnthropicAuthorizationCodeAt(allocator, anthropic_url, "acid", "code", "state", "verifier", "http://cb");
    defer freeOAuthCredentials(allocator, &a);
    try std.testing.expectEqualStrings("a-access", a.access);
}

test "github copilot oauth helpers work with mocked endpoints" {
    const allocator = std.testing.allocator;

    const device_and_poll = [_]MockResponse{
        .{ .body = "{\"device_code\":\"dev\",\"user_code\":\"user\",\"verification_uri\":\"https://verify\",\"interval\":0,\"expires_in\":10}" },
        .{ .body = "{\"error\":\"authorization_pending\"}" },
        .{ .body = "{\"access_token\":\"gh-device-access\"}" },
    };
    var srv = try startMockServer(allocator, &device_and_poll);
    defer {
        srv.thread.join();
        allocator.free(srv.url);
        allocator.destroy(srv.server_storage);
        allocator.destroy(srv.args);
        allocator.destroy(srv.ready_ptr);
    }
    const device_url = try std.fmt.allocPrint(allocator, "{s}/device", .{srv.url});
    defer allocator.free(device_url);
    const poll_url = try std.fmt.allocPrint(allocator, "{s}/poll", .{srv.url});
    defer allocator.free(poll_url);

    var d = try startGitHubCopilotDeviceFlowAt(allocator, device_url, "cid");
    defer freeDeviceCodeFlow(allocator, &d);
    try std.testing.expectEqualStrings("dev", d.device_code);

    const access = try pollGitHubCopilotDeviceAccessTokenAt(allocator, poll_url, "cid", d.device_code, 0, 10);
    defer allocator.free(access);
    try std.testing.expectEqualStrings("gh-device-access", access);

    const refresh_resp = [_]MockResponse{
        .{ .body = "{\"token\":\"copilot-token\",\"expires_at\":4102444800}" },
    };
    var refresh_srv = try startMockServer(allocator, &refresh_resp);
    defer {
        refresh_srv.thread.join();
        allocator.free(refresh_srv.url);
        allocator.destroy(refresh_srv.server_storage);
        allocator.destroy(refresh_srv.args);
        allocator.destroy(refresh_srv.ready_ptr);
    }
    const refresh_url = try std.fmt.allocPrint(allocator, "{s}/copilot", .{refresh_srv.url});
    defer allocator.free(refresh_url);
    var r = try refreshGitHubCopilotTokenAt(allocator, refresh_url, "refresh-token", "example.com");
    defer freeOAuthCredentials(allocator, &r);
    try std.testing.expectEqualStrings("copilot-token", r.access);
    try std.testing.expect(r.enterprise_url != null);
    try std.testing.expectEqualStrings("example.com", r.enterprise_url.?);
}

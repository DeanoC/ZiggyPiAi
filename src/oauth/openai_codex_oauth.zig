const std = @import("std");

pub const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_URL = "https://auth.openai.com/oauth/token";
pub const REDIRECT_URI = "http://localhost:1455/auth/callback";
pub const SCOPE = "openid profile email offline_access";
pub const JWT_CLAIM_PATH = "https://api.openai.com/auth";

pub const OAuthCredentials = struct {
    access: []const u8,
    refresh: []const u8,
    expires_at_ms: u64,
    account_id: []const u8,
};

pub const AuthorizationFlow = struct {
    verifier: []const u8,
    state: []const u8,
    url: []const u8,
};

pub const ParsedAuthorizationInput = struct {
    code: ?[]const u8 = null,
    state: ?[]const u8 = null,
};

pub const CodexAuthTokens = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    id_token: ?[]const u8,
    account_id: ?[]const u8,
    expires_at_ms: u64,
};

pub fn freeCredentials(allocator: std.mem.Allocator, credentials: *OAuthCredentials) void {
    allocator.free(credentials.access);
    allocator.free(credentials.refresh);
    allocator.free(credentials.account_id);
    credentials.* = undefined;
}

pub fn freeCodexAuthTokens(allocator: std.mem.Allocator, tokens: *CodexAuthTokens) void {
    allocator.free(tokens.access_token);
    allocator.free(tokens.refresh_token);
    if (tokens.id_token) |id| allocator.free(id);
    if (tokens.account_id) |acct| allocator.free(acct);
    tokens.* = undefined;
}

pub fn freeAuthorizationFlow(allocator: std.mem.Allocator, flow: *AuthorizationFlow) void {
    allocator.free(flow.verifier);
    allocator.free(flow.state);
    allocator.free(flow.url);
    flow.* = undefined;
}

pub fn codexAuthPathFromHome(allocator: std.mem.Allocator, home: []const u8) ?[]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/.codex/auth.json", .{home}) catch null;
}

fn decodeJwtExpiration(token: []const u8) ?u64 {
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next();
    const payload = parts.next() orelse return null;

    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(payload) catch return null;
    const decoded = std.heap.page_allocator.alloc(u8, decoded_len) catch return null;
    defer std.heap.page_allocator.free(decoded);
    std.base64.url_safe.Decoder.decode(decoded, payload) catch return null;

    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, decoded, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const exp = parsed.value.object.get("exp") orelse return null;
    if (exp != .integer or exp.integer < 0) return null;
    const exp_u64: u64 = @intCast(exp.integer);
    return exp_u64 * 1000;
}

fn parseCodexAuthTokens(allocator: std.mem.Allocator, tokens_obj: std.json.Value) ?CodexAuthTokens {
    if (tokens_obj != .object) return null;
    const access_v = tokens_obj.object.get("access_token") orelse return null;
    const refresh_v = tokens_obj.object.get("refresh_token") orelse return null;
    if (access_v != .string or refresh_v != .string) return null;

    const access = access_v.string;
    const refresh = refresh_v.string;
    const expires = decodeJwtExpiration(access) orelse 0;

    var id_token: ?[]const u8 = null;
    if (tokens_obj.object.get("id_token")) |id_v| {
        if (id_v == .string) id_token = allocator.dupe(u8, id_v.string) catch return null;
    }

    var account_id: ?[]const u8 = null;
    if (tokens_obj.object.get("account_id")) |account_v| {
        if (account_v == .string) account_id = allocator.dupe(u8, account_v.string) catch return null;
    }
    if (account_id == null) {
        account_id = extractAccountId(allocator, access) catch null;
    }

    return .{
        .access_token = allocator.dupe(u8, access) catch return null,
        .refresh_token = allocator.dupe(u8, refresh) catch return null,
        .id_token = id_token,
        .account_id = account_id,
        .expires_at_ms = expires,
    };
}

pub fn readCodexAuthFile(allocator: std.mem.Allocator, auth_path: []const u8) ?CodexAuthTokens {
    const auth_file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch return null;
    defer auth_file.close();

    const contents = auth_file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(contents);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const tokens = parsed.value.object.get("tokens") orelse return null;
    return parseCodexAuthTokens(allocator, tokens);
}

pub fn writeCodexAuthFile(auth_path: []const u8, tokens: CodexAuthTokens) !void {
    const writer = try std.fs.createFileAbsolute(auth_path, .{ .read = true, .truncate = true });
    defer writer.close();

    try writer.writeAll("{\"OPENAI_API_KEY\":null,\"tokens\":{");
    try writer.writeAll("\"access_token\":\"");
    try writer.writeAll(tokens.access_token);
    try writer.writeAll("\",\"refresh_token\":\"");
    try writer.writeAll(tokens.refresh_token);
    if (tokens.id_token) |id| {
        try writer.writeAll("\",\"id_token\":\"");
        try writer.writeAll(id);
    }
    if (tokens.account_id) |acct| {
        try writer.writeAll("\",\"account_id\":\"");
        try writer.writeAll(acct);
    }
    try writer.writeAll("\"}}\n");
}

pub fn needsRefresh(tokens: CodexAuthTokens) bool {
    return std.time.milliTimestamp() >= tokens.expires_at_ms - (2 * 60 * 1000);
}

fn refreshCodexAuthTokens(allocator: std.mem.Allocator, auth_path: []const u8, tokens: CodexAuthTokens) ?CodexAuthTokens {
    var refreshed = refreshOpenAICodexToken(allocator, tokens.refresh_token) catch return null;
    defer freeCredentials(allocator, &refreshed);

    var id_token: ?[]const u8 = null;
    if (tokens.id_token) |id| {
        id_token = allocator.dupe(u8, id) catch return null;
    }

    const refreshed_tokens: CodexAuthTokens = .{
        .access_token = allocator.dupe(u8, refreshed.access) catch return null,
        .refresh_token = allocator.dupe(u8, refreshed.refresh) catch return null,
        .id_token = id_token,
        .account_id = allocator.dupe(u8, refreshed.account_id) catch return null,
        .expires_at_ms = refreshed.expires_at_ms,
    };
    writeCodexAuthFile(auth_path, refreshed_tokens) catch return null;
    return refreshed_tokens;
}

pub fn getCodexOauthApiKey(allocator: std.mem.Allocator) ?[]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);

    const auth_path = codexAuthPathFromHome(allocator, home) orelse return null;
    defer allocator.free(auth_path);

    var tokens = readCodexAuthFile(allocator, auth_path) orelse return null;
    defer freeCodexAuthTokens(allocator, &tokens);

    if (needsRefresh(tokens)) {
        const refreshed = refreshCodexAuthTokens(allocator, auth_path, tokens) orelse return null;
        freeCodexAuthTokens(allocator, &tokens);
        tokens = refreshed;
    }
    return allocator.dupe(u8, tokens.access_token) catch null;
}

fn randomHex(allocator: std.mem.Allocator, byte_len: usize) ![]const u8 {
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);
    std.crypto.random.bytes(bytes);

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    for (bytes) |b| {
        try out.writer().print("{x:0>2}", .{b});
    }
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

pub fn createAuthorizationFlow(allocator: std.mem.Allocator, originator: []const u8) !AuthorizationFlow {
    const verifier = try generatePkceVerifier(allocator);
    errdefer allocator.free(verifier);

    const challenge = try generatePkceChallenge(allocator, verifier);
    defer allocator.free(challenge);

    const state = try randomHex(allocator, 16);
    errdefer allocator.free(state);

    const url = try std.fmt.allocPrint(
        allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}&scope={s}&code_challenge={s}&code_challenge_method=S256&state={s}&id_token_add_organizations=true&codex_cli_simplified_flow=true&originator={s}",
        .{ AUTHORIZE_URL, CLIENT_ID, REDIRECT_URI, SCOPE, challenge, state, originator },
    );

    return .{
        .verifier = verifier,
        .state = state,
        .url = url,
    };
}

fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const ch = input[i];
        if (ch == '+') {
            try out.append(' ');
            continue;
        }
        if (ch == '%' and i + 2 < input.len) {
            const hi = std.fmt.charToDigit(input[i + 1], 16) catch {
                try out.append(ch);
                continue;
            };
            const lo = std.fmt.charToDigit(input[i + 2], 16) catch {
                try out.append(ch);
                continue;
            };
            try out.append(@as(u8, @intCast(hi * 16 + lo)));
            i += 2;
            continue;
        }
        try out.append(ch);
    }

    return out.toOwnedSlice();
}

pub fn parseAuthorizationInput(allocator: std.mem.Allocator, input: []const u8) !ParsedAuthorizationInput {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return .{};

    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;

    if (std.mem.indexOf(u8, trimmed, "code=")) |_| {
        const query_start = std.mem.indexOfScalar(u8, trimmed, '?');
        const params = if (query_start) |idx| trimmed[idx + 1 ..] else trimmed;

        var pairs = std.mem.splitScalar(u8, params, '&');
        while (pairs.next()) |pair| {
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, "code")) {
                if (code) |prev| allocator.free(prev);
                code = try urlDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "state")) {
                if (state) |prev| allocator.free(prev);
                state = try urlDecode(allocator, value);
            }
        }
        return .{ .code = code, .state = state };
    }

    if (std.mem.indexOfScalar(u8, trimmed, '#')) |sep| {
        code = try allocator.dupe(u8, trimmed[0..sep]);
        state = try allocator.dupe(u8, trimmed[sep + 1 ..]);
        return .{ .code = code, .state = state };
    }

    code = try allocator.dupe(u8, trimmed);
    return .{ .code = code, .state = null };
}

pub fn extractAccountId(allocator: std.mem.Allocator, access_token: []const u8) ![]const u8 {
    var parts = std.mem.splitScalar(u8, access_token, '.');
    _ = parts.next() orelse return error.InvalidToken;
    const payload = parts.next() orelse return error.InvalidToken;

    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(payload) catch return error.InvalidToken;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    std.base64.url_safe.Decoder.decode(decoded, payload) catch return error.InvalidToken;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, decoded, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidToken;

    const auth = parsed.value.object.get(JWT_CLAIM_PATH) orelse return error.InvalidToken;
    if (auth != .object) return error.InvalidToken;
    const account = auth.object.get("chatgpt_account_id") orelse return error.InvalidToken;
    if (account != .string or account.string.len == 0) return error.InvalidToken;

    return try allocator.dupe(u8, account.string);
}

fn readAllResponseBody(reader: *std.Io.Reader, out: *std.array_list.Managed(u8)) !void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&tmp);
        if (n == 0) return;
        try out.appendSlice(tmp[0..n]);
    }
}

fn exchangeToken(
    allocator: std.mem.Allocator,
    body: []const u8,
) !OAuthCredentials {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.POST, try std.Uri.parse(TOKEN_URL), .{
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

    var expires_in_sec: u64 = 0;
    switch (expires_v) {
        .integer => |i| {
            if (i <= 0) return error.TokenExchangeFailed;
            expires_in_sec = @intCast(i);
        },
        .float => |f| {
            if (f <= 0) return error.TokenExchangeFailed;
            expires_in_sec = @intFromFloat(f);
        },
        else => return error.TokenExchangeFailed,
    }

    const account_id = try extractAccountId(allocator, access_v.string);
    errdefer allocator.free(account_id);

    return .{
        .access = try allocator.dupe(u8, access_v.string),
        .refresh = try allocator.dupe(u8, refresh_v.string),
        .expires_at_ms = @as(u64, @intCast(std.time.milliTimestamp())) + expires_in_sec * 1000,
        .account_id = account_id,
    };
}

pub fn exchangeAuthorizationCode(
    allocator: std.mem.Allocator,
    code: []const u8,
    verifier: []const u8,
    redirect_uri: []const u8,
) !OAuthCredentials {
    const body = try std.fmt.allocPrint(
        allocator,
        "grant_type=authorization_code&client_id={s}&code={s}&code_verifier={s}&redirect_uri={s}",
        .{ CLIENT_ID, code, verifier, redirect_uri },
    );
    defer allocator.free(body);
    return exchangeToken(allocator, body);
}

pub fn refreshOpenAICodexToken(allocator: std.mem.Allocator, refresh_token: []const u8) !OAuthCredentials {
    const body = try std.fmt.allocPrint(
        allocator,
        "grant_type=refresh_token&refresh_token={s}&client_id={s}",
        .{ refresh_token, CLIENT_ID },
    );
    defer allocator.free(body);
    return exchangeToken(allocator, body);
}

pub fn captureAuthorizationCodeViaCallback(allocator: std.mem.Allocator, expected_state: []const u8) ![]const u8 {
    const address = try std.net.Address.parseIp("127.0.0.1", 1455);
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

    const ok_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Connection: close\r\n\r\n" ++
        "<html><body><p>Authentication successful. Return to your terminal.</p></body></html>";

    const bad_response =
        "HTTP/1.1 400 Bad Request\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n" ++
        "Connection: close\r\n\r\n" ++
        "State mismatch or missing code.";

    const parsed = try parseAuthorizationInput(allocator, path);
    defer {
        if (parsed.code) |c| allocator.free(c);
        if (parsed.state) |s| allocator.free(s);
    }

    if (parsed.state == null or !std.mem.eql(u8, parsed.state.?, expected_state) or parsed.code == null) {
        _ = try connection.stream.write(bad_response);
        return error.StateMismatch;
    }

    _ = try connection.stream.write(ok_response);
    return try allocator.dupe(u8, parsed.code.?);
}

test "createAuthorizationFlow populates PKCE and URL" {
    const allocator = std.testing.allocator;
    var flow = try createAuthorizationFlow(allocator, "pi");
    defer freeAuthorizationFlow(allocator, &flow);

    try std.testing.expect(flow.verifier.len > 20);
    try std.testing.expect(flow.state.len == 32);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "code_challenge=") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "originator=pi") != null);
}

test "parseAuthorizationInput handles query and raw code" {
    const allocator = std.testing.allocator;

    const parsed_query = try parseAuthorizationInput(allocator, "http://localhost:1455/auth/callback?code=abc123&state=s1");
    defer {
        if (parsed_query.code) |c| allocator.free(c);
        if (parsed_query.state) |s| allocator.free(s);
    }
    try std.testing.expect(parsed_query.code != null);
    try std.testing.expect(parsed_query.state != null);
    try std.testing.expectEqualStrings("abc123", parsed_query.code.?);
    try std.testing.expectEqualStrings("s1", parsed_query.state.?);

    const parsed_raw = try parseAuthorizationInput(allocator, "just-a-code");
    defer {
        if (parsed_raw.code) |c| allocator.free(c);
        if (parsed_raw.state) |s| allocator.free(s);
    }
    try std.testing.expect(parsed_raw.code != null);
    try std.testing.expectEqualStrings("just-a-code", parsed_raw.code.?);
}

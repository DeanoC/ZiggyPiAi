const std = @import("std");

const CodexAuthTokens = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    id_token: ?[]const u8,
    account_id: ?[]const u8,
    expires_at_ms: u64,
};

fn freeCodexTokens(allocator: std.mem.Allocator, tokens: *CodexAuthTokens) void {
    allocator.free(tokens.access_token);
    allocator.free(tokens.refresh_token);
    if (tokens.id_token) |id| allocator.free(id);
    if (tokens.account_id) |acct| allocator.free(acct);
    tokens.* = undefined;
}

fn codexAuthPathFromHome(allocator: std.mem.Allocator, home: []const u8) ?[]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/.codex/auth.json", .{home}) catch null;
}

fn decodeJwtExpiration(token: []const u8) ?u64 {
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next();
    const payload = parts.next() orelse return null;

    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(payload) catch return null;
    const buffer = std.heap.page_allocator.alloc(u8, decoded_len) catch return null;
    defer std.heap.page_allocator.free(buffer);
    std.base64.url_safe.Decoder.decode(buffer, payload) catch return null;

    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, buffer, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const exp = parsed.value.object.get("exp") orelse return null;
    if (exp != .integer) return null;
    const exp_int = exp.integer;
    if (exp_int < 0) return null;
    const exp_u64: u64 = @intCast(exp_int);
    return exp_u64 * 1000;
}

fn extractAccountId(allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next();
    const payload = parts.next() orelse return null;

    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(payload) catch return null;
    const buffer = std.heap.page_allocator.alloc(u8, decoded_len) catch return null;
    defer std.heap.page_allocator.free(buffer);
    std.base64.url_safe.Decoder.decode(buffer, payload) catch return null;

    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, buffer, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const auth = parsed.value.object.get("https://api.openai.com/auth") orelse return null;
    if (auth != .object) return null;

    const id = auth.object.get("chatgpt_account_id") orelse return null;
    if (id != .string) return null;

    return allocator.dupe(u8, id.string) catch null;
}

fn parseCodexTokens(allocator: std.mem.Allocator, tokens_obj: std.json.Value) ?CodexAuthTokens {
    if (tokens_obj != .object) return null;
    const access_v = tokens_obj.object.get("access_token") orelse return null;
    const refresh_v = tokens_obj.object.get("refresh_token") orelse return null;
    if (access_v != .string or refresh_v != .string) return null;

    const access = access_v.string;
    const refresh = refresh_v.string;
    const expires = decodeJwtExpiration(access) orelse 0;

    var id_token: ?[]const u8 = null;
    const id_v = tokens_obj.object.get("id_token");
    if (id_v) |v| {
        if (v == .string) {
            const dup = allocator.dupe(u8, v.string) catch return null;
            id_token = dup;
        }
    }

    var account_id: ?[]const u8 = null;
    const account_v = tokens_obj.object.get("account_id");
    if (account_v) |v| {
        if (v == .string) {
            const dup = allocator.dupe(u8, v.string) catch return null;
            account_id = dup;
        }
    }
    if (account_id == null) {
        account_id = extractAccountId(allocator, access);
    }

    const access_copy = allocator.dupe(u8, access) catch return null;
    const refresh_copy = allocator.dupe(u8, refresh) catch return null;
    return CodexAuthTokens{
        .access_token = access_copy,
        .refresh_token = refresh_copy,
        .id_token = id_token,
        .account_id = account_id,
        .expires_at_ms = expires,
    };
}

fn readCodexAuthFile(allocator: std.mem.Allocator, auth_path: []const u8) ?CodexAuthTokens {
    const auth_file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch return null;
    defer auth_file.close();

    const contents = auth_file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(contents);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const tokens = parsed.value.object.get("tokens") orelse return null;
    return parseCodexTokens(allocator, tokens);
}

fn needsRefresh(tokens: CodexAuthTokens) bool {
    return std.time.milliTimestamp() >= tokens.expires_at_ms - (2 * 60 * 1000);
}

fn writeCodexAuthFile(auth_path: []const u8, tokens: CodexAuthTokens) !void {
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

fn refreshCodexTokens(allocator: std.mem.Allocator, auth_path: []const u8, tokens: CodexAuthTokens) ?CodexAuthTokens {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse("https://auth.openai.com/oauth/token") catch return null;

    const body = std.fmt.allocPrint(
        allocator,
        "grant_type=refresh_token&refresh_token={s}&client_id=app_EMoamEEZ73f0CkXaXp7hrann",
        .{tokens.refresh_token},
    ) catch return null;
    defer allocator.free(body);

    var request = client.request(.POST, uri, .{
        .extra_headers = &.{ .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" } },
    }) catch return null;
    defer request.deinit();

    request.sendBodyComplete(body) catch return null;
    var redirect_buf: [1024]u8 = undefined;
    var response = request.receiveHead(&redirect_buf) catch return null;

    if (response.head.status != .ok) return null;

    var buf: [4096]u8 = undefined;
    var reader = response.reader(&buf);
    var body_arr = std.array_list.Managed(u8).init(allocator);
    defer body_arr.deinit();
    read_loop: while (true) {
        var chunk_array: [1][]u8 = undefined;
        chunk_array[0] = buf[0..];
        const n = reader.readVec(chunk_array[0..]) catch |err| switch (err) {
            error.EndOfStream => break :read_loop,
            error.ReadFailed => return null,
        };
        if (n == 0) break;
        body_arr.appendSlice(buf[0..n]) catch return null;
    }

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body_arr.items, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const access_v = parsed.value.object.get("access_token") orelse return null;
    const refresh_v = parsed.value.object.get("refresh_token") orelse return null;
    if (access_v != .string or refresh_v != .string) return null;

    const access = access_v.string;
    const refresh = refresh_v.string;
    const expires = decodeJwtExpiration(access) orelse return null;

    var id_token: ?[]const u8 = null;
    const id_v = parsed.value.object.get("id_token");
    if (id_v) |v| {
        if (v == .string) {
            id_token = allocator.dupe(u8, v.string) catch return null;
        }
    } else if (tokens.id_token) |id| {
        id_token = allocator.dupe(u8, id) catch return null;
    }

    var account_id: ?[]const u8 = null;
    if (tokens.account_id) |acct| {
        account_id = allocator.dupe(u8, acct) catch return null;
    } else {
        account_id = extractAccountId(allocator, access);
    }

    const access_dup = allocator.dupe(u8, access) catch return null;
    const refresh_dup = allocator.dupe(u8, refresh) catch return null;
    const refreshed = CodexAuthTokens{
        .access_token = access_dup,
        .refresh_token = refresh_dup,
        .id_token = id_token,
        .account_id = account_id,
        .expires_at_ms = expires,
    };

    writeCodexAuthFile(auth_path, refreshed) catch return null;
    return refreshed;
}

fn getCodexOauthApiKey(allocator: std.mem.Allocator) ?[]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);

    const auth_path = codexAuthPathFromHome(allocator, home) orelse return null;
    defer allocator.free(auth_path);

    var tokens = readCodexAuthFile(allocator, auth_path) orelse return null;
    defer freeCodexTokens(allocator, &tokens);
    if (needsRefresh(tokens)) {
        const refreshed = refreshCodexTokens(allocator, auth_path, tokens) orelse return null;
        freeCodexTokens(allocator, &tokens);
        tokens = refreshed;
    }

    return allocator.dupe(u8, tokens.access_token) catch null;
}

pub fn getEnvApiKey(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, provider, "openai"))
        return std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    if (std.mem.eql(u8, provider, "openai-codex")) {
        return std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_API_KEY") catch
            getCodexOauthApiKey(allocator) orelse
            std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "anthropic"))
        return std.process.getEnvVarOwned(allocator, "ANTHROPIC_API_KEY") catch null;
    if (std.mem.eql(u8, provider, "kimi-coding") or std.mem.eql(u8, provider, "kimi-code")) {
        return std.process.getEnvVarOwned(allocator, "KIMICODE_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "KIMI_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "ANTHROPIC_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "azure-openai-responses")) {
        return std.process.getEnvVarOwned(allocator, "AZURE_OPENAI_API_KEY") catch null;
    }
    return null;
}

test "getEnvApiKey returns azure openai api key" {
    const allocator = std.testing.allocator;
    const v = getEnvApiKey(allocator, "azure-openai-responses");
    if (v) |key| allocator.free(key);
}

test "readCodexAuthFile resolves tokens" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".codex");
    const file = try tmp.dir.createFile(".codex/auth.json", .{});
    defer file.close();
    try file.writeAll(
        \\{"OPENAI_API_KEY":null,"tokens":{"access_token":"codex-access","refresh_token":"refresh","id_token":"id","account_id":"acct"}}
    );

    const cwd_realpath = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_realpath);

    const full_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/.codex/auth.json",
        .{ cwd_realpath, tmp.sub_path },
    );
    defer allocator.free(full_path);

    const tokens = readCodexAuthFile(allocator, full_path);
    try std.testing.expect(tokens != null);
    defer if (tokens) |t| {
        allocator.free(t.access_token);
        allocator.free(t.refresh_token);
        if (t.id_token) |id| allocator.free(id);
        if (t.account_id) |acct| allocator.free(acct);
    };
    try std.testing.expectEqualStrings("codex-access", tokens.?.access_token);
}

// Additional tests could go here to verify Codex file parsing, but they are skipped to avoid touching real files.

const std = @import("std");
const openai_codex = @import("openai_codex_oauth.zig");
const provider_login = @import("provider_login_oauth.zig");

pub const TokenSet = struct {
    access: []const u8,
    refresh: []const u8,
    expires_at_ms: u64,
    project_id: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
    email: ?[]const u8 = null,
    enterprise_url: ?[]const u8 = null,
};

pub fn freeTokenSet(allocator: std.mem.Allocator, tokens: *TokenSet) void {
    allocator.free(tokens.access);
    allocator.free(tokens.refresh);
    if (tokens.project_id) |v| allocator.free(v);
    if (tokens.account_id) |v| allocator.free(v);
    if (tokens.email) |v| allocator.free(v);
    if (tokens.enterprise_url) |v| allocator.free(v);
    tokens.* = undefined;
}

pub fn freeOAuthProvidersList(allocator: std.mem.Allocator, providers: []OAuthProvider) void {
    for (providers) |provider| {
        allocator.free(provider.name);
    }
    allocator.free(providers);
}

pub const BrowserAuthStart = struct {
    verifier: []const u8,
    state: []const u8,
    url: []const u8,
};

pub fn freeBrowserAuthStart(allocator: std.mem.Allocator, start: *BrowserAuthStart) void {
    allocator.free(start.verifier);
    allocator.free(start.state);
    allocator.free(start.url);
    start.* = undefined;
}

pub const DeviceAuthStart = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: []const u8,
    interval_seconds: u32,
    expires_in_seconds: u32,
};

pub fn freeDeviceAuthStart(allocator: std.mem.Allocator, start: *DeviceAuthStart) void {
    allocator.free(start.device_code);
    allocator.free(start.user_code);
    allocator.free(start.verification_uri);
    start.* = undefined;
}

pub const AuthStart = union(enum) {
    browser: BrowserAuthStart,
    device: DeviceAuthStart,
};

pub fn freeAuthStart(allocator: std.mem.Allocator, start: *AuthStart) void {
    switch (start.*) {
        .browser => |*browser| freeBrowserAuthStart(allocator, browser),
        .device => |*device| freeDeviceAuthStart(allocator, device),
    }
}

pub const BeginAuthParams = struct {
    originator: ?[]const u8 = null,
    enterprise_domain: ?[]const u8 = null,
};

pub const ExchangeTokenParams = struct {
    code: ?[]const u8 = null,
    state: ?[]const u8 = null,
    verifier: ?[]const u8 = null,
    redirect_uri: ?[]const u8 = null,
    device_code: ?[]const u8 = null,
    interval_seconds: ?u32 = null,
    expires_in_seconds: ?u32 = null,
    enterprise_domain: ?[]const u8 = null,
};

pub const RefreshTokenParams = struct {
    refresh_token: []const u8,
    project_id: ?[]const u8 = null,
    enterprise_domain: ?[]const u8 = null,
};

pub const BeginAuthFn = *const fn (allocator: std.mem.Allocator, params: BeginAuthParams) anyerror!AuthStart;
pub const ExchangeTokenFn = *const fn (allocator: std.mem.Allocator, params: ExchangeTokenParams) anyerror!TokenSet;
pub const RefreshTokenFn = *const fn (allocator: std.mem.Allocator, params: RefreshTokenParams) anyerror!TokenSet;
pub const FormatApiKeyFn = *const fn (allocator: std.mem.Allocator, tokens: TokenSet) anyerror![]const u8;

pub const OAuthProvider = struct {
    name: []const u8,
    begin_auth: ?BeginAuthFn = null,
    exchange_token: ?ExchangeTokenFn = null,
    refresh_token: ?RefreshTokenFn = null,
    format_api_key: ?FormatApiKeyFn = null,
};

const RegistryState = struct {
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMapUnmanaged(OAuthProvider) = .{},
    builtins_registered: bool = false,

    fn clear(self: *RegistryState, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.name);
        }
        self.map.deinit(allocator);
        self.map = .{};
        self.builtins_registered = false;
    }
};

var registry_state: RegistryState = .{};

fn tokenSetFromCodex(creds: openai_codex.OAuthCredentials) TokenSet {
    return .{
        .access = creds.access,
        .refresh = creds.refresh,
        .expires_at_ms = creds.expires_at_ms,
        .account_id = creds.account_id,
    };
}

fn tokenSetFromProviderLogin(creds: provider_login.OAuthCredentials) TokenSet {
    return .{
        .access = creds.access,
        .refresh = creds.refresh,
        .expires_at_ms = creds.expires_at_ms,
        .project_id = creds.project_id,
        .email = creds.email,
        .enterprise_url = creds.enterprise_url,
    };
}

fn browserStartFromCodex(flow: openai_codex.AuthorizationFlow) AuthStart {
    return .{ .browser = .{
        .verifier = flow.verifier,
        .state = flow.state,
        .url = flow.url,
    } };
}

fn browserStartFromProviderLogin(flow: provider_login.AuthorizationFlow) AuthStart {
    return .{ .browser = .{
        .verifier = flow.verifier,
        .state = flow.state,
        .url = flow.url,
    } };
}

fn deviceStartFromProviderLogin(flow: provider_login.DeviceCodeFlow) AuthStart {
    return .{ .device = .{
        .device_code = flow.device_code,
        .user_code = flow.user_code,
        .verification_uri = flow.verification_uri,
        .interval_seconds = flow.interval_seconds,
        .expires_in_seconds = flow.expires_in_seconds,
    } };
}

fn registerLocked(provider: OAuthProvider) !void {
    const allocator = std.heap.page_allocator;
    const owned_name = try allocator.dupe(u8, provider.name);
    errdefer allocator.free(owned_name);

    if (registry_state.map.fetchRemove(provider.name)) |removed| {
        allocator.free(removed.value.name);
    }

    var owned_provider = provider;
    owned_provider.name = owned_name;
    try registry_state.map.put(allocator, owned_name, owned_provider);
}

fn beginOpenAICodex(allocator: std.mem.Allocator, params: BeginAuthParams) !AuthStart {
    const flow = try openai_codex.createAuthorizationFlow(allocator, params.originator orelse "pi");
    return browserStartFromCodex(flow);
}

fn exchangeOpenAICodex(allocator: std.mem.Allocator, params: ExchangeTokenParams) !TokenSet {
    const code = params.code orelse return error.MissingAuthorizationCode;
    const verifier = params.verifier orelse return error.MissingVerifier;
    const redirect_uri = params.redirect_uri orelse openai_codex.REDIRECT_URI;
    const creds = try openai_codex.exchangeAuthorizationCode(allocator, code, verifier, redirect_uri);
    return tokenSetFromCodex(creds);
}

fn refreshOpenAICodex(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
    const creds = try openai_codex.refreshOpenAICodexToken(allocator, params.refresh_token);
    return tokenSetFromCodex(creds);
}

fn beginGoogleGeminiCli(allocator: std.mem.Allocator, _: BeginAuthParams) !AuthStart {
    const flow = try provider_login.createGoogleGeminiCliAuthorizationFlow(allocator);
    return browserStartFromProviderLogin(flow);
}

fn exchangeGoogleGeminiCli(allocator: std.mem.Allocator, params: ExchangeTokenParams) !TokenSet {
    const code = params.code orelse return error.MissingAuthorizationCode;
    const verifier = params.verifier orelse return error.MissingVerifier;
    const creds = try provider_login.exchangeGoogleGeminiCliAuthorizationCode(allocator, code, verifier);
    return tokenSetFromProviderLogin(creds);
}

fn refreshGoogleGeminiCli(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
    const project_id = params.project_id orelse return error.MissingProjectId;
    const creds = try provider_login.refreshGoogleGeminiCliToken(allocator, params.refresh_token, project_id);
    return tokenSetFromProviderLogin(creds);
}

fn beginGoogleAntigravity(allocator: std.mem.Allocator, _: BeginAuthParams) !AuthStart {
    const flow = try provider_login.createGoogleAntigravityAuthorizationFlow(allocator);
    return browserStartFromProviderLogin(flow);
}

fn exchangeGoogleAntigravity(allocator: std.mem.Allocator, params: ExchangeTokenParams) !TokenSet {
    const code = params.code orelse return error.MissingAuthorizationCode;
    const verifier = params.verifier orelse return error.MissingVerifier;
    const creds = try provider_login.exchangeGoogleAntigravityAuthorizationCode(allocator, code, verifier);
    return tokenSetFromProviderLogin(creds);
}

fn refreshGoogleAntigravity(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
    const project_id = params.project_id orelse return error.MissingProjectId;
    const creds = try provider_login.refreshGoogleAntigravityToken(allocator, params.refresh_token, project_id);
    return tokenSetFromProviderLogin(creds);
}

fn beginAnthropic(allocator: std.mem.Allocator, _: BeginAuthParams) !AuthStart {
    const flow = try provider_login.createAnthropicAuthorizationFlow(allocator);
    return browserStartFromProviderLogin(flow);
}

fn exchangeAnthropic(allocator: std.mem.Allocator, params: ExchangeTokenParams) !TokenSet {
    const code = params.code orelse return error.MissingAuthorizationCode;
    const state = params.state orelse return error.MissingState;
    const verifier = params.verifier orelse return error.MissingVerifier;
    const creds = try provider_login.exchangeAnthropicAuthorizationCode(allocator, code, state, verifier);
    return tokenSetFromProviderLogin(creds);
}

fn refreshAnthropic(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
    const creds = try provider_login.refreshAnthropicToken(allocator, params.refresh_token);
    return tokenSetFromProviderLogin(creds);
}

fn beginGitHubCopilot(allocator: std.mem.Allocator, params: BeginAuthParams) !AuthStart {
    const flow = try provider_login.startGitHubCopilotDeviceFlow(allocator, params.enterprise_domain);
    return deviceStartFromProviderLogin(flow);
}

fn exchangeGitHubCopilot(allocator: std.mem.Allocator, params: ExchangeTokenParams) !TokenSet {
    const device_code = params.device_code orelse return error.MissingDeviceCode;
    const interval_seconds = params.interval_seconds orelse return error.MissingDeviceInterval;
    const expires_in_seconds = params.expires_in_seconds orelse return error.MissingDeviceExpiry;
    const access_token = try provider_login.pollGitHubCopilotDeviceAccessToken(
        allocator,
        device_code,
        interval_seconds,
        expires_in_seconds,
        params.enterprise_domain,
    );
    defer allocator.free(access_token);
    const creds = try provider_login.refreshGitHubCopilotToken(allocator, access_token, params.enterprise_domain);
    return tokenSetFromProviderLogin(creds);
}

fn refreshGitHubCopilot(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
    const creds = try provider_login.refreshGitHubCopilotToken(allocator, params.refresh_token, params.enterprise_domain);
    return tokenSetFromProviderLogin(creds);
}

fn defaultFormatApiKey(allocator: std.mem.Allocator, tokens: TokenSet) ![]const u8 {
    return try allocator.dupe(u8, tokens.access);
}

fn formatGoogleApiKey(allocator: std.mem.Allocator, tokens: TokenSet) ![]const u8 {
    const project_id = tokens.project_id orelse return error.MissingProjectId;
    return try std.fmt.allocPrint(
        allocator,
        "{{\"token\":\"{s}\",\"projectId\":\"{s}\"}}",
        .{ tokens.access, project_id },
    );
}

fn ensureBuiltinsRegistered() !void {
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();
    if (registry_state.builtins_registered) return;

    try registerLocked(.{
        .name = "openai-codex",
        .begin_auth = beginOpenAICodex,
        .exchange_token = exchangeOpenAICodex,
        .refresh_token = refreshOpenAICodex,
    });
    try registerLocked(.{
        .name = "anthropic",
        .begin_auth = beginAnthropic,
        .exchange_token = exchangeAnthropic,
        .refresh_token = refreshAnthropic,
    });
    try registerLocked(.{
        .name = "google-gemini-cli",
        .begin_auth = beginGoogleGeminiCli,
        .exchange_token = exchangeGoogleGeminiCli,
        .refresh_token = refreshGoogleGeminiCli,
        .format_api_key = formatGoogleApiKey,
    });
    try registerLocked(.{
        .name = "google-antigravity",
        .begin_auth = beginGoogleAntigravity,
        .exchange_token = exchangeGoogleAntigravity,
        .refresh_token = refreshGoogleAntigravity,
        .format_api_key = formatGoogleApiKey,
    });
    try registerLocked(.{
        .name = "github-copilot",
        .begin_auth = beginGitHubCopilot,
        .exchange_token = exchangeGitHubCopilot,
        .refresh_token = refreshGitHubCopilot,
    });

    registry_state.builtins_registered = true;
}

pub fn registerOAuthProvider(provider: OAuthProvider) !void {
    try ensureBuiltinsRegistered();
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();
    try registerLocked(provider);
}

pub fn unregisterOAuthProvider(name: []const u8) void {
    ensureBuiltinsRegistered() catch return;
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();
    if (registry_state.map.fetchRemove(name)) |removed| {
        std.heap.page_allocator.free(removed.value.name);
    }
}

pub fn getOAuthProvider(name: []const u8) ?OAuthProvider {
    ensureBuiltinsRegistered() catch return null;
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();
    return registry_state.map.get(name);
}

pub fn listOAuthProviders(allocator: std.mem.Allocator) ![]OAuthProvider {
    try ensureBuiltinsRegistered();
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();

    const out = try allocator.alloc(OAuthProvider, registry_state.map.count());
    var idx: usize = 0;
    errdefer freeOAuthProvidersList(allocator, out[0..idx]);
    var it = registry_state.map.iterator();
    while (it.next()) |entry| : (idx += 1) {
        out[idx] = entry.value_ptr.*;
        out[idx].name = try allocator.dupe(u8, entry.value_ptr.name);
    }
    return out;
}

pub fn resetOAuthProvidersForTests() void {
    registry_state.mutex.lock();
    defer registry_state.mutex.unlock();
    registry_state.clear(std.heap.page_allocator);
}

pub fn beginAuth(allocator: std.mem.Allocator, provider_name: []const u8, params: BeginAuthParams) !AuthStart {
    const provider = getOAuthProvider(provider_name) orelse return error.OAuthProviderNotRegistered;
    const begin_fn = provider.begin_auth orelse return error.OAuthBeginNotSupported;
    return try begin_fn(allocator, params);
}

pub fn exchangeToken(allocator: std.mem.Allocator, provider_name: []const u8, params: ExchangeTokenParams) !TokenSet {
    const provider = getOAuthProvider(provider_name) orelse return error.OAuthProviderNotRegistered;
    const exchange_fn = provider.exchange_token orelse return error.OAuthExchangeNotSupported;
    return try exchange_fn(allocator, params);
}

pub fn refreshToken(allocator: std.mem.Allocator, provider_name: []const u8, params: RefreshTokenParams) !TokenSet {
    const provider = getOAuthProvider(provider_name) orelse return error.OAuthProviderNotRegistered;
    const refresh_fn = provider.refresh_token orelse return error.OAuthRefreshNotSupported;
    return try refresh_fn(allocator, params);
}

pub fn formatApiKey(allocator: std.mem.Allocator, provider_name: []const u8, tokens: TokenSet) ![]const u8 {
    const provider = getOAuthProvider(provider_name) orelse return error.OAuthProviderNotRegistered;
    const formatter = provider.format_api_key orelse defaultFormatApiKey;
    return try formatter(allocator, tokens);
}

fn formatStoredApiKey(allocator: std.mem.Allocator, provider_name: []const u8, tokens: TokenSet) ![]const u8 {
    const provider = getOAuthProvider(provider_name);
    const formatter = if (provider) |p| p.format_api_key orelse defaultFormatApiKey else defaultFormatApiKey;
    return try formatter(allocator, tokens);
}

fn parseExpiresMs(value: std.json.Value) ?u64 {
    const raw: u64 = switch (value) {
        .integer => |v| if (v > 0) @intCast(v) else return null,
        .float => |v| if (v > 0) @intFromFloat(v) else return null,
        else => return null,
    };
    if (raw < 10_000_000_000) return raw * 1000;
    return raw;
}

fn duplicateJsonString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string or v.string.len == 0) return null;
    return allocator.dupe(u8, v.string) catch null;
}

fn readApiKeyEntryFromFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
) ?[]const u8 {
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
    const type_v = entry.get("type") orelse return null;
    if (type_v != .string or !std.mem.eql(u8, type_v.string, "api_key")) return null;
    return duplicateJsonString(allocator, entry, "key");
}

pub fn piAuthPathFromHome(allocator: std.mem.Allocator, home: []const u8) ?[]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/.pi/agent/auth.json", .{home}) catch null;
}

const AuthFileLock = struct {
    file: std.fs.File,
    path: []const u8,

    fn release(self: *AuthFileLock, allocator: std.mem.Allocator) void {
        self.file.close();
        std.fs.deleteFileAbsolute(self.path) catch {};
        allocator.free(self.path);
        self.* = undefined;
    }
};

fn acquireAuthFileLock(allocator: std.mem.Allocator, auth_path: []const u8) !AuthFileLock {
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{auth_path});
    errdefer allocator.free(lock_path);

    const max_attempts: u32 = 100;
    var attempt: u32 = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        const file = std.fs.createFileAbsolute(lock_path, .{
            .exclusive = true,
            .truncate = false,
            .mode = 0o600,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                std.Thread.sleep(20 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };

        return .{ .file = file, .path = lock_path };
    }
    return error.AuthFileLockTimeout;
}

fn readOAuthCredentialsFromFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
) ?TokenSet {
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
        .account_id = duplicateJsonString(allocator, entry, "accountId"),
        .email = duplicateJsonString(allocator, entry, "email"),
        .enterprise_url = duplicateJsonString(allocator, entry, "enterpriseUrl"),
    };
}

fn ensureAbsolutePath(path: []const u8) !void {
    if (path.len == 0 or path[0] != '/') return error.InvalidPath;
    var partial = std.array_list.Managed(u8).init(std.heap.page_allocator);
    defer partial.deinit();
    try partial.append('/');

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0) continue;
        if (partial.items.len > 1) try partial.append('/');
        try partial.appendSlice(segment);
        std.fs.makeDirAbsolute(partial.items) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }
}

fn deinitOwnedJsonValue(value: *std.json.Value, allocator: std.mem.Allocator) void {
    switch (value.*) {
        .string => |s| allocator.free(s),
        .number_string => |s| allocator.free(s),
        .array => |*array| {
            for (array.items) |*item| deinitOwnedJsonValue(item, allocator);
            array.deinit();
        },
        .object => |*object| {
            var it = object.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                deinitOwnedJsonValue(entry.value_ptr, allocator);
            }
            object.deinit();
        },
        else => {},
    }
}

fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .null, .bool, .integer, .float => value,
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .number_string => |s| .{ .number_string = try allocator.dupe(u8, s) },
        .array => |array| blk: {
            var out = std.json.Array.init(allocator);
            errdefer {
                for (out.items) |*item| deinitOwnedJsonValue(item, allocator);
                out.deinit();
            }
            for (array.items) |item| {
                try out.append(try cloneJsonValue(allocator, item));
            }
            break :blk .{ .array = out };
        },
        .object => |object| blk: {
            var out = std.json.ObjectMap.init(allocator);
            errdefer {
                var it = out.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    deinitOwnedJsonValue(entry.value_ptr, allocator);
                }
                out.deinit();
            }
            var it = object.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(key);
                try out.put(key, try cloneJsonValue(allocator, entry.value_ptr.*));
            }
            break :blk .{ .object = out };
        },
    };
}

fn writeOAuthCredentialsToFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
    creds: TokenSet,
) !void {
    var root_value = std.json.Value{ .object = std.json.ObjectMap.init(allocator) };
    defer deinitOwnedJsonValue(&root_value, allocator);

    const existing_file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch null;
    if (existing_file) |f| {
        defer f.close();
        const contents = try f.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(contents);
        if (std.json.parseFromSlice(std.json.Value, allocator, contents, .{})) |parsed| {
            defer parsed.deinit();
            if (parsed.value == .object) {
                var it = parsed.value.object.iterator();
                while (it.next()) |entry| {
                    const key = try allocator.dupe(u8, entry.key_ptr.*);
                    errdefer allocator.free(key);
                    try root_value.object.put(key, try cloneJsonValue(allocator, entry.value_ptr.*));
                }
            }
        } else |_| {}
    }

    var entry = std.json.ObjectMap.init(allocator);
    errdefer {
        var entry_value = std.json.Value{ .object = entry };
        deinitOwnedJsonValue(&entry_value, allocator);
    }
    try entry.put(try allocator.dupe(u8, "type"), .{ .string = try allocator.dupe(u8, "oauth") });
    try entry.put(try allocator.dupe(u8, "access"), .{ .string = try allocator.dupe(u8, creds.access) });
    try entry.put(try allocator.dupe(u8, "refresh"), .{ .string = try allocator.dupe(u8, creds.refresh) });
    try entry.put(try allocator.dupe(u8, "expires"), .{ .integer = @intCast(creds.expires_at_ms) });
    if (creds.project_id) |v| try entry.put(try allocator.dupe(u8, "projectId"), .{ .string = try allocator.dupe(u8, v) });
    if (creds.account_id) |v| try entry.put(try allocator.dupe(u8, "accountId"), .{ .string = try allocator.dupe(u8, v) });
    if (creds.email) |v| try entry.put(try allocator.dupe(u8, "email"), .{ .string = try allocator.dupe(u8, v) });
    if (creds.enterprise_url) |v| try entry.put(try allocator.dupe(u8, "enterpriseUrl"), .{ .string = try allocator.dupe(u8, v) });

    if (root_value.object.fetchSwapRemove(provider)) |removed| {
        allocator.free(removed.key);
        var removed_value = removed.value;
        deinitOwnedJsonValue(&removed_value, allocator);
    }
    try root_value.object.put(try allocator.dupe(u8, provider), .{ .object = entry });

    const parent = std.fs.path.dirname(auth_path);
    if (parent) |p| try ensureAbsolutePath(p);

    const file = try std.fs.createFileAbsolute(auth_path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    const json_payload = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(root_value, .{})});
    defer allocator.free(json_payload);
    try file.writeAll(json_payload);
    try file.writeAll("\n");
}

fn removeProviderEntryFromFile(
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    provider: []const u8,
) !void {
    const file = std.fs.openFileAbsolute(auth_path, .{ .mode = .read_only }) catch return;
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, contents, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;

    _ = parsed.value.object.swapRemove(provider);

    const out_file = try std.fs.createFileAbsolute(auth_path, .{ .truncate = true, .mode = 0o600 });
    defer out_file.close();
    const json_payload = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(parsed.value, .{})});
    defer allocator.free(json_payload);
    try out_file.writeAll(json_payload);
    try out_file.writeAll("\n");
}

pub fn getPiOAuthApiKey(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    const auth_path = piAuthPathFromHome(allocator, home) orelse return null;
    defer allocator.free(auth_path);
    return getPiOAuthApiKeyFromPath(allocator, provider, auth_path);
}

pub fn getPiApiKeyEntry(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    const auth_path = piAuthPathFromHome(allocator, home) orelse return null;
    defer allocator.free(auth_path);
    return readApiKeyEntryFromFile(allocator, auth_path, provider);
}

pub fn savePiOAuthCredentials(
    allocator: std.mem.Allocator,
    provider: []const u8,
    creds: TokenSet,
) !void {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    const auth_path = piAuthPathFromHome(allocator, home) orelse return error.OutOfMemory;
    defer allocator.free(auth_path);
    try writeOAuthCredentialsToFile(allocator, auth_path, provider, creds);
}

pub fn removePiAuthProviderEntry(
    allocator: std.mem.Allocator,
    provider: []const u8,
) !void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);
    const auth_path = piAuthPathFromHome(allocator, home) orelse return;
    defer allocator.free(auth_path);
    try removeProviderEntryFromFile(allocator, auth_path, provider);
}

pub fn getPiOAuthApiKeyFromPath(
    allocator: std.mem.Allocator,
    provider: []const u8,
    auth_path: []const u8,
) ?[]const u8 {
    var tokens = readOAuthCredentialsFromFile(allocator, auth_path, provider) orelse return null;
    defer freeTokenSet(allocator, &tokens);

    const now_ms: u64 = @intCast(std.time.milliTimestamp());
    if (now_ms >= tokens.expires_at_ms) {
        var lock = acquireAuthFileLock(allocator, auth_path) catch return null;
        defer lock.release(allocator);

        var latest = readOAuthCredentialsFromFile(allocator, auth_path, provider) orelse return null;
        defer freeTokenSet(allocator, &latest);

        const latest_now_ms: u64 = @intCast(std.time.milliTimestamp());
        if (latest_now_ms < latest.expires_at_ms) {
            return formatStoredApiKey(allocator, provider, latest) catch null;
        }

        var refreshed = refreshToken(allocator, provider, .{
            .refresh_token = latest.refresh,
            .project_id = latest.project_id,
            .enterprise_domain = latest.enterprise_url,
        }) catch return null;
        defer freeTokenSet(allocator, &refreshed);
        writeOAuthCredentialsToFile(allocator, auth_path, provider, refreshed) catch {};
        return formatStoredApiKey(allocator, provider, refreshed) catch null;
    }
    return formatStoredApiKey(allocator, provider, tokens) catch null;
}

test "oauth registry lists builtin providers" {
    const allocator = std.testing.allocator;
    const providers = try listOAuthProviders(allocator);
    defer freeOAuthProvidersList(allocator, providers);

    var saw_codex = false;
    var saw_anthropic = false;
    var saw_gemini = false;
    var saw_antigravity = false;
    var saw_copilot = false;
    for (providers) |provider| {
        saw_codex = saw_codex or std.mem.eql(u8, provider.name, "openai-codex");
        saw_anthropic = saw_anthropic or std.mem.eql(u8, provider.name, "anthropic");
        saw_gemini = saw_gemini or std.mem.eql(u8, provider.name, "google-gemini-cli");
        saw_antigravity = saw_antigravity or std.mem.eql(u8, provider.name, "google-antigravity");
        saw_copilot = saw_copilot or std.mem.eql(u8, provider.name, "github-copilot");
    }

    try std.testing.expect(saw_codex);
    try std.testing.expect(saw_anthropic);
    try std.testing.expect(saw_gemini);
    try std.testing.expect(saw_antigravity);
    try std.testing.expect(saw_copilot);
}

test "oauth registry list snapshot owns provider names" {
    const Custom = struct {
        fn refresh(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
            _ = params;
            return .{
                .access = try allocator.dupe(u8, "snapshot-access"),
                .refresh = try allocator.dupe(u8, "snapshot-refresh"),
                .expires_at_ms = 4_102_444_800_000,
            };
        }
    };

    defer resetOAuthProvidersForTests();
    try registerOAuthProvider(.{
        .name = "snapshot-provider",
        .refresh_token = Custom.refresh,
    });

    const allocator = std.testing.allocator;
    const providers = try listOAuthProviders(allocator);
    defer freeOAuthProvidersList(allocator, providers);

    unregisterOAuthProvider("snapshot-provider");

    var saw_snapshot = false;
    for (providers) |provider| {
        if (std.mem.eql(u8, provider.name, "snapshot-provider")) {
            saw_snapshot = true;
        }
    }
    try std.testing.expect(saw_snapshot);
}

test "oauth registry resolves custom provider auth entries without core edits" {
    const Custom = struct {
        fn refresh(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
            _ = params;
            return .{
                .access = try allocator.dupe(u8, "fresh-access"),
                .refresh = try allocator.dupe(u8, "fresh-refresh"),
                .expires_at_ms = 4_102_444_800_000,
            };
        }

        fn format(allocator: std.mem.Allocator, tokens: TokenSet) ![]const u8 {
            return try std.fmt.allocPrint(allocator, "Bearer {s}", .{tokens.access});
        }
    };

    defer resetOAuthProvidersForTests();
    try registerOAuthProvider(.{
        .name = "custom-oauth",
        .refresh_token = Custom.refresh,
        .format_api_key = Custom.format,
    });

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath(".pi/agent");
    const file = try tmp.dir.createFile(".pi/agent/auth.json", .{});
    defer file.close();
    try file.writeAll(
        \\{"custom-oauth":{"type":"oauth","access":"stale","refresh":"stale-refresh","expires":1}}
    );

    const cwd_realpath = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_realpath);
    const full_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/.pi/agent/auth.json",
        .{ cwd_realpath, tmp.sub_path },
    );
    defer allocator.free(full_path);

    const api_key = getPiOAuthApiKeyFromPath(allocator, "custom-oauth", full_path) orelse return error.TestExpectedEqual;
    defer allocator.free(api_key);
    try std.testing.expectEqualStrings("Bearer fresh-access", api_key);

    const provider = getOAuthProvider("custom-oauth") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("custom-oauth", provider.name);

    unregisterOAuthProvider("custom-oauth");
    try std.testing.expect(getOAuthProvider("custom-oauth") == null);
}

test "oauth registry preserves stored token fallback for unregistered providers" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath(".pi/agent");
    const file = try tmp.dir.createFile(".pi/agent/auth.json", .{});
    defer file.close();
    try file.writeAll(
        \\{"legacy-provider":{"type":"oauth","access":"legacy-access","refresh":"legacy-refresh","expires":4102444800000}}
    );

    const cwd_realpath = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_realpath);
    const full_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/.pi/agent/auth.json",
        .{ cwd_realpath, tmp.sub_path },
    );
    defer allocator.free(full_path);

    const api_key = getPiOAuthApiKeyFromPath(allocator, "legacy-provider", full_path) orelse return error.TestExpectedEqual;
    defer allocator.free(api_key);
    try std.testing.expectEqualStrings("legacy-access", api_key);
}

test "oauth registry reset removes custom providers and restores builtins" {
    const Custom = struct {
        fn refresh(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
            _ = params;
            return .{
                .access = try allocator.dupe(u8, "custom-access"),
                .refresh = try allocator.dupe(u8, "custom-refresh"),
                .expires_at_ms = 4_102_444_800_000,
            };
        }
    };

    defer resetOAuthProvidersForTests();
    try registerOAuthProvider(.{
        .name = "custom-reset-provider",
        .refresh_token = Custom.refresh,
    });

    try std.testing.expect(getOAuthProvider("custom-reset-provider") != null);
    resetOAuthProvidersForTests();
    try std.testing.expect(getOAuthProvider("custom-reset-provider") == null);
    try std.testing.expect(getOAuthProvider("openai-codex") != null);
    try std.testing.expect(getOAuthProvider("github-copilot") != null);
}

test "oauth registry surfaces unsupported operation errors" {
    const Custom = struct {
        fn refresh(allocator: std.mem.Allocator, params: RefreshTokenParams) !TokenSet {
            _ = params;
            return .{
                .access = try allocator.dupe(u8, "refresh-only-access"),
                .refresh = try allocator.dupe(u8, "refresh-only-refresh"),
                .expires_at_ms = 4_102_444_800_000,
            };
        }
    };

    defer resetOAuthProvidersForTests();
    try registerOAuthProvider(.{
        .name = "refresh-only-provider",
        .refresh_token = Custom.refresh,
    });

    const allocator = std.testing.allocator;
    try std.testing.expectError(error.OAuthBeginNotSupported, beginAuth(allocator, "refresh-only-provider", .{}));
    try std.testing.expectError(error.OAuthExchangeNotSupported, exchangeToken(allocator, "refresh-only-provider", .{}));
    try std.testing.expectError(error.OAuthProviderNotRegistered, refreshToken(allocator, "missing-provider", .{
        .refresh_token = "missing",
    }));
}

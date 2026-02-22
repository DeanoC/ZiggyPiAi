const std = @import("std");
const ziggy_piai = @import("ziggypiai");

const codex_oauth = ziggy_piai.oauth.openai_codex;
const provider_oauth = ziggy_piai.oauth.provider_oauth;
const provider_login = ziggy_piai.oauth.provider_login_oauth;

const SupportedProvider = enum {
    openai_codex,
    openai_codex_spark,
    anthropic,
    google_gemini_cli,
    google_antigravity,
    github_copilot,
};

fn parseProvider(value: []const u8) ?SupportedProvider {
    if (std.mem.eql(u8, value, "openai-codex")) return .openai_codex;
    if (std.mem.eql(u8, value, "openai-codex-spark")) return .openai_codex_spark;
    if (std.mem.eql(u8, value, "anthropic")) return .anthropic;
    if (std.mem.eql(u8, value, "google-gemini-cli")) return .google_gemini_cli;
    if (std.mem.eql(u8, value, "google-antigravity")) return .google_antigravity;
    if (std.mem.eql(u8, value, "github-copilot")) return .github_copilot;
    return null;
}

fn storageProviderName(provider: SupportedProvider) []const u8 {
    return switch (provider) {
        .openai_codex, .openai_codex_spark => "openai-codex",
        .anthropic => "anthropic",
        .google_gemini_cli => "google-gemini-cli",
        .google_antigravity => "google-antigravity",
        .github_copilot => "github-copilot",
    };
}

fn printUsage() !void {
    const usage =
        \\OAuth Login Example (for ZiggyPiAi integrators)
        \\
        \\Usage:
        \\  zig build example-oauth-login -- <provider> [--enterprise-domain <domain>]
        \\
        \\Providers:
        \\  openai-codex
        \\  openai-codex-spark
        \\  anthropic
        \\  google-gemini-cli
        \\  google-antigravity
        \\  github-copilot
        \\
        \\Notes:
        \\  - Credentials are persisted to ~/.pi/agent/auth.json
        \\  - This example is intentionally simple and terminal-driven.
        \\  - Google/Anthropic login flows require provider OAuth client env vars.
        \\
    ;
    try std.fs.File.stdout().writeAll(usage);
}

fn print(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try std.fs.File.stdout().writeAll(msg);
}

fn println(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt ++ "\n", args);
    try std.fs.File.stdout().writeAll(msg);
}

fn readLineTrimmedAlloc(allocator: std.mem.Allocator, max_len: usize) !?[]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var stdin = std.fs.File.stdin();
    var saw_any = false;
    var byte: [1]u8 = undefined;
    while (true) {
        const n = try stdin.read(byte[0..]);
        if (n == 0) break;
        saw_any = true;

        const ch = byte[0];
        if (ch == '\n') break;
        if (ch == '\r') continue;

        if (out.items.len >= max_len) return error.InputTooLong;
        try out.append(allocator, ch);
    }

    if (!saw_any and out.items.len == 0) return null;

    const trimmed = std.mem.trim(u8, out.items, " \t");
    if (trimmed.len == 0) {
        out.deinit(allocator);
        return try allocator.dupe(u8, "");
    }

    const dup = try allocator.dupe(u8, trimmed);
    out.deinit(allocator);
    return dup;
}

fn promptAuthorizationCode(allocator: std.mem.Allocator, auth_url: []const u8, expected_state: []const u8) ![]u8 {
    try println("", .{});
    try println("Open this URL in your browser:", .{});
    try println("  {s}", .{auth_url});
    try println("", .{});
    try println("Paste the full callback URL (or code#state):", .{});
    try print("> ", .{});

    const raw = (try readLineTrimmedAlloc(allocator, 8192)) orelse return error.MissingAuthorizationCode;
    defer allocator.free(raw);

    const parsed = try codex_oauth.parseAuthorizationInput(allocator, raw);
    defer {
        if (parsed.code) |value| allocator.free(value);
        if (parsed.state) |value| allocator.free(value);
    }

    const code = parsed.code orelse return error.MissingAuthorizationCode;
    const state = parsed.state orelse return error.StateMismatch;
    if (!std.mem.eql(u8, state, expected_state)) return error.StateMismatch;

    return allocator.dupe(u8, code);
}

fn saveFromCodexCredentials(
    allocator: std.mem.Allocator,
    provider: SupportedProvider,
    creds: codex_oauth.OAuthCredentials,
) !void {
    var to_store = provider_oauth.OAuthCredentials{
        .access = try allocator.dupe(u8, creds.access),
        .refresh = try allocator.dupe(u8, creds.refresh),
        .expires_at_ms = creds.expires_at_ms,
        .project_id = null,
        .enterprise_url = null,
    };
    defer provider_oauth.freeOAuthCredentials(allocator, &to_store);

    try provider_oauth.savePiOAuthCredentials(allocator, storageProviderName(provider), to_store);
}

fn saveFromProviderLoginCredentials(
    allocator: std.mem.Allocator,
    provider: SupportedProvider,
    creds: provider_login.OAuthCredentials,
) !void {
    var to_store = provider_oauth.OAuthCredentials{
        .access = try allocator.dupe(u8, creds.access),
        .refresh = try allocator.dupe(u8, creds.refresh),
        .expires_at_ms = creds.expires_at_ms,
        .project_id = if (creds.project_id) |value| try allocator.dupe(u8, value) else null,
        .enterprise_url = if (creds.enterprise_url) |value| try allocator.dupe(u8, value) else null,
    };
    defer provider_oauth.freeOAuthCredentials(allocator, &to_store);

    try provider_oauth.savePiOAuthCredentials(allocator, storageProviderName(provider), to_store);
}

fn runOpenAICodexFlow(allocator: std.mem.Allocator, provider: SupportedProvider) !void {
    var flow = try codex_oauth.createAuthorizationFlow(allocator, "pi");
    defer codex_oauth.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try codex_oauth.exchangeAuthorizationCode(allocator, code, flow.verifier, codex_oauth.REDIRECT_URI);
    defer codex_oauth.freeCredentials(allocator, &creds);

    try saveFromCodexCredentials(allocator, provider, creds);
}

fn runAnthropicFlow(allocator: std.mem.Allocator) !void {
    var flow = try provider_login.createAnthropicAuthorizationFlow(allocator);
    defer provider_login.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login.exchangeAnthropicAuthorizationCode(allocator, code, flow.state, flow.verifier);
    defer provider_login.freeOAuthCredentials(allocator, &creds);

    try saveFromProviderLoginCredentials(allocator, .anthropic, creds);
}

fn runGoogleGeminiCliFlow(allocator: std.mem.Allocator) !void {
    var flow = try provider_login.createGoogleGeminiCliAuthorizationFlow(allocator);
    defer provider_login.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login.exchangeGoogleGeminiCliAuthorizationCode(allocator, code, flow.verifier);
    defer provider_login.freeOAuthCredentials(allocator, &creds);

    try saveFromProviderLoginCredentials(allocator, .google_gemini_cli, creds);
}

fn runGoogleAntigravityFlow(allocator: std.mem.Allocator) !void {
    var flow = try provider_login.createGoogleAntigravityAuthorizationFlow(allocator);
    defer provider_login.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login.exchangeGoogleAntigravityAuthorizationCode(allocator, code, flow.verifier);
    defer provider_login.freeOAuthCredentials(allocator, &creds);

    try saveFromProviderLoginCredentials(allocator, .google_antigravity, creds);
}

fn runGithubCopilotFlow(allocator: std.mem.Allocator, enterprise_domain: ?[]const u8) !void {
    var device_flow = try provider_login.startGitHubCopilotDeviceFlow(allocator, enterprise_domain);
    defer provider_login.freeDeviceCodeFlow(allocator, &device_flow);

    try println("", .{});
    try println("Complete device login:", .{});
    try println("  URL:  {s}", .{device_flow.verification_uri});
    try println("  Code: {s}", .{device_flow.user_code});
    try println("Waiting for authorization...", .{});

    const device_access = try provider_login.pollGitHubCopilotDeviceAccessToken(
        allocator,
        device_flow.device_code,
        device_flow.interval_seconds,
        device_flow.expires_in_seconds,
        enterprise_domain,
    );
    defer allocator.free(device_access);

    var creds = try provider_login.refreshGitHubCopilotToken(allocator, device_access, enterprise_domain);
    defer provider_login.freeOAuthCredentials(allocator, &creds);

    try saveFromProviderLoginCredentials(allocator, .github_copilot, creds);
}

fn printSavedPath(allocator: std.mem.Allocator) void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);

    const path = provider_oauth.piAuthPathFromHome(allocator, home) orelse return;
    defer allocator.free(path);

    std.log.info("Saved OAuth credentials to {s}", .{path});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }
    if (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        try printUsage();
        return;
    }

    const provider = parseProvider(args[1]) orelse {
        std.log.err("Unsupported provider: {s}", .{args[1]});
        try printUsage();
        return error.InvalidArguments;
    };

    var enterprise_domain: ?[]const u8 = null;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--enterprise-domain")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            enterprise_domain = args[i];
        } else {
            std.log.err("Unknown option: {s}", .{args[i]});
            return error.InvalidArguments;
        }
    }

    switch (provider) {
        .openai_codex, .openai_codex_spark => try runOpenAICodexFlow(allocator, provider),
        .anthropic => try runAnthropicFlow(allocator),
        .google_gemini_cli => try runGoogleGeminiCliFlow(allocator),
        .google_antigravity => try runGoogleAntigravityFlow(allocator),
        .github_copilot => try runGithubCopilotFlow(allocator, enterprise_domain),
    }

    printSavedPath(allocator);
}

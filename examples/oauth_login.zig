const std = @import("std");
const ziggy_piai = @import("ziggypiai");

const codex_oauth = ziggy_piai.oauth.openai_codex;
const oauth_registry = ziggy_piai.oauth.registry;

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

fn runOAuthFlow(allocator: std.mem.Allocator, provider: SupportedProvider, enterprise_domain: ?[]const u8) !void {
    const provider_name = storageProviderName(provider);
    var auth_start = try oauth_registry.beginAuth(allocator, provider_name, .{
        .originator = "pi",
        .enterprise_domain = enterprise_domain,
    });
    defer oauth_registry.freeAuthStart(allocator, &auth_start);

    var tokens = switch (auth_start) {
        .browser => |browser| try blk: {
            const code = try promptAuthorizationCode(allocator, browser.url, browser.state);
            defer allocator.free(code);

            break :blk oauth_registry.exchangeToken(allocator, provider_name, .{
                .code = code,
                .state = browser.state,
                .verifier = browser.verifier,
                .redirect_uri = if (provider == .openai_codex or provider == .openai_codex_spark) codex_oauth.REDIRECT_URI else null,
            });
        },
        .device => |device| try blk: {
            try println("", .{});
            try println("Complete device login:", .{});
            try println("  URL:  {s}", .{device.verification_uri});
            try println("  Code: {s}", .{device.user_code});
            try println("Waiting for authorization...", .{});

            break :blk oauth_registry.exchangeToken(allocator, provider_name, .{
                .device_code = device.device_code,
                .interval_seconds = device.interval_seconds,
                .expires_in_seconds = device.expires_in_seconds,
                .enterprise_domain = enterprise_domain,
            });
        },
    };
    defer oauth_registry.freeTokenSet(allocator, &tokens);

    try oauth_registry.savePiOAuthCredentials(allocator, provider_name, tokens);
}

fn printSavedPath(allocator: std.mem.Allocator) void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);

    const path = oauth_registry.piAuthPathFromHome(allocator, home) orelse return;
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
        .openai_codex,
        .openai_codex_spark,
        .anthropic,
        .google_gemini_cli,
        .google_antigravity,
        .github_copilot,
        => try runOAuthFlow(allocator, provider, enterprise_domain),
    }

    printSavedPath(allocator);
}

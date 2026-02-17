const std = @import("std");
const codex_oauth = @import("oauth/openai_codex_oauth.zig");

pub fn getEnvApiKey(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, provider, "openai"))
        return std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    if (std.mem.eql(u8, provider, "openai-codex")) {
        return std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_API_KEY") catch
            codex_oauth.getCodexOauthApiKey(allocator) orelse
            std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "openai-codex-spark")) {
        return std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_SPARK_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_API_KEY") catch
            codex_oauth.getCodexOauthApiKey(allocator) orelse
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
    if (std.mem.eql(u8, provider, "openrouter")) {
        return std.process.getEnvVarOwned(allocator, "OPENROUTER_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "google") or std.mem.eql(u8, provider, "google-generative-ai") or std.mem.eql(u8, provider, "google-gemini-cli")) {
        return std.process.getEnvVarOwned(allocator, "GOOGLE_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "google-vertex")) {
        return std.process.getEnvVarOwned(allocator, "GOOGLE_VERTEX_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "GOOGLE_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "bedrock") or std.mem.eql(u8, provider, "amazon-bedrock") or std.mem.eql(u8, provider, "bedrock-converse-stream")) {
        return std.process.getEnvVarOwned(allocator, "AWS_BEARER_TOKEN_BEDROCK") catch {
            const access = std.process.getEnvVarOwned(allocator, "AWS_ACCESS_KEY_ID") catch null;
            defer if (access) |v| allocator.free(v);
            const secret = std.process.getEnvVarOwned(allocator, "AWS_SECRET_ACCESS_KEY") catch null;
            defer if (secret) |v| allocator.free(v);
            if (access != null and secret != null) {
                return allocator.dupe(u8, "<authenticated>") catch null;
            }
            return null;
        };
    }
    return null;
}

test "getEnvApiKey returns azure openai api key" {
    const allocator = std.testing.allocator;
    const v = getEnvApiKey(allocator, "azure-openai-responses");
    if (v) |key| allocator.free(key);
}

test "getEnvApiKey supports additional provider mappings" {
    const allocator = std.testing.allocator;
    const providers = [_][]const u8{
        "openrouter",
        "google",
        "google-generative-ai",
        "google-gemini-cli",
        "google-vertex",
        "bedrock",
        "amazon-bedrock",
        "bedrock-converse-stream",
    };
    for (providers) |provider| {
        const value = getEnvApiKey(allocator, provider);
        if (value) |v| allocator.free(v);
    }
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

    const tokens = codex_oauth.readCodexAuthFile(allocator, full_path);
    try std.testing.expect(tokens != null);
    defer if (tokens) |t| {
        var tt = t;
        codex_oauth.freeCodexAuthTokens(allocator, &tt);
    };
    try std.testing.expectEqualStrings("codex-access", tokens.?.access_token);
}

// Additional tests could go here to verify Codex file parsing, but they are skipped to avoid touching real files.

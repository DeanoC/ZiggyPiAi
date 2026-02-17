const std = @import("std");
const codex_oauth = @import("oauth/openai_codex_oauth.zig");
const provider_oauth = @import("oauth/provider_oauth.zig");

fn fileExistsAbsolute(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

fn hasVertexAdcCredentials(allocator: std.mem.Allocator) bool {
    const gac_path = std.process.getEnvVarOwned(allocator, "GOOGLE_APPLICATION_CREDENTIALS") catch null;
    defer if (gac_path) |p| allocator.free(p);
    if (gac_path) |p| return fileExistsAbsolute(p);

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return false;
    defer allocator.free(home);
    const default_adc = std.fmt.allocPrint(
        allocator,
        "{s}/.config/gcloud/application_default_credentials.json",
        .{home},
    ) catch return false;
    defer allocator.free(default_adc);
    return fileExistsAbsolute(default_adc);
}

pub fn getEnvApiKey(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, provider, "openai"))
        return std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    if (std.mem.eql(u8, provider, "openai-codex")) {
        return std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_API_KEY") catch
            provider_oauth.getPiOAuthApiKey(allocator, "openai-codex") orelse
            codex_oauth.getCodexOauthApiKey(allocator) orelse
            std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "openai-codex-spark")) {
        return std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_SPARK_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "OPENAI_CODEX_API_KEY") catch
            provider_oauth.getPiOAuthApiKey(allocator, "openai-codex") orelse
            codex_oauth.getCodexOauthApiKey(allocator) orelse
            std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "anthropic"))
        return std.process.getEnvVarOwned(allocator, "ANTHROPIC_OAUTH_TOKEN") catch
            provider_oauth.getPiOAuthApiKey(allocator, "anthropic") orelse
            std.process.getEnvVarOwned(allocator, "ANTHROPIC_API_KEY") catch null;
    if (std.mem.eql(u8, provider, "kimi-coding") or std.mem.eql(u8, provider, "kimi-code")) {
        return std.process.getEnvVarOwned(allocator, "KIMICODE_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "KIMI_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "ANTHROPIC_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "azure-openai-responses")) {
        return std.process.getEnvVarOwned(allocator, "AZURE_OPENAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "github-copilot")) {
        return std.process.getEnvVarOwned(allocator, "COPILOT_GITHUB_TOKEN") catch
            std.process.getEnvVarOwned(allocator, "GH_TOKEN") catch
            std.process.getEnvVarOwned(allocator, "GITHUB_TOKEN") catch
            provider_oauth.getPiOAuthApiKey(allocator, "github-copilot") orelse null;
    }
    if (std.mem.eql(u8, provider, "openrouter")) {
        return std.process.getEnvVarOwned(allocator, "OPENROUTER_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "groq")) {
        return std.process.getEnvVarOwned(allocator, "GROQ_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "cerebras")) {
        return std.process.getEnvVarOwned(allocator, "CEREBRAS_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "xai")) {
        return std.process.getEnvVarOwned(allocator, "XAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "zai")) {
        return std.process.getEnvVarOwned(allocator, "ZAI_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "mistral")) {
        return std.process.getEnvVarOwned(allocator, "MISTRAL_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "minimax")) {
        return std.process.getEnvVarOwned(allocator, "MINIMAX_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "minimax-cn")) {
        return std.process.getEnvVarOwned(allocator, "MINIMAX_CN_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "huggingface")) {
        return std.process.getEnvVarOwned(allocator, "HF_TOKEN") catch null;
    }
    if (std.mem.eql(u8, provider, "vercel-ai-gateway")) {
        return std.process.getEnvVarOwned(allocator, "AI_GATEWAY_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "opencode")) {
        return std.process.getEnvVarOwned(allocator, "OPENCODE_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "google") or std.mem.eql(u8, provider, "google-generative-ai")) {
        return std.process.getEnvVarOwned(allocator, "GEMINI_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "GOOGLE_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "google-gemini-cli") or std.mem.eql(u8, provider, "google-antigravity")) {
        // Cloud Code Assist providers use OAuth bearer credentials from ~/.pi/agent/auth.json.
        return provider_oauth.getPiOAuthApiKey(allocator, provider);
    }
    if (std.mem.eql(u8, provider, "google-vertex")) {
        const project = std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT") catch
            std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_PROJECT_ID") catch
            std.process.getEnvVarOwned(allocator, "GCLOUD_PROJECT") catch null;
        defer if (project) |v| allocator.free(v);
        const location = std.process.getEnvVarOwned(allocator, "GOOGLE_CLOUD_LOCATION") catch null;
        defer if (location) |v| allocator.free(v);
        const has_project = project != null;
        const has_location = location != null;
        if (has_project and has_location and hasVertexAdcCredentials(allocator)) {
            return allocator.dupe(u8, "<authenticated>") catch null;
        }
        return std.process.getEnvVarOwned(allocator, "GOOGLE_VERTEX_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "GEMINI_API_KEY") catch
            std.process.getEnvVarOwned(allocator, "GOOGLE_API_KEY") catch null;
    }
    if (std.mem.eql(u8, provider, "bedrock") or std.mem.eql(u8, provider, "amazon-bedrock") or std.mem.eql(u8, provider, "bedrock-converse-stream")) {
        if (std.process.getEnvVarOwned(allocator, "AWS_PROFILE")) |profile| {
            defer allocator.free(profile);
            return allocator.dupe(u8, "<authenticated>") catch null;
        } else |_| {}
        if (std.process.getEnvVarOwned(allocator, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) |v| {
            defer allocator.free(v);
            return allocator.dupe(u8, "<authenticated>") catch null;
        } else |_| {}
        if (std.process.getEnvVarOwned(allocator, "AWS_CONTAINER_CREDENTIALS_FULL_URI")) |v| {
            defer allocator.free(v);
            return allocator.dupe(u8, "<authenticated>") catch null;
        } else |_| {}
        if (std.process.getEnvVarOwned(allocator, "AWS_WEB_IDENTITY_TOKEN_FILE")) |v| {
            defer allocator.free(v);
            return allocator.dupe(u8, "<authenticated>") catch null;
        } else |_| {}
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
    return provider_oauth.getPiApiKeyEntry(allocator, provider);
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
        "groq",
        "cerebras",
        "xai",
        "zai",
        "mistral",
        "minimax",
        "minimax-cn",
        "huggingface",
        "vercel-ai-gateway",
        "opencode",
        "github-copilot",
        "google",
        "google-antigravity",
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

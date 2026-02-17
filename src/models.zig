const std = @import("std");
const types = @import("types.zig");
const generated = @import("models_supported_generated.zig");

pub const ModelRegistry = struct {
    allocator: std.mem.Allocator,
    models: std.array_list.Managed(types.Model),

    pub fn init(allocator: std.mem.Allocator) ModelRegistry {
        return .{
            .allocator = allocator,
            .models = std.array_list.Managed(types.Model).init(allocator),
        };
    }

    pub fn deinit(self: *ModelRegistry) void {
        self.models.deinit();
    }

    pub fn register(self: *ModelRegistry, model: types.Model) !void {
        try self.models.append(model);
    }

    pub fn getModel(self: *const ModelRegistry, provider: []const u8, model_id: []const u8) ?types.Model {
        for (self.models.items) |m| {
            if (std.mem.eql(u8, m.provider, provider) and std.mem.eql(u8, m.id, model_id)) return m;
        }
        return null;
    }

    pub fn getProviders(self: *const ModelRegistry, allocator: std.mem.Allocator) ![][]const u8 {
        var providers = std.array_list.Managed([]const u8).init(allocator);
        errdefer providers.deinit();

        for (self.models.items) |model| {
            var found = false;
            for (providers.items) |provider| {
                if (std.mem.eql(u8, provider, model.provider)) {
                    found = true;
                    break;
                }
            }
            if (!found) try providers.append(model.provider);
        }
        return providers.toOwnedSlice();
    }

    pub fn getModels(self: *const ModelRegistry, allocator: std.mem.Allocator, provider: []const u8) ![]types.Model {
        var items = std.array_list.Managed(types.Model).init(allocator);
        errdefer items.deinit();

        for (self.models.items) |model| {
            if (std.mem.eql(u8, model.provider, provider)) {
                try items.append(model);
            }
        }
        return items.toOwnedSlice();
    }
};

pub fn supportsXhigh(model: types.Model) bool {
    if (std.mem.indexOf(u8, model.id, "gpt-5.2") != null or std.mem.indexOf(u8, model.id, "gpt-5.3") != null) {
        return true;
    }

    if (std.mem.eql(u8, model.api, "anthropic-messages")) {
        return std.mem.indexOf(u8, model.id, "opus-4-6") != null or std.mem.indexOf(u8, model.id, "opus-4.6") != null;
    }

    return false;
}

pub fn modelsAreEqual(a: ?types.Model, b: ?types.Model) bool {
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?.id, b.?.id) and std.mem.eql(u8, a.?.provider, b.?.provider);
}

pub fn findModel(self: *const ModelRegistry, provider: ?[]const u8, query: []const u8) ?types.Model {
    if (provider) |p| {
        if (self.getModel(p, query)) |exact| return exact;
    } else if (std.mem.indexOfScalar(u8, query, '/')) |slash| {
        const query_provider = query[0..slash];
        const query_model = query[slash + 1 ..];
        if (self.getModel(query_provider, query_model)) |exact_scoped| return exact_scoped;
    }

    for (self.models.items) |model| {
        if (provider) |p| {
            if (!std.mem.eql(u8, model.provider, p)) continue;
        }
        if (std.mem.eql(u8, model.id, query)) return model;
    }
    for (self.models.items) |model| {
        if (provider) |p| {
            if (!std.mem.eql(u8, model.provider, p)) continue;
        }
        if (std.ascii.indexOfIgnoreCase(model.id, query) != null) return model;
    }
    for (self.models.items) |model| {
        if (provider) |p| {
            if (!std.mem.eql(u8, model.provider, p)) continue;
        }
        if (std.ascii.indexOfIgnoreCase(model.name, query) != null) return model;
    }
    return null;
}

pub fn selectDefaultModel(
    self: *const ModelRegistry,
    preferred_provider: ?[]const u8,
    preferred_model_id: ?[]const u8,
) ?types.Model {
    if (preferred_provider != null and preferred_model_id != null) {
        if (self.getModel(preferred_provider.?, preferred_model_id.?)) |preferred| return preferred;
    }

    if (preferred_provider) |provider| {
        for (self.models.items) |model| {
            if (std.mem.eql(u8, model.provider, provider)) return model;
        }
    }

    const provider_priority = [_][]const u8{
        "openai-codex-spark",
        "openai-codex",
        "openai",
        "anthropic",
        "kimi-code",
        "kimi-coding",
        "azure-openai-responses",
    };
    for (provider_priority) |provider| {
        for (self.models.items) |model| {
            if (std.mem.eql(u8, model.provider, provider)) return model;
        }
    }

    if (self.models.items.len == 0) return null;
    return self.models.items[0];
}

pub fn registerDefaultModels(registry: *ModelRegistry) !void {
    try generated.registerSupportedModelsFromTs(registry);

    try registry.register(.{
        .id = "kimi-k2-thinking",
        .name = "Kimi K2 Thinking",
        .api = "anthropic-messages",
        .provider = "kimi-code",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "k2p5",
        .name = "Kimi K2.5",
        .api = "anthropic-messages",
        .provider = "kimi-code",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "kimi-for-coding",
        .name = "Kimi For Coding",
        .api = "anthropic-messages",
        .provider = "kimi-code",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "kimi-k2.5",
        .name = "Kimi K2.5",
        .api = "anthropic-messages",
        .provider = "kimi-coding",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "kimi-k2.5",
        .name = "Kimi K2.5",
        .api = "anthropic-messages",
        .provider = "kimi-code",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "chatgpt5.3-spark",
        .name = "ChatGPT 5.3 Spark",
        .api = "openai-codex-responses",
        .provider = "openai-codex-spark",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 128_000,
        .max_tokens = 128_000,
    });
}

test "registerDefaultModels includes kimi-code provider aliases" {
    const allocator = std.testing.allocator;
    var registry = ModelRegistry.init(allocator);
    defer registry.deinit();
    try registerDefaultModels(&registry);

    const kimi_coding = registry.getModel("kimi-coding", "k2p5");
    try std.testing.expect(kimi_coding != null);
    try std.testing.expect(std.mem.eql(u8, kimi_coding.?.provider, "kimi-coding"));

    const kimi_code = registry.getModel("kimi-code", "k2p5");
    try std.testing.expect(kimi_code != null);
    try std.testing.expect(std.mem.eql(u8, kimi_code.?.provider, "kimi-code"));

    const kimi_for_coding = registry.getModel("kimi-code", "kimi-for-coding");
    try std.testing.expect(kimi_for_coding != null);
    try std.testing.expect(std.mem.eql(u8, kimi_for_coding.?.api, "anthropic-messages"));
}

test "registerDefaultModels includes openai-codex variants" {
    const allocator = std.testing.allocator;
    var registry = ModelRegistry.init(allocator);
    defer registry.deinit();
    try registerDefaultModels(&registry);

    const mini = registry.getModel("openai-codex", "gpt-5.1-codex-mini");
    const v5_1 = registry.getModel("openai-codex", "gpt-5.1");
    const v5_2 = registry.getModel("openai-codex", "gpt-5.2");
    const v5_3 = registry.getModel("openai-codex", "gpt-5.3-codex");
    const spark = registry.getModel("openai-codex", "gpt-5.3-codex-spark");
    const chatgpt_spark = registry.getModel("openai-codex-spark", "chatgpt5.3-spark");
    const google = registry.getModel("google", "gemini-2.5-pro");
    const google_cli = registry.getModel("google-gemini-cli", "gemini-2.5-pro");
    const google_vertex = registry.getModel("google-vertex", "gemini-2.5-pro");
    const bedrock = registry.getModel("amazon-bedrock", "anthropic.claude-3-7-sonnet-20250219-v1:0");
    const openrouter = registry.getModel("openrouter", "ai21/jamba-large-1.7");
    const groq = registry.getModel("groq", "deepseek-r1-distill-llama-70b");
    const minimax = registry.getModel("minimax", "MiniMax-M2");
    const vercel_gateway = registry.getModel("vercel-ai-gateway", "alibaba/qwen-3-14b");

    try std.testing.expect(mini != null);
    try std.testing.expect(v5_1 != null);
    try std.testing.expect(v5_2 != null);
    try std.testing.expect(v5_3 != null);
    try std.testing.expect(spark != null);
    try std.testing.expect(chatgpt_spark != null);
    try std.testing.expect(google != null);
    try std.testing.expect(google_cli != null);
    try std.testing.expect(google_vertex != null);
    try std.testing.expect(bedrock != null);
    try std.testing.expect(openrouter != null);
    try std.testing.expect(groq != null);
    try std.testing.expect(minimax != null);
    try std.testing.expect(vercel_gateway != null);
    try std.testing.expect(std.mem.eql(u8, mini.?.api, "openai-codex-responses"));
    try std.testing.expect(std.mem.eql(u8, v5_1.?.provider, "openai-codex"));
    try std.testing.expect(std.mem.eql(u8, v5_2.?.provider, "openai-codex"));
    try std.testing.expect(std.mem.eql(u8, spark.?.api, "openai-codex-responses"));
    try std.testing.expect(std.mem.eql(u8, chatgpt_spark.?.provider, "openai-codex-spark"));
    try std.testing.expect(std.mem.eql(u8, google.?.api, "google-generative-ai"));
    try std.testing.expect(std.mem.eql(u8, google_cli.?.api, "google-gemini-cli"));
    try std.testing.expect(std.mem.eql(u8, google_vertex.?.api, "google-vertex"));
    try std.testing.expect(std.mem.eql(u8, bedrock.?.api, "bedrock-converse-stream"));
    try std.testing.expect(std.mem.eql(u8, openrouter.?.api, "openai-completions"));
    try std.testing.expect(std.mem.eql(u8, groq.?.api, "openai-completions"));
    try std.testing.expect(std.mem.eql(u8, minimax.?.api, "anthropic-messages"));
    try std.testing.expect(std.mem.eql(u8, vercel_gateway.?.api, "anthropic-messages"));
}

test "supportsXhigh matches TS behavior" {
    const gpt_5_3: types.Model = .{
        .id = "gpt-5.3-codex",
        .name = "GPT-5.3 Codex",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    };
    const gpt_5_1: types.Model = .{
        .id = "gpt-5.1-codex-mini",
        .name = "GPT-5.1 Codex Mini",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    };
    const anthropic_opus: types.Model = .{
        .id = "claude-opus-4-6",
        .name = "Claude Opus 4.6",
        .api = "anthropic-messages",
        .provider = "anthropic",
        .base_url = "https://api.anthropic.com",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 200_000,
        .max_tokens = 32_000,
    };
    const openrouter_opus: types.Model = .{
        .id = "anthropic/claude-opus-4.6",
        .name = "OpenRouter Opus 4.6",
        .api = "openai-completions",
        .provider = "openrouter",
        .base_url = "https://openrouter.ai/api/v1",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 200_000,
        .max_tokens = 32_000,
    };

    try std.testing.expect(supportsXhigh(gpt_5_3));
    try std.testing.expect(!supportsXhigh(gpt_5_1));
    try std.testing.expect(supportsXhigh(anthropic_opus));
    try std.testing.expect(!supportsXhigh(openrouter_opus));
}

test "modelsAreEqual compares provider and id" {
    const model_a: types.Model = .{
        .id = "gpt-5.3-codex",
        .name = "GPT-5.3 Codex",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    };
    const model_b: types.Model = .{
        .id = "gpt-5.3-codex",
        .name = "GPT-5.3 Codex duplicate",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1, .output = 1 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    };
    const model_other_provider: types.Model = .{
        .id = "gpt-5.3-codex",
        .name = "GPT-5.3 Codex",
        .api = "openai-responses",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 400_000,
        .max_tokens = 128_000,
    };

    try std.testing.expect(modelsAreEqual(model_a, model_b));
    try std.testing.expect(!modelsAreEqual(model_a, model_other_provider));
    try std.testing.expect(!modelsAreEqual(model_a, null));
    try std.testing.expect(!modelsAreEqual(null, model_b));
}

test "ModelRegistry getProviders and getModels enumerate registry entries" {
    const allocator = std.testing.allocator;
    var registry = ModelRegistry.init(allocator);
    defer registry.deinit();
    try registerDefaultModels(&registry);

    const providers = try registry.getProviders(allocator);
    defer allocator.free(providers);
    try std.testing.expect(providers.len > 0);

    const openai_models = try registry.getModels(allocator, "openai");
    defer allocator.free(openai_models);
    try std.testing.expect(openai_models.len > 0);
}

test "findModel resolves exact, provider scoped, and fuzzy queries" {
    const allocator = std.testing.allocator;
    var registry = ModelRegistry.init(allocator);
    defer registry.deinit();
    try registerDefaultModels(&registry);

    const exact = findModel(&registry, "openai-codex", "gpt-5.1-codex-mini");
    try std.testing.expect(exact != null);
    try std.testing.expect(std.mem.eql(u8, exact.?.provider, "openai-codex"));

    const scoped = findModel(&registry, null, "openai-codex/gpt-5.3-codex");
    try std.testing.expect(scoped != null);
    try std.testing.expect(std.mem.eql(u8, scoped.?.id, "gpt-5.3-codex"));

    const provider_scoped = findModel(&registry, "openai-codex-spark", "chatgpt5.3");
    try std.testing.expect(provider_scoped != null);
    try std.testing.expect(std.mem.eql(u8, provider_scoped.?.id, "chatgpt5.3-spark"));

    const name_fuzzy = findModel(&registry, "openai-codex", "codex spark");
    try std.testing.expect(name_fuzzy != null);
    try std.testing.expect(std.mem.eql(u8, name_fuzzy.?.id, "gpt-5.3-codex-spark"));
}

test "selectDefaultModel applies preference and fallback policy" {
    const allocator = std.testing.allocator;
    var registry = ModelRegistry.init(allocator);
    defer registry.deinit();
    try registerDefaultModels(&registry);

    const preferred_exact = selectDefaultModel(&registry, "openai-codex", "gpt-5.1");
    try std.testing.expect(preferred_exact != null);
    try std.testing.expect(std.mem.eql(u8, preferred_exact.?.id, "gpt-5.1"));

    const preferred_provider = selectDefaultModel(&registry, "kimi-code", null);
    try std.testing.expect(preferred_provider != null);
    try std.testing.expect(std.mem.eql(u8, preferred_provider.?.provider, "kimi-code"));

    const prioritized = selectDefaultModel(&registry, null, null);
    try std.testing.expect(prioritized != null);
    try std.testing.expect(std.mem.eql(u8, prioritized.?.provider, "openai-codex-spark"));
}

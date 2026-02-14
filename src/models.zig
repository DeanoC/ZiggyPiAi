const std = @import("std");
const types = @import("types.zig");

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
};

pub fn registerDefaultModels(registry: *ModelRegistry) !void {
    try registry.register(.{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    });
    try registry.register(.{
        .id = "gpt-4.1-mini",
        .name = "GPT-4.1 mini",
        .api = "openai-responses",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = true,
        .cost = .{ .input = 0.40, .output = 1.60 },
        .context_window = 1_047_576,
        .max_tokens = 32_768,
    });
    try registry.register(.{
        .id = "gpt-5.1-codex-mini",
        .name = "GPT-5.1 Codex Mini",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 0.25, .output = 2.0, .cache_read = 0.025 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.1",
        .name = "GPT-5.1",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1.25, .output = 10.0, .cache_read = 0.125 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.1-codex-max",
        .name = "GPT-5.1 Codex Max",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1.25, .output = 10.0, .cache_read = 0.125 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.2",
        .name = "GPT-5.2",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1.75, .output = 14.0, .cache_read = 0.175 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.2-codex",
        .name = "GPT-5.2 Codex",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1.75, .output = 14.0, .cache_read = 0.175 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.3-codex",
        .name = "GPT-5.3 Codex",
        .api = "openai-codex-responses",
        .provider = "openai-codex",
        .base_url = "https://chatgpt.com/backend-api",
        .reasoning = true,
        .cost = .{ .input = 1.75, .output = 14.0, .cache_read = 0.175 },
        .context_window = 272_000,
        .max_tokens = 128_000,
    });
    try registry.register(.{
        .id = "gpt-5.3-codex-spark",
        .name = "GPT-5.3 Codex Spark",
        .api = "openai-responses",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    });
    try registry.register(.{
        .id = "k2p5",
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
        .id = "kimi-k2-thinking",
        .name = "Kimi K2 Thinking",
        .api = "anthropic-messages",
        .provider = "kimi-coding",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0, .cache_read = 0, .cache_write = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });
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

    try std.testing.expect(mini != null);
    try std.testing.expect(v5_1 != null);
    try std.testing.expect(v5_2 != null);
    try std.testing.expect(v5_3 != null);
    try std.testing.expect(std.mem.eql(u8, mini.?.api, "openai-codex-responses"));
    try std.testing.expect(std.mem.eql(u8, v5_1.?.provider, "openai-codex"));
    try std.testing.expect(std.mem.eql(u8, v5_2.?.provider, "openai-codex"));
}

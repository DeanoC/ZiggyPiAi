const std = @import("std");

pub const Api = []const u8;
pub const Provider = []const u8;

pub const StopReason = enum {
    stop,
    length,
    tool_use,
    err,
    aborted,
};

pub const UsageCost = struct {
    input: f64 = 0,
    output: f64 = 0,
    cache_read: f64 = 0,
    cache_write: f64 = 0,
    total: f64 = 0,
};

pub const Usage = struct {
    input: u32 = 0,
    output: u32 = 0,
    cache_read: u32 = 0,
    cache_write: u32 = 0,
    total_tokens: u32 = 0,
    cost: UsageCost = .{},
};

pub const MessageRole = enum {
    system,
    user,
    assistant,
    tool,
    tool_result,
};

pub const TextContent = struct {
    text: []const u8,
};

pub const ThinkingContent = struct {
    thinking: []const u8,
    signature: ?[]const u8 = null,
    redacted: bool = false,
    continuation_token: ?[]const u8 = null,
};

pub const ImageContent = struct {
    data: []const u8,
    mime_type: []const u8,
};

pub const MessageContent = union(enum) {
    text: TextContent,
    thinking: ThinkingContent,
    image: ImageContent,
};

pub const Message = struct {
    role: MessageRole,
    content: []const u8 = "",
    content_blocks: ?[]const MessageContent = null,
    tool_calls: ?[]const ToolCall = null,
    tool_call_id: ?[]const u8 = null,
    tool_name: ?[]const u8 = null,
    is_error: bool = false,
    stop_reason: StopReason = .stop,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Transport = enum {
    auto,
    sse,
    websocket,
};

pub const ThinkingLevel = enum {
    minimal,
    low,
    medium,
    high,
    xhigh,
};

pub const ThinkingBudget = struct {
    tokens: ?u32 = null,
    level: ?ThinkingLevel = null,
};

pub const GeminiThinking = union(enum) {
    budget_tokens: u32,
    level: ThinkingLevel,
};

pub const ToolChoice = union(enum) {
    auto,
    any,
    tool: []const u8,
};

pub const ReasoningOptions = struct {
    effort: ?ThinkingLevel = null,
};

pub const BedrockOptions = struct {
    region: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    tool_choice: ?ToolChoice = null,
    reasoning: ?ReasoningOptions = null,
    thinking_budget: ?ThinkingBudget = null,
    interleaved_thinking: ?bool = null,
};

pub const AntigravityConfig = struct {
    base_url: ?[]const u8 = null,
    fallback_base_url: ?[]const u8 = null,
    client_version: ?[]const u8 = null,
};

pub const MetadataEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    parameters_json: []const u8 = "{\"type\":\"object\",\"properties\":{}}",
};

pub const ModelCost = struct {
    input: f64,
    output: f64,
    cache_read: f64 = 0,
    cache_write: f64 = 0,
};

pub const Model = struct {
    id: []const u8,
    name: []const u8,
    api: Api,
    provider: Provider,
    base_url: []const u8,
    reasoning: bool,
    cost: ModelCost,
    context_window: u32,
    max_tokens: u32,
};

pub const StreamOptions = struct {
    temperature: ?f64 = null,
    max_tokens: ?u32 = null,
    api_key: ?[]const u8 = null,
    reasoning: ?[]const u8 = null,
    reasoning_summary: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    text_verbosity: ?[]const u8 = null,
    headers: ?[]const Header = null,
    transport: Transport = .auto,
    cache_retention: ?[]const u8 = null,
    max_retry_delay_ms: ?u32 = null,
    metadata: ?[]const MetadataEntry = null,
    thinking_budget: ?ThinkingBudget = null,
    gemini_thinking: ?GeminiThinking = null,
    bedrock: ?BedrockOptions = null,
    antigravity: ?AntigravityConfig = null,
    on_payload: ?*const fn (ctx: ?*anyopaque, payload: ProviderPayload) anyerror!void = null,
    on_payload_ctx: ?*anyopaque = null,
};

pub const Context = struct {
    system_prompt: ?[]const u8 = null,
    messages: []const Message,
    tools: ?[]const Tool = null,
};

pub const AssistantMessage = struct {
    text: []const u8,
    thinking: []const u8 = "",
    content_blocks: ?[]const MessageContent = null,
    tool_calls: []const ToolCall = &.{},
    api: Api,
    provider: Provider,
    model: []const u8,
    usage: Usage,
    stop_reason: StopReason = .stop,
    error_message: ?[]const u8 = null,
};

pub const ToolCall = struct {
    id: []const u8,
    name: []const u8,
    arguments_json: []const u8,
};

pub const TextDeltaEvent = struct {
    content_index: usize,
    delta: []const u8,
};

pub const TextEndEvent = struct {
    content_index: usize,
    content: []const u8,
};

pub const ToolCallDeltaEvent = struct {
    content_index: usize,
    delta: []const u8,
};

pub const ToolCallEndEvent = struct {
    content_index: usize,
    tool_call: ToolCall,
};

pub const ThinkingDeltaEvent = struct {
    content_index: usize,
    delta: []const u8,
};

pub const ThinkingEndEvent = struct {
    content_index: usize,
    content: []const u8,
};

pub const ProviderPayload = union(enum) {
    text_delta: TextDeltaEvent,
    thinking_delta: ThinkingDeltaEvent,
    tool_call_delta: ToolCallDeltaEvent,
    usage: Usage,
    raw_json: []const u8,
    done,
};

pub const AssistantMessageEvent = union(enum) {
    start: AssistantMessage,
    text_start: usize,
    text_delta: TextDeltaEvent,
    text_end: TextEndEvent,
    thinking_start: usize,
    thinking_delta: ThinkingDeltaEvent,
    thinking_end: ThinkingEndEvent,
    toolcall_start: usize,
    toolcall_delta: ToolCallDeltaEvent,
    toolcall_end: ToolCallEndEvent,
    done: AssistantMessage,
    err: []const u8,
};

pub fn calculateCost(model: Model, usage: *Usage) void {
    usage.cost.input = (model.cost.input / 1_000_000.0) * @as(f64, @floatFromInt(usage.input));
    usage.cost.output = (model.cost.output / 1_000_000.0) * @as(f64, @floatFromInt(usage.output));
    usage.cost.cache_read = (model.cost.cache_read / 1_000_000.0) * @as(f64, @floatFromInt(usage.cache_read));
    usage.cost.cache_write = (model.cost.cache_write / 1_000_000.0) * @as(f64, @floatFromInt(usage.cache_write));
    usage.cost.total = usage.cost.input + usage.cost.output + usage.cost.cache_read + usage.cost.cache_write;
}

pub fn cloneMessageContent(
    allocator: std.mem.Allocator,
    source: MessageContent,
) !MessageContent {
    return switch (source) {
        .text => |value| .{
            .text = .{
                .text = try allocator.dupe(u8, value.text),
            },
        },
        .thinking => |value| .{
            .thinking = .{
                .thinking = try allocator.dupe(u8, value.thinking),
                .signature = if (value.signature) |signature| try allocator.dupe(u8, signature) else null,
                .redacted = value.redacted,
                .continuation_token = if (value.continuation_token) |token| try allocator.dupe(u8, token) else null,
            },
        },
        .image => |value| .{
            .image = .{
                .data = try allocator.dupe(u8, value.data),
                .mime_type = try allocator.dupe(u8, value.mime_type),
            },
        },
    };
}

pub fn cloneMessageContents(
    allocator: std.mem.Allocator,
    source: []const MessageContent,
) ![]const MessageContent {
    if (source.len == 0) return &.{};
    const cloned = try allocator.alloc(MessageContent, source.len);
    var initialized: usize = 0;
    errdefer {
        while (initialized > 0) {
            initialized -= 1;
            switch (cloned[initialized]) {
                .text => |value| allocator.free(value.text),
                .thinking => |value| {
                    allocator.free(value.thinking);
                    if (value.signature) |signature| allocator.free(signature);
                    if (value.continuation_token) |token| allocator.free(token);
                },
                .image => |value| {
                    allocator.free(value.data);
                    allocator.free(value.mime_type);
                },
            }
        }
        allocator.free(cloned);
    }

    for (source, 0..) |block, index| {
        cloned[index] = try cloneMessageContent(allocator, block);
        initialized += 1;
    }

    return cloned;
}

pub fn freeMessageContents(
    allocator: std.mem.Allocator,
    blocks: []const MessageContent,
) void {
    for (blocks) |block| {
        switch (block) {
            .text => |value| allocator.free(value.text),
            .thinking => |value| {
                allocator.free(value.thinking);
                if (value.signature) |signature| allocator.free(signature);
                if (value.continuation_token) |token| allocator.free(token);
            },
            .image => |value| {
                allocator.free(value.data);
                allocator.free(value.mime_type);
            },
        }
    }
    if (blocks.len > 0) allocator.free(blocks);
}

test "calculateCost mirrors TS model" {
    var usage: Usage = .{
        .input = 1000,
        .output = 2000,
    };
    const model: Model = .{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://api.openai.com/v1",
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.60 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };
    calculateCost(model, &usage);
    try std.testing.expectApproxEqAbs(@as(f64, 0.00015), usage.cost.input, 0.000000001);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0012), usage.cost.output, 0.000000001);
}

test "stream options include parity defaults" {
    const opts: StreamOptions = .{};
    try std.testing.expect(opts.transport == .auto);
    try std.testing.expect(opts.cache_retention == null);
    try std.testing.expect(opts.max_retry_delay_ms == null);
    try std.testing.expect(opts.metadata == null);
    try std.testing.expect(opts.thinking_budget == null);
    try std.testing.expect(opts.gemini_thinking == null);
    try std.testing.expect(opts.bedrock == null);
    try std.testing.expect(opts.antigravity == null);
    try std.testing.expect(opts.on_payload == null);
    try std.testing.expect(opts.on_payload_ctx == null);
}

test "thinking budget can use tokens or level" {
    const level_budget: ThinkingBudget = .{ .level = .high };
    const token_budget: ThinkingBudget = .{ .tokens = 2048 };
    try std.testing.expect(level_budget.level == .high);
    try std.testing.expect(level_budget.tokens == null);
    try std.testing.expect(token_budget.tokens == 2048);
    try std.testing.expect(token_budget.level == null);
}

test "thinking content metadata defaults preserve compatibility" {
    const thinking: ThinkingContent = .{
        .thinking = "draft reasoning",
    };

    try std.testing.expectEqualStrings("draft reasoning", thinking.thinking);
    try std.testing.expect(thinking.signature == null);
    try std.testing.expect(!thinking.redacted);
    try std.testing.expect(thinking.continuation_token == null);
}

test "gemini thinking can use budget tokens or level" {
    const level_thinking: GeminiThinking = .{ .level = .medium };
    const budget_thinking: GeminiThinking = .{ .budget_tokens = 4096 };
    try std.testing.expect(level_thinking == .level);
    try std.testing.expect(level_thinking.level == .medium);
    try std.testing.expect(budget_thinking == .budget_tokens);
    try std.testing.expectEqual(@as(u32, 4096), budget_thinking.budget_tokens);
}

test "bedrock options support provider-specific overrides" {
    const bedrock: BedrockOptions = .{
        .region = "us-west-2",
        .profile = "dev",
        .tool_choice = .{ .tool = "get_weather" },
        .reasoning = .{ .effort = .high },
        .thinking_budget = .{ .tokens = 4096 },
        .interleaved_thinking = true,
    };

    try std.testing.expectEqualStrings("us-west-2", bedrock.region.?);
    try std.testing.expectEqualStrings("dev", bedrock.profile.?);
    try std.testing.expect(bedrock.tool_choice.? == .tool);
    try std.testing.expectEqualStrings("get_weather", bedrock.tool_choice.?.tool);
    try std.testing.expect(bedrock.reasoning.?.effort.? == .high);
    try std.testing.expectEqual(@as(u32, 4096), bedrock.thinking_budget.?.tokens.?);
    try std.testing.expectEqual(true, bedrock.interleaved_thinking.?);
}

test "antigravity config supports endpoint and version overrides" {
    const antigravity: AntigravityConfig = .{
        .base_url = "https://daily-cloudcode-pa.sandbox.googleapis.com",
        .fallback_base_url = "https://autopush-cloudcode-pa.sandbox.googleapis.com",
        .client_version = "1.18.4",
    };

    try std.testing.expectEqualStrings("https://daily-cloudcode-pa.sandbox.googleapis.com", antigravity.base_url.?);
    try std.testing.expectEqualStrings("https://autopush-cloudcode-pa.sandbox.googleapis.com", antigravity.fallback_base_url.?);
    try std.testing.expectEqualStrings("1.18.4", antigravity.client_version.?);
}

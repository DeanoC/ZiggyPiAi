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
};

pub const SimpleStreamOptions = struct {
    temperature: ?f64 = null,
    max_tokens: ?u32 = null,
    api_key: ?[]const u8 = null,
    reasoning: ?[]const u8 = null,
    reasoning_summary: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    text_verbosity: ?[]const u8 = null,
    headers: ?[]const Header = null,
};

pub const Context = struct {
    system_prompt: ?[]const u8 = null,
    messages: []const Message,
    tools: ?[]const Tool = null,
};

pub const AssistantMessage = struct {
    text: []const u8,
    thinking: []const u8 = "",
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

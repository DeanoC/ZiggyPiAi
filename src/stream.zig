const std = @import("std");
const types = @import("types.zig");
const api_registry_mod = @import("api_registry.zig");
const model_registry_mod = @import("models.zig");
const env_api_keys = @import("env_api_keys.zig");
const payload_hooks = @import("payload_hooks.zig");

fn freeMessageContent(
    allocator: std.mem.Allocator,
    message: *types.AssistantMessage,
) void {
    if (message.text.len > 0) allocator.free(message.text);
    if (message.thinking.len > 0) allocator.free(message.thinking);
    if (message.content_blocks) |blocks| types.freeMessageContents(allocator, blocks);
    if (message.error_message) |error_message| allocator.free(error_message);
    if (message.tool_calls.len > 0) {
        for (message.tool_calls) |tc| {
            allocator.free(tc.id);
            allocator.free(tc.name);
            allocator.free(tc.arguments_json);
        }
        allocator.free(message.tool_calls);
    }
}

fn freeMessageFromEvent(allocator: std.mem.Allocator, message: *types.AssistantMessage) void {
    freeMessageContent(allocator, message);
}

fn cloneToolCalls(
    allocator: std.mem.Allocator,
    source: []const types.ToolCall,
) ![]const types.ToolCall {
    if (source.len == 0) return &.{};
    const cloned = try allocator.alloc(types.ToolCall, source.len);
    var initialized: usize = 0;
    errdefer {
        while (initialized > 0) {
            initialized -= 1;
            allocator.free(cloned[initialized].id);
            allocator.free(cloned[initialized].name);
            allocator.free(cloned[initialized].arguments_json);
        }
        allocator.free(cloned);
    }
    for (source, 0..) |tool_call, i| {
        cloned[i] = .{
            .id = try allocator.dupe(u8, tool_call.id),
            .name = try allocator.dupe(u8, tool_call.name),
            .arguments_json = try allocator.dupe(u8, tool_call.arguments_json),
        };
        initialized += 1;
    }
    return cloned;
}

fn cloneAssistantMessage(
    allocator: std.mem.Allocator,
    source: types.AssistantMessage,
) !types.AssistantMessage {
    const cloned_tool_calls = try cloneToolCalls(allocator, source.tool_calls);
    errdefer {
        if (cloned_tool_calls.len > 0) {
            for (cloned_tool_calls) |tool_call| {
                allocator.free(tool_call.id);
                allocator.free(tool_call.name);
                allocator.free(tool_call.arguments_json);
            }
            allocator.free(cloned_tool_calls);
        }
    }
    const cloned_content_blocks = if (source.content_blocks) |blocks|
        try types.cloneMessageContents(allocator, blocks)
    else
        null;
    errdefer if (cloned_content_blocks) |blocks| types.freeMessageContents(allocator, blocks);
    return .{
        .text = try allocator.dupe(u8, source.text),
        .thinking = try allocator.dupe(u8, source.thinking),
        .content_blocks = cloned_content_blocks,
        .tool_calls = cloned_tool_calls,
        .api = try allocator.dupe(u8, source.api),
        .provider = try allocator.dupe(u8, source.provider),
        .model = try allocator.dupe(u8, source.model),
        .usage = source.usage,
        .stop_reason = source.stop_reason,
        .error_message = if (source.error_message) |err| try allocator.dupe(u8, err) else null,
    };
}

fn cloneFallbackError(
    allocator: std.mem.Allocator,
    model: types.Model,
    error_message: []const u8,
) !types.AssistantMessage {
    return types.AssistantMessage{
        .text = try allocator.dupe(u8, ""),
        .thinking = try allocator.dupe(u8, ""),
        .content_blocks = null,
        .tool_calls = &.{},
        .api = try allocator.dupe(u8, model.api),
        .provider = try allocator.dupe(u8, model.provider),
        .model = try allocator.dupe(u8, model.id),
        .usage = .{},
        .stop_reason = .err,
        .error_message = try allocator.dupe(u8, error_message),
    };
}

fn extractFinalMessage(allocator: std.mem.Allocator, model: types.Model, events: []const types.AssistantMessageEvent) !types.AssistantMessage {
    var done: ?types.AssistantMessage = null;
    for (events) |event| {
        switch (event) {
            .done => |msg| done = msg,
            .err => |error_message| {
                return try cloneFallbackError(allocator, model, error_message);
            },
            else => {},
        }
    }
    return try cloneAssistantMessage(allocator, done orelse return error.CompleteErrorUnavailable);
}

pub fn freeCompleteMessage(
    allocator: std.mem.Allocator,
    message: *types.AssistantMessage,
) void {
    if (message.api.len > 0) allocator.free(message.api);
    if (message.provider.len > 0) allocator.free(message.provider);
    if (message.model.len > 0) allocator.free(message.model);
    freeMessageContent(allocator, message);
    message.* = .{
        .text = "",
        .thinking = "",
        .content_blocks = null,
        .tool_calls = &.{},
        .api = "",
        .provider = "",
        .model = "",
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    };
}

fn freeEventPayloads(allocator: std.mem.Allocator, event: *types.AssistantMessageEvent) void {
    switch (event.*) {
        .start => |*start| freeMessageFromEvent(allocator, start),
        .done => |*done| freeMessageFromEvent(allocator, done),
        .text_delta => |*v| allocator.free(v.delta),
        .text_end => |*v| allocator.free(v.content),
        .thinking_delta => |*v| allocator.free(v.delta),
        .thinking_end => |*v| allocator.free(v.content),
        .toolcall_delta => |*v| allocator.free(v.delta),
        .toolcall_end => |*v| {
            allocator.free(v.tool_call.id);
            allocator.free(v.tool_call.name);
            allocator.free(v.tool_call.arguments_json);
        },
        .err => |v| allocator.free(v),
        else => {},
    }
}

fn resolveTransport(provider: api_registry_mod.ApiProvider, requested: types.Transport) !types.Transport {
    return switch (requested) {
        .sse => {
            if (!provider.supports_sse) return error.UnsupportedTransport;
            return .sse;
        },
        .websocket => {
            if (!provider.supports_websocket) return error.UnsupportedTransport;
            return .websocket;
        },
        .auto => {
            if (provider.supports_sse) return .sse;
            if (provider.supports_websocket) return .websocket;
            return error.UnsupportedTransport;
        },
    };
}

pub fn streamByModel(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const provider = api_registry.get(model.api) orelse return error.ProviderNotRegistered;
    var opts = options;
    var env_key: ?[]const u8 = null;
    defer if (env_key) |k| allocator.free(k);
    opts.transport = try resolveTransport(provider, opts.transport);
    if (opts.api_key == null) {
        env_key = env_api_keys.getEnvApiKey(allocator, model.provider);
        opts.api_key = env_key;
    }
    try provider.stream(allocator, client, model, context, opts, events);
}

pub fn streamByProviderModelId(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model_registry: *const model_registry_mod.ModelRegistry,
    provider: []const u8,
    model_id: []const u8,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const model = model_registry.getModel(provider, model_id) orelse return error.ModelNotFound;
    try streamByModel(allocator, client, api_registry, model, context, options, events);
}

pub fn streamSimpleByModel(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const provider = api_registry.get(model.api) orelse return error.ProviderNotRegistered;
    var opts = options;
    var env_key: ?[]const u8 = null;
    defer if (env_key) |k| allocator.free(k);
    opts.transport = try resolveTransport(provider, opts.transport);
    if (opts.api_key == null) {
        env_key = env_api_keys.getEnvApiKey(allocator, model.provider);
        opts.api_key = env_key;
    }

    if (provider.stream_simple) |stream_simple| {
        try stream_simple(allocator, client, model, context, opts, events);
        return;
    }

    try streamByModel(allocator, client, api_registry, model, context, opts, events);
}

pub fn streamSimpleByProviderModelId(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model_registry: *const model_registry_mod.ModelRegistry,
    provider: []const u8,
    model_id: []const u8,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    const model = model_registry.getModel(provider, model_id) orelse return error.ModelNotFound;
    try streamSimpleByModel(allocator, client, api_registry, model, context, options, events);
}

pub fn completeByModel(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
) !types.AssistantMessage {
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }
    try streamByModel(allocator, client, api_registry, model, context, options, &events);
    return try extractFinalMessage(allocator, model, events.items);
}

pub fn completeSimpleByModel(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
) !types.AssistantMessage {
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }
    try streamSimpleByModel(allocator, client, api_registry, model, context, options, &events);
    return try extractFinalMessage(allocator, model, events.items);
}

pub fn completeByProviderModelId(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model_registry: *const model_registry_mod.ModelRegistry,
    provider: []const u8,
    model_id: []const u8,
    context: types.Context,
    options: types.StreamOptions,
) !types.AssistantMessage {
    const model = model_registry.getModel(provider, model_id) orelse return error.ModelNotFound;
    return try completeByModel(allocator, client, api_registry, model, context, options);
}

pub fn completeSimpleByProviderModelId(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_registry: *api_registry_mod.ApiRegistry,
    model_registry: *const model_registry_mod.ModelRegistry,
    provider: []const u8,
    model_id: []const u8,
    context: types.Context,
    options: types.StreamOptions,
) !types.AssistantMessage {
    const model = model_registry.getModel(provider, model_id) orelse return error.ModelNotFound;
    return try completeSimpleByModel(allocator, client, api_registry, model, context, options);
}

fn fakeStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    _ = client;
    _ = context;
    const msg: types.AssistantMessage = .{
        .text = try allocator.dupe(u8, model.id),
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
        .stop_reason = if (options.api_key != null) .stop else .err,
    };
    try payload_hooks.appendDone(events, options, msg);
}

fn fakeErrStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    _ = client;
    _ = model;
    _ = context;
    _ = options;
    try events.append(.{ .err = try allocator.dupe(u8, "forced error") });
}

fn fakeSimpleStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    _ = client;
    _ = model;
    _ = context;
    const msg: types.AssistantMessage = .{
        .text = try allocator.dupe(u8, options.reasoning orelse "simple"),
        .thinking = "",
        .tool_calls = &.{},
        .api = "simple",
        .provider = "simple",
        .model = "simple",
        .usage = .{},
        .stop_reason = if (options.api_key != null) .stop else .err,
    };
    try payload_hooks.appendDone(events, options, msg);
}

fn fakeHookStream(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) !void {
    _ = client;
    _ = context;
    try events.append(.{ .start = .{
        .text = "",
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
    } });
    try payload_hooks.dispatchRawJson(options, "{\"frame\":\"hook\"}");
    try payload_hooks.appendTextDelta(allocator, events, options, 0, "hello");
    try payload_hooks.dispatchUsage(options, .{ .input = 1, .output = 2, .total_tokens = 3 });
    const msg: types.AssistantMessage = .{
        .text = try allocator.dupe(u8, "hello"),
        .thinking = "",
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{ .input = 1, .output = 2, .total_tokens = 3 },
        .stop_reason = .stop,
    };
    try payload_hooks.appendDone(events, options, msg);
}

test "streamByProviderModelId dispatches registered provider" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeStream });

    var model_registry = model_registry_mod.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try model_registry.register(.{
        .id = "m",
        .name = "m",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    });

    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamByProviderModelId(allocator, &client, &api_registry, &model_registry, "openai", "m", ctx, .{ .api_key = "x" }, &events);
    try std.testing.expect(events.items.len == 1);
}

test "resolveTransport prefers sse for current providers" {
    const transport = try resolveTransport(.{
        .api = "openai-completions",
        .stream = fakeStream,
    }, .auto);
    try std.testing.expect(transport == .sse);
}

test "resolveTransport rejects unsupported websocket transport" {
    try std.testing.expectError(error.UnsupportedTransport, resolveTransport(.{
        .api = "openai-completions",
        .stream = fakeStream,
    }, .websocket));
}

test "streamSimpleByProviderModelId dispatches registered provider" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeStream });

    var model_registry = model_registry_mod.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try model_registry.register(.{
        .id = "m2",
        .name = "m2",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    });

    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamSimpleByProviderModelId(allocator, &client, &api_registry, &model_registry, "openai", "m2", ctx, .{ .api_key = "x" }, &events);
    try std.testing.expect(events.items.len == 1);
}

test "streamSimpleByModel uses provider stream_simple when available" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{
        .api = "openai-completions",
        .stream = fakeStream,
        .stream_simple = fakeSimpleStream,
    });

    const model: types.Model = .{
        .id = "m_simple",
        .name = "m_simple",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    };
    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamSimpleByModel(allocator, &client, &api_registry, model, ctx, .{ .api_key = "x", .reasoning = "from-simple" }, &events);
    try std.testing.expect(events.items.len == 1);
    switch (events.items[0]) {
        .done => |done| try std.testing.expectEqualStrings("from-simple", done.text),
        else => return error.TestUnexpectedResult,
    }
}

test "streamByModel dispatches normalized payload hooks" {
    const Capture = struct {
        raw_json_count: usize = 0,
        text_delta_count: usize = 0,
        usage_count: usize = 0,
        done_count: usize = 0,

        fn handle(raw_ctx: ?*anyopaque, payload: types.ProviderPayload) !void {
            const ctx_ptr = raw_ctx orelse return error.MissingContext;
            const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr));
            switch (payload) {
                .raw_json => ctx.raw_json_count += 1,
                .text_delta => ctx.text_delta_count += 1,
                .usage => ctx.usage_count += 1,
                .done => ctx.done_count += 1,
                else => {},
            }
        }
    };

    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeHookStream });

    const model: types.Model = .{
        .id = "m_hook",
        .name = "m_hook",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    };
    const ctx: types.Context = .{ .messages = &.{} };
    var capture = Capture{};
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamByModel(allocator, &client, &api_registry, model, ctx, .{
        .api_key = "x",
        .on_payload = Capture.handle,
        .on_payload_ctx = &capture,
    }, &events);

    try std.testing.expectEqual(@as(usize, 1), capture.raw_json_count);
    try std.testing.expectEqual(@as(usize, 1), capture.text_delta_count);
    try std.testing.expectEqual(@as(usize, 1), capture.usage_count);
    try std.testing.expectEqual(@as(usize, 1), capture.done_count);
}

test "streamByModel aborts when payload hook fails" {
    const FailingCapture = struct {
        fn handle(_: ?*anyopaque, payload: types.ProviderPayload) !void {
            if (payload == .text_delta) return error.PayloadHookFailed;
        }
    };

    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeHookStream });

    const model: types.Model = .{
        .id = "m_hook_fail",
        .name = "m_hook_fail",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    };
    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try std.testing.expectError(error.PayloadHookFailed, streamByModel(allocator, &client, &api_registry, model, ctx, .{
        .api_key = "x",
        .on_payload = FailingCapture.handle,
    }, &events));
}

test "completeByModel returns final assistant message" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeStream });

    const model: types.Model = .{
        .id = "m3",
        .name = "m3",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    };
    const ctx: types.Context = .{ .messages = &.{} };

    var done = try completeByModel(allocator, &client, &api_registry, model, ctx, .{ .api_key = "x" });
    defer freeCompleteMessage(allocator, &done);
    try std.testing.expectEqualStrings(done.model, "m3");
    try std.testing.expect(done.stop_reason == .stop);
}

test "completeByProviderModelId returns error response event as fallback" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-completions", .stream = fakeErrStream });

    var model_registry = model_registry_mod.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try model_registry.register(.{
        .id = "m4",
        .name = "m4",
        .api = "openai-completions",
        .provider = "openai",
        .base_url = "https://example.com",
        .reasoning = false,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 1,
        .max_tokens = 1,
    });
    const ctx: types.Context = .{ .messages = &.{} };

    var fallback = try completeByProviderModelId(allocator, &client, &api_registry, &model_registry, "openai", "m4", ctx, .{});
    defer freeCompleteMessage(allocator, &fallback);
    try std.testing.expect(fallback.stop_reason == .err);
    try std.testing.expect(fallback.error_message != null);
}

test "streamByProviderModelId dispatches openai-codex provider" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "openai-codex-responses", .stream = fakeStream });

    var model_registry = model_registry_mod.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try model_registry.register(.{
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

    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamByProviderModelId(allocator, &client, &api_registry, &model_registry, "openai-codex", "gpt-5.1-codex-mini", ctx, .{ .api_key = "x" }, &events);
    try std.testing.expect(events.items.len == 1);
}

test "streamByProviderModelId dispatches kimi-code provider via anthropic adapter" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var api_registry = api_registry_mod.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try api_registry.register(.{ .api = "anthropic-messages", .stream = fakeStream });

    var model_registry = model_registry_mod.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try model_registry.register(.{
        .id = "k2p5",
        .name = "Kimi K2.5",
        .api = "anthropic-messages",
        .provider = "kimi-code",
        .base_url = "https://api.kimi.com/coding",
        .reasoning = true,
        .cost = .{ .input = 0, .output = 0 },
        .context_window = 262_144,
        .max_tokens = 32_768,
    });

    const ctx: types.Context = .{ .messages = &.{} };
    var events = std.array_list.Managed(types.AssistantMessageEvent).init(allocator);
    defer {
        for (events.items) |*event| freeEventPayloads(allocator, event);
        events.deinit();
    }

    try streamByProviderModelId(allocator, &client, &api_registry, &model_registry, "kimi-code", "k2p5", ctx, .{ .api_key = "x" }, &events);
    try std.testing.expect(events.items.len == 1);
}

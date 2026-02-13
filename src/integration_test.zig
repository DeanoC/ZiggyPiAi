const std = @import("std");
const api_registry = @import("api_registry.zig");
const models = @import("models.zig");
const providers = @import("providers/register_builtins.zig");
const stream = @import("stream.zig");
const types = @import("types.zig");

const net = std.net;
const json = std.json;
const fmt = std.fmt;
const mem = std.mem;
const atomic = std.atomic;
const AtomicBool = atomic.Value(bool);
const Thread = std.Thread;
const http = std.http;

const IntegrationServerArgs = struct {
    allocator: std.mem.Allocator,
    server: *net.Server,
    ready: *AtomicBool,
    expected_api_key: []const u8,
    expected_message: []const u8,
    expected_response_message: []const u8,
    expected_model_id: []const u8,
};

fn readDotEnvKey(allocator: std.mem.Allocator, key: []const u8) ?[]const u8 {
    const cwd = std.fs.cwd();
    const file = cwd.openFile(".env", .{ .mode = .read_only }) catch return null;
    defer file.close();

    const contents = file.readToEndAlloc(allocator, 8 * 1024) catch return null;
    defer allocator.free(contents);

    var lines = mem.splitSequence(u8, contents, "\n");
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const eq = mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const name = mem.trim(u8, trimmed[0..eq], " \t");
        if (!mem.eql(u8, name, key)) continue;
        var value = mem.trim(u8, trimmed[eq + 1 ..], " \t\r");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1..value.len - 1];
        }
        return allocator.dupe(u8, value) catch return null;
    }
    return null;
}

fn loadOpenAiApiKey(allocator: std.mem.Allocator) ?[]const u8 {
    const env_value = std.process.getEnvVarOwned(allocator, "OPENAI_API_KEY") catch null;
    if (env_value) |value| return value;
    return readDotEnvKey(allocator, "OPENAI_API_KEY");
}

fn shouldRunLiveCodexSmokeTest() bool {
    const allocator = std.heap.page_allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "ZIGGY_RUN_LIVE_CODEX_TEST") catch return false;
    defer allocator.free(enabled);
    return mem.eql(u8, enabled, "1") or mem.eql(u8, enabled, "true") or mem.eql(u8, enabled, "yes");
}

fn shouldRunLiveKimiSmokeTest() bool {
    const allocator = std.heap.page_allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "ZIGGY_RUN_LIVE_KIMI_TEST") catch return false;
    defer allocator.free(enabled);
    return mem.eql(u8, enabled, "1") or mem.eql(u8, enabled, "true") or mem.eql(u8, enabled, "yes");
}

fn assertRequestHeaderMatches(authorization: []const u8, expected_key: []const u8) void {
    const prefix = "Bearer ";
    if (authorization.len != prefix.len + expected_key.len) {
        std.debug.panic(
            "authorization header length mismatch (got {d}, want {d})\n",
            .{ authorization.len, prefix.len + expected_key.len },
        );
    }
    if (!mem.startsWith(u8, authorization, prefix)) {
        std.debug.panic("authorization header missing 'Bearer ' prefix\n", .{});
    }
    if (!mem.eql(u8, authorization[prefix.len..], expected_key)) {
        std.debug.panic("authorization header value does not match expected key\n", .{});
    }
}

fn integrationServerWorker(args: *IntegrationServerArgs) void {
    defer args.server.deinit();
    args.ready.*.store(true, .seq_cst);

    const connection = args.server.accept() catch |err| {
        std.debug.panic("server accept failed: {s}\n", .{@errorName(err)});
    };
    defer connection.stream.close();

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader_stream = net.Stream.reader(connection.stream, &read_buf);
    var writer_stream = net.Stream.writer(connection.stream, &write_buf);
    var server = http.Server.init(reader_stream.interface(), &writer_stream.interface);

    var request = server.receiveHead() catch |err| {
        std.debug.panic("failed to read request head: {s}\n", .{@errorName(err)});
    };

    if (request.head.method != .POST) {
        std.debug.panic("expected POST request but got {s}\n", .{ @tagName(request.head.method) });
    }

    var headers = mem.splitSequence(u8, request.head_buffer, "\r\n");
    _ = headers.next(); // Skip the request line.
    var found_auth = false;
    while (headers.next()) |line| {
        if (line.len == 0) break;
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            const value = mem.trim(u8, line[colon + 1 ..], " \t");
            assertRequestHeaderMatches(value, args.expected_api_key);
            found_auth = true;
        }
    }
    if (!found_auth) {
        std.debug.panic("missing Authorization header\n", .{});
    }

    var body_buf: [4096]u8 = undefined;
    const body_reader = request.readerExpectNone(&body_buf);
    var body_arr = std.array_list.Managed(u8).init(args.allocator);
    defer body_arr.deinit();
    read_loop: while (true) {
        var chunk_array: [1][]u8 = undefined;
        chunk_array[0] = body_buf[0..];
        const n = body_reader.readVec(chunk_array[0..]) catch |err| switch (err) {
            error.EndOfStream => break :read_loop,
            error.ReadFailed => std.debug.panic("failed to read request body: {s}\n", .{@errorName(error.ReadFailed)}),
        };
        if (n == 0) break;
        body_arr.appendSlice(body_buf[0..n]) catch |err| std.debug.panic("failed to buffer request body: {s}\n", .{@errorName(err)});
    }

    const body = body_arr.toOwnedSlice() catch |err| std.debug.panic("failed to allocate request body: {s}\n", .{@errorName(err)});
    defer args.allocator.free(body);

    var parsed = json.parseFromSlice(json.Value, args.allocator, body, .{}) catch |err| {
        std.debug.panic("failed to parse JSON body: {s}\n", .{@errorName(err)});
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        std.debug.panic("request body is not a JSON object\n", .{});
    }

    if (parsed.value.object.get("model") orelse null) |model_v| {
        if (model_v != .string or !mem.eql(u8, model_v.string, args.expected_model_id)) {
            std.debug.panic("model mismatch in request\n", .{});
        }
    } else {
        std.debug.panic("model field missing in request\n", .{});
    }

    const input_field = parsed.value.object.get("input") orelse std.debug.panic("input field missing\n", .{});
    if (input_field != .array or input_field.array.items.len == 0) {
        std.debug.panic("input must be a non-empty array\n", .{});
    }
    const first_item = input_field.array.items[0];
    if (first_item != .object) {
        std.debug.panic("first input entry must be an object\n", .{});
    }
    const content_field = first_item.object.get("content") orelse std.debug.panic("input entry missing content\n", .{});
    if (content_field != .array or content_field.array.items.len == 0) {
        std.debug.panic("content must be an array with at least one item\n", .{});
    }
    const first_content = content_field.array.items[0];
    if (first_content != .object) {
        std.debug.panic("content entry must be an object\n", .{});
    }
    const content_type = first_content.object.get("type") orelse std.debug.panic("content entry missing type\n", .{});
    if (content_type != .string or !mem.eql(u8, content_type.string, "input_text")) {
        std.debug.panic("content entry must have type \"input_text\"\n", .{});
    }
    const text_field = first_content.object.get("text") orelse std.debug.panic("content entry missing text\n", .{});
    if (text_field != .string or !mem.eql(u8, text_field.string, args.expected_message)) {
        std.debug.panic("input text does not match expectation\n", .{});
    }

    var payload = std.array_list.Managed(u8).init(args.allocator);
    defer payload.deinit();

    payload.writer().writeAll("data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"message\"}}\r\n\r\n") catch |err| std.debug.panic("failed to write payload header: {s}\n", .{@errorName(err)});
    const delta_line = fmt.allocPrint(args.allocator, "data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{s}\"}}\r\n\r\n", .{args.expected_response_message}) catch |err| std.debug.panic("failed to format delta line: {s}\n", .{@errorName(err)});
    defer args.allocator.free(delta_line);
    payload.writer().writeAll(delta_line) catch |err| std.debug.panic("failed to write delta chunk: {s}\n", .{@errorName(err)});
    payload.writer().writeAll("data: {\"type\":\"response.output_item.done\"}\r\n\r\n") catch |err| std.debug.panic("failed to write end chunk: {s}\n", .{@errorName(err)});
    payload.writer().writeAll("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\r\n\r\n") catch |err| std.debug.panic("failed to write completed chunk: {s}\n", .{@errorName(err)});
    payload.writer().writeAll("data: {\"type\":\"response.done\",\"response\":{\"status\":\"completed\"}}\r\n\r\n") catch |err| std.debug.panic("failed to write done chunk: {s}\n", .{@errorName(err)});
    payload.writer().writeAll("data: [DONE]\r\n\r\n") catch |err| std.debug.panic("failed to write done marker: {s}\n", .{@errorName(err)});

    const payload_slice = payload.toOwnedSlice() catch |err| std.debug.panic("failed to finalize payload: {s}\n", .{@errorName(err)});
    defer args.allocator.free(payload_slice);

    const writer = &writer_stream.interface;
    writer.writeAll("HTTP/1.1 200 OK\r\n") catch |err| std.debug.panic("failed to write response head: {s}\n", .{@errorName(err)});
    writer.writeAll("content-type: text/event-stream\r\nconnection: close\r\n\r\n") catch |err| std.debug.panic("failed to write response headers: {s}\n", .{@errorName(err)});
    writer.writeAll(payload_slice) catch |err| std.debug.panic("failed to write payload: {s}\n", .{@errorName(err)});
    writer.flush() catch |err| std.debug.panic("failed to flush response: {s}\n", .{@errorName(err)});
}

test "openai responses integration" {
    const allocator = std.testing.allocator;
    const api_key = loadOpenAiApiKey(allocator) orelse return;
    defer allocator.free(api_key);

    const prompt = "integration test ping";
    const server_response = "integration response text";

    const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
    var server_value = try net.Address.listen(listen_addr, .{});
    const port = server_value.listen_address.getPort();

    const server_storage = try allocator.create(net.Server);
    server_storage.* = server_value;
    defer allocator.destroy(server_storage);

    var server_ready = AtomicBool.init(false);
    var server_ctx = IntegrationServerArgs{
        .allocator = allocator,
        .server = server_storage,
        .ready = &server_ready,
        .expected_api_key = api_key,
        .expected_message = prompt,
        .expected_response_message = server_response,
        .expected_model_id = "gpt-4o-mini",
    };

    const server_thread = try Thread.spawn(.{}, integrationServerWorker, .{ &server_ctx });
    defer server_thread.join();
    while (!server_ready.load(.seq_cst)) {
        _ = Thread.yield() catch {};
    }

    const base_url = try fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{port});
    defer allocator.free(base_url);

    const model = types.Model{
        .id = "gpt-4o-mini",
        .name = "GPT-4o mini",
        .api = "openai-responses",
        .provider = "openai",
        .base_url = base_url,
        .reasoning = false,
        .cost = .{ .input = 0.15, .output = 0.6 },
        .context_window = 128_000,
        .max_tokens = 16_384,
    };

    const user_message = types.Message{ .role = .user, .content = prompt };
    var context_messages: [1]types.Message = .{ user_message };
    const context = types.Context{ .messages = context_messages[0..] };

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var registry = api_registry.ApiRegistry.init(allocator);
    defer registry.deinit();
    try providers.registerBuiltInApiProviders(&registry);

    var completed = try stream.completeSimpleByModel(allocator, &client, &registry, model, context, .{ .api_key = api_key });
    defer stream.freeCompleteMessage(allocator, &completed);

    try std.testing.expectEqualStrings(completed.text, server_response);
    try std.testing.expect(mem.eql(u8, completed.model, model.id));
}

test "openai codex live smoke" {
    if (!shouldRunLiveCodexSmokeTest()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const prompt = "Answer with exactly one character: 4";
    const user_message = types.Message{ .role = .user, .content = prompt };
    var context_messages: [1]types.Message = .{ user_message };
    const context = types.Context{
        .system_prompt = "You are a concise assistant. Follow the user's instruction exactly.",
        .messages = context_messages[0..],
    };

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var registry = api_registry.ApiRegistry.init(allocator);
    defer registry.deinit();
    try providers.registerBuiltInApiProviders(&registry);

    var model_registry = models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try models.registerDefaultModels(&model_registry);

    const model = model_registry.getModel("openai-codex", "gpt-5.1-codex-mini") orelse return error.ModelNotFound;
    var completed = try stream.completeSimpleByModel(allocator, &client, &registry, model, context, .{});
    defer stream.freeCompleteMessage(allocator, &completed);

    if (completed.error_message) |message| {
        std.debug.print("live codex call returned error: {s}\n", .{message});
        return error.TestUnexpectedResult;
    }
    try std.testing.expect(completed.text.len > 0);
    try std.testing.expect(mem.indexOf(u8, completed.text, "4") != null);
}

test "kimi code live smoke" {
    if (!shouldRunLiveKimiSmokeTest()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const prompt = "Answer with exactly one character: 4";
    const user_message = types.Message{ .role = .user, .content = prompt };
    var context_messages: [1]types.Message = .{ user_message };
    const context = types.Context{
        .system_prompt = "You are a concise assistant. Follow the user's instruction exactly.",
        .messages = context_messages[0..],
    };

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var registry = api_registry.ApiRegistry.init(allocator);
    defer registry.deinit();
    try providers.registerBuiltInApiProviders(&registry);

    var model_registry = models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try models.registerDefaultModels(&model_registry);

    const model = model_registry.getModel("kimi-code", "k2p5") orelse return error.ModelNotFound;
    var completed = try stream.completeSimpleByModel(allocator, &client, &registry, model, context, .{});
    defer stream.freeCompleteMessage(allocator, &completed);

    if (completed.error_message) |message| {
        std.debug.print("live kimi call returned error: {s}\n", .{message});
        return error.TestUnexpectedResult;
    }
    try std.testing.expect(completed.text.len > 0);
    try std.testing.expect(mem.indexOf(u8, completed.text, "4") != null);
}

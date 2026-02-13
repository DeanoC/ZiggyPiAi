const std = @import("std");
const types = @import("types.zig");

pub const StreamFn = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    model: types.Model,
    context: types.Context,
    options: types.StreamOptions,
    events: *std.array_list.Managed(types.AssistantMessageEvent),
) anyerror!void;

pub const ApiProvider = struct {
    api: []const u8,
    stream: StreamFn,
};

pub const ApiRegistry = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(ApiProvider),

    pub fn init(allocator: std.mem.Allocator) ApiRegistry {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(ApiProvider).init(allocator),
        };
    }

    pub fn deinit(self: *ApiRegistry) void {
        self.map.deinit();
    }

    pub fn register(self: *ApiRegistry, provider: ApiProvider) !void {
        try self.map.put(provider.api, provider);
    }

    pub fn get(self: *ApiRegistry, api: []const u8) ?ApiProvider {
        return self.map.get(api);
    }

    pub fn clear(self: *ApiRegistry) void {
        self.map.clearAndFree();
    }
};

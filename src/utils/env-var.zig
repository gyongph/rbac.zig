const std = @import("std");

pub fn get(key: []const u8) ![]const u8 {
    const allocator = std.heap.page_allocator;
    const env = try std.process.getEnvVarOwned(allocator, key);
    defer allocator.free(env);
    return std.heap.page_allocator.dupe(u8, env);
}

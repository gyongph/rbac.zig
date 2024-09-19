const std = @import("std");
const random = std.crypto.random;
const fmt = std.fmt;

pub fn randomInt(min: usize, max: usize) usize {
    return random.intRangeAtMost(usize, min, max);
}
pub fn allocToString(allocator: std.mem.Allocator, number: usize, comptime _fmt: []const u8) ![]u8 {
    return fmt.allocPrint(allocator, _fmt, .{number});
}

pub fn toString(comptime num: anytype, comptime _fmt: []const u8) *const [fmt.count(_fmt, .{num}):0]u8 {
    return fmt.comptimePrint(_fmt, .{num});
}

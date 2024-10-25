const std = @import("std");
const testing = std.testing;

const seed = "c3DEuvSTUVWLMAa1b2HdOPpFG56fmn0ostq7g84eBCwxyKQijklrzRNh9IJXYZ";
pub fn random(comptime len: usize) [len]u8 {
    std.debug.assert(len > 0);
    var buff: [len]u8 = undefined;
    var counter = len;
    const rand = std.crypto.random;

    while (counter > 0) : (counter -= 1) {
        const random_index = rand.intRangeAtMost(u6, 0, seed.len - 1);
        buff[counter - 1] = seed[random_index];
    }
    return buff;
}

test "random" {
    const random_sample = random(25);
    try testing.expect(random_sample.len == 25);
    try testing.expect(@TypeOf(random_sample) == [25]u8);
    const invalid_char_pos = std.mem.indexOfNonePos(u8, &random_sample, 0, seed); // checks if found unknown character
    try testing.expect(invalid_char_pos == null);
}

pub fn allocRandom(allocator: std.mem.Allocator, len: usize) ![]u8 {
    std.debug.assert(len > 0);
    var buff = try allocator.alloc(u8, len);
    var counter = len;
    const rand = std.crypto.random;

    while (counter > 0) : (counter -= 1) {
        const random_index = rand.intRangeAtMost(u6, 0, seed.len - 1);
        buff[counter - 1] = seed[random_index];
    }
    return buff;
}
test "allocRandom" {
    const random_sample = try allocRandom(testing.allocator, 25);
    defer testing.allocator.free(random_sample);
    try testing.expect(random_sample.len == 25);
    try testing.expectEqual(@TypeOf(random_sample), []u8);
    const invalid_char_pos = std.mem.indexOfNonePos(u8, random_sample, 0, seed); // checks if found unknown character
    try testing.expect(invalid_char_pos == null);
}

pub fn isStringType(T: type) bool {
    const info = @typeInfo(T);
    switch (info) {
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) return true;
            return isStringType(ptr.child);
        },
        .optional => |opt| return isStringType(opt.child),
        .array => |arr| {
            if (arr.child == u8) return true;
            return false;
        },
        else => return false,
    }
}

test isStringType {
    try testing.expect(isStringType([]u8));
    try testing.expect(isStringType(*[]u8));
    try testing.expect(isStringType(*?[]u8));
    try testing.expect(isStringType(?*[]u8));
    try testing.expect(isStringType(?[]u8));
    try testing.expect(isStringType([]const u8));
    try testing.expect(isStringType(*[]const u8));
    try testing.expect(isStringType(?[]const u8));
    try testing.expect(isStringType(?*[]const u8));
    try testing.expect(isStringType(u8) == false);
    try testing.expect(isStringType(?u8) == false);
    try testing.expect(isStringType(*u8) == false);
    try testing.expect(isStringType(?*u8) == false);
    try testing.expect(isStringType(*?u8) == false);
    try testing.expect(isStringType(u1) == false);
    try testing.expect(isStringType([]u1) == false);
    try testing.expect(isStringType(*[]u1) == false);
    try testing.expect(isStringType(?[]u1) == false);
    try testing.expect(isStringType(*?[]u1) == false);
    try testing.expect(isStringType(?*[]u1) == false);
    try testing.expect(isStringType(i16) == false);
    try testing.expect(isStringType(?i16) == false);
    try testing.expect(isStringType(*i16) == false);
    try testing.expect(isStringType(?*i16) == false);
    try testing.expect(isStringType(*?i16) == false);
    try testing.expect(isStringType(i16) == false);
    try testing.expect(isStringType([]i16) == false);
    try testing.expect(isStringType(*[]i16) == false);
    try testing.expect(isStringType(?[]i16) == false);
    try testing.expect(isStringType(*?[]i16) == false);
    try testing.expect(isStringType(?*[]i16) == false);
}

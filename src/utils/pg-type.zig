const std = @import("std");
const EnumSet = std.EnumSet;
const ArrayList = std.ArrayList;
const testing = std.testing;

fn getBaseType(T: type) type {
    const info = @typeInfo(T);
    switch (info) {
        .pointer => |ptr| {
            if (ptr.size == .Slice) return T;
            return getBaseType(ptr.child);
        },
        .optional => |opt| return getBaseType(opt.child),
        else => return T,
    }
}

const number_enum = enum { one, two, thre };

test getBaseType {
    try testing.expectEqual(u8, getBaseType(*u8));
    try testing.expectEqual(u8, getBaseType(?u8));
    try testing.expectEqual(u8, getBaseType(?*u8));
    try testing.expectEqual(u8, getBaseType(*?u8));
    try testing.expectEqual([]u8, getBaseType(*[]u8));
    try testing.expectEqual([]u8, getBaseType(?[]u8));
    try testing.expectEqual([]u8, getBaseType(?*[]u8));
    try testing.expectEqual([]u8, getBaseType(*?[]u8));
    try testing.expectEqual([][]*?u8, getBaseType([][]*?u8));
    try testing.expectEqual(number_enum, getBaseType(*number_enum));
    try testing.expectEqual(number_enum, getBaseType(?number_enum));
    try testing.expectEqual(number_enum, getBaseType(?*number_enum));
    try testing.expectEqual(number_enum, getBaseType(*?number_enum));
    try testing.expectEqual([]number_enum, getBaseType(*[]number_enum));
    try testing.expectEqual([]number_enum, getBaseType(?[]number_enum));
    try testing.expectEqual([]number_enum, getBaseType(?*[]number_enum));
    try testing.expectEqual([]number_enum, getBaseType(*?[]number_enum));
    try testing.expectEqual([][]*?number_enum, getBaseType([][]*?number_enum));
}

pub fn get(comptime T: type) switch (getBaseType(T)) {
    []const u8, []u8 => *const [2 + 4:0]u8,
    [][]const u8, [][]u8 => *const [2 + 6:0]u8,
    i16 => *const [2 + 8:0]u8,
    []i16 => *const [2 + 10:0]u8,
    i64 => *const [2 + 6:0]u8,
    []i64 => *const [2 + 8:0]u8,
    bool => *const [2 + 4:0]u8,
    []bool => *const [2 + 6:0]u8,
    else => *const [0:0]u8,
} {
    const base_type = getBaseType(T);
    return switch (base_type) {
        []const u8, []u8 => "::TEXT",
        [][]const u8, [][]u8 => "::TEXT[]",
        i16 => "::SMALLINT",
        []i16 => "::SMALLINT[]",
        i64 => "::BIGINT",
        []i64 => "::BIGINT[]",
        else => "",
    };
}

test get {
    const _enum = enum { admin, customer };
    try testing.expectEqualStrings("::TEXT", get([]const u8));
    try testing.expectEqualStrings("::TEXT", get(?[]const u8));
    try testing.expectEqualStrings("::TEXT", get(*[]const u8));
    try testing.expectEqualStrings("::TEXT", get(?*[]const u8));
    try testing.expectEqualStrings("::TEXT", get(*?[]const u8));
    try testing.expectEqualStrings("::TEXT[]", get([][]const u8));
    try testing.expectEqualStrings("::TEXT[]", get(?[][]const u8));
    try testing.expectEqualStrings("::TEXT[]", get(*[][]const u8));
    try testing.expectEqualStrings("::TEXT[]", get(?*[][]const u8));
    try testing.expectEqualStrings("::TEXT[]", get(*?[][]const u8));
    try testing.expectEqualStrings("::TEXT", get([]u8));
    try testing.expectEqualStrings("::TEXT", get(?[]u8));
    try testing.expectEqualStrings("::TEXT", get(*[]u8));
    try testing.expectEqualStrings("::TEXT", get(?*[]u8));
    try testing.expectEqualStrings("::TEXT", get(*?[]u8));
    try testing.expectEqualStrings("::TEXT[]", get([][]u8));
    try testing.expectEqualStrings("::TEXT[]", get(?[][]u8));
    try testing.expectEqualStrings("::TEXT[]", get(*[][]u8));
    try testing.expectEqualStrings("::TEXT[]", get(?*[][]u8));
    try testing.expectEqualStrings("::TEXT[]", get(*?[][]u8));
    try testing.expectEqualStrings("::SMALLINT", get(i16));
    try testing.expectEqualStrings("::SMALLINT", get(?i16));
    try testing.expectEqualStrings("::SMALLINT", get(*i16));
    try testing.expectEqualStrings("::SMALLINT", get(?*i16));
    try testing.expectEqualStrings("::SMALLINT", get(*?i16));
    try testing.expectEqualStrings("::SMALLINT[]", get([]i16));
    try testing.expectEqualStrings("::SMALLINT[]", get(?[]i16));
    try testing.expectEqualStrings("::SMALLINT[]", get(*[]i16));
    try testing.expectEqualStrings("::SMALLINT[]", get(?*[]i16));
    try testing.expectEqualStrings("::SMALLINT[]", get(*?[]i16));
    try testing.expectEqualStrings("::BIGINT", get(i64));
    try testing.expectEqualStrings("::BIGINT", get(?i64));
    try testing.expectEqualStrings("::BIGINT", get(*i64));
    try testing.expectEqualStrings("::BIGINT", get(?*i64));
    try testing.expectEqualStrings("::BIGINT", get(*?i64));
    try testing.expectEqualStrings("::BIGINT[]", get([]i64));
    try testing.expectEqualStrings("::BIGINT[]", get(?[]i64));
    try testing.expectEqualStrings("::BIGINT[]", get(*[]i64));
    try testing.expectEqualStrings("::BIGINT[]", get(?*[]i64));
    try testing.expectEqualStrings("::BIGINT[]", get(*?[]i64));
    try testing.expectEqualStrings("", get(_enum));
    try testing.expectEqualStrings("", get(?_enum));
    try testing.expectEqualStrings("", get(*_enum));
    try testing.expectEqualStrings("", get(?*_enum));
    try testing.expectEqualStrings("", get(*?_enum));
    try testing.expectEqualStrings("", get([]_enum));
    try testing.expectEqualStrings("", get(?[]_enum));
    try testing.expectEqualStrings("", get(*[]_enum));
    try testing.expectEqualStrings("", get(?*[]_enum));
    try testing.expectEqualStrings("", get(*?[]_enum));
}

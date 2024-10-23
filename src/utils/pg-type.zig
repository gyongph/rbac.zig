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

const types = [6][]const u8{
    "::TEXT",
    "::SMALLINT",
    "::BIGINT",
    "::BOOL",
    "::TEXT[]",
    "::SMALLINT[]",
    "::BIGINT[]",
    "::BOOL[]",
};

pub fn get(comptime T: type) switch (getBaseType(T)) {
    []const u8, []u8 => *const [types[0].len]u8,
    [][]const u8, [][]u8 => *const [types[1].len]u8,
    i16 => *const [types[2].len]u8,
    []i16 => *const [types[3].len]u8,
    i64 => *const [types[4].len]u8,
    []i64 => *const [types[5].len]u8,
    bool => *const [types[6].len]u8,
    []bool => *const [types[7].len]u8,
    else => *const [0:0]u8,
} {
    const base_type = getBaseType(T);
    return switch (base_type) {
        []const u8, []u8 => types[0],
        [][]const u8, [][]u8 => types[1],
        i16 => types[2],
        []i16 => types[3],
        i64 => types[4],
        []i64 => types[5],
        bool => types[6],
        []bool => types[7],
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

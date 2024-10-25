const std = @import("std");
const testing = std.testing;

pub fn get(T: type) type {
    const info = @typeInfo(T);
    switch (info) {
        .pointer => |ptr| {
            if (ptr.size == .Slice) return []get(ptr.child);
            return get(ptr.child);
        },
        .optional => |opt| return get(opt.child),
        else => return T,
    }
}

const number_enum = enum { one, two, thre };

test get {
    try testing.expectEqual(u8, get(*u8));
    try testing.expectEqual(u8, get(?u8));
    try testing.expectEqual(u8, get(?*u8));
    try testing.expectEqual(u8, get(*?u8));
    try testing.expectEqual([]u8, get(*[]u8));
    try testing.expectEqual([]u8, get(?[]u8));
    try testing.expectEqual([]u8, get(?*[]u8));
    try testing.expectEqual([]u8, get(*?[]u8));
    try testing.expectEqual([][]u8, get([][]*?u8));
    try testing.expectEqual(number_enum, get(*number_enum));
    try testing.expectEqual(number_enum, get(?number_enum));
    try testing.expectEqual(number_enum, get(?*number_enum));
    try testing.expectEqual(number_enum, get(*?number_enum));
    try testing.expectEqual([]number_enum, get(*[]number_enum));
    try testing.expectEqual([]number_enum, get(?[]number_enum));
    try testing.expectEqual([]number_enum, get(?*[]number_enum));
    try testing.expectEqual([]number_enum, get(*?[]number_enum));
    try testing.expectEqual([][]number_enum, get([][]*?number_enum));
}

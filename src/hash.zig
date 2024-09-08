const std = @import("std");
const crypto = std.crypto;
const base64 = @import("base64.zig");

pub fn hash(input: []const u8) ![]const u8 {
    var hasher = crypto.hash.sha3.Sha3_512.init(.{});
    hasher.update(input);
    var signature = [_]u8{undefined} ** 64;
    hasher.final(&signature);
    return std.heap.page_allocator.dupe(u8, &signature);
}

test "Sha512 Hash" {
    const input = "2gIJOg9EkqEMX01/Q3GYrYX4M1iRb4VKKF85gZ";
    const output_base64 = "FCQCOXOZpzx+HU8f7nPY2AHdciCPjs9ErRx8tCtAfSj9DHSRYUTffOYspz81L3rMqXO1ukOiSnqAaEb9ylDBZg==";
    const result_hash_buf = try hash(input);
    const result_base64 = try base64.encode(result_hash_buf);
    const equal = std.mem.eql(u8, output_base64, result_base64);
    if (!equal) {
        std.debug.print("{any}\n", .{result_hash_buf});
        std.debug.print("{s}\n", .{result_base64});
    }
    try std.testing.expect(equal);
}

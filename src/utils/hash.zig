const std = @import("std");
const crypto = std.crypto;
const base64 = @import("base64.zig");

pub fn hash(input: []const u8, dest: *[64]u8) !void {
    var hasher = crypto.hash.sha3.Sha3_512.init(.{});
    hasher.update(input);
    hasher.final(dest);
}

test "Sha512 Hash" {
    const allocator = std.testing.allocator;
    const input = "2gIJOg9EkqEMX01/Q3GYrYX4M1iRb4VKKF85gZ";
    const output_base64 = "FCQCOXOZpzx-HU8f7nPY2AHdciCPjs9ErRx8tCtAfSj9DHSRYUTffOYspz81L3rMqXO1ukOiSnqAaEb9ylDBZg";
    var result_hash_buf = [_]u8{undefined} ** 64;
    try hash(input, &result_hash_buf);
    const result_base64 = try base64.encode(allocator, &result_hash_buf);
    defer allocator.free(result_base64);
    const equal = std.mem.eql(u8, output_base64, result_base64);
    if (!equal) {
        std.debug.print("result buff{any}\n", .{result_hash_buf});
        std.debug.print("result {s}\n", .{result_base64});
    }
    try std.testing.expect(equal);
}

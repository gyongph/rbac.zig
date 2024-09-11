const std = @import("std");
const print = std.debug.print;
const testing = std.testing;
const Encoder = std.base64.standard.Encoder;
const Decoder = std.base64.standard.Decoder;

/// need to free buffer
pub fn encode(alloc: std.mem.Allocator, src: []const u8) ![]const u8 {
    const encoded_length = Encoder.calcSize(src.len);
    const encoded_buffer = try alloc.alloc(u8, encoded_length);
    const encoded = Encoder.encode(encoded_buffer, src);
    return encoded;
}

pub fn decode(alloc: std.mem.Allocator, encoded_buffer: []const u8) ![]u8 {
    const decoded_length = try Decoder.calcSizeForSlice(encoded_buffer);
    const decoded_buffer = try alloc.alloc(u8, decoded_length);
    try Decoder.decode(decoded_buffer, encoded_buffer);
    return decoded_buffer;
}

test "Base64 encoding" {
    const allocator = std.testing.allocator;
    var buffer = [_]u8{0} ** 32;
    std.crypto.random.bytes(&buffer);
    const random: []const u8 = &buffer;
    const encoded = try encode(allocator, random);
    defer allocator.free(encoded);
    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try testing.expectEqualStrings(random, decoded);
}

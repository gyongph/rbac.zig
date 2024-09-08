const std = @import("std");
const print = std.debug.print;
const Encoder = std.base64.standard.Encoder;
const Decoder = std.base64.standard.Decoder;

pub fn encode(src: []const u8) ![]const u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const encoded_length = Encoder.calcSize(src.len);
    const encoded_buffer = try alloc.alloc(u8, encoded_length);
    defer alloc.free(encoded_buffer);

    const encoded = Encoder.encode(encoded_buffer, src);

    return std.heap.page_allocator.dupe(u8, encoded);
}

pub fn decode(encoded_buffer: []const u8) ![]u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const decoded_length = try Decoder.calcSizeForSlice(encoded_buffer);
    const decoded_buffer = try allocator.alloc(u8, decoded_length);
    defer allocator.free(decoded_buffer);

    try Decoder.decode(decoded_buffer, encoded_buffer);
    return std.heap.page_allocator.dupe(u8, decoded_buffer);
}

test "Base64 encoding" {
    var random = [_]u8{0} ** 32;
    for (random, 0..) |_, index| {
        random[index] = std.crypto.random.int(u8);
    }
    const encoded = try encode(&random);
    const decoded = try decode(encoded);

    std.debug.assert(std.mem.eql(u8, &random, decoded));

    const known_string = "Hello-world!";
    const known_encoded = try encode(&known_string.*);
    std.debug.assert(std.mem.eql(u8, "SGVsbG8td29ybGQh", known_encoded));
    const known_decoded = try decode(known_encoded);
    std.debug.assert(std.mem.eql(u8, known_string, known_decoded));
}

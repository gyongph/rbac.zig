const std = @import("std");
const sha512 = @import("./hash.zig");
const base64 = @import("./base64.zig");
const random = std.crypto.random;

const token_data_separator = "‎:";

pub fn generate(alloc: std.mem.Allocator, Payload: type, secret: []const u8) ![]const u8 {
    var stream = std.ArrayList(u8).init(alloc);
    stream.deinit();
    try std.json.stringify(Payload, .{}, stream.writer());

    var salt = [_]u8{undefined} ** 64;
    random.bytes(&salt);

    const hash_payload = try std.mem.concat(alloc, u8, &.{ &salt, stream.items, secret });
    var signature = [_]u8{undefined} ** 64;
    try sha512.hash(hash_payload, &signature);

    alloc.free(hash_payload);
    const token = try std.mem.join(alloc, token_data_separator, &.{ &salt, stream.items, &signature });
    defer alloc.free(token);

    const base_64_token = try base64.encode(alloc, token);
    return base_64_token;
}

/// requires an arena allocator to free everything at once
pub fn parse(allocator: std.mem.Allocator, Payload: type, token: []const u8, secret: []const u8) !Payload {
    const now = std.time.milliTimestamp();
    const raw_buf = try base64.decode(allocator, token);
    var token_parts = std.mem.splitSequence(u8, raw_buf, token_data_separator);
    const random_bytes = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
    const payload = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
    const signature = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
    const challenge = try std.mem.concat(allocator, u8, &.{ random_bytes, payload, secret });
    defer allocator.free(challenge);
    var resulted_hash = [_]u8{undefined} ** 64;
    try sha512.hash(challenge, &resulted_hash);
    const same_hash = std.mem.eql(u8, signature, &resulted_hash);
    if (!same_hash) return error.INVALID_TOKEN;

    const parsed_payload = try std.json.parseFromSlice(Payload, allocator, payload, .{});
    if (parsed_payload.value.expires_at < now) return error.EXPIRED_TOKEN;
    return parsed_payload.value;
}

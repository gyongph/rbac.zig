const std = @import("std");
const random = std.crypto.random;
const Utils = @import("utils/lib.zig");
const base64 = Utils.Base64;
const sha512 = Utils.Hash;

// example of token payload data that has the maximum size
// if you want to add something in the token payload you need to update this


pub fn create(alloc: std.mem.Allocator, payload: anytype, secret: []const u8) ![]const u8 {
    var stream = std.ArrayList(u8).init(allocator);
    try std.json.stringify(payload, .{}, stream.writer());
    const stringified_payload = try std.heap.page_allocator.dupe(u8, stream.items[0..stream.items.len]);
    stream.deinit();

    var salt = [_]u8{undefined} ** 64;
    random.bytes(&salt);
    const hash_payload = try std.mem.concat(allocator, u8, &.{ &salt, stringified_payload, secret });

    const signature = try sha512.hash(hash_payload);

    allocator.free(hash_payload);
    const token = try std.mem.join(allocator, token_data_separator, &.{ &salt, stringified_payload, signature });
    defer allocator.free(token);

    const url_safe_token = try base64.encode(token);
    return url_safe_token;
}

pub fn parseToken(T: type, allocator: std.mem.Allocator, token: []const u8, secret: []const u8) !T {
    const raw_buf = try base64.decode(token);
    var token_parts = std.mem.split(u8, raw_buf, token_data_separator);
    const random_bytes = token_parts.next().?;
    const payload = token_parts.next().?;
    const signature = token_parts.next().?;
    const challenge = try std.mem.concat(allocator, u8, &.{ random_bytes, payload, secret });
    defer allocator.free(challenge);
    const resulted_hash = try sha512.hash(challenge);
    const same_hash = std.mem.eql(u8, signature, resulted_hash);
    if (!same_hash) return error.INVALID_TOKEN;
    const parsed_payload = try std.json.parseFromSlice(T, allocator, payload, .{});
    defer parsed_payload.deinit();
    return parsed_payload.value;
}

test "Auth Token" {
    const Auth = struct { name: []const u8 };
    const auth_secret = "012345678901234567890123456789";
    const sample_payload = .{ .id = "BERTO PENDUKO", .role };
    const token = try create(sample_payload, auth_secret);
    const parsed_token_payload = try parseToken(Auth, std.testing.allocator, token, auth_secret);
    const same = std.mem.eql(u8, sample_payload.name, parsed_token_payload.name);
    try std.testing.expect(same);
}

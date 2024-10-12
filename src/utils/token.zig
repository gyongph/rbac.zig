const std = @import("std");
const sha512 = @import("./hash.zig");
const base64 = @import("./base64.zig");
const random = std.crypto.random;

const token_data_separator = "‎:";

pub const GeneratedToken = struct {
    token: []const u8,
    created_at: i64,
    expires_at: i64,
};

pub fn parseExpiration(expiration: []const u8) !i64 {
    if (expiration.len < 2) {
        return error.InvalidFormat;
    }
    const time_part = expiration[0 .. expiration.len - 1];
    const unit = expiration[expiration.len - 1];
    const time_value = try std.fmt.parseInt(i64, time_part, 10);
    const now = std.time.milliTimestamp();
    switch (unit) {
        's' => {
            return now + (time_value * std.time.ms_per_s); // Add seconds
        },
        'm' => {
            return now + (time_value * std.time.ms_per_min); // Add minutes
        },
        'h' => {
            return now + (time_value * std.time.ms_per_hour); // Add hours
        },
        'd' => {
            return now + (time_value * std.time.ms_per_day); // Add days
        },
        'w' => {
            return now + (time_value * std.time.ms_per_week); // Add weeks
        },
        else => return error.InvalidUnit,
    }
}
pub fn generate(alloc: std.mem.Allocator, payload: anytype, expires_at: []const u8, secret: []const u8) !GeneratedToken {
    var stream = std.ArrayList(u8).init(alloc);
    stream.deinit();
    const now = std.time.milliTimestamp();
    const expiration: i64 = try parseExpiration(expires_at);

    const token_data = .{
        .data = payload,
        .created_at = now,
        .expires_at = expiration,
    };

    try std.json.stringify(token_data, .{}, stream.writer());

    var salt = [_]u8{undefined} ** 64;
    random.bytes(&salt);

    const hash_payload = try std.mem.concat(alloc, u8, &.{ &salt, stream.items, secret });
    var signature = [_]u8{undefined} ** 64;
    try sha512.hash(hash_payload, &signature);

    alloc.free(hash_payload);
    const token = try std.mem.join(alloc, token_data_separator, &.{ &salt, stream.items, &signature });
    defer alloc.free(token);

    const base_64_token = try base64.encode(alloc, token);
    return .{
        .token = base_64_token,
        .created_at = now,
        .expires_at = expiration,
    };
}

pub fn ParsedToken(data: type) type {
    return struct {
        data: data,
        created_at: i64,
        expires_at: i64,
    };
}

/// requires an arena allocator to free everything at once
pub fn parse(allocator: std.mem.Allocator, Payload: type, token: []const u8, secret: []const u8) !ParsedToken(Payload) {
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

    const parsed_payload = try std.json.parseFromSlice(ParsedToken(Payload), allocator, payload, .{});
    if (parsed_payload.value.expires_at < now) return error.EXPIRED_TOKEN;
    return parsed_payload.value;
}

test "Token" {
    const Payload = struct {
        name: []const u8,
        age: usize,
    };
    const secret = "asdfkjjkljdfsfaslkdjf";
    const testing_allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(testing_allocator);
    const allocator = arena.allocator();
    defer arena.deinit();
    const payload = Payload{ .name = "user1", .age = 18 };
    const result = try generate(allocator, payload, "5m", secret);
    const parsed = try parse(allocator, Payload, result.token, secret);
    try std.testing.expectEqualStrings(parsed.data.name, payload.name);
    try std.testing.expectEqual(parsed.data.age, payload.age);
}

const std = @import("std");
const pg = @import("pg");
const envVar = @import("utils/env-var.zig");
pub const log = std.log.scoped(.example);
pub fn init(allocator: std.mem.Allocator, connection: u16) !*pg.Pool {
    const DB_USERNAME = try envVar.get("DB_USERNAME");
    const DB_PASSWORD = try envVar.get("DB_PASSWORD");
    const DB_NAME = try envVar.get("DB_NAME");
    const pg_pool = pg.Pool.init(allocator, .{ .size = connection, .connect = .{
        .port = 5432,
        .host = "127.0.0.1",
    }, .auth = .{
        .username = DB_USERNAME,
        .database = DB_NAME,
        .password = DB_PASSWORD,
        .timeout = 10_000,
    } }) catch |err| {
        log.err("Failed to connect: {}", .{err});
        std.posix.exit(1);
    };
    return pg_pool;
}

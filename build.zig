const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dep_opts = .{ .target = target, .optimize = optimize };
    const httpz = b.dependency("httpz", dep_opts).module("httpz");
    const pg = b.dependency("pg", dep_opts).module("pg");

    _ = b.addModule("rbac", .{
        .root_source_file = b.path("src/root.zig"),
        .imports = &.{
            .{ .name = "httpz", .module = httpz },
            .{ .name = "pg", .module = pg },
        },
    });
}

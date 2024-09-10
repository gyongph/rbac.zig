const std = @import("std");
const httpz = @import("httpz");
const MainModule = @import("main.zig").MainModule;
const Request = httpz.Request;
const Response = httpz.Response;
const testing = std.testing;
const mock_server = httpz.testing;

const Role = enum { Admin, Guest, Customer };
const UserSchema = struct { id: i16, name: []const u8, email: []const u8 };
const UserField = enum { id, name, email };
const main_module = MainModule(Role);
const Accesor = enum {
    Admin,
    Owner,
    Public,
    const Self = @This();
    pub fn getAccessor(ctx: *main_module.Global, req: *Request, res: *Response) !?Self {
        _ = ctx;
        _ = req;
        _ = res;
        return Self.Admin;
    }
};

const RoleSet = std.EnumSet(Role);
const AccesorSet = std.EnumSet(Accesor);
const UserFieldSet = std.EnumSet(UserField);

const Actions = struct {
    pub fn list(ctx: *main_module.Global, req: *Request, res: *Response) !void {
        _ = ctx;
        _ = req;
        _ = res;
    }
    pub fn create(ctx: *main_module.Global, req: *Request, res: *Response) !void {
        _ = ctx;
        _ = req;
        _ = res;
    }
    pub fn delete(ctx: *main_module.Global, req: *Request, res: *Response) !void {
        _ = ctx;
        _ = req;
        _ = res;
    }
};

const SubModule = main_module.Module(UserSchema, UserField, Accesor).init(.{
    .name = "users",
    .path = "/users",
    .getAccessor = Accesor.getAccessor,
    .record_access = .{
        .list = .{
            .role = RoleSet.initFull(),
            .handler = Actions.list,
        },
        .create = .{
            .role = RoleSet.initMany(&.{ .Admin, .Guest }),
            .handler = Actions.create,
        },
        .delete = .{
            .accessor = AccesorSet.initMany(&.{.Admin}),
            .handler = Actions.delete,
        },
    },
    .field_access = .{
        .Admin = .{
            .update = UserFieldSet.initEmpty(),
            .read = UserFieldSet.initEmpty(),
        },
        .Owner = .{
            .update = UserFieldSet.initEmpty(),
            .read = UserFieldSet.initEmpty(),
        },
        .Public = .{
            .update = UserFieldSet.initEmpty(),
            .read = UserFieldSet.initEmpty(),
        },
    },
});

test "SubModule" {
    try testing.expectEqualStrings(SubModule.name, "users");
    try testing.expectEqualStrings(SubModule.path, "/users");
    try testing.expectEqual(SubModule.getAccessor, Accesor.getAccessor);
    const record_access = SubModule.record_access;
    try testing.expect(@hasField(@TypeOf(record_access), "list"));
    try testing.expect(@hasField(@TypeOf(record_access), "create"));
    try testing.expect(@hasField(@TypeOf(record_access), "delete"));
    try testing.expect(@hasField(@TypeOf(record_access.list), "role"));
    try testing.expect(@hasField(@TypeOf(record_access.create), "role"));
    try testing.expect(@hasField(@TypeOf(record_access.delete), "accessor"));
    try testing.expect(@TypeOf(record_access.list.role) == RoleSet);
    try testing.expect(@TypeOf(record_access.create.role) == RoleSet);
    try testing.expect(@TypeOf(record_access.delete.accessor) == AccesorSet);
    try testing.expect(@hasField(@TypeOf(record_access.list), "handler"));
    try testing.expect(@hasField(@TypeOf(record_access.create), "handler"));
    try testing.expect(@hasField(@TypeOf(record_access.delete), "handler"));
    try testing.expect(@TypeOf(record_access.list.handler) == httpz.Action(*main_module.Global));
    try testing.expect(@TypeOf(record_access.create.handler) == httpz.Action(*main_module.Global));
    try testing.expect(@TypeOf(record_access.delete.handler) == httpz.Action(*main_module.Global));
}

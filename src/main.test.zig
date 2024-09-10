const std = @import("std");
const httpz = @import("httpz");
const MainModule = @import("main.zig").MainModule;
const Utils = @import("utils/lib.zig");
const EnvVar = Utils.EnvVar;
const Request = httpz.Request;
const Response = httpz.Response;
const testing = std.testing;
const mock_server = httpz.testing;

const Role = enum { Admin, Guest, Customer };
const User = struct { id: i16, name: []const u8, email: []const u8 };
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

const UserDB = &.{
    User{ .id = 0, .email = "user-0@email.com", .name = "jhon doe" },
    User{ .id = 1, .email = "user-1@email.com", .name = "Jane Smith" },
    User{ .id = 2, .email = "user-2@email.com", .name = "Alice Johnson" },
    User{ .id = 3, .email = "user-3@email.com", .name = "Bob Brown" },
    User{ .id = 4, .email = "user-4@email.com", .name = "Carol White" },
    User{ .id = 5, .email = "user-5@email.com", .name = "David Lee" },
    User{ .id = 6, .email = "user-6@email.com", .name = "Emma Davis" },
    User{ .id = 7, .email = "user-7@email.com", .name = "Frank Miller" },
    User{ .id = 8, .email = "user-8@email.com", .name = "Grace Wilson" },
    User{ .id = 9, .email = "user-9@email.com", .name = "Hannah Moore" },
};

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

const SubModule = main_module.Module(User, UserField, Accesor).init(.{
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
    const Action = httpz.Action(*main_module.Global);
    try testing.expectEqualStrings(SubModule.name, "users");
    try testing.expectEqualStrings(SubModule.path, "/users");
    try testing.expectEqual(SubModule.getAccessor, Accesor.getAccessor);

    const record_access = SubModule.record_access;
    const T_record_access = @TypeOf(record_access);
    try testing.expect(@hasField(T_record_access, "list"));
    try testing.expect(@hasField(T_record_access, "create"));
    try testing.expect(@hasField(T_record_access, "delete"));
    try testing.expect(@hasField(@TypeOf(record_access.list), "role"));
    try testing.expect(@hasField(@TypeOf(record_access.create), "role"));
    try testing.expect(@hasField(@TypeOf(record_access.delete), "accessor"));
    try testing.expect(@TypeOf(record_access.list.role) == RoleSet);
    try testing.expect(@TypeOf(record_access.create.role) == RoleSet);
    try testing.expect(@TypeOf(record_access.delete.accessor) == AccesorSet);
    try testing.expect(@hasField(@TypeOf(record_access.list), "handler"));
    try testing.expect(@hasField(@TypeOf(record_access.create), "handler"));
    try testing.expect(@hasField(@TypeOf(record_access.delete), "handler"));
    try testing.expect(@TypeOf(record_access.list.handler) == Action);
    try testing.expect(@TypeOf(record_access.create.handler) == Action);
    try testing.expect(@TypeOf(record_access.delete.handler) == Action);

    const field_access = SubModule.field_access;
    const T_field_access = @TypeOf(field_access);
    try testing.expect(@hasField(T_field_access, "Admin"));
    try testing.expect(@hasField(T_field_access, "Owner"));
    try testing.expect(@hasField(T_field_access, "Public"));
    try testing.expect(@typeInfo(T_field_access).Struct.fields.len == 3);
    try testing.expect(@TypeOf(field_access.Admin.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Admin.?.update) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Owner.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Owner.?.update) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Public.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Public.?.update) == UserFieldSet);
}

test "Token" {
    const ACCESS_TOKEN_SECRET = try EnvVar.get("ACCESS_TOKEN_SECRET");
    const REFRESH_TOKEN_SECRET = try EnvVar.get("REFRESH_TOKEN_SECRET");
    const allocator = testing.allocator;
    const Token = main_module.Token;
    const payload = .{ .id = "user1", .role = .Admin };
    const result = try Token.create(allocator, payload);
    const access_token_payload = try Token.parse(allocator, result.access_token, ACCESS_TOKEN_SECRET);
    const refresh_token_payload = try Token.parse(allocator, result.refresh_token, REFRESH_TOKEN_SECRET);
    try testing.expectEqualStrings(access_token_payload.id.?, "user1");
    try testing.expectEqualStrings(refresh_token_payload.id.?, "user1");
    try testing.expectEqual(access_token_payload.role, .Admin);
    try testing.expectEqual(refresh_token_payload.role, .Admin);
    try testing.expect(@hasField(@TypeOf(access_token_payload), "expires_at"));
    try testing.expect(@hasField(@TypeOf(refresh_token_payload), "expires_at"));
    try testing.expect(@hasField(@TypeOf(access_token_payload), "created_at"));
    try testing.expect(@hasField(@TypeOf(refresh_token_payload), "created_at"));
}

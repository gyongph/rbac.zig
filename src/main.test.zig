const std = @import("std");
const httpz = @import("httpz");
const MainModule = @import("main.zig").MainModule;
const Utils = @import("utils/lib.zig");
const TypeUtils = @import("type-utils.zig");
const StructFieldsAsEnum = TypeUtils.StructFieldsAsEnum;
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

const Address = struct { line_1: []const u8, line_2: []const u8, city: []const u8 };
const AddressField = enum { line_1, line_2, city };
const AddressFieldSet = std.EnumSet(AddressField);
const AddressModule = main_module.Module(Address, AddressField, Accesor, null).init(.{
    .name = "address",
    .path = "/address",
    .getAccessor = Accesor.getAccessor,
    .record_access = .{
        .create = .{
            .role = RoleSet.initEmpty(),
            .handler = Actions.list,
        },
        .list = .{
            .role = RoleSet.initEmpty(),
            .handler = .{
                .config = .{
                    .select = .{ .fields = AddressFieldSet.initFull() },
                    .where = "true",
                },
            },
        },
        .delete = .{
            .accessor = AccesorSet.initEmpty(),
            .handler = Actions.list,
        },
    },
    .field_access = .{
        .Admin = .{
            .update = AddressFieldSet.initEmpty(),
            .read = AddressFieldSet.initEmpty(),
        },
        .Owner = .{
            .update = AddressFieldSet.initEmpty(),
            .read = AddressFieldSet.initEmpty(),
        },
        .Public = .{
            .update = AddressFieldSet.initEmpty(),
            .read = AddressFieldSet.initEmpty(),
        },
    },
});
const sub_modules = &.{AddressModule};
const UserModule = main_module.Module(User, UserField, Accesor, sub_modules).init(.{
    .name = "users",
    .path = "/users",
    .getAccessor = Accesor.getAccessor,
    .record_access = .{
        .list = .{
            .role = RoleSet.initFull(),
            .handler = .{
                .custom = Actions.list,
            },
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

test "UserModule" {
    const Action = httpz.Action(*main_module.Global);
    try testing.expectEqualStrings(UserModule.name, "users");
    try testing.expectEqualStrings(UserModule.path, "/users");
    try testing.expectEqual(UserModule.getAccessor, Accesor.getAccessor);

    const record_access = UserModule.record_access;
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
    try testing.expect(std.meta.activeTag(record_access.list.handler) == .custom);
    try testing.expect(@TypeOf(record_access.create.handler) == Action);
    try testing.expect(@TypeOf(record_access.delete.handler) == Action);

    const field_access = UserModule.field_access;
    const T_field_access = @TypeOf(field_access);
    try testing.expect(@hasField(T_field_access, "Admin"));
    try testing.expect(@hasField(T_field_access, "Owner"));
    try testing.expect(@hasField(T_field_access, "Public"));
    try testing.expect(@typeInfo(T_field_access).@"struct".fields.len == 3);
    try testing.expect(@TypeOf(field_access.Admin.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Admin.?.update) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Owner.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Owner.?.update) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Public.?.read) == UserFieldSet);
    try testing.expect(@TypeOf(field_access.Public.?.update) == UserFieldSet);
}

test "Token" {
    const secret = "asdfkjjkljdfsfaslkdjf";
    const testing_allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(testing_allocator);
    const allocator = arena.allocator();
    defer arena.deinit();
    const Token = main_module.Token;
    const payload = .{ .id = "user1", .role = .Admin, .expires_at = 5 };
    const result = try Token.create(allocator, payload, secret);
    const parsed = try Token.parse(allocator, result.token, secret);
    try testing.expectEqualStrings(parsed.id, payload.id);
    try testing.expectEqual(parsed.role, payload.role);
}

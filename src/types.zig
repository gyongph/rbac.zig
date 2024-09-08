const pg = @import("pg");
const httpz = @import("httpz");
const std = @import("std");
const EnumPlus = @import("../../utils/enum-plus.zig").EnumPlus;

pub const UserRoles = enum {
    Admin,
    Guest,
    Customer,
    Application,
};

pub const Role = EnumPlus(enum {
    Admin,
    Developer,
    Application,
    Customer,
    Guest,
}, u5);

pub const Accesor = EnumPlus(enum {
    Admin,
    Owner,
    AuthorizeApplication,
    Public,
}, u3);

pub const Global = struct {
    handler_index: usize,
    pg_pool: *pg.Pool,
    user: ?struct { id: ?usize, role: UserRoles },
};

pub const access_config = enum {
    getAccessPermission,
    access_permission,
};

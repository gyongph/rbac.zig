const std = @import("std");
const httpz = @import("httpz");
const testing = std.testing;
const mem = std.mem;

pub fn CreateStructFromEnum(comptime enum_type: type, comptime val_type: type, comptime field_default: ?val_type) type {
    const enum_fields = @typeInfo(enum_type).Enum.fields;
    var fields: [enum_fields.len]std.builtin.Type.StructField = undefined;
    for (enum_fields, 0..) |field, i| {
        fields[i] = .{
            .name = field.name,
            .type = val_type,
            .default_value = if (field_default) |d| @as(?*const anyopaque, @ptrCast(&d)) else null,
            .is_comptime = false,
            .alignment = 0,
        };
    }
    @setEvalBranchQuota(enum_fields.len);
    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn changeStructFieldValueType(comptime str: type, comptime val_type: type) type {
    const real_struct = comptime switch (@typeInfo(str)) {
        .Struct => |struct_info| struct_info,
        else => @compileError("str must be a struct"),
    };

    var fields: [real_struct.fields.len]std.builtin.Type.StructField = undefined;
    inline for (real_struct.fields, 0..) |field, i| {
        fields[i] = .{
            .name = field.name,
            .type = val_type,
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}
pub fn Partial(comptime str: type) type {
    const real_struct = comptime switch (@typeInfo(str)) {
        .Struct => |struct_info| struct_info,
        else => @compileError("str must be a struct"),
    };

    var fields: [real_struct.fields.len]std.builtin.Type.StructField = undefined;
    inline for (real_struct.fields, 0..) |field, i| {
        const b: ?field.type = null;
        fields[i] = .{
            .name = field.name,
            .type = @Type(.{ .Optional = .{ .child = field.type } }),
            .default_value = @as(*const anyopaque, @ptrCast(&b)),
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn createPermission(comptime str: type, comptime enum_val: type) type {
    const real_struct = comptime switch (@typeInfo(str)) {
        .Struct => |struct_info| struct_info,
        else => @compileError("str must be a struct"),
    };
    const real_enum = comptime switch (@typeInfo(enum_val)) {
        .Enum => enum_val,
        .Optional => enum_val,
        else => @compileError("enum_val must be an enum"),
    };

    var fields: [real_struct.fields.len]std.builtin.Type.StructField = undefined;
    inline for (real_struct.fields, 0..) |field, i| {
        fields[i] = .{
            .name = field.name,
            .type = []const real_enum,
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn StructFieldsAsEnum(comptime s: anytype) type {
    const info = @typeInfo(s);
    var fields: [info.Struct.fields.len]std.builtin.Type.EnumField = undefined;
    var value = 0;
    inline for (info.Struct.fields, 0..) |field, i| {
        fields[i] = .{
            .name = field.name,
            .value = value,
        };
        value += 1;
    }

    return @Type(.{ .Enum = .{
        .tag_type = @Type(.{ .Int = .{
            .signedness = .unsigned,
            .bits = info.Struct.fields.len,
        } }),
        .fields = fields[0..],
        .decls = &[_]std.builtin.Type.Declaration{},
        .is_exhaustive = true,
    } });
}

pub fn Omit(comptime s: type, comptime f: anytype) type {
    const s_info = @typeInfo(s);
    const f_info = @typeInfo(@TypeOf(f));
    if (s_info != .Struct) @compileError("First argument should be a struct type but received " ++ @typeName(s));
    if (f_info != .Struct) @compileError("Second argument should be a tuple of strings but received " ++ @typeName(@TypeOf(f)));
    const s_items = s_info.Struct.fields;
    const f_items = f_info.Struct.fields;
    var included_count = 0;

    var new_fields: [s_items.len]std.builtin.Type.StructField = undefined;
    inline for (s_items) |s_field| {
        const name = s_field.name;
        var included = false;
        inline for (f_items) |f_field| {
            const field_name = @field(f, f_field.name);
            const match = std.mem.eql(u8, field_name, name);
            if (match) {
                included = true;
                break;
            }
        }
        if (!included) {
            new_fields[included_count] = s_field;
            included_count += 1;
        }
    }
    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = new_fields[0..included_count],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn Pick(comptime s: type, comptime f: anytype) type {
    const s_info = @typeInfo(s);
    const f_info = @typeInfo(@TypeOf(f));
    if (s_info != .Struct) @compileError("First argument should be a struct type but received " ++ @typeName(s));
    if (f_info != .Struct) @compileError("Second argument should be a tuple of strings but received " ++ @typeName(@TypeOf(f)));
    const f_items = f_info.Struct.fields;
    const s_items = s_info.Struct.fields;

    var new_fields: [f_items.len]std.builtin.Type.StructField = undefined;
    inline for (f_items, 0..) |item, i| {
        const field_name = @field(f, item.name);
        var included = false;
        inline for (s_items) |s_field| {
            const match = std.mem.eql(u8, field_name, s_field.name);
            if (match) {
                new_fields[i] = s_field;
                included = true;
                break;
            }
        }
        if (!included) @compileError(field_name ++ " is not a member of " ++ @typeName(s));
    }
    return @Type(.{
        .Struct = .{
            .layout = .auto,
            .fields = new_fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

test "Omit" {
    const data = struct {
        id: []const u8,
        email: []const u8,
        username: []const u8,
        password: []const u8,
        password_salt: []const u8,
    };
    const omitted = Omit(data, .{ "id", "password_salt" });
    try testing.expect(!@hasField(omitted, "id"));
    try testing.expect(!@hasField(omitted, "password_salt"));
    try testing.expect(@hasField(omitted, "email"));
    try testing.expect(@hasField(omitted, "username"));
    try testing.expect(@hasField(omitted, "password"));
    try testing.expect(@typeInfo(omitted).Struct.fields.len == 3);
}

test "Pick" {
    const data = struct {
        id: []const u8,
        email: []const u8,
        username: []const u8,
        password: []const u8,
        password_salt: []const u8,
    };
    const picked = Pick(data, .{ "password_salt", "id" });
    try testing.expect(@hasField(picked, "password_salt"));
    try testing.expect(@hasField(picked, "id"));
    try testing.expect(@typeInfo(picked).Struct.fields.len == 2);
}

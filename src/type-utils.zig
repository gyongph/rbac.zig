const std = @import("std");
const httpz = @import("httpz");
const Types = @import("types.zig");

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
pub fn createNullableStructField(comptime str: type) type {
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

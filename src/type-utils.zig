const std = @import("std");
const httpz = @import("httpz");
const pg = @import("pg");
const testing = std.testing;
const mem = std.mem;

pub fn CreateStructFromEnum(comptime enum_type: type, comptime val_type: type, comptime field_default: ?val_type) type {
    const enum_fields = @typeInfo(enum_type).@"enum".fields;
    var fields: [enum_fields.len]std.builtin.Type.StructField = undefined;
    for (enum_fields, 0..) |field, i| {
        fields[i] = .{
            .name = field.name,
            .type = val_type,
            .default_value = if (field_default) |d| @as(?*const anyopaque, @ptrCast(&d)) else field.default,
            .is_comptime = false,
            .alignment = 0,
        };
    }
    @setEvalBranchQuota(enum_fields.len);
    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

pub fn changeStructFieldValueType(comptime str: type, comptime val_type: type) type {
    const real_struct = comptime switch (@typeInfo(str)) {
        .@"struct" => |struct_info| struct_info,
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
        .@"struct" = .{
            .layout = .auto,
            .fields = fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}
pub fn Partial(comptime str: type) type {
    const real_struct = comptime switch (@typeInfo(str)) {
        .@"struct" => |struct_info| struct_info,
        else => @compileError("str must be a struct"),
    };

    var fields: [real_struct.fields.len]std.builtin.Type.StructField = undefined;
    inline for (real_struct.fields, 0..) |field, i| {
        const t = if (@typeInfo(field.type) == .optional) field.type else ?field.type;
        const b: t = null;
        fields[i] = .{
            .name = field.name,
            .type = t,
            .default_value = @as(*const anyopaque, @ptrCast(&b)),
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .@"struct" = .{
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

    return @Type(.{ .@"enum" = .{
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
    if (s_info != .@"struct") @compileError("First argument should be a struct type but received " ++ @typeName(s));
    if (f_info != .@"struct") @compileError("Second argument should be a tuple of strings but received " ++ @typeName(@TypeOf(f)));
    const s_items = s_info.@"struct".fields;
    const f_items = f_info.@"struct".fields;
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
        .@"struct" = .{
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
    if (s_info != .@"struct") @compileError("First argument should be a struct type but received " ++ @typeName(s));
    if (f_info != .@"struct") @compileError("Second argument should be a tuple of strings but received " ++ @typeName(@TypeOf(f)));
    const f_items = f_info.@"struct".fields;
    const s_items = s_info.@"struct".fields;

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
        .@"struct" = .{
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
    try testing.expect(@typeInfo(omitted).@"struct".fields.len == 3);
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
    try testing.expect(@typeInfo(picked).@"struct".fields.len == 2);
}

pub fn ReplaceField(comptime s: type, comptime name: [:0]const u8, comptime new_name: [:0]const u8, comptime t: type, comptime default: ?t) type {
    const fields = @typeInfo(s).@"struct".fields;
    var new_fields = [_]std.builtin.Type.StructField{undefined} ** fields.len;
    var found = false;
    for (fields, 0..) |f, i| {
        if (std.mem.eql(u8, f.name, name)) {
            found = true;
            const info = @typeInfo(t);
            var default_value: ?*const anyopaque = undefined;
            if (info == .optional and default == null) {
                const null_val: t = null;
                default_value = @as(*const anyopaque, &null_val);
            } else {
                default_value = if (default) |d| @as(*const anyopaque, @ptrCast(&d)) else null;
            }
            new_fields[i] = std.builtin.Type.StructField{
                .alignment = 0,
                .default_value = default_value,
                .is_comptime = false,
                .name = new_name,
                .type = t,
            };
        } else new_fields[i] = f;
    }
    if (!found) @compileError(name ++ "does not exist in " ++ @typeName(s));
    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = new_fields[0..],
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

test "ReplaceField" {
    const Sample = struct { name: []const u8, age: usize };
    const NewSample = ReplaceField(Sample, "age", "birthdate", []const u8, null);
    try testing.expect(@hasField(NewSample, "birthdate"));
}

pub fn ChangeFieldType(comptime s: type, comptime name: [:0]const u8, comptime t: type, comptime default: ?t) type {
    return ReplaceField(s, name, name, t, default);
}

test "ChangeFieldType" {
    const Sample = struct { name: []const u8, age: []const u8 };
    const NewSample = ChangeFieldType(Sample, "age", ?usize, null);
    try testing.expect(@typeInfo(NewSample).@"struct".fields[1].type == ?usize);
    const sample_a = NewSample{ .name = "jhon" };
    try testing.expect(sample_a.age == null);
    const sample_b = NewSample{ .name = "jhon", .age = 10 };
    try testing.expect(sample_b.age == 10);
}

pub fn MatchStructFields(str: type, field_enum: type) type {
    const struct_info = @typeInfo(str);
    if (struct_info != .@"struct") @compileError("str not a struct");
    const enum_info = @typeInfo(field_enum);
    if (enum_info != .@"enum") @compileError("field_enum not an enum");
    const str_fields = std.meta.fields(str);
    inline for (str_fields) |f| {
        _ = std.enums.nameCast(field_enum, f.name);
    }
    const enum_fields = std.meta.fields(field_enum);
    inline for (enum_fields) |f| {
        if (!@hasField(str, f.name)) {
            @compileError(f.name ++ " field does not exist in " ++ @typeName(str));
        }
    }
    return field_enum;
}

const config = @import("config.zig");
const std = @import("std");
const httpz = @import("httpz");
const pg = @import("pg");
const TypeUtils = @import("type-utils.zig");
const Utils = @import("utils/lib.zig");

const Request = httpz.Request;
const Response = httpz.Response;

const print = std.debug.print;
const allocPrint = std.fmt.allocPrint;
const random = std.crypto.random;
const assert = Utils.assert;
const EnvVar = Utils.EnvVar;
const sha512 = Utils.Hash;
const base64 = Utils.Base64;
const Token = Utils.Token;

pub fn SecurityToken(role: type) type {
    return struct {
        const Self = @This();
        const CreatePayload = struct {
            id: []const u8,
            role: role,
        };
        id: []const u8,
        role: role = .Guest,
        pub fn create(alloc: std.mem.Allocator, payload: CreatePayload, expires_at: []const u8, secret: []const u8) !Token.GeneratedToken {
            return try Token.generate(alloc, payload, expires_at, secret);
        }
        pub fn parse(alloc: std.mem.Allocator, token: []const u8, secret: []const u8) !Token.ParsedToken(Self) {
            return try Token.parse(alloc, Self, token, secret);
        }
    };
}

pub fn MainModule(role: type) type {
    const RBAC = struct {
        pub fn ListOptions(f_set: type) type {
            return struct {
                pub const SelectOption = enum { fields, raw };
                pub const Select = union(SelectOption) {
                    fields: std.EnumSet(f_set),
                    raw: []const u8,
                };
                select: Select,
                where: []const u8,
                page: usize = 1,
                limit: usize = config.default_max_list_limit,
            };
        }
        pub const Global = struct {
            request_id: [7]u8,
            pg_pool: *pg.Pool,
            auth: struct { id: ?[]const u8, role: role },
            pub fn dispatch(
                ctx: *Global,
                action: httpz.Action(*Global),
                req: *httpz.Request,
                res: *httpz.Response,
            ) !void {
                const request_id = Utils.String.random(7);
                const bearer_token = req.header("authorization");
                var global: Global = .{
                    .request_id = request_id,
                    .auth = .{
                        .id = null,
                        .role = .Guest,
                    },
                    .pg_pool = ctx.pg_pool,
                };
                if (bearer_token != null) {
                    const ACCESS_TOKEN_SECRET = try EnvVar.get("ACCESS_TOKEN_SECRET");
                    var itr = std.mem.splitSequence(u8, bearer_token.?, " ");
                    _ = itr.next();
                    const maybe_token = itr.next();
                    if (maybe_token) |token| {
                        const payload = try Token.parse(req.arena, SecurityToken(role), token, ACCESS_TOKEN_SECRET);
                        global.auth.id = payload.data.id;
                        global.auth.role = payload.data.role;
                    } else return error.BAD_REQUEST;
                }
                try action(&global, req, res);
            }
            pub fn uncaughtError(global: *Global, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
                _ = global;
                switch (err) {
                    error.UNAUTHORIZED => {
                        res.status = 401;
                        std.log.info("401 {s} {s} {}", .{ @tagName(req.method), req.url.path, err });
                    },
                    error.INVALID_TOKEN => {
                        res.status = 401;
                        res.body = "Invalid token";
                    },
                    error.EXPIRED_TOKEN => {
                        res.status = 401;
                        res.body = "Expired token";
                    },
                    else => |_err| {
                        std.log.warn("{s} {s} => {}", .{ @tagName(req.method), req.url.path, _err });
                        res.status = 500;
                    },
                }
            }
        };
        var _global: Global = undefined;

        const Server = struct {
            pg_pool: *pg.Pool,
            port: u16,
            http_server: httpz.Server(*Global) = undefined,

            pub fn register(self: *Server, module: anytype) !void {
                const info = @typeInfo(@TypeOf(module));
                if (info != .pointer) @panic("Expects a pointer to a module");
                try self.registerModule("", module);
            }
            fn registerModule(self: *Server, comptime parent_path: []const u8, comptime module: anytype) !void {
                var router = self.http_server.router(.{});
                const path = parent_path ++ module.path;
                const id_param = "/:" ++ module.name ++ "_id";
                print("\x1b[34mModule_loaded: {s} {s}: {s}\x1b[m\n", .{ module.name, path, @typeName(@TypeOf(module)) });
                var group = router.group(path, .{});
                group.get("/", module.listHandler().action, .{});
                std.log.info("\x1b[32mRoute added: GET {s}/\x1b[m", .{path});
                group.post("/", module.createAction().action, .{});
                std.log.info("\x1b[32mRoute added: POST {s}/\x1b[m", .{path});
                group.delete(id_param, module.deleteHandler().action, .{});
                std.log.info("\x1b[32mRoute added: DELETE {s}{s}\x1b[m", .{ path, id_param });
                group.get(id_param, module.getById, .{});
                std.log.info("\x1b[32mRoute added: GET {s}{s}\x1b[m", .{ path, id_param });
                group.patch(id_param, module.updateById, .{});
                std.log.info("\x1b[32mRoute added: PATCH {s}{s}\x1b[m", .{ path, id_param });

                // other routes
                if (module.routes) |routes| {
                    inline for (routes) |route| {
                        switch (route.method) {
                            .POST => group.post(route.path, route.createHandler().action, .{}),
                            .GET => group.get(route.path, route.createHandler().action, .{}),
                            .PATCH => group.patch(route.path, route.createHandler().action, .{}),
                            .DELETE => group.delete(route.path, route.createHandler().action, .{}),
                            .PUT => group.put(route.path, route.createHandler().action, .{}),
                            .OPTIONS => group.options(route.path, route.createHandler().action, .{}),
                            .HEAD => group.head(route.path, route.createHandler().action, .{}),
                        }
                        std.log.info("\x1b[32mRoute added: {s} {s}{s}\x1b[m", .{ @tagName(route.method), path, route.path });
                    }
                }
                const sub = module.sub_modules;
                const sub_info = @typeInfo(@TypeOf(sub));
                if (sub_info == .pointer) {
                    const child_info = @typeInfo(sub_info.pointer.child);
                    if (child_info == .@"struct" and child_info.@"struct".is_tuple == true) {
                        inline for (sub.*) |mod| {
                            try self.registerModule(path ++ id_param, &mod);
                        }
                    }
                }
            }
        };
        pub fn createServer(
            alloc: std.mem.Allocator,
            args: struct {
                pg_pool: *pg.Pool,
                port: u16,
            },
        ) !Server {
            _global = Global{
                .request_id = "1234567".*,
                .pg_pool = args.pg_pool,
                .auth = .{
                    .id = null,
                    .role = .Guest,
                },
            };
            var server = try httpz.Server(*Global).init(
                alloc,
                .{
                    .port = args.port,
                    .request = .{ .max_form_count = 25 },
                },
                &_global,
            );
            _ = &server;
            return Server{
                .pg_pool = args.pg_pool,
                .port = args.port,
                .http_server = server,
            };
        }

        /// Field of your schema should follow the pg.zig constraints \
        /// check pg.zig [supported types](https://github.com/karlseguin/pg.zig?tab=readme-ov-file#array-columns)
        pub fn Module(comptime Schema: type, schema_fields: ?type, Accesor: type, sub_modules: anytype) type {
            const OptionalSchema = TypeUtils.Partial(Schema);
            const Fields = if (schema_fields) |f| TypeUtils.MatchStructFields(Schema, f) else TypeUtils.StructFieldsAsEnum(Schema);
            const Route = struct {
                method: httpz.Method,
                path: []const u8,
                role: std.EnumSet(role),
                action: httpz.Action(*Global),

                pub fn createHandler(self: *const @This()) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            if (!self.role.contains(ctx.auth.role)) return error.UNAUTHORIZED;
                            try self.action(ctx, req, res);
                        }
                    };
                }
            };
            return struct {
                types: struct { schema: type, fields: type, accessor: type, accessor_permission: type } = undefined,
                name: []const u8,
                path: []const u8,
                record_access: struct {
                    list: struct {
                        const HandlerOption = enum { config, getOptions, custom };
                        role: std.EnumSet(role),
                        handler: union(HandlerOption) {
                            config: struct {
                                select: ListOptions(Fields).Select,
                                where: []const u8,
                                max_limit: usize = config.default_max_list_limit,
                            },
                            getOptions: *const fn (ctx: *Global, req: *Request, res: *Response) anyerror!ListOptions(Fields),
                            custom: httpz.Action(*Global),
                        },
                    },
                    create: struct { role: std.EnumSet(role), handler: httpz.Action(*Global) },
                    delete: struct { accessor: std.EnumSet(Accesor), handler: httpz.Action(*Global) },
                },
                getAccessor: *const fn (*Global, *httpz.Request, *httpz.Response) anyerror!?Accesor,
                field_access: TypeUtils.CreateStructFromEnum(
                    Accesor,
                    ?struct {
                        const Options = enum {
                            fields,
                            getFields,
                        };
                        update: union(Options) {
                            fields: ?std.EnumSet(Fields),
                            getFields: *const fn (ctx: *Global, req: *Request, res: *Response) anyerror!?std.EnumSet(Fields),
                        },
                        read: union(Options) {
                            fields: ?std.EnumSet(Fields),
                            getFields: *const fn (ctx: *Global, req: *Request, res: *Response) anyerror!?std.EnumSet(Fields),
                        },
                    },
                    null,
                ),
                routes: ?[]const Route = null,
                getById: httpz.Action(*Global) = undefined,
                updateById: httpz.Action(*Global) = undefined,
                sub_modules: @TypeOf(sub_modules) = sub_modules,
                const Self = @This();

                pub fn init(self: Self) Self {
                    return Self{
                        .types = .{
                            .schema = Schema,
                            .fields = Fields,
                            .accessor = Accesor,
                            .accessor_permission = undefined,
                        },
                        .field_access = self.field_access,
                        .getAccessor = self.getAccessor,
                        .getById = getByIdHandler(self).action,
                        .updateById = updateByIdHandler(self).action,
                        .record_access = self.record_access,
                        .routes = self.routes,
                        .name = self.name,
                        .path = self.path,
                    };
                }

                pub fn createAction(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            const user_role = ctx.auth.role;
                            const allowed = self.record_access.create.role.contains(user_role);
                            if (!allowed) return error.UNAUTHORIZED;
                            try self.record_access.create.handler(ctx, req, res);
                        }
                    };
                }

                pub fn listHandler(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            const user_role = ctx.auth.role;
                            const allowed = self.record_access.list.role.contains(user_role);
                            if (!allowed) return error.UNAUTHORIZED;
                            switch (self.record_access.list.handler) {
                                .config => |_config| {
                                    const query = try req.query();
                                    const page = try std.fmt.parseInt(usize, if (query.get("page")) |page| page else "1", 10);
                                    const limit = try std.fmt.parseInt(usize, if (query.get("limit")) |limit| limit else "10", 10);
                                    try self.listAction(.{
                                        .select = _config.select,
                                        .where = _config.where,
                                        .page = page,
                                        .limit = limit,
                                    }, ctx, req, res);
                                },
                                .getOptions => |getOptions| {
                                    const options = try getOptions(ctx, req, res);
                                    try self.listAction(options, ctx, req, res);
                                },
                                .custom => |custom| try custom(ctx, req, res),
                            }
                        }
                    };
                }
                pub fn listAction(
                    self: Self,
                    options: ListOptions(Fields),
                    ctx: *Global,
                    req: *Request,
                    res: *Response,
                ) !void {
                    const request_id = Utils.String.random(8);
                    var timer = try std.time.Timer.start();
                    defer std.log.info("{s}: ({}ms) end", .{ request_id, timer.read() / std.time.ns_per_ms });
                    const allocator = req.arena;
                    if (options.where.len == 0) @panic("[where] field is empty");
                    const select = switch (options.select) {
                        .fields => |f| blk: {
                            if (f.bits.mask == 0) @panic("Empty selected_fields, must have at least one");
                            var fields = std.ArrayList([]const u8).init(allocator);
                            defer fields.deinit();
                            inline for (std.meta.fields(Schema)) |sch_field| {
                                const tag = std.meta.stringToEnum(Fields, sch_field.name).?;
                                if (f.contains(tag)) {
                                    const base_type = Utils.BaseType.get(sch_field.type);
                                    switch (base_type) {
                                        []u8, []const u8 => try fields.append(sch_field.name ++ "::TEXT"),
                                        [][]u8, [][]const u8 => try fields.append(sch_field.name ++ "::TEXT[]"),
                                        else => try fields.append(sch_field.name),
                                    }
                                }
                            }
                            break :blk try std.mem.join(allocator, ",", fields.items);
                        },
                        .raw => |f| blk: {
                            if (f.len == 0) @panic("[select.raw] field is empty");
                            break :blk f;
                        },
                    };
                    const page = if (options.page < 1) 1 else options.page;
                    const limit = if (options.limit < 1) config.default_max_list_limit else options.limit;
                    std.log.info("{s}: ({}ms) beginning -> args prep", .{ request_id, timer.read() / std.time.ns_per_ms });
                    const conn = try ctx.pg_pool.acquire();
                    defer conn.release();
                    const total_count = blk: {
                        const row = conn.query(
                            try std.fmt.allocPrint(req.arena, "SELECT COUNT(*)::BIGINT FROM {s} where {s}", .{ self.name, options.where }),
                            .{},
                        ) catch {
                            if (conn.err) |pg_err| {
                                res.status = 400;

                                try res.json(.{
                                    .code = pg_err.code,
                                    .message = pg_err.message,
                                    .detail = pg_err.detail,
                                    .constraint = pg_err.constraint,
                                }, .{});
                            }
                            return; // end request
                        };
                        defer row.deinit();
                        const row_1 = try row.next();
                        try row.drain();
                        break :blk row_1.?.get(i64, 0);
                    };

                    std.log.info("{s}: ({}ms) args prep -> getCount", .{ request_id, timer.read() / std.time.ns_per_ms });

                    const results = conn.queryOpts(
                        try std.fmt.allocPrint(req.arena, "SELECT {s} from {s} WHERE {s} limit $1 OFFSET ($2 - 1) * $1", .{ select, self.name, options.where }),
                        .{ limit, page },
                        .{ .column_names = true },
                    ) catch {
                        if (conn.err) |pg_err| {
                            res.status = 400;

                            try res.json(.{
                                .code = pg_err.code,
                                .message = pg_err.message,
                                .detail = pg_err.detail,
                                .constraint = pg_err.constraint,
                            }, .{});
                        }
                        return; // end request
                    };
                    defer results.deinit();

                    std.log.info("{s}: ({}ms) getCount -> getquery", .{ request_id, timer.read() / std.time.ns_per_ms });

                    const mapper = results.mapper(OptionalSchema, .{ .allocator = allocator, .dupe = true });
                    var list = std.ArrayList(OptionalSchema).init(req.arena);
                    defer list.deinit();
                    while (try mapper.next()) |item| {
                        try list.append(item);
                    }
                    std.log.info("{s}: ({}ms) getQuery-> mapper", .{ request_id, timer.read() / std.time.ns_per_ms });

                    res.status = 200;
                    try res.json(.{
                        .page = page,
                        .total_pages = try std.math.divCeil(f64, @as(f64, @floatFromInt(total_count)), @as(f64, @floatFromInt(limit))),
                        .limit = limit,
                        .total_count = total_count,
                        .items = list.items,
                    }, .{ .emit_null_optional_fields = false });
                }
                pub fn deleteHandler(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            const maybe_accessor = try self.getAccessor(ctx, req, res);
                            const delete_access = self.record_access.delete;
                            if (maybe_accessor) |accessor| {
                                if (delete_access.accessor.contains(accessor)) {
                                    return try delete_access.handler(ctx, req, res);
                                }
                            }
                            return error.UNAUTHORIZED;
                        }
                    };
                }
                pub fn getByIdHandler(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            var timer = try std.time.Timer.start();
                            defer std.log.info("getById: {}ms ", .{timer.read() / std.time.ns_per_ms});
                            const alloc = req.arena;
                            const id = req.param(self.name ++ "_id").?;
                            const type_info = @typeInfo(@TypeOf(self.field_access));
                            assert(type_info == .@"struct", "Expects struct but found" ++ @typeName(@TypeOf(self.field_access)));
                            const accessor = try self.getAccessor(ctx, req, res);
                            if (accessor == null) return error.UNAUTHORIZED;
                            const accessor_name = @tagName(accessor.?);
                            const field_access_fields = type_info.@"struct".fields;

                            const maybe_read_access: ?std.EnumSet(Fields) = blk: {
                                inline for (field_access_fields) |f| {
                                    if (std.mem.eql(u8, accessor_name, f.name)) {
                                        const field_access = @field(self.field_access, f.name);
                                        if (field_access) |x| {
                                            switch (x.read) {
                                                .fields => |fs| break :blk fs,
                                                .getFields => |getFields| break :blk try getFields(ctx, req, res),
                                            }
                                        }
                                        break :blk null;
                                    }
                                }
                                break :blk null;
                            };

                            if (maybe_read_access == null or maybe_read_access.?.count() == 0) return error.UNAUTHORIZED;

                            const read_access = maybe_read_access.?;
                            const selected_fields = try req.jsonObject();
                            const query: []const u8 = blk: {
                                if (selected_fields) |sf| {
                                    var q: []const u8 = "SELECT ";
                                    const keys = sf.keys();
                                    var first = true;
                                    for (keys) |field_name| {
                                        const field_tag = std.meta.stringToEnum(Fields, field_name);
                                        if (field_tag != null and read_access.contains(field_tag.?)) {
                                            q = if (first) try std.mem.concat(alloc, u8, &.{ q, field_name }) else try std.mem.concat(alloc, u8, &.{ q, ", ", field_name });
                                            if (first) first = false;
                                        }
                                    }
                                    q = try std.mem.concat(alloc, u8, &.{ q, " FROM ", self.name, " WHERE id = $1" });
                                    break :blk q;
                                } else {
                                    var columns = std.ArrayList([]const u8).init(alloc);
                                    defer columns.deinit();
                                    inline for (std.meta.fields(Schema)) |f| {
                                        const tag = std.meta.stringToEnum(schema_fields.?, f.name).?;
                                        if (read_access.contains(tag)) {
                                            const base_type = Utils.BaseType.get(f.type);
                                            switch (base_type) {
                                                []u8, []const u8 => try columns.append(f.name ++ "::TEXT"),
                                                [][]u8, [][]const u8 => try columns.append(f.name ++ "::TEXT[]"),
                                                else => try columns.append(f.name),
                                            }
                                        }
                                    }
                                    const stringed_columns = try std.mem.join(alloc, ", ", columns.items);
                                    defer alloc.free(stringed_columns);
                                    break :blk try allocPrint(alloc, "SELECT {s} FROM {s} WHERE id = $1", .{ stringed_columns, self.name });
                                }
                            };
                            defer alloc.free(query);
                            const conn = try ctx.pg_pool.acquire();

                            const result = conn.queryOpts(query, .{id}, .{ .column_names = true, .release_conn = true }) catch |err| {
                                if (conn.err) |pg_err| {
                                    std.log.warn("get failure: {s}", .{pg_err.message});
                                }
                                return err;
                            };
                            defer result.deinit();
                            const mapper = result.mapper(OptionalSchema, .{ .allocator = alloc });
                            res.status = 404;
                            while (try mapper.next()) |data| {
                                res.status = 200;
                                try res.json(data, .{ .emit_null_optional_fields = false });
                            }
                            std.log.info("getById: {}ms {s}", .{ timer.read() / std.time.ns_per_ms, query });
                        }
                    };
                }
                pub fn updateByIdHandler(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            const request_id = Utils.String.random(6);
                            var timer = try std.time.Timer.start();
                            defer std.log.info("{s}: {}ms", .{ request_id, timer.read() / std.time.ns_per_ms });
                            const alloc = req.arena;
                            const id = req.param(self.name ++ "_id").?;
                            const type_info = @typeInfo(@TypeOf(self.field_access));
                            assert(type_info == .@"struct", "Expects struct type but found " ++ @typeName(@TypeOf(self.field_access)));
                            const accessor = try self.getAccessor(ctx, req, res);
                            if (accessor == null) return error.UNAUTHORIZED;
                            const accessor_name = @tagName(accessor.?);
                            const field_access_fields = type_info.@"struct".fields;

                            const maybe_update_access: ?std.EnumSet(Fields) = blk: {
                                inline for (field_access_fields) |f| {
                                    if (std.mem.eql(u8, accessor_name, f.name)) {
                                        const field_access = @field(self.field_access, f.name);
                                        if (field_access) |x| {
                                            switch (x.update) {
                                                .fields => |fs| break :blk fs,
                                                .getFields => |getFields| break :blk try getFields(ctx, req, res),
                                            }
                                        }
                                        break :blk null;
                                    }
                                }
                                break :blk null;
                            };
                            if (maybe_update_access == null or maybe_update_access.?.count() == 0) return error.UNAUTHORIZED;

                            const update_access = maybe_update_access.?;
                            const maybe_payload = try req.jsonObject();
                            if (maybe_payload == null) return;
                            const selected_fields = maybe_payload.?;
                            const values = selected_fields.values();
                            const keys = selected_fields.keys();
                            var update_arg_count: usize = 0;
                            std.log.info("{s}: ({}ms) beginning -> var preparation", .{ request_id, timer.read() / std.time.ns_per_ms });
                            const args: []const u8 = blk: {
                                var _args = std.ArrayList([]const u8).init(alloc);
                                defer _args.deinit();
                                for (keys, 0..) |field_name, i| {
                                    const field_tag = std.meta.stringToEnum(Fields, field_name);
                                    if (field_tag == null) {
                                        res.status = 400;
                                        try res.json(.{
                                            .code = 400,
                                            .message = "Invalid payload",
                                            .details = try allocPrint(alloc, "Trying to update an unknown field: {s}", .{field_name}),
                                        }, .{});
                                        return;
                                    }
                                    if (!update_access.contains(field_tag.?)) {
                                        res.status = 401;
                                        try res.json(.{
                                            .code = 401,
                                            .message = "UNAUTHORIZED",
                                            .detail = try allocPrint(alloc, "Updating {s} field is not included in your permission.", .{field_name}),
                                        }, .{});
                                        return;
                                    }
                                    const set_args: ?[]const u8 = switch (values[i]) {
                                        .string, .integer, .float, .null, .bool => arg_blk: {
                                            update_arg_count += 1;
                                            break :arg_blk try allocPrint(alloc, " {s} = ${d} ", .{ field_name, update_arg_count });
                                        },
                                        .array => |arr| arr_blk: {
                                            if (arr.items.len == 0) {
                                                break :arr_blk try allocPrint(alloc, " {s} = '{{}}' ", .{field_name});
                                            }
                                            update_arg_count += 1;
                                            break :arr_blk switch (arr.items[0]) {
                                                .string => try allocPrint(alloc, " {s} = ${d}::TEXT[] ", .{ field_name, update_arg_count }),
                                                .integer => try allocPrint(alloc, " {s} = ${d}::BIGINT[] ", .{ field_name, update_arg_count }),
                                                .float => try allocPrint(alloc, " {s} = ${d}::FLOAT[] ", .{ field_name, update_arg_count }),
                                                .bool => try allocPrint(alloc, " {s} = ${d}::BOOLEAN[] ", .{ field_name, update_arg_count }),
                                                else => null,
                                            };
                                        },
                                        else => null,
                                    };
                                    if (set_args == null) {
                                        res.status = 400;
                                        try res.json(.{
                                            .code = 400,
                                            .message = "Invalid paylo1ad",
                                            .details = try allocPrint(alloc, "The {s} field has an unsupported data type", .{field_name}),
                                        }, .{});
                                        return;
                                    }
                                    try _args.append(set_args.?);
                                }
                                break :blk try std.mem.join(alloc, " , ", _args.items);
                            };
                            std.log.info("{s}: ({}ms) var preparation -> arg preparation ", .{ request_id, timer.read() / std.time.ns_per_ms });

                            const conn = try ctx.pg_pool.acquire();
                            defer conn.release();
                            var columns = std.ArrayList([]const u8).init(req.arena);
                            defer columns.deinit();

                            inline for (std.meta.fields(Schema)) |f| {
                                var found = false;
                                for (keys) |k| {
                                    if (std.mem.eql(u8, f.name, k)) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (found) {
                                    const base_type = Utils.BaseType.get(f.type);
                                    switch (base_type) {
                                        []u8, []const u8 => try columns.append(f.name ++ "::TEXT"),
                                        [][]u8, [][]const u8 => try columns.append(f.name ++ "::TEXT[]"),
                                        else => try columns.append(f.name),
                                    }
                                }
                            }

                            const query_args = try std.mem.concat(
                                alloc,
                                u8,
                                &.{
                                    try allocPrint(alloc, "update {s} set ", .{self.name}), // update operation
                                    args,
                                    try allocPrint(alloc, " where id = ${d} returning {s}", .{ update_arg_count + 1, try std.mem.join(req.arena, ",", columns.items) }), //where,
                                },
                            );

                            std.log.info("DB QUERY: {s}", .{query_args});

                            var stmt = try pg.Stmt.init(conn, .{ .column_names = true, .allocator = alloc });
                            errdefer stmt.deinit();
                            stmt.prepare(query_args) catch |err| {
                                if (conn.err) |pg_err| {
                                    res.status = 400;
                                    try res.json(.{
                                        .code = pg_err.code,
                                        .message = pg_err.message,
                                        .detail = pg_err.detail,
                                        .constraint = pg_err.constraint,
                                    }, .{});
                                    std.log.warn("Failed stmt preparation: {s}", .{pg_err.message});
                                }
                                print("{}\n", .{err});
                                return;
                            };

                            std.log.info("{s}: ({}ms) arg preparation -> stmt.prepare", .{ request_id, timer.read() / std.time.ns_per_ms });

                            for (values) |v| {
                                switch (v) {
                                    .string => |_v| try stmt.bind(_v),
                                    .integer => |_v| try stmt.bind(_v),
                                    .float => |_v| try stmt.bind(_v),
                                    .bool => |_v| try stmt.bind(_v),
                                    .null => try stmt.bind(null),
                                    .array => |_v| {
                                        if (_v.items.len > 0) {
                                            switch (_v.items[0]) {
                                                .string => {
                                                    var items = std.ArrayList([]const u8).init(alloc);
                                                    for (_v.items) |val| {
                                                        if (val == .string) try items.append(val.string);
                                                    }
                                                    try stmt.bind(try items.toOwnedSlice());
                                                },
                                                .bool => {
                                                    var items = std.ArrayList(bool).init(alloc);
                                                    for (_v.items) |val| {
                                                        if (val == .bool) try items.append(val.bool);
                                                    }
                                                    try stmt.bind(try items.toOwnedSlice());
                                                },
                                                .float => {
                                                    var items = std.ArrayList(f64).init(alloc);
                                                    for (_v.items) |val| {
                                                        if (val == .float) try items.append(val.float);
                                                    }
                                                    try stmt.bind(try items.toOwnedSlice());
                                                },
                                                .integer => {
                                                    var items = std.ArrayList(i64).init(alloc);
                                                    for (_v.items) |val| {
                                                        if (val == .integer) try items.append(val.integer);
                                                    }
                                                    try stmt.bind(try items.toOwnedSlice());
                                                },
                                                else => {},
                                            }
                                        }
                                    },
                                    else => {
                                        res.status = 400;
                                        res.body = "Unable to bin";
                                        return;
                                    },
                                }
                            }
                            try stmt.bind(id);
                            std.log.info("{s}: ({}ms) stmt.prepare -> stmt.bind", .{ request_id, timer.read() / std.time.ns_per_ms });

                            const result = stmt.execute() catch |err| {
                                if (conn.err) |pg_err| {
                                    res.status = 400;
                                    try res.json(.{
                                        .code = pg_err.code,
                                        .message = pg_err.message,
                                        .detail = pg_err.detail,
                                        .constraint = pg_err.constraint,
                                    }, .{});
                                    std.log.warn("update failure: {s}", .{pg_err.message});
                                }
                                print("{}\n", .{err});
                                return;
                            };
                            std.log.info("{s}: ({}ms) stmt.bind -> stmt.execute", .{ request_id, timer.read() / std.time.ns_per_ms });
                            const mapper = result.mapper(OptionalSchema, .{ .allocator = alloc });
                            res.status = 404; // default

                            while (try mapper.next()) |data| {
                                res.status = 200;
                                try res.json(data, .{ .emit_null_optional_fields = false });
                            }
                        }
                    };
                }
            };
        }
    };
    return RBAC;
}

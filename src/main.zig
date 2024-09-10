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

pub fn MainModule(role: type) type {
    const RBA = struct {
        pub const Global = struct { pg_pool: *pg.Pool, auth: struct { id: ?[]const u8, role: role } };
        pub const Token = struct {
            const Self = @This();
            const Payload = struct {
                id: ?[]const u8,
                role: role = .Guest,
                created_at: i64,
                expires_at: i64,
            };
            const ReturnToken = struct {
                access_token: []const u8,
                refresh_token: []const u8,
                access_token_expires_at: i64,
                refresh_token_expires_at: i64,
            };
            const token_data_separator = "‎"; // empty space

            /// expires_at is in minutes;
            pub fn create(alloc: std.mem.Allocator, payload: struct { id: []const u8, role: role }) !ReturnToken {
                const ACCESS_TOKEN_SECRET = try EnvVar.get("ACCESS_TOKEN_SECRET");
                const REFRESH_TOKEN_SECRET = try EnvVar.get("REFRESH_TOKEN_SECRET");
                const ACCESS_TOKEN_EXPIRES_AT_MIN = try std.fmt.parseInt(i64, try EnvVar.get("ACCESS_TOKEN_EXPIRES_AT_MIN"), 10);
                const REFRESH_TOKEN_EXPIRES_AT_MIN = try std.fmt.parseInt(i64, try EnvVar.get("REFRESH_TOKEN_EXPIRES_AT_MIN"), 10);
                const now = std.time.timestamp();
                const access_token_expires_at = now + (ACCESS_TOKEN_EXPIRES_AT_MIN * std.time.ms_per_min);
                const refresh_token_expires_at = now + (REFRESH_TOKEN_EXPIRES_AT_MIN * std.time.ms_per_min);
                const access_token = .{ .id = payload.id, .role = payload.role, .created_at = now, .expires_at = access_token_expires_at };
                const refresh_token = .{ .id = payload.id, .role = payload.role, .created_at = now, .expires_at = refresh_token_expires_at };
                return ReturnToken{
                    .access_token = try generateToken(alloc, access_token, ACCESS_TOKEN_SECRET),
                    .refresh_token = try generateToken(alloc, refresh_token, REFRESH_TOKEN_SECRET),
                    .access_token_expires_at = access_token_expires_at,
                    .refresh_token_expires_at = refresh_token_expires_at,
                };
            }

            pub fn generateToken(alloc: std.mem.Allocator, payload: anytype, secret: []const u8) ![]const u8 {
                var stream = std.ArrayList(u8).init(alloc);
                try std.json.stringify(payload, .{}, stream.writer());
                const stringified_payload = try std.heap.page_allocator.dupe(u8, stream.items[0..stream.items.len]);
                stream.deinit();

                var salt = [_]u8{undefined} ** 64;
                random.bytes(&salt);
                const hash_payload = try std.mem.concat(alloc, u8, &.{ &salt, stringified_payload, secret });

                const signature = try sha512.hash(hash_payload);

                alloc.free(hash_payload);
                const token = try std.mem.join(alloc, token_data_separator, &.{ &salt, stringified_payload, signature });
                defer alloc.free(token);

                const url_safe_token = try base64.encode(token);
                return url_safe_token;
            }

            pub fn parse(allocator: std.mem.Allocator, token: []const u8, secret: []const u8) !Payload {
                const now = std.time.timestamp();
                const raw_buf = try base64.decode(token);
                var token_parts = std.mem.split(u8, raw_buf, token_data_separator);
                const random_bytes = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
                const payload = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
                const signature = if (token_parts.next()) |part| part else return error.INVALID_TOKEN;
                const challenge = try std.mem.concat(allocator, u8, &.{ random_bytes, payload, secret });
                defer allocator.free(challenge);
                const resulted_hash = try sha512.hash(challenge);
                const same_hash = std.mem.eql(u8, signature, resulted_hash);
                if (!same_hash) return error.INVALID_TOKEN;
                const parsed_payload = try std.json.parseFromSlice(Payload, allocator, payload, .{});
                if (parsed_payload.value.expires_at < now) return error.EXPIRED_TOKEN;
                defer parsed_payload.deinit();
                return parsed_payload.value;
            }
        };
        var _global: Global = undefined;

        const Server = struct {
            pg_pool: *pg.Pool,
            port: u16,
            http_server: httpz.ServerApp(*Global) = undefined,

            pub fn register(self: *Server, module: anytype) !void {
                const info = @typeInfo(@TypeOf(module));
                if (info != .Pointer) @panic("Expects a pointer to a module");
                print("module_loaded: {s} {s}: {}\n", .{ module.name, module.path, @TypeOf(module) });
                var router = self.http_server.router();
                var group = router.group(module.path, .{});

                group.get("/", module.listHandler().action);
                std.log.info("Route added: GET {s}/", .{module.path});
                group.post("/", module.createAction().action);
                std.log.info("Route added: POST {s}/", .{module.path});
                group.delete("/:id", module.deleteHandler().action);
                std.log.info("Route added: DELETE {s}/:id", .{module.path});
                group.get("/:id", module.getById);
                std.log.info("Route added: GET {s}/:id", .{module.path});
                group.patch("/:id", module.updateById);
                std.log.info("Route added: PATCH {s}/:id", .{module.path});

                // other routes
                if (module.routes) |routes| {
                    inline for (routes) |route| {
                        switch (route.method) {
                            .POST => group.post(route.path, route.createHandler().action),
                            .GET => group.get(route.path, route.createHandler().action),
                            .PATCH => group.patch(route.path, route.createHandler().action),
                            .DELETE => group.delete(route.path, route.createHandler().action),
                            .PUT => group.put(route.path, route.createHandler().action),
                            .OPTIONS => group.options(route.path, route.createHandler().action),
                            .HEAD => group.head(route.path, route.createHandler().action),
                        }
                        std.log.info("Route added: {s} {s}{s}", .{ @tagName(route.method), module.path, route.path });
                    }
                }
            }

            pub fn dispatcher(
                global: *Global,
                action: httpz.Action(*Global),
                req: *httpz.Request,
                res: *httpz.Response,
            ) !void {
                const bearer_token = req.header("authorization");
                if (bearer_token == null) {
                    global.auth.id = null;
                    global.auth.role = .Guest;
                } else {
                    const ACCESS_TOKEN_SECRET = try EnvVar.get("ACCESS_TOKEN_SECRET");
                    var itr = std.mem.split(u8, bearer_token.?, "Bearer ");
                    const maybe_token = itr.next();
                    if (maybe_token) |token| {
                        const payload = try Token.parse(req.arena, token, ACCESS_TOKEN_SECRET);
                        global.auth.id = payload.id;
                        global.auth.role = payload.role;
                    } else return error.BAD_REQUEST;
                }
                try action(global, req, res);
            }
            pub fn errorHandler(global: *Global, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
                _ = global;
                switch (err) {
                    error.UNAUTHORIZED => {
                        res.status = 401;
                        std.log.info("401 {s} {s} {}", .{ @tagName(req.method), req.url.path, err });
                    },
                    else => {
                        res.status = 500;
                        res.body = "bad request";
                    },
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
                .pg_pool = args.pg_pool,
                .auth = .{
                    .id = null,
                    .role = .Guest,
                },
            };
            var server = try httpz.ServerApp(*Global).init(
                alloc,
                .{
                    .port = args.port,
                    .request = .{ .max_form_count = 25 },
                },
                &_global,
            );
            server.dispatcher(Server.dispatcher);
            server.errorHandler(Server.errorHandler);
            return Server{
                .pg_pool = args.pg_pool,
                .port = args.port,
                .http_server = server,
            };
        }

        const ModuleStruct = struct {};
        /// Field of your schema should follow the pg.zig constraints \
        /// check pg.zig [supported types](https://github.com/karlseguin/pg.zig?tab=readme-ov-file#array-columns)
        pub fn Module(comptime Schema: type, schema_fields: ?type, Accesor: type) type {
            const OptionalSchema = TypeUtils.Partial(Schema);
            const Fields = if (schema_fields == null) TypeUtils.StructFieldsAsEnum(Schema) else schema_fields.?;
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
                    list: struct { role: std.EnumSet(role), handler: httpz.Action(*Global) },
                    create: struct { role: std.EnumSet(role), handler: httpz.Action(*Global) },
                    delete: struct { accessor: std.EnumSet(Accesor), handler: httpz.Action(*Global) },
                },
                getAccessor: *const fn (*Global, *httpz.Request, *httpz.Response) anyerror!?Accesor,
                field_access: TypeUtils.CreateStructFromEnum(
                    Accesor,
                    ?struct {
                        update: std.EnumSet(Fields),
                        read: std.EnumSet(Fields),
                    },
                    null,
                ),
                routes: ?[]const Route = null,
                getById: httpz.Action(*Global) = undefined,
                updateById: httpz.Action(*Global) = undefined,

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
                            try self.record_access.list.handler(ctx, req, res);
                        }
                    };
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
                            const alloc = req.arena;
                            const id = req.param("id").?;
                            const type_info = @typeInfo(@TypeOf(self.field_access));
                            assert(type_info == .Struct, "Expects struct but found" ++ @typeName(@TypeOf(self.field_access)));
                            const accessor = try self.getAccessor(ctx, req, res);
                            if (accessor == null) return error.UNAUTHORIZED;
                            const accessor_name = @tagName(accessor.?);
                            const field_access_fields = type_info.Struct.fields;

                            const maybe_read_access: ?std.EnumSet(Fields) = blk: {
                                inline for (field_access_fields) |f| {
                                    if (std.mem.eql(u8, accessor_name, f.name)) {
                                        const field_access = @field(self.field_access, f.name);
                                        if (field_access) |x| break :blk x.read;
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
                                    var itr = read_access.iterator();
                                    while (itr.next()) |field_tag| {
                                        try columns.append(@tagName(field_tag));
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
                            var mapper = result.mapper(OptionalSchema, .{ .dupe = true });
                            const item = try mapper.next();
                            if (item == null) {
                                res.status = 404;
                            } else {
                                try res.json(item.?, .{ .emit_null_optional_fields = false });
                                try result.drain();
                            }
                        }
                    };
                }
                pub fn updateByIdHandler(self: Self) type {
                    return struct {
                        pub fn action(ctx: *Global, req: *Request, res: *Response) !void {
                            const alloc = req.arena;
                            const id = req.param("id").?;
                            const type_info = @typeInfo(@TypeOf(self.field_access));
                            assert(type_info == .Struct, "Expectes struct type but found " ++ @typeName(@TypeOf(self.field_access)));
                            const accessor = try self.getAccessor(ctx, req, res);
                            if (accessor == null) return error.UNAUTHORIZED;
                            const accessor_name = @tagName(accessor.?);
                            const field_access_fields = type_info.Struct.fields;

                            const maybe_update_access: ?std.EnumSet(Fields) = blk: {
                                inline for (field_access_fields) |f| {
                                    if (std.mem.eql(u8, accessor_name, f.name)) {
                                        const field_access = @field(self.field_access, f.name);
                                        if (field_access) |x| break :blk x.update;
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

                            const query: []const u8 = blk: {
                                var q: []const u8 = try allocPrint(alloc, "UPDATE {s} SET ", .{self.name});
                                defer alloc.free(q);
                                var first = true;
                                for (keys, 0..) |field_name, i| {
                                    const field_tag = std.meta.stringToEnum(Fields, field_name);
                                    if (field_tag == null) {
                                        res.status = 400;
                                        res.body = try allocPrint(alloc, "Trying to update an unknown field: {s}", .{field_name});
                                        alloc.free(q);
                                        return;
                                    }
                                    if (update_access.contains(field_tag.?)) {
                                        const string_val = try std.json.stringifyAlloc(alloc, values[i], .{});
                                        defer alloc.free(string_val);
                                        const count = std.fmt.count("{s}, {s} = '{s}' ", .{ q, field_name, string_val });
                                        const buf = try alloc.alloc(u8, count);
                                        const new_query = switch (values[i]) {
                                            .string => |v| if (first) try std.fmt.bufPrintZ(buf, "{s} {s} = '{s}' ", .{ q, field_name, v }) else try std.fmt.bufPrint(buf, "{s} , {s} = '{s}' ", .{ q, field_name, v }),
                                            .integer => |v| if (first) try std.fmt.bufPrintZ(buf, "{s} {s} = {} ", .{ q, field_name, v }) else try std.fmt.bufPrint(buf, "{s} , {s} = {} ", .{ q, field_name, v }),
                                            .bool => |v| if (first) try std.fmt.bufPrint(buf, "{s} {s} = {} ", .{ q, field_name, v }) else try std.fmt.bufPrint(buf, "{s} , {s} = {} ", .{ q, field_name, v }),
                                            .float => |v| if (first) try std.fmt.bufPrint(buf, "{s} {s} = {d} ", .{ q, field_name, v }) else try std.fmt.bufPrint(buf, "{s} , {s} = {d} ", .{ q, field_name, v }),
                                            else => q,
                                        };
                                        if (first) first = false;
                                        alloc.free(q);
                                        q = try alloc.dupe(u8, new_query);
                                        alloc.free(buf);
                                    } else {
                                        res.status = 401;
                                        const detail = try allocPrint(alloc, "Updating {s} field is not included in your permission.", .{field_name});
                                        try res.json(.{
                                            .code = 401,
                                            .message = "UNAUTHORIZED",
                                            .detail = detail,
                                        }, .{});
                                        alloc.free(detail);
                                        alloc.free(q);
                                        return;
                                    }
                                }
                                break :blk try allocPrint(alloc, "{s} WHERE id = '{s}';", .{ q, id });
                            };

                            defer alloc.free(query);

                            const conn = try ctx.pg_pool.acquire();
                            defer conn.release();
                            const affected = conn.exec(query, .{}) catch |err| {
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
                            if (affected == 0) {
                                res.status = 404;
                                return;
                            }

                            const columns = try std.mem.join(alloc, ", ", keys);
                            defer alloc.free(columns);
                            const get_query = try allocPrint(alloc, "SELECT {s} FROM {s} where id = '{s}'", .{ columns, self.name, id });
                            defer alloc.free(get_query);
                            const result = conn.queryOpts(get_query, .{}, .{ .column_names = true }) catch |err| {
                                if (conn.err) |pg_err| {
                                    std.log.warn("update failure: {s}", .{pg_err.message});
                                }
                                return err;
                            };
                            defer result.deinit();
                            var mapper = result.mapper(OptionalSchema, .{ .dupe = true });
                            const updated = try mapper.next();
                            try res.json(updated.?, .{ .emit_null_optional_fields = false });
                            try result.drain();
                        }
                    };
                }
            };
        }
    };
    return RBA;
}

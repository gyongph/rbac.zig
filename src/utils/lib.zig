pub fn assert(ok: bool, comptime error_message: []const u8) void {
    if (!ok) @panic(error_message);
}
pub const Base64 = @import("base64.zig");
pub const Hash = @import("hash.zig");
pub const EnvVar = @import("env-var.zig");
pub const String = @import("string.zig");
pub const Number = @import("number.zig");

const std = @import("std");
const zstd_c = @import("zstd_c.zig");

pub const buffer_size = 128 * 1024;

fn checked(result: usize) !usize {
    if (zstd_c.ZSTD_isError(result) != 0) return error.ZstdFailed;
    return result;
}

pub const Encoder = struct {
    io: std.Io,
    file: std.Io.File,
    ctx: *zstd_c.ZstdCStream,
    position: u64,
    bytes: [buffer_size]u8 = undefined,

    pub fn init(io: std.Io, file: std.Io.File, offset: u64, level: c_int, workers: c_int, size: ?u64) !Encoder {
        if (workers < 0 or workers > 64) return error.InvalidWorkers;
        const ctx = zstd_c.ZSTD_createCStream() orelse return error.OutOfMemory;
        errdefer _ = zstd_c.ZSTD_freeCStream(ctx);
        _ = try checked(zstd_c.ZSTD_CCtx_setParameter(ctx, 100, level));
        // tar outer checksum; sized streams retain bounded 8 MiB history
        _ = try checked(zstd_c.ZSTD_CCtx_setParameter(ctx, 201, if (size == null) 1 else 0));
        if (workers != 0) _ = try checked(zstd_c.ZSTD_CCtx_setParameter(ctx, 400, workers));
        if (size) |pledged| {
            _ = try checked(zstd_c.ZSTD_CCtx_setPledgedSrcSize(ctx, pledged));
            var log: u6 = 23;
            while (log > 10 and (@as(u64, 1) << (log - 1)) >= pledged) log -= 1;
            _ = try checked(zstd_c.ZSTD_CCtx_setParameter(ctx, zstd_c.zstd_c_window_log, log));
        }
        return .{ .io = io, .file = file, .ctx = ctx, .position = offset };
    }
    pub fn deinit(self: *Encoder) void {
        _ = zstd_c.ZSTD_freeCStream(self.ctx);
    }
    fn pump(self: *Encoder, bytes: []const u8, directive: c_int) !void {
        var input: zstd_c.ZstdInBuffer = .{ .src = bytes.ptr, .size = bytes.len, .pos = 0 };
        while (input.pos < input.size or directive == 2) {
            var output: zstd_c.ZstdOutBuffer = .{ .dst = &self.bytes, .size = self.bytes.len, .pos = 0 };
            const remaining = try checked(zstd_c.ZSTD_compressStream2(self.ctx, &output, &input, directive));
            if (output.pos != 0) {
                try self.file.writePositionalAll(self.io, self.bytes[0..output.pos], self.position);
                self.position = std.math.add(u64, self.position, output.pos) catch return error.OutputOverflow;
            }
            if (directive == 2 and remaining == 0) break;
            if (directive != 2 and input.pos == input.size) break;
        }
    }
    pub fn write(self: *Encoder, bytes: []const u8) !void {
        try self.pump(bytes, 0);
    }
    pub fn finish(self: *Encoder) !void {
        try self.pump(&.{}, 2);
    }
};

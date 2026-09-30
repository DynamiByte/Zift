// exact-size single-frame zstd for zift formats

const std = @import("std");
const zstd_c = @import("zstd_c.zig");

const zstd_window_log_min: u8 = 10;
const zstd_window_log_max: u8 = if (@bitSizeOf(usize) == 32) 30 else 31;

pub const Error = error{
    CompressFailed,
    DecompressFailed,
    OutputTooLarge,
    OutputSizeMismatch,
    TrailingCompressedData,
    TruncatedFrame,
};

// zstd history limit: log2, 1 KiB minimum
pub fn initBoundedDStream(stream: *zstd_c.ZstdDStream, max_plain_len: u64) Error!void {
    const extent = @max(max_plain_len, 1);
    const needed_log: u8 = @intCast(std.math.log2_int_ceil(u64, extent));
    const window_log = std.math.clamp(needed_log, zstd_window_log_min, zstd_window_log_max);

    // ZSTD_initDStream: session reset only, window parameter retained
    const parameter_result = zstd_c.ZSTD_DCtx_setParameter(
        stream,
        zstd_c.zstd_d_window_log_max,
        window_log,
    );
    if (zstd_c.ZSTD_isError(parameter_result) != 0) return error.DecompressFailed;
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_initDStream(stream)) != 0) return error.DecompressFailed;
}

pub fn compressAlloc(
    allocator: std.mem.Allocator,
    plain: []const u8,
    level: c_int,
) (std.mem.Allocator.Error || Error)![]u8 {
    const capacity = zstd_c.ZSTD_compressBound(plain.len);
    if (zstd_c.ZSTD_isError(capacity) != 0) return error.CompressFailed;
    const storage = try allocator.alloc(u8, capacity);
    errdefer allocator.free(storage);
    const written = zstd_c.ZSTD_compress(
        if (storage.len == 0) null else storage.ptr,
        storage.len,
        if (plain.len == 0) null else plain.ptr,
        plain.len,
        level,
    );
    if (zstd_c.ZSTD_isError(written) != 0 or written > storage.len) return error.CompressFailed;
    return allocator.realloc(storage, written);
}

pub fn decompressExact(
    allocator: std.mem.Allocator,
    frame: []const u8,
    plain_len: usize,
) (std.mem.Allocator.Error || Error)![]u8 {
    const stream = zstd_c.ZSTD_createDStream() orelse return error.DecompressFailed;
    defer _ = zstd_c.ZSTD_freeDStream(stream);
    try initBoundedDStream(stream, @intCast(plain_len));

    const plain = try allocator.alloc(u8, plain_len);
    errdefer allocator.free(plain);
    var empty_out: [1]u8 = undefined;
    var input: zstd_c.ZstdInBuffer = .{
        .src = if (frame.len == 0) null else frame.ptr,
        .size = frame.len,
        .pos = 0,
    };
    var produced: usize = 0;

    while (true) {
        var output: zstd_c.ZstdOutBuffer = if (produced < plain.len)
            .{ .dst = plain.ptr + produced, .size = plain.len - produced, .pos = 0 }
        else
            .{ .dst = &empty_out, .size = empty_out.len, .pos = 0 };
        const before_input = input.pos;
        const remaining = zstd_c.ZSTD_decompressStream(stream, &output, &input);
        if (zstd_c.ZSTD_isError(remaining) != 0) return error.DecompressFailed;
        if (output.pos > plain.len - produced) return error.OutputTooLarge;
        produced += output.pos;

        if (produced > plain_len) return error.OutputTooLarge;
        if (remaining == 0) {
            if (input.pos != input.size) return error.TrailingCompressedData;
            if (produced != plain_len) return error.OutputSizeMismatch;
            return plain;
        }
        if (produced == plain_len and output.pos != 0) return error.OutputTooLarge;
        if (input.pos == before_input and output.pos == 0) return error.TruncatedFrame;
        if (input.pos == input.size and output.pos == 0) return error.TruncatedFrame;
    }
}

test "single zstd frame round trip is exact" {
    const allocator = std.testing.allocator;
    var bytes: [131_071]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index *% 37 +% index / 251);
    const frame = try compressAlloc(allocator, &bytes, 5);
    defer allocator.free(frame);
    const decoded = try decompressExact(allocator, frame, bytes.len);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &bytes, decoded);
}

test "single zstd frame rejects wrong size, truncation, and trailing bytes" {
    const allocator = std.testing.allocator;
    const frame = try compressAlloc(allocator, "directory bytes", 5);
    defer allocator.free(frame);

    try std.testing.expectError(error.OutputSizeMismatch, decompressExact(allocator, frame, "directory bytes".len + 1));
    try std.testing.expectError(error.OutputTooLarge, decompressExact(allocator, frame, "directory bytes".len - 1));
    try std.testing.expectError(error.TruncatedFrame, decompressExact(allocator, frame[0 .. frame.len - 1], "directory bytes".len));

    const with_tail = try allocator.alloc(u8, frame.len + 1);
    defer allocator.free(with_tail);
    @memcpy(with_tail[0..frame.len], frame);
    with_tail[frame.len] = 0;
    try std.testing.expectError(error.TrailingCompressedData, decompressExact(allocator, with_tail, "directory bytes".len));
}

test "decoder rejects a frame window larger than its approved output extent" {
    const allocator = std.testing.allocator;

    // equal one-byte output; 1 KiB vs 1 MiB history
    const bounded_frame = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd, // magic
        0x00, // non-single-segment frame, no content-size field
        0x00, // 1 KiB window
        0x09, 0x00, 0x00, // one-byte raw block, last block
        'x',
    };
    const oversized_window_frame = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd,
        0x00,
        0x50, // 1 MiB window
        0x09,
        0x00,
        0x00,
        'x',
    };

    const decoded = try decompressExact(allocator, &bounded_frame, 1);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("x", decoded);
    try std.testing.expectError(
        error.DecompressFailed,
        decompressExact(allocator, &oversized_window_frame, 1),
    );
}

test "every truncated frame prefix is refused without publishing output" {
    const allocator = std.testing.allocator;
    var plain: [4097]u8 = undefined;
    for (&plain, 0..) |*byte, index| byte.* = @truncate(index *% 19);
    const frame = try compressAlloc(allocator, &plain, 5);
    defer allocator.free(frame);

    for (0..frame.len) |cut| {
        if (decompressExact(allocator, frame[0..cut], plain.len)) |unexpected| {
            allocator.free(unexpected);
            return error.TruncatedFrameAccepted;
        } else |_| {}
    }
}

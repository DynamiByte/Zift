const std = @import("std");
pub const Error = error{ Truncated, IntegerOverflow, NonCanonical };

pub const max_uleb128_bytes: usize = 10;

pub fn appendUleb128(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) std.mem.Allocator.Error!void {
    var encoded: [max_uleb128_bytes]u8 = undefined;
    const bytes = encodeUleb128(value, &encoded);
    try out.appendSlice(allocator, bytes);
}

pub fn encodeUleb128(value: u64, out: *[max_uleb128_bytes]u8) []const u8 {
    var remaining = value;
    var len: usize = 0;
    while (remaining >= 0x80) {
        out[len] = @intCast((remaining & 0x7f) | 0x80);
        remaining >>= 7;
        len += 1;
    }
    out[len] = @intCast(remaining);
    return out[0 .. len + 1];
}

// pos unchanged on failure
pub fn decodeUleb128(bytes: []const u8, pos: *usize) Error!u64 {
    var cursor = pos.*;
    var value: u64 = 0;

    var byte_index: usize = 0;
    while (byte_index < max_uleb128_bytes) : (byte_index += 1) {
        if (cursor >= bytes.len) return Error.Truncated;
        const byte = bytes[cursor];
        cursor += 1;
        const payload = byte & 0x7f;

        // u64: one payload bit in tenth ULEB128 byte
        if (byte_index == max_uleb128_bytes - 1 and
            (payload > 1 or (byte & 0x80) != 0)) return Error.IntegerOverflow;

        const shift: u6 = @intCast(byte_index * 7);
        value |= @as(u64, payload) << shift;

        if ((byte & 0x80) == 0) {
            if (byte_index != 0 and payload == 0) return Error.NonCanonical;
            pos.* = cursor;
            return value;
        }
    }
    unreachable;
}

pub fn zigZagEncodeI64(value: i64) u64 {
    const bits: u64 = @bitCast(value);
    const sign: u64 = @bitCast(value >> 63);
    return (bits << 1) ^ sign;
}

pub fn zigZagDecodeI64(value: u64) i64 {
    const sign_mask = 0 -% (value & 1);
    return @bitCast((value >> 1) ^ sign_mask);
}

test "ULEB128 refuses truncation overflow and non-canonical spellings atomically" {
    const Case = struct { encoded: []const u8, wanted: Error };
    const cases = [_]Case{
        .{ .encoded = &.{0x80}, .wanted = Error.Truncated },
        .{ .encoded = &.{ 0x80, 0x00 }, .wanted = Error.NonCanonical },
        .{ .encoded = &.{ 0x81, 0x00 }, .wanted = Error.NonCanonical },
        .{ .encoded = &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 }, .wanted = Error.IntegerOverflow },
        .{ .encoded = &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, .wanted = Error.IntegerOverflow },
    };

    for (cases) |case| {
        var pos: usize = 0;
        try std.testing.expectError(case.wanted, decodeUleb128(case.encoded, &pos));
        try std.testing.expectEqual(@as(usize, 0), pos);
    }
}

test "canonical ULEB128 golden encodings" {
    const Case = struct { value: u64, encoded: []const u8 };
    const cases = [_]Case{
        .{ .value = 0, .encoded = &.{0x00} },
        .{ .value = 1, .encoded = &.{0x01} },
        .{ .value = 127, .encoded = &.{0x7f} },
        .{ .value = 128, .encoded = &.{ 0x80, 0x01 } },
        .{ .value = 300, .encoded = &.{ 0xac, 0x02 } },
        .{ .value = 16_383, .encoded = &.{ 0xff, 0x7f } },
        .{ .value = 16_384, .encoded = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = std.math.maxInt(u64), .encoded = &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 } },
    };

    for (cases) |case| {
        var storage: [max_uleb128_bytes]u8 = undefined;
        try std.testing.expectEqualSlices(u8, case.encoded, encodeUleb128(case.value, &storage));
        var pos: usize = 0;
        try std.testing.expectEqual(case.value, try decodeUleb128(case.encoded, &pos));
        try std.testing.expectEqual(case.encoded.len, pos);
    }
}

test "ZigZag covers the full signed domain" {
    for ([_]i64{ std.math.minInt(i64), -9_223_372_036_854_775_807, -128, -1, 0, 1, 127, std.math.maxInt(i64) }) |value| {
        try std.testing.expectEqual(value, zigZagDecodeI64(zigZagEncodeI64(value)));
    }
    try std.testing.expectEqual(@as(u64, 0), zigZagEncodeI64(0));
    try std.testing.expectEqual(@as(u64, 1), zigZagEncodeI64(-1));
    try std.testing.expectEqual(std.math.maxInt(u64), zigZagEncodeI64(std.math.minInt(i64)));
}

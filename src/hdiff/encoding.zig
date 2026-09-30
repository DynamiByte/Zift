// HDiff packUInt, cover deltas, rle0

const std = @import("std");

pub const Error = error{
    Truncated,
    IntegerOverflow,
    InvalidTagBits,
    OutOfRange,
    CoverOutOfRange,
    TargetOverflow,
    TargetUnderflow,
    RleUnderrun,
    RleOverrun,
};

pub const max_hdiff_pack_uint_bytes: usize = 10;

pub const HdiffPackUInt = struct {
    value: u64,
    tag: u8,
};

// leading zero groups allowed for fixed-width field rewrites
pub fn decodeHdiffPackUIntWithTag(bytes: []const u8, pos: *usize, tag_bits: u3) Error!HdiffPackUInt {
    if (tag_bits > 6) return Error.InvalidTagBits;

    var cursor = pos.*;
    if (cursor >= bytes.len) return Error.Truncated;
    const first = bytes[cursor];
    cursor += 1;

    const continuation_shift: u3 = @intCast(7 - @as(u8, tag_bits));
    const continuation_mask: u8 = @as(u8, 1) << continuation_shift;
    const tag: u8 = if (tag_bits == 0)
        0
    else
        first >> @intCast(8 - @as(u8, tag_bits));
    var value: u64 = first & (continuation_mask - 1);
    var used: usize = 1;
    var continued = (first & continuation_mask) != 0;

    while (continued) {
        // length cap for zero prefixes without shift overflow
        if (used == max_hdiff_pack_uint_bytes) return Error.IntegerOverflow;
        if (cursor >= bytes.len) return Error.Truncated;
        const byte = bytes[cursor];
        cursor += 1;
        if (value > (std.math.maxInt(u64) >> 7)) return Error.IntegerOverflow;
        value = (value << 7) | (byte & 0x7f);
        continued = (byte & 0x80) != 0;
        used += 1;
    }

    pos.* = cursor;
    return .{ .value = value, .tag = tag };
}

pub fn decodeHdiffPackUInt(bytes: []const u8, pos: *usize) Error!u64 {
    return (try decodeHdiffPackUIntWithTag(bytes, pos, 0)).value;
}

pub fn checkedAddU64(a: u64, b: u64) Error!u64 {
    return std.math.add(u64, a, b) catch Error.IntegerOverflow;
}

pub fn checkedU64ToUsize(value: u64) Error!usize {
    return std.math.cast(usize, value) orelse Error.IntegerOverflow;
}

pub const Cover = struct {
    old_pos: u64,
    new_pos: u64,
    length: u64,
};

// end-relative cover deltas; carried across steps, reset per window
pub const CoverReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    last_old_end: u64,
    last_new_end: u64,

    pub fn init(bytes: []const u8, last_old_end: u64, last_new_end: u64) CoverReader {
        return .{
            .bytes = bytes,
            .last_old_end = last_old_end,
            .last_new_end = last_new_end,
        };
    }

    pub fn next(self: *CoverReader) Error!Cover {
        var cursor = self.pos;

        const encoded_old = try decodeHdiffPackUIntWithTag(self.bytes, &cursor, 1);
        const old_pos = if (encoded_old.tag == 0)
            std.math.add(u64, self.last_old_end, encoded_old.value) catch return Error.CoverOutOfRange
        else blk: {
            if (encoded_old.value > self.last_old_end) return Error.CoverOutOfRange;
            break :blk self.last_old_end - encoded_old.value;
        };

        const new_delta = try decodeHdiffPackUInt(self.bytes, &cursor);
        const new_pos = std.math.add(u64, self.last_new_end, new_delta) catch return Error.TargetOverflow;
        const length = try decodeHdiffPackUInt(self.bytes, &cursor);

        const old_end = std.math.add(u64, old_pos, length) catch return Error.CoverOutOfRange;
        const new_end = std.math.add(u64, new_pos, length) catch return Error.TargetOverflow;

        self.pos = cursor;
        self.last_old_end = old_end;
        self.last_new_end = new_end;
        return .{ .old_pos = old_pos, .new_pos = new_pos, .length = length };
    }

    pub fn atEnd(self: *const CoverReader) bool {
        return self.pos == self.bytes.len;
    }
};

// W26 rle0: alternating zero runs / modulo-256 ADD bytes
pub const Rle0 = struct {
    code: []const u8,
    pos: usize = 0,
    zero_remaining: u64 = 0,
    value_remaining: u64 = 0,
    next_is_zero: bool = true,

    pub fn init(code: []const u8) Rle0 {
        return .{ .code = code };
    }

    pub fn addTo(self: *Rle0, out: []u8) Error!void {
        var out_pos: usize = 0;
        while (out_pos < out.len) {
            if (self.zero_remaining != 0) {
                const available: u64 = @intCast(out.len - out_pos);
                const take_u64 = @min(self.zero_remaining, available);
                const take: usize = @intCast(take_u64);
                self.zero_remaining -= take_u64;
                out_pos += take;
                continue;
            }

            if (self.value_remaining != 0) {
                const available: u64 = @intCast(out.len - out_pos);
                const take_u64 = @min(self.value_remaining, available);
                const take: usize = @intCast(take_u64);
                if (self.pos > self.code.len or take > self.code.len - self.pos)
                    return Error.RleOverrun;
                for (out[out_pos..][0..take], self.code[self.pos..][0..take]) |*byte, addend| {
                    byte.* +%= addend;
                }
                self.pos += take;
                self.value_remaining -= take_u64;
                out_pos += take;
                continue;
            }

            var cursor = self.pos;
            const length = decodeHdiffPackUInt(self.code, &cursor) catch |err| switch (err) {
                Error.Truncated => return Error.RleUnderrun,
                else => |e| return e,
            };
            if (self.next_is_zero) {
                self.pos = cursor;
                self.zero_remaining = length;
                self.next_is_zero = false;
            } else {
                const encoded_left: u64 = @intCast(self.code.len - cursor);
                if (length > encoded_left) return Error.RleOverrun;
                self.pos = cursor;
                self.value_remaining = length;
                self.next_is_zero = true;
            }
        }
    }

    // trailing zero-length field still trailing data
    pub fn atEnd(self: *const Rle0) bool {
        return self.zero_remaining == 0 and
            self.value_remaining == 0 and
            self.pos == self.code.len;
    }

    pub fn finish(self: *const Rle0) Error!void {
        if (!self.atEnd()) return Error.RleOverrun;
    }
};

test "HDiff packUInt handles tags and valid non-minimal fields" {
    var pos: usize = 0;
    const tagged = try decodeHdiffPackUIntWithTag(&.{ 0xc2, 0x2c }, &pos, 1);
    try std.testing.expectEqual(@as(u64, 300), tagged.value);
    try std.testing.expectEqual(@as(u8, 1), tagged.tag);
    try std.testing.expectEqual(@as(usize, 2), pos);

    pos = 0;
    try std.testing.expectEqual(@as(u64, 0), try decodeHdiffPackUInt(&.{ 0x80, 0x00 }, &pos));

    pos = 0;
    try std.testing.expectEqual(
        std.math.maxInt(u64),
        try decodeHdiffPackUInt(&.{ 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, &pos),
    );
}

test "HDiff packUInt refuses truncation overflow and overlength atomically" {
    var pos: usize = 0;
    try std.testing.expectError(Error.Truncated, decodeHdiffPackUInt(&.{0x82}, &pos));
    try std.testing.expectEqual(@as(usize, 0), pos);

    try std.testing.expectError(Error.IntegerOverflow, decodeHdiffPackUInt(&.{ 0x82, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, &pos));
    try std.testing.expectEqual(@as(usize, 0), pos);

    try std.testing.expectError(Error.IntegerOverflow, decodeHdiffPackUInt(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }, &pos));
    try std.testing.expectEqual(@as(usize, 0), pos);

    try std.testing.expectError(Error.InvalidTagBits, decodeHdiffPackUIntWithTag(&.{0}, &pos, 7));
    try std.testing.expectEqual(@as(usize, 0), pos);
}

test "cover reader supports backward Source deltas and transactional past-start refusal" {
    // covers: (old 0, new 0, len 10), (old 0, new 12, len 5)
    const bytes = [_]u8{ 0x00, 0x00, 10, 0x8a, 0x02, 5 };
    var reader = CoverReader.init(&bytes, 0, 0);

    try std.testing.expectEqual(Cover{ .old_pos = 0, .new_pos = 0, .length = 10 }, try reader.next());
    try std.testing.expectEqual(Cover{ .old_pos = 0, .new_pos = 12, .length = 5 }, try reader.next());
    try std.testing.expect(reader.atEnd());
    try std.testing.expectEqual(@as(u64, 5), reader.last_old_end);
    try std.testing.expectEqual(@as(u64, 17), reader.last_new_end);

    var invalid = CoverReader.init(&.{ 0x85, 0x00, 1 }, 4, 9);
    const before = invalid;
    try std.testing.expectError(Error.CoverOutOfRange, invalid.next());
    try expectCoverReaderStateEqual(before, invalid);
}

test "cover reader failures preserve cursor and carried ends" {
    const Case = struct {
        bytes: []const u8,
        old_end: u64,
        new_end: u64,
        wanted: Error,
    };
    const cases = [_]Case{
        .{ .bytes = &.{}, .old_end = 7, .new_end = 11, .wanted = Error.Truncated },
        .{ .bytes = &.{ 1, 0x82 }, .old_end = 7, .new_end = 11, .wanted = Error.Truncated },
        .{ .bytes = &.{ 1, 0, 0 }, .old_end = std.math.maxInt(u64), .new_end = 0, .wanted = Error.CoverOutOfRange },
        .{ .bytes = &.{ 0, 0, 2 }, .old_end = std.math.maxInt(u64) - 1, .new_end = 0, .wanted = Error.CoverOutOfRange },
        .{ .bytes = &.{ 0, 1, 0 }, .old_end = 0, .new_end = std.math.maxInt(u64), .wanted = Error.TargetOverflow },
        .{ .bytes = &.{ 0, 0, 2 }, .old_end = 0, .new_end = std.math.maxInt(u64) - 1, .wanted = Error.TargetOverflow },
        .{
            .bytes = &.{ 0x40, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
            .old_end = 7,
            .new_end = 11,
            .wanted = Error.IntegerOverflow,
        },
    };

    for (cases) |case| {
        var reader = CoverReader.init(case.bytes, case.old_end, case.new_end);
        const before = reader;
        try std.testing.expectError(case.wanted, reader.next());
        try expectCoverReaderStateEqual(before, reader);
    }
}

test "rle0 crosses zero and value boundaries across arbitrary output chunks" {
    // rle0: zero 2, values {1,2,3}, zero 2, value {10}
    const code = [_]u8{ 2, 3, 1, 2, 3, 2, 1, 10 };
    var decoder = Rle0.init(&code);
    var out = [_]u8{250} ** 8;

    try decoder.addTo(out[0..1]);
    try decoder.addTo(out[1..4]);
    try decoder.addTo(out[4..5]);
    try decoder.addTo(out[5..]);
    try decoder.finish();
    try std.testing.expectEqualSlices(u8, &.{ 250, 250, 251, 252, 253, 250, 250, 4 }, &out);
}

test "rle0 reports truncated malformed and oversized runs" {
    var absent = Rle0.init(&.{});
    var one = [_]u8{17};
    try std.testing.expectError(Error.RleUnderrun, absent.addTo(&one));
    try std.testing.expectEqualSlices(u8, &.{17}, &one);

    var truncated = Rle0.init(&.{ 0, 0x82 });
    try std.testing.expectError(Error.RleUnderrun, truncated.addTo(&one));
    try std.testing.expectEqual(@as(usize, 1), truncated.pos);

    var overflow = Rle0.init(&.{ 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 });
    try std.testing.expectError(Error.IntegerOverflow, overflow.addTo(&one));

    var overrun = Rle0.init(&.{ 0, 3, 1, 2 });
    try std.testing.expectError(Error.RleOverrun, overrun.addTo(&one));
    try std.testing.expectEqual(@as(usize, 1), overrun.pos);
    try std.testing.expect(!overrun.next_is_zero);

    var too_short = Rle0.init(&.{1});
    var two = [_]u8{ 9, 9 };
    try std.testing.expectError(Error.RleUnderrun, too_short.addTo(&two));
}

test "rle0 finish requires exact consumption and rejects trailing fields" {
    var empty = Rle0.init(&.{});
    try empty.finish();

    var exact_zero = Rle0.init(&.{3});
    var zeros = [_]u8{ 1, 2, 3 };
    try exact_zero.addTo(&zeros);
    try exact_zero.finish();
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, &zeros);

    var exact_value = Rle0.init(&.{ 0, 2, 4, 5 });
    var values = [_]u8{ 1, 1 };
    try exact_value.addTo(&values);
    try exact_value.finish();
    try std.testing.expectEqualSlices(u8, &.{ 5, 6 }, &values);

    var partial = Rle0.init(&.{3});
    try partial.addTo(zeros[0..2]);
    try std.testing.expectError(Error.RleOverrun, partial.finish());

    var trailing = Rle0.init(&.{ 3, 0 });
    try trailing.addTo(&zeros);
    try std.testing.expectError(Error.RleOverrun, trailing.finish());
}

fn expectCoverReaderStateEqual(expected: CoverReader, actual: CoverReader) !void {
    try std.testing.expectEqual(expected.pos, actual.pos);
    try std.testing.expectEqual(expected.last_old_end, actual.last_old_end);
    try std.testing.expectEqual(expected.last_new_end, actual.last_new_end);
    try std.testing.expectEqualSlices(u8, expected.bytes, actual.bytes);
}

pub fn readUInt(reader: anytype) !u64 {
    return readUIntTagged(reader, 0, null);
}
pub fn readUIntTagged(reader: anytype, tag_bits: u3, tag_out: ?*u8) !u64 {
    if (tag_bits > 6) return Error.InvalidTagBits;

    const first = try reader.byte();
    const continuation_shift: u3 = @intCast(7 - @as(u8, tag_bits));
    const continuation_mask: u8 = @as(u8, 1) << continuation_shift;
    const tag: u8 = if (tag_bits == 0)
        0
    else
        first >> @intCast(8 - @as(u8, tag_bits));
    var value: u64 = first & (continuation_mask - 1);
    var used: usize = 1;
    var continued = (first & continuation_mask) != 0;
    while (continued) {
        if (used == max_hdiff_pack_uint_bytes) return Error.IntegerOverflow;
        if (value > (std.math.maxInt(u64) >> 7)) return Error.IntegerOverflow;
        const next = try reader.byte();
        value = (value << 7) | (next & 0x7f);
        continued = (next & 0x80) != 0;
        used += 1;
    }
    if (tag_out) |out| out.* = tag;
    return value;
}

pub fn encodeUIntTagged(value: u64, tag: u8, tag_bits: u3, storage: *[max_hdiff_pack_uint_bytes]u8) []const u8 {
    std.debug.assert(tag_bits <= 6);
    var remaining = value;
    var reversed: [max_hdiff_pack_uint_bytes]u8 = undefined;
    var count: usize = 0;
    const first_bits: u6 = 7 - @as(u6, tag_bits);
    while (remaining >= @as(u64, 1) << first_bits) {
        reversed[count] = @as(u8, @truncate(remaining & 0x7f)) | (if (count == 0) @as(u8, 0) else 0x80);
        count += 1;
        remaining >>= 7;
    }
    storage[0] = @as(u8, @intCast(remaining)) | (if (tag_bits == 0) @as(u8, 0) else tag << @intCast(8 - @as(u4, tag_bits))) | (if (count == 0) @as(u8, 0) else @as(u8, 1) << @intCast(first_bits));
    for (0..count) |i| storage[i + 1] = reversed[count - i - 1];
    return storage[0 .. count + 1];
}

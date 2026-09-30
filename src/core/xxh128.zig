// shared XXH3-64 stripe accumulator; distinct mixing/finalization
// xxHash mixing/finalization: Copyright (c) Yann Collet, BSD-2-Clause
const std = @import("std");

pub const Digest = struct { low: u64, high: u64 };
const p1: u64 = 0x9e3779b185ebca87;
const p2: u64 = 0xc2b2ae3d27d4eb4f;
const p3: u64 = 0x165667b19e3779f9;
const p4: u64 = 0x85ebca77c2b2ae63;

inline fn r64(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .little);
}
inline fn r32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}
inline fn avalanche(x: u64) u64 {
    const y = (x ^ (x >> 37)) *% 0x165667919e3779f9;
    return y ^ (y >> 32);
}
inline fn avalanche64(x: u64) u64 {
    const y = (x ^ (x >> 33)) *% p2;
    const z = (y ^ (y >> 29)) *% p3;
    return z ^ (z >> 32);
}
inline fn multiply(a: u64, b: u64) Digest {
    const wide = @as(u128, a) * b;
    return .{ .low = @truncate(wide), .high = @truncate(wide >> 64) };
}
inline fn fold(a: u64, b: u64) u64 {
    const v = multiply(a, b);
    return v.low ^ v.high;
}
inline fn mix16(input: []const u8, secret: []const u8) u64 {
    return fold(r64(input) ^ r64(secret), r64(input[8..]) ^ r64(secret[8..]));
}
fn mix32(acc: *Digest, a: []const u8, b: []const u8, secret: []const u8) void {
    acc.low +%= mix16(a, secret);
    acc.low ^= r64(b) +% r64(b[8..]);
    acc.high +%= mix16(b, secret[16..]);
    acc.high ^= r64(a) +% r64(a[8..]);
}
fn converge(acc: Digest, len: usize) Digest {
    return .{
        .low = avalanche(acc.low +% acc.high),
        .high = 0 -% avalanche(acc.low *% p1 +% acc.high *% p4 +% @as(u64, len) *% p2),
    };
}

fn short(input: []const u8, secret: []const u8) Digest {
    const len = input.len;
    if (len > 128) {
        var acc: Digest = .{ .low = @as(u64, len) *% p1, .high = 0 };
        var i: usize = 32;
        while (i < 160) : (i += 32)
            mix32(&acc, input[i - 32 ..], input[i - 16 ..], secret[i - 32 ..]);
        acc.low = avalanche(acc.low);
        acc.high = avalanche(acc.high);
        while (i <= len) : (i += 32)
            mix32(&acc, input[i - 32 ..], input[i - 16 ..], secret[3 + i - 160 ..]);
        mix32(&acc, input[len - 16 ..], input[len - 32 ..], secret[103..]);
        return converge(acc, len);
    }
    if (len > 16) {
        var acc: Digest = .{ .low = @as(u64, len) *% p1, .high = 0 };
        var i = (len - 1) / 32;
        while (true) {
            mix32(&acc, input[16 * i ..], input[len - 16 * (i + 1) ..], secret[32 * i ..]);
            if (i == 0) break;
            i -= 1;
        }
        return converge(acc, len);
    }
    if (len > 8) {
        var m = multiply(r64(input) ^ r64(input[len - 8 ..]) ^ r64(secret[32..]) ^ r64(secret[40..]), p1);
        m.low +%= @as(u64, len - 1) << 54;
        const hi = r64(input[len - 8 ..]) ^ r64(secret[48..]) ^ r64(secret[56..]);
        m.high +%= hi +% @as(u64, @as(u32, @truncate(hi))) *% (0x85ebca77 - 1);
        m.low ^= @byteSwap(m.high);
        var result = multiply(m.low, p2);
        result.high +%= m.high *% p2;
        return .{ .low = avalanche(result.low), .high = avalanche(result.high) };
    }
    if (len >= 4) {
        const combined = @as(u64, r32(input)) | (@as(u64, r32(input[len - 4 ..])) << 32);
        var m = multiply(combined ^ r64(secret[16..]) ^ r64(secret[24..]), p1 +% (@as(u64, len) << 2));
        m.high +%= m.low << 1;
        m.low ^= m.high >> 3;
        m.low = (m.low ^ (m.low >> 35)) *% 0x9fb21c651e98df25;
        return .{ .low = m.low ^ (m.low >> 28), .high = avalanche(m.high) };
    }
    if (len != 0) {
        const combined = (@as(u32, input[0]) << 16) | (@as(u32, input[len / 2]) << 24) |
            @as(u32, input[len - 1]) | (@as(u32, @intCast(len)) << 8);
        return .{
            .low = avalanche64(@as(u64, combined) ^ r32(secret) ^ r32(secret[4..])),
            .high = avalanche64(@as(u64, std.math.rotl(u32, @byteSwap(combined), 13)) ^ r32(secret[8..]) ^ r32(secret[12..])),
        };
    }
    return .{
        .low = avalanche64(r64(secret[64..]) ^ r64(secret[72..])),
        .high = avalanche64(r64(secret[80..]) ^ r64(secret[88..])),
    };
}

fn round(state: *@Vector(8, u64), input: []const u8, secret: []const u8) void {
    inline for (0..8) |i| {
        const data = r64(input[i * 8 ..]);
        const mixed = data ^ r64(secret[i * 8 ..]);
        state[i] +%= (mixed & 0xffffffff) *% (mixed >> 32);
        state[i ^ 1] +%= data;
    }
}
fn consume(acc: anytype, bytes: []const u8) void {
    var pos: usize = 0;
    while (pos < bytes.len) : (pos += 64) {
        round(&acc.state, bytes[pos..], acc.secret[acc.consumed * 8 ..]);
        acc.consumed += 1;
        if (acc.consumed == 16) {
            inline for (0..8) |i| {
                acc.state[i] ^= acc.state[i] >> 47;
                acc.state[i] ^= r64(acc.secret[128 + i * 8 ..]);
                acc.state[i] *%= 0x9e3779b1;
            }
            acc.consumed = 0;
        }
    }
}
fn merge(state: @Vector(8, u64), secret: []const u8, start: u64) u64 {
    var result = start;
    inline for (0..4) |i|
        result +%= fold(state[2 * i] ^ r64(secret[16 * i ..]), state[2 * i + 1] ^ r64(secret[16 * i + 8 ..]));
    return avalanche(result);
}

pub const Hasher = struct {
    stream: std.hash.XxHash3 = .init(0),

    pub fn update(self: *Hasher, bytes: []const u8) void {
        self.stream.update(bytes);
    }
    pub fn final(self: *const Hasher) Digest {
        const stream = &self.stream;
        if (stream.total_len <= 240) return short(stream.buffer[0..stream.total_len], &stream.accumulator.secret);
        var acc = stream.accumulator;
        var last: [64]u8 = undefined;
        if (stream.buffered >= 64) {
            consume(&acc, stream.buffer[0 .. ((stream.buffered - 1) / 64) * 64]);
            @memcpy(&last, stream.buffer[stream.buffered - 64 ..][0..64]);
        } else {
            const remaining = 64 - stream.buffered;
            @memcpy(last[0..remaining], stream.buffer[256 - remaining ..]);
            @memcpy(last[remaining..], stream.buffer[0..stream.buffered]);
        }
        round(&acc.state, &last, acc.secret[121..]);
        return .{
            .low = merge(acc.state, acc.secret[11..], @as(u64, stream.total_len) *% p1),
            .high = merge(acc.state, acc.secret[117..], ~(@as(u64, stream.total_len) *% p2)),
        };
    }
};

pub fn hash(bytes: []const u8) Digest {
    var self: Hasher = .{};
    self.update(bytes);
    return self.final();
}

test "XXH3-128 upstream vectors and arbitrary streaming boundaries" {
    try std.testing.expectEqual(Digest{ .low = 0x6001c324468d497f, .high = 0x99aa06d3014798d8 }, hash(""));
    var bytes: [8193]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 137 + i / 7);
    const lengths = [_]usize{ 1, 2, 3, 4, 8, 9, 16, 17, 32, 64, 96, 128, 129, 160, 192, 240, 241, 256, 257, 1024, 1025, 8193 };
    // independent libxxhash XXH3_128bits vectors
    const vectors = [_]Digest{
        .{ .low = 0xc44bdff4074eecdb, .high = 0xa6cd5e9392000f6a },
        .{ .low = 0xf45e75ec095bdd9b, .high = 0x4959bc6edac4a850 },
        .{ .low = 0x1ba32b78927b958b, .high = 0xd70d30d4ce518d81 },
        .{ .low = 0x365b868f94a88848, .high = 0x65cfaff15c3aee1e },
        .{ .low = 0x9dc8d524cd1a61db, .high = 0x63c3a8b111086bad },
        .{ .low = 0x491eddf78ee25695, .high = 0xb7af75e4246ceecc },
        .{ .low = 0x4e9cbad48b9553a7, .high = 0xa0105c60db8130f9 },
        .{ .low = 0x8a4ce5f8877c194c, .high = 0x086a8d6ea1e0343e },
        .{ .low = 0x9b6bbe18bf4afbfd, .high = 0xda34a88798aec547 },
        .{ .low = 0x8597626fe605fd6f, .high = 0xc4f65b12a06422a0 },
        .{ .low = 0xa5287b010153896e, .high = 0x109098f356767fca },
        .{ .low = 0x6c8510b0c583649b, .high = 0xbeaa1e840b21ea7a },
        .{ .low = 0x544dd663eb4bc17e, .high = 0x1033e1b98665566a },
        .{ .low = 0x54adb6d88795753d, .high = 0xb4d7d9df0dc3ecc6 },
        .{ .low = 0x87c224c53da7d7f8, .high = 0xa28dfc69303aee92 },
        .{ .low = 0x7579a2e341b35820, .high = 0x0ebd08115a97ac17 },
        .{ .low = 0x38cce0ca7103218a, .high = 0xa48589b0fbaa9230 },
        .{ .low = 0xedca073ef3800b95, .high = 0x520ca98fb94a1f61 },
        .{ .low = 0xd79890096dc54758, .high = 0x7faa7e654fd056f8 },
        .{ .low = 0x9b3bc318fe994a68, .high = 0xfd9c256bf95215a5 },
        .{ .low = 0xff78b23ba11ef273, .high = 0x72efd548b8831509 },
        .{ .low = 0x03cbbee137fe139b, .high = 0x93d5f58d4eaed163 },
    };
    for (lengths, vectors) |len, expected| {
        try std.testing.expectEqual(expected, hash(bytes[0..len]));
        for ([_]usize{ 1, 3, 63, 64, 65, 127, 255, 256, 1024 }) |chunk| {
            var stream: Hasher = .{};
            var pos: usize = 0;
            while (pos < len) {
                const end = @min(len, pos + chunk);
                stream.update(bytes[pos..end]);
                _ = stream.final();
                pos = end;
            }
            try std.testing.expectEqual(expected, stream.final());
        }
    }
}

const std = @import("std");

pub const ReadWindow = struct {
    bytes: []u8,
    offset: u64 = 0,
    len: usize = 0,
    pub fn reset(self: *ReadWindow) void {
        self.len = 0;
    }
    // reset on source change
    pub fn read(self: *ReadWindow, source: anytype, out: []u8, offset: u64, limit: u64) !void {
        if (offset > limit or out.len > limit - offset) return error.BufferedReadOutOfBounds;
        var done: usize = 0;
        while (done < out.len) {
            const at = offset + done;
            if (at >= self.offset and at - self.offset < self.len) {
                const start: usize = @intCast(at - self.offset);
                const n = @min(out.len - done, self.len - start);
                @memcpy(out[done..][0..n], self.bytes[start..][0..n]);
                done += n;
                continue;
            }
            if (self.bytes.len == 0 or out.len - done >= self.bytes.len) {
                try source.readExact(out[done..], at);
                return;
            }
            // failed refill must not leave stale cached bytes
            self.len = 0;
            self.offset = at;
            const n: usize = @intCast(@min(@as(u64, self.bytes.len), limit - at));
            try source.readExact(self.bytes[0..n], at);
            self.len = n;
        }
    }
};
pub const WriteBuffer = struct {
    bytes: []u8,
    offset: u64 = 0,
    len: usize = 0,
    // explicit flush before sync/truncation
    pub fn flush(self: *WriteBuffer, sink: anytype) !void {
        if (self.len == 0) return;
        try sink.writeExact(self.bytes[0..self.len], self.offset);
        self.len = 0;
    }
    pub fn write(self: *WriteBuffer, sink: anytype, input: []const u8, offset: u64) !void {
        if (input.len > std.math.maxInt(u64) - offset) return error.BufferedWriteOverflow;
        if (input.len == 0) return;
        if (self.len != 0 and offset != self.offset + self.len) try self.flush(sink);
        var done: usize = 0;
        while (done < input.len) {
            if (self.len == 0) {
                self.offset = offset + done;
                if (self.bytes.len == 0 or input.len - done >= @min(self.bytes.len, 128 * 1024)) {
                    try sink.writeExact(input[done..], offset + done);
                    return;
                }
            }
            const n = @min(input.len - done, self.bytes.len - self.len);
            @memcpy(self.bytes[self.len..][0..n], input[done..][0..n]);
            self.len += n;
            done += n;
            if (self.len == self.bytes.len) try self.flush(sink);
        }
    }
};
const Fake = struct {
    data: [128]u8 = @splat(99),
    reads: usize = 0,
    writes: usize = 0,
    fail: bool = false,
    pub fn readExact(self: *Fake, out: []u8, offset: u64) !void {
        self.reads += 1;
        if (self.fail) return error.InjectedRead;
        @memcpy(out, self.data[@intCast(offset)..][0..out.len]);
    }
    pub fn writeExact(self: *Fake, data: []const u8, offset: u64) !void {
        self.writes += 1;
        if (self.fail) return error.InjectedWrite;
        @memcpy(self.data[@intCast(offset)..][0..data.len], data);
    }
};
test "write buffer coalesces adjacent fragments without touching gaps" {
    var mem: [16]u8 = undefined;
    var b: WriteBuffer = .{ .bytes = &mem };
    var f: Fake = .{};
    try b.write(&f, "ab", 2);
    try b.write(&f, "cde", 4);
    try std.testing.expectEqual(@as(usize, 0), f.writes);
    try b.write(&f, "XY", 20);
    try std.testing.expectEqual(@as(usize, 1), f.writes);
    try b.flush(&f);
    try std.testing.expectEqual(@as(usize, 2), f.writes);
    try std.testing.expectEqualStrings("abcde", f.data[2..7]);
    try std.testing.expectEqualStrings("XY", f.data[20..22]);
    for (f.data[7..20]) |byte| try std.testing.expectEqual(@as(u8, 99), byte);
}
test "write buffer drains bounded blocks and supports an unbuffered control" {
    var mem: [4]u8 = undefined;
    var b: WriteBuffer = .{ .bytes = &mem };
    var f: Fake = .{};
    try b.write(&f, "ab", 0);
    try b.write(&f, "cdefghijk", 2);
    try b.flush(&f);
    try std.testing.expectEqualStrings("abcdefghijk", f.data[0..11]);
    try std.testing.expectEqual(@as(usize, 2), f.writes);
    b = .{ .bytes = &.{} };
    try b.write(&f, "xy", 30);
    try std.testing.expectEqualStrings("xy", f.data[30..32]);
    try std.testing.expectError(error.BufferedWriteOverflow, b.write(&f, "xy", std.math.maxInt(u64)));
}
test "failed buffered write is propagated and not marked flushed" {
    var mem: [8]u8 = undefined;
    var b: WriteBuffer = .{ .bytes = &mem };
    var f: Fake = .{ .fail = true };
    try b.write(&f, "abc", 2);
    try std.testing.expectError(error.InjectedWrite, b.flush(&f));
    try std.testing.expectEqual(@as(usize, 3), b.len);
}
test "read window confines read-ahead and invalidates before a failed refill" {
    var mem: [16]u8 = undefined;
    var b: ReadWindow = .{ .bytes = &mem };
    var f: Fake = .{};
    var out: [4]u8 = undefined;
    for (&f.data, 0..) |*v, i| v.* = @intCast(i);
    try b.read(&f, &out, 8, 18);
    try b.read(&f, &out, 12, 18);
    try std.testing.expectEqual(@as(usize, 1), f.reads);
    try std.testing.expectEqual(@as(usize, 10), b.len);
    try std.testing.expectEqualSlices(u8, f.data[12..16], &out);
    try std.testing.expectError(error.BufferedReadOutOfBounds, b.read(&f, &out, 16, 18));
    b.reset();
    f.fail = true;
    try std.testing.expectError(error.InjectedRead, b.read(&f, &out, 8, 18));
    try std.testing.expectEqual(@as(usize, 0), b.len);
}
test "read window combines partial hits with direct large reads" {
    var mem: [8]u8 = undefined;
    var b: ReadWindow = .{ .bytes = &mem };
    var f: Fake = .{};
    var out: [16]u8 = undefined;
    for (&f.data, 0..) |*v, i| v.* = @intCast(i);
    try b.read(&f, out[0..4], 0, 128);
    try b.read(&f, &out, 6, 128);
    try std.testing.expectEqualSlices(u8, f.data[6..22], &out);
    try std.testing.expectEqual(@as(usize, 2), f.reads);
    b = .{ .bytes = &.{} };
    try b.read(&f, out[0..4], 30, 128);
    try std.testing.expectEqualSlices(u8, f.data[30..34], out[0..4]);
}

test "already large output blocks bypass copying into a larger buffer" {
    const a = std.testing.allocator;
    const storage = try a.alloc(u8, 256 * 1024);
    defer a.free(storage);
    const input = try a.alloc(u8, 128 * 1024);
    defer a.free(input);
    @memset(input, 7);
    const Sink = struct {
        calls: usize = 0,
        total: usize = 0,
        pub fn writeExact(self: *@This(), data: []const u8, offset: u64) !void {
            try std.testing.expectEqual(@as(u64, @intCast(self.total)), offset);
            for (data) |v| try std.testing.expectEqual(@as(u8, 7), v);
            self.calls += 1;
            self.total += data.len;
        }
    };
    var sink: Sink = .{};
    var b: WriteBuffer = .{ .bytes = storage };
    try b.write(&sink, input, 0);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(@as(usize, 0), b.len);
    try b.write(&sink, input[0..16384], input.len);
    try b.write(&sink, input[0..16384], input.len + 16384);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try b.flush(&sink);
    try std.testing.expectEqual(@as(usize, 2), sink.calls);
}

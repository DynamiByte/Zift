// bounded stored/zstd file cursor

const std = @import("std");
const zstd_c = @import("zstd_c.zig");
const fs = @import("../core/fs.zig");
const scan = @import("../core/scan.zig");

pub const stream_buffer_bytes: usize = 128 * 1024;
pub const zstd_window_bytes_min: u64 = 1024;
const zstd_window_log_min: u8 = 10;
const zstd_window_log_max: u8 = if (@bitSizeOf(usize) == 32) 30 else 31;

pub const Error = error{
    AlreadyFinished,
    DecompressFailed,
    DecompressStalled,
    InvalidReadCount,
    InvalidWindowCap,
    OutputBudgetExceeded,
    OutputSizeMismatch,
    OutputTooLarge,
    RangeOutOfBounds,
    TrailingCompressedData,
    TruncatedBody,
    TruncatedFrame,
};

pub const Options = struct {
    // applier-selected history budget
    max_window_bytes: u64,
    reader: scan.Reader = .direct,
};

const Mode = union(enum) {
    stored,
    zstd: *zstd_c.ZstdDStream,
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    reader: scan.Reader,
    mode: Mode,

    range_end: u64,
    file_position: u64,
    stored_remaining: u64,
    decoded_remaining: u64,

    input_storage: []u8,
    input_len: usize = 0,
    input_pos: usize = 0,
    output_storage: []u8,
    output_len: usize = 0,
    output_pos: usize = 0,

    frame_finished: bool = false,
    finished: bool = false,

    // compressed_size == 0: stored uncompressed_size bytes
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        file: std.Io.File,
        offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        options: Options,
    ) !Decoder {
        try validateWindowCap(options.max_window_bytes);

        const stored_size = if (compressed_size == 0) uncompressed_size else compressed_size;
        const range_end = std.math.add(u64, offset, stored_size) catch
            return Error.RangeOutOfBounds;
        if (range_end > try file.length(io)) return Error.RangeOutOfBounds;

        const input_storage = try allocator.alloc(u8, @intCast(@min(compressed_size, stream_buffer_bytes)));
        errdefer allocator.free(input_storage);
        const output_storage = try allocator.alloc(u8, @intCast(@min(uncompressed_size, stream_buffer_bytes)));
        errdefer allocator.free(output_storage);

        const mode: Mode = if (compressed_size == 0)
            .stored
        else blk: {
            const stream = zstd_c.ZSTD_createDStream() orelse return Error.DecompressFailed;
            errdefer _ = zstd_c.ZSTD_freeDStream(stream);
            try initBoundedDStream(stream, uncompressed_size, options.max_window_bytes);
            break :blk .{ .zstd = stream };
        };

        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .reader = options.reader,
            .mode = mode,
            .range_end = range_end,
            .file_position = offset,
            .stored_remaining = stored_size,
            .decoded_remaining = uncompressed_size,
            .input_storage = input_storage,
            .output_storage = output_storage,
        };
    }

    pub fn deinit(self: *Decoder) void {
        switch (self.mode) {
            .stored => {},
            .zstd => |stream| _ = zstd_c.ZSTD_freeDStream(stream),
        }
        self.allocator.free(self.input_storage);
        self.allocator.free(self.output_storage);
        self.* = undefined;
    }

    pub fn remaining(self: *const Decoder) u64 {
        return self.decoded_remaining;
    }

    // discard cursor on decode error; possible partial dst
    pub fn readInto(self: *Decoder, dst: []u8) !void {
        if (self.finished) return Error.AlreadyFinished;
        if (@as(u64, dst.len) > self.decoded_remaining) return Error.OutputBudgetExceeded;

        var written: usize = 0;
        while (written != dst.len) {
            if (self.output_pos == self.output_len) try self.refillOutput();
            const take = @min(dst.len - written, self.output_len - self.output_pos);
            if (take == 0) return Error.TruncatedBody;
            @memcpy(dst[written..][0..take], self.output_storage[self.output_pos..][0..take]);
            self.output_pos += take;
            self.decoded_remaining -= take;
            written += take;
        }
    }

    pub fn skip(self: *Decoder, count: u64) !void {
        if (self.finished) return Error.AlreadyFinished;
        if (count > self.decoded_remaining) return Error.OutputBudgetExceeded;
        var left = count;
        while (left != 0) {
            if (self.output_pos == self.output_len) try self.refillOutput();
            const take: usize = @intCast(@min(self.output_len - self.output_pos, left));
            if (take == 0) return Error.TruncatedBody;
            self.output_pos += take;
            self.decoded_remaining -= take;
            left -= take;
        }
    }

    pub fn byte(self: *Decoder) !u8 {
        var result: [1]u8 = undefined;
        try self.readInto(&result);
        return result[0];
    }

    // frame-end probe against overflow, truncation, extra frames
    pub fn finish(self: *Decoder) !void {
        if (self.finished) return;
        if (self.decoded_remaining != 0) return Error.OutputSizeMismatch;
        if (self.output_pos != self.output_len) return Error.OutputTooLarge;

        switch (self.mode) {
            .stored => {
                if (self.stored_remaining != 0 or self.file_position != self.range_end)
                    return Error.OutputSizeMismatch;
            },
            .zstd => try self.finishZstd(),
        }
        self.finished = true;
    }

    fn refillOutput(self: *Decoder) !void {
        self.output_pos = 0;
        self.output_len = 0;
        switch (self.mode) {
            .stored => try self.refillStored(),
            .zstd => try self.refillZstd(),
        }
    }

    fn refillStored(self: *Decoder) !void {
        if (self.stored_remaining == 0) return Error.TruncatedBody;
        const wanted: usize = @intCast(@min(@as(u64, self.output_storage.len), self.stored_remaining));
        const count = try self.reader.read(
            self.io,
            self.file,
            self.output_storage[0..wanted],
            self.file_position,
        );
        try self.acceptReadCount(count, wanted);
        if (count == 0) return Error.TruncatedBody;
        self.output_len = count;
    }

    fn refillZstd(self: *Decoder) !void {
        if (self.frame_finished) return Error.OutputSizeMismatch;
        while (true) {
            _ = try self.ensureInput();

            const capacity: usize = @intCast(@min(
                @as(u64, self.output_storage.len),
                self.decoded_remaining,
            ));
            if (capacity == 0) return Error.OutputTooLarge;
            var input: zstd_c.ZstdInBuffer = .{
                .src = if (self.input_pos == self.input_len) null else self.input_storage.ptr,
                .size = self.input_len,
                .pos = self.input_pos,
            };
            var output: zstd_c.ZstdOutBuffer = .{
                .dst = self.output_storage.ptr,
                .size = capacity,
                .pos = 0,
            };
            const before_input = input.pos;
            const remaining_hint = zstd_c.ZSTD_decompressStream(
                self.zstdStream(),
                &output,
                &input,
            );
            if (zstd_c.ZSTD_isError(remaining_hint) != 0) return Error.DecompressFailed;
            if (input.pos > input.size or output.pos > output.size) return Error.DecompressFailed;
            self.input_pos = input.pos;

            if (remaining_hint == 0) {
                self.frame_finished = true;
                try self.requireNoCompressedTail();
                if (@as(u64, output.pos) != self.decoded_remaining)
                    return Error.OutputSizeMismatch;
            }
            if (output.pos != 0) {
                self.output_len = output.pos;
                return;
            }
            if (remaining_hint == 0) return Error.OutputSizeMismatch;
            if (input.pos == before_input) {
                if (self.input_pos == self.input_len and self.stored_remaining == 0)
                    return Error.TruncatedFrame;
                return Error.DecompressStalled;
            }
            if (self.input_pos == self.input_len and self.stored_remaining == 0)
                return Error.TruncatedFrame;
        }
    }

    fn finishZstd(self: *Decoder) !void {
        var overflow_probe: [1]u8 = undefined;
        while (!self.frame_finished) {
            _ = try self.ensureInput();
            var input: zstd_c.ZstdInBuffer = .{
                .src = if (self.input_pos == self.input_len) null else self.input_storage.ptr,
                .size = self.input_len,
                .pos = self.input_pos,
            };
            var output: zstd_c.ZstdOutBuffer = .{
                .dst = &overflow_probe,
                .size = overflow_probe.len,
                .pos = 0,
            };
            const before_input = input.pos;
            const remaining_hint = zstd_c.ZSTD_decompressStream(
                self.zstdStream(),
                &output,
                &input,
            );
            if (zstd_c.ZSTD_isError(remaining_hint) != 0) return Error.DecompressFailed;
            if (input.pos > input.size or output.pos > output.size) return Error.DecompressFailed;
            self.input_pos = input.pos;
            if (output.pos != 0) return Error.OutputTooLarge;
            if (remaining_hint == 0) {
                self.frame_finished = true;
                try self.requireNoCompressedTail();
                break;
            }
            if (input.pos == before_input) {
                if (self.input_pos == self.input_len and self.stored_remaining == 0)
                    return Error.TruncatedFrame;
                return Error.DecompressStalled;
            }
            if (self.input_pos == self.input_len and self.stored_remaining == 0)
                return Error.TruncatedFrame;
        }
        try self.requireNoCompressedTail();
    }

    fn ensureInput(self: *Decoder) !bool {
        if (self.input_pos != self.input_len) return true;
        self.input_pos = 0;
        self.input_len = 0;
        if (self.stored_remaining == 0) return false;

        const wanted: usize = @intCast(@min(@as(u64, self.input_storage.len), self.stored_remaining));
        const count = try self.reader.read(
            self.io,
            self.file,
            self.input_storage[0..wanted],
            self.file_position,
        );
        try self.acceptReadCount(count, wanted);
        if (count == 0) return Error.TruncatedFrame;
        self.input_len = count;
        return true;
    }

    fn acceptReadCount(self: *Decoder, count: usize, wanted: usize) !void {
        if (count > wanted or @as(u64, count) > self.stored_remaining)
            return Error.InvalidReadCount;
        if (count == 0) return;
        const next = std.math.add(u64, self.file_position, count) catch
            return Error.RangeOutOfBounds;
        if (next > self.range_end) return Error.InvalidReadCount;
        self.file_position = next;
        self.stored_remaining -= count;
    }

    fn requireNoCompressedTail(self: *const Decoder) !void {
        if (self.input_pos != self.input_len or self.stored_remaining != 0 or
            self.file_position != self.range_end)
            return Error.TrailingCompressedData;
    }

    fn zstdStream(self: *Decoder) *zstd_c.ZstdDStream {
        return switch (self.mode) {
            .stored => unreachable,
            .zstd => |stream| stream,
        };
    }
};

fn validateWindowCap(max_window_bytes: u64) Error!void {
    if (max_window_bytes < zstd_window_bytes_min or
        (max_window_bytes & (max_window_bytes - 1)) != 0)
        return Error.InvalidWindowCap;
}

fn initBoundedDStream(
    stream: *zstd_c.ZstdDStream,
    uncompressed_size: u64,
    max_window_bytes: u64,
) Error!void {
    const policy_log: u8 = @intCast(std.math.log2_int(u64, max_window_bytes));
    const extent_log: u8 = @intCast(std.math.log2_int_ceil(u64, @max(uncompressed_size, 1)));
    const selected_log = std.math.clamp(
        @min(policy_log, extent_log),
        zstd_window_log_min,
        zstd_window_log_max,
    );
    const parameter_result = zstd_c.ZSTD_DCtx_setParameter(
        stream,
        zstd_c.zstd_d_window_log_max,
        selected_log,
    );
    if (zstd_c.ZSTD_isError(parameter_result) != 0) return Error.DecompressFailed;
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_initDStream(stream)) != 0)
        return Error.DecompressFailed;
}

// tests

fn makeContainer(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    body: []const u8,
    suffix: []const u8,
) ![]u8 {
    const result = try allocator.alloc(u8, prefix.len + body.len + suffix.len);
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..][0..body.len], body);
    @memcpy(result[prefix.len + body.len ..], suffix);
    return result;
}

const ChunkReader = struct {
    max_chunk: usize,
    calls: usize = 0,

    fn read(
        context: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        buffer: []u8,
        offset: u64,
    ) !usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        const take = @min(buffer.len, self.max_chunk);
        return scan.Reader.direct.read(io, file, buffer[0..take], offset);
    }

    fn reader(self: *@This()) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

const CountFaultReader = struct {
    kind: enum { overcount, zero },

    fn read(
        context: ?*anyopaque,
        _: std.Io,
        _: std.Io.File,
        buffer: []u8,
        _: u64,
    ) !usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return switch (self.kind) {
            .overcount => buffer.len + 1,
            .zero => 0,
        };
    }

    fn reader(self: *@This()) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

test "stored cursor is exact at a nonzero offset and accepts chunked reads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const body = "stored W26 body with integers and literal bytes" ** 7000;
    const prefix = "container-prefix";
    const storage = try makeContainer(allocator, prefix, body, "outside-range");
    defer allocator.free(storage);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "stored.bin", .data = storage });
    var file = try fs.openRead(io, tmp.dir, "stored.bin");
    defer file.close(io);

    var chunk_reader: ChunkReader = .{ .max_chunk = 37 };
    var clip = try Decoder.init(
        allocator,
        io,
        file,
        prefix.len,
        0,
        body.len,
        .{ .max_window_bytes = 1024, .reader = chunk_reader.reader() },
    );
    defer clip.deinit();

    try std.testing.expectEqual(@as(usize, 0), clip.input_storage.len);
    var decoded = try allocator.alloc(u8, body.len);
    defer allocator.free(decoded);
    try clip.readInto(decoded[0..17]);
    const skipped = stream_buffer_bytes + 11;
    try clip.skip(skipped);
    try clip.readInto(decoded[17 + skipped ..]);
    @memcpy(decoded[17 .. 17 + skipped], body[17 .. 17 + skipped]);
    try clip.finish();
    try clip.finish();
    try std.testing.expect(chunk_reader.calls > 1);
    try std.testing.expectEqualSlices(u8, body, decoded);
}

test "zstd cursor streams one exact frame at a nonzero offset" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const plain = try allocator.alloc(u8, 3 * stream_buffer_bytes + 1237);
    defer allocator.free(plain);
    var random = std.Random.DefaultPrng.init(0x26c1_1a7e);
    random.random().bytes(plain);
    const frame = try @import("frame.zig").compressAlloc(allocator, plain, 5);
    defer allocator.free(frame);
    try std.testing.expect(frame.len > stream_buffer_bytes);
    const prefix = "w26-prefix-at-nonzero-offset";
    const storage = try makeContainer(allocator, prefix, frame, "unrelated-suffix");
    defer allocator.free(storage);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zstd.bin", .data = storage });
    var file = try fs.openRead(io, tmp.dir, "zstd.bin");
    defer file.close(io);

    var chunk_reader: ChunkReader = .{ .max_chunk = 7919 };
    var clip = try Decoder.init(
        allocator,
        io,
        file,
        prefix.len,
        frame.len,
        plain.len,
        .{ .max_window_bytes = 1 << 20, .reader = chunk_reader.reader() },
    );
    defer clip.deinit();
    var decoded = try allocator.alloc(u8, plain.len);
    defer allocator.free(decoded);
    const skipped = stream_buffer_bytes + 23;
    try clip.skip(skipped);
    @memcpy(decoded[0..skipped], plain[0..skipped]);
    var pos: usize = skipped;
    while (pos != decoded.len) {
        const take = @min(decoded.len - pos, 7001);
        try clip.readInto(decoded[pos..][0..take]);
        pos += take;
    }
    try clip.finish();
    try std.testing.expect(chunk_reader.calls > 2);
    try std.testing.expectEqualSlices(u8, plain, decoded);
}

test "empty stored body and empty zstd frame finish exactly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const empty_frame = try @import("frame.zig").compressAlloc(allocator, "", 5);
    defer allocator.free(empty_frame);
    const storage = try makeContainer(allocator, "prefix", empty_frame, "suffix");
    defer allocator.free(storage);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "empty.bin", .data = storage });
    var file = try fs.openRead(io, tmp.dir, "empty.bin");
    defer file.close(io);

    var stored = try Decoder.init(allocator, io, file, 0, 0, 0, .{ .max_window_bytes = 1024 });
    defer stored.deinit();
    try std.testing.expectEqual(@as(usize, 0), stored.input_storage.len);
    try std.testing.expectEqual(@as(usize, 0), stored.output_storage.len);
    try stored.finish();

    var compressed = try Decoder.init(
        allocator,
        io,
        file,
        "prefix".len,
        empty_frame.len,
        0,
        .{ .max_window_bytes = 1024 },
    );
    defer compressed.deinit();
    try std.testing.expectEqual(empty_frame.len, compressed.input_storage.len);
    try std.testing.expectEqual(@as(usize, 0), compressed.output_storage.len);
    try compressed.finish();
}

test "cursor rejects invalid windows and file ranges before reading" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "tiny.bin", .data = "tiny" });
    var file = try fs.openRead(io, tmp.dir, "tiny.bin");
    defer file.close(io);

    try std.testing.expectError(
        Error.InvalidWindowCap,
        Decoder.init(allocator, io, file, 0, 0, 0, .{ .max_window_bytes = 512 }),
    );
    try std.testing.expectError(
        Error.InvalidWindowCap,
        Decoder.init(allocator, io, file, 0, 0, 0, .{ .max_window_bytes = 1536 }),
    );
    try std.testing.expectError(
        Error.RangeOutOfBounds,
        Decoder.init(allocator, io, file, 3, 0, 2, .{ .max_window_bytes = 1024 }),
    );
    try std.testing.expectError(
        Error.RangeOutOfBounds,
        Decoder.init(allocator, io, file, std.math.maxInt(u64), 0, 2, .{ .max_window_bytes = 1024 }),
    );
}

test "stored requests and reader counts fail without range escape" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "body.bin", .data = "12345678" });
    var file = try fs.openRead(io, tmp.dir, "body.bin");
    defer file.close(io);

    var clip = try Decoder.init(allocator, io, file, 0, 0, 8, .{ .max_window_bytes = 1024 });
    defer clip.deinit();
    var untouched: [9]u8 = @splat(0xa7);
    try std.testing.expectError(Error.OutputBudgetExceeded, clip.readInto(&untouched));
    try std.testing.expectEqualSlices(u8, &(@as([9]u8, @splat(0xa7))), &untouched);
    try std.testing.expectEqual(@as(u64, 8), clip.remaining());

    var overcount: CountFaultReader = .{ .kind = .overcount };
    var overcount_clip = try Decoder.init(
        allocator,
        io,
        file,
        0,
        0,
        8,
        .{ .max_window_bytes = 1024, .reader = overcount.reader() },
    );
    defer overcount_clip.deinit();
    var byte_buf: [1]u8 = undefined;
    try std.testing.expectError(Error.InvalidReadCount, overcount_clip.readInto(&byte_buf));

    var zero: CountFaultReader = .{ .kind = .zero };
    var zero_clip = try Decoder.init(
        allocator,
        io,
        file,
        0,
        0,
        8,
        .{ .max_window_bytes = 1024, .reader = zero.reader() },
    );
    defer zero_clip.deinit();
    try std.testing.expectError(Error.TruncatedBody, zero_clip.readInto(&byte_buf));
}

test "finish rejects stored under-consumption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "stored.bin", .data = "body+tail" });
    var file = try fs.openRead(io, tmp.dir, "stored.bin");
    defer file.close(io);

    var clip = try Decoder.init(allocator, io, file, 0, 0, 9, .{ .max_window_bytes = 1024 });
    defer clip.deinit();
    var body: [4]u8 = undefined;
    try clip.readInto(&body);
    try std.testing.expectEqualStrings("body", &body);
    try std.testing.expectError(Error.OutputSizeMismatch, clip.finish());
}

fn expectZstdFailureAfterConsumption(clip: *Decoder, wanted: []u8, expected: anyerror) !void {
    if (clip.readInto(wanted)) {
        try std.testing.expectError(expected, clip.finish());
    } else |err| {
        try std.testing.expectEqual(expected, err);
    }
}

test "zstd finish rejects short trailing concatenated and wrong declared extents" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const plain = "one bounded zstd frame" ** 1000;
    const frame = try @import("frame.zig").compressAlloc(allocator, plain, 5);
    defer allocator.free(frame);
    const second = try @import("frame.zig").compressAlloc(allocator, "second frame", 5);
    defer allocator.free(second);
    const storage = try makeContainer(allocator, "pre", frame, "X");
    defer allocator.free(storage);
    const concatenated = try makeContainer(allocator, "pre", frame, second);
    defer allocator.free(concatenated);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "frame.bin", .data = storage });
    try tmp.dir.writeFile(io, .{ .sub_path = "concat.bin", .data = concatenated });
    var file = try fs.openRead(io, tmp.dir, "frame.bin");
    defer file.close(io);
    var concat_file = try fs.openRead(io, tmp.dir, "concat.bin");
    defer concat_file.close(io);

    var short = try Decoder.init(allocator, io, file, 3, frame.len - 1, plain.len, .{ .max_window_bytes = 1 << 20 });
    defer short.deinit();
    var exact_output: [plain.len]u8 = undefined;
    try expectZstdFailureAfterConsumption(&short, &exact_output, Error.TruncatedFrame);

    var trailing = try Decoder.init(allocator, io, file, 3, frame.len + 1, plain.len, .{ .max_window_bytes = 1 << 20 });
    defer trailing.deinit();
    try expectZstdFailureAfterConsumption(&trailing, &exact_output, Error.TrailingCompressedData);

    var concat = try Decoder.init(
        allocator,
        io,
        concat_file,
        3,
        frame.len + second.len,
        plain.len,
        .{ .max_window_bytes = 1 << 20 },
    );
    defer concat.deinit();
    try expectZstdFailureAfterConsumption(&concat, &exact_output, Error.TrailingCompressedData);

    var too_small = try Decoder.init(allocator, io, file, 3, frame.len, plain.len - 1, .{ .max_window_bytes = 1 << 20 });
    defer too_small.deinit();
    var short_output: [plain.len - 1]u8 = undefined;
    try expectZstdFailureAfterConsumption(&too_small, &short_output, Error.OutputTooLarge);

    var too_large = try Decoder.init(allocator, io, file, 3, frame.len, plain.len + 1, .{ .max_window_bytes = 1 << 20 });
    defer too_large.deinit();
    var long_output: [plain.len + 1]u8 = undefined;
    try expectZstdFailureAfterConsumption(&too_large, &long_output, Error.OutputSizeMismatch);
}

test "zstd reader count faults and oversized frame windows are refused" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bounded_frame = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd,
        0x00, 0x00, 0x09, 0x00,
        0x00, 'x',
    };
    const oversized_window_frame = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd,
        0x00, 0x50, 0x09, 0x00,
        0x00, 'x',
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "bounded.zst", .data = &bounded_frame });
    try tmp.dir.writeFile(io, .{ .sub_path = "oversized.zst", .data = &oversized_window_frame });
    var bounded_file = try fs.openRead(io, tmp.dir, "bounded.zst");
    defer bounded_file.close(io);
    var oversized_file = try fs.openRead(io, tmp.dir, "oversized.zst");
    defer oversized_file.close(io);

    var good = try Decoder.init(allocator, io, bounded_file, 0, bounded_frame.len, 1, .{ .max_window_bytes = 1024 });
    defer good.deinit();
    try std.testing.expectEqual(@as(u8, 'x'), try good.byte());
    try good.finish();

    var oversized = try Decoder.init(allocator, io, oversized_file, 0, oversized_window_frame.len, 1, .{ .max_window_bytes = 1024 });
    defer oversized.deinit();
    var one: [1]u8 = undefined;
    try std.testing.expectError(Error.DecompressFailed, oversized.readInto(&one));

    var overcount: CountFaultReader = .{ .kind = .overcount };
    var bad_count = try Decoder.init(
        allocator,
        io,
        bounded_file,
        0,
        bounded_frame.len,
        1,
        .{ .max_window_bytes = 1024, .reader = overcount.reader() },
    );
    defer bad_count.deinit();
    try std.testing.expectError(Error.InvalidReadCount, bad_count.readInto(&one));

    var zero: CountFaultReader = .{ .kind = .zero };
    var short_read = try Decoder.init(
        allocator,
        io,
        bounded_file,
        0,
        bounded_frame.len,
        1,
        .{ .max_window_bytes = 1024, .reader = zero.reader() },
    );
    defer short_read.deinit();
    try std.testing.expectError(Error.TruncatedFrame, short_read.readInto(&one));
}

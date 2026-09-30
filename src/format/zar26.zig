// ZAR26: Zift Anchored Residual 2026
// anchors/residuals/literals in one zstd frame per target

const std = @import("std");
const zstd_c = @import("../compression/zstd_c.zig");
const production_options = @import("../production_options.zig");
const ranges = @import("../core/ranges.zig");
const wire = @import("../core/varint.zig");
const merge = @import("../match/merge.zig");

pub const magic = "ZAR26";
pub const revision: u8 = 0;
pub const header_size: usize = 48;
pub const max_residual_gap: usize = 64 * 1024 - 1;
pub const stream_buffer_bytes: usize = 128 * 1024;
// 4 MiB history cap, independent of target size
const window_log: u8 = 22;
const zstd_continue: c_int = 0;
const zstd_end: c_int = 2;

pub const ReadFn = *const fn (?*anyopaque, u64, []u8) anyerror!void;
pub const WriteFn = *const fn (?*anyopaque, u64, []const u8) anyerror!void;

pub const Input = struct {
    context: ?*anyopaque,
    size: u64,
    read_at: ReadFn,

    pub fn readExact(self: Input, offset: u64, destination: []u8) !void {
        if (offset > self.size or destination.len > self.size - offset)
            return error.ReadOutOfBounds;
        try self.read_at(self.context, offset, destination);
    }
};

pub const Output = struct {
    context: ?*anyopaque,
    write_at: WriteFn,

    pub fn writeAll(self: Output, offset: u64, bytes: []const u8) !void {
        try self.write_at(self.context, offset, bytes);
    }
};

pub const Stats = struct {
    anchors: u64 = 0,
    copy_bytes: u64 = 0,
    literal_bytes: u64 = 0,
    residual_candidates: u64 = 0,
    residual_candidate_bytes: u64 = 0,
    residual_segments: u64 = 0,
    residual_bytes: u64 = 0,
    plain_body_bytes: u64 = 0,
    stored_body_bytes: u64 = 0,
};

pub const EncodeResult = struct {
    allocator: std.mem.Allocator,
    payload_length: u64,
    stats: Stats,
    residual_reads: []ranges.Range,

    pub fn deinit(self: *EncodeResult) void {
        self.allocator.free(self.residual_reads);
        self.* = undefined;
    }
};

const Header = struct {
    source_size: u64,
    target_size: u64,
    record_count: u64,
    plain_body_len: u64,
    stored_body_len: u64,
};

fn checkedAdd(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch return error.IntegerOverflow;
}

fn encodeHeader(header: Header) [header_size]u8 {
    var bytes: [header_size]u8 = @splat(0);
    @memcpy(bytes[0..5], magic);
    bytes[5] = revision;
    std.mem.writeInt(u64, bytes[8..16], header.source_size, .little);
    std.mem.writeInt(u64, bytes[16..24], header.target_size, .little);
    std.mem.writeInt(u64, bytes[24..32], header.record_count, .little);
    std.mem.writeInt(u64, bytes[32..40], header.plain_body_len, .little);
    std.mem.writeInt(u64, bytes[40..48], header.stored_body_len, .little);
    return bytes;
}

fn decodeHeader(bytes: *const [header_size]u8) !Header {
    if (!std.mem.eql(u8, bytes[0..5], magic)) return error.InvalidMagic;
    if (bytes[5] != revision) return error.UnsupportedRevision;
    if (!std.mem.allEqual(u8, bytes[6..8], 0)) return error.InvalidReserved;
    return .{
        .source_size = std.mem.readInt(u64, bytes[8..16], .little),
        .target_size = std.mem.readInt(u64, bytes[16..24], .little),
        .record_count = std.mem.readInt(u64, bytes[24..32], .little),
        .plain_body_len = std.mem.readInt(u64, bytes[32..40], .little),
        .stored_body_len = std.mem.readInt(u64, bytes[40..48], .little),
    };
}

fn appendUleb(storage: *[wire.max_uleb128_bytes]u8, value: u64) []const u8 {
    return wire.encodeUleb128(value, storage);
}

fn ulebSize(value: u64) usize {
    var storage: [wire.max_uleb128_bytes]u8 = undefined;
    return appendUleb(&storage, value).len;
}

const BodyWriter = struct {
    stream: *zstd_c.ZstdCStream,
    output: Output,
    output_buffer: []u8,
    stored: u64 = 0,
    plain: u64 = 0,

    fn write(self: *@This(), bytes: []const u8) !void {
        self.plain = try checkedAdd(self.plain, bytes.len);
        var input: zstd_c.ZstdInBuffer = .{
            .src = if (bytes.len == 0) null else bytes.ptr,
            .size = bytes.len,
            .pos = 0,
        };
        while (input.pos < input.size) {
            var compressed: zstd_c.ZstdOutBuffer = .{
                .dst = self.output_buffer.ptr,
                .size = self.output_buffer.len,
                .pos = 0,
            };
            const before = input.pos;
            const remaining = zstd_c.ZSTD_compressStream2(
                self.stream,
                &compressed,
                &input,
                zstd_continue,
            );
            if (zstd_c.ZSTD_isError(remaining) != 0) return error.CompressFailed;
            if (compressed.pos != 0) {
                try self.output.writeAll(
                    try checkedAdd(header_size, self.stored),
                    self.output_buffer[0..compressed.pos],
                );
                self.stored = try checkedAdd(self.stored, compressed.pos);
            }
            if (input.pos == before and compressed.pos == 0) return error.CompressMadeNoProgress;
        }
    }

    fn finish(self: *@This()) !void {
        var input: zstd_c.ZstdInBuffer = .{ .src = null, .size = 0, .pos = 0 };
        while (true) {
            var compressed: zstd_c.ZstdOutBuffer = .{
                .dst = self.output_buffer.ptr,
                .size = self.output_buffer.len,
                .pos = 0,
            };
            const remaining = zstd_c.ZSTD_compressStream2(
                self.stream,
                &compressed,
                &input,
                zstd_end,
            );
            if (zstd_c.ZSTD_isError(remaining) != 0) return error.CompressFailed;
            if (compressed.pos != 0) {
                try self.output.writeAll(
                    try checkedAdd(header_size, self.stored),
                    self.output_buffer[0..compressed.pos],
                );
                self.stored = try checkedAdd(self.stored, compressed.pos);
            }
            if (remaining == 0) return;
            if (compressed.pos == 0) return error.CompressMadeNoProgress;
        }
    }
};

fn compressedSize(context: *zstd_c.ZstdCCtx, storage: []u8, bytes: []const u8, level: c_int) !usize {
    const written = zstd_c.ZSTD_compressCCtx(
        context,
        if (storage.len == 0) null else storage.ptr,
        storage.len,
        if (bytes.len == 0) null else bytes.ptr,
        bytes.len,
        level,
    );
    if (zstd_c.ZSTD_isError(written) != 0 or written > storage.len)
        return error.CompressFailed;
    return written;
}

fn validateAnchor(anchor: merge.Cover, previous_target_end: u64, source_size: u64, target_size: u64) !void {
    if (anchor.length == 0 or anchor.target_offset < previous_target_end)
        return error.InvalidExactAnchors;
    if (try checkedAdd(anchor.source_offset, anchor.length) > source_size or
        try checkedAdd(anchor.target_offset, anchor.length) > target_size)
        return error.AnchorOutOfRange;
}

pub fn encode(
    allocator: std.mem.Allocator,
    source: Input,
    target: Input,
    anchors: []const merge.Cover,
    output: Output,
) !EncodeResult {
    if (anchors.len > target.size) return error.ImpossibleRecordCount;
    const metadata_bound = std.math.mul(u64, anchors.len, 30) catch return error.IntegerOverflow;
    _ = try checkedAdd(target.size, metadata_bound);

    var residual_reads: std.ArrayList(ranges.Range) = .empty;
    errdefer residual_reads.deinit(allocator);
    try residual_reads.ensureTotalCapacity(allocator, @min(anchors.len, 4096));

    const candidate_bound = zstd_c.ZSTD_compressBound(max_residual_gap);
    if (zstd_c.ZSTD_isError(candidate_bound) != 0) return error.CompressFailed;
    const work_len = stream_buffer_bytes + max_residual_gap * 3 + candidate_bound;
    const work = try allocator.alloc(u8, work_len);
    defer allocator.free(work);
    var work_cursor: usize = 0;
    const output_buffer = work[work_cursor .. work_cursor + stream_buffer_bytes];
    work_cursor += stream_buffer_bytes;
    const target_gap_buffer = work[work_cursor .. work_cursor + max_residual_gap];
    work_cursor += max_residual_gap;
    const source_gap_buffer = work[work_cursor .. work_cursor + max_residual_gap];
    work_cursor += max_residual_gap;
    const residual_buffer = work[work_cursor .. work_cursor + max_residual_gap];
    work_cursor += max_residual_gap;
    const candidate_compressed = work[work_cursor .. work_cursor + candidate_bound];

    const placeholder = encodeHeader(.{
        .source_size = source.size,
        .target_size = target.size,
        .record_count = anchors.len,
        .plain_body_len = 0,
        .stored_body_len = 0,
    });
    try output.writeAll(0, &placeholder);

    const stream = zstd_c.ZSTD_createCStream() orelse return error.CompressFailed;
    defer _ = zstd_c.ZSTD_freeCStream(stream);
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_initCStream(stream, production_options.zstd_level_patch)) != 0)
        return error.CompressFailed;
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_CCtx_setParameter(
        stream,
        zstd_c.zstd_c_window_log,
        window_log,
    )) != 0) return error.CompressFailed;

    var writer: BodyWriter = .{
        .stream = stream,
        .output = output,
        .output_buffer = output_buffer,
    };
    var stats: Stats = .{ .anchors = anchors.len };
    var source_cursor: u64 = 0;
    var target_cursor: u64 = 0;
    var candidate_context: ?*zstd_c.ZstdCCtx = null;
    defer {
        if (candidate_context) |context| _ = zstd_c.ZSTD_freeCCtx(context);
    }

    for (anchors, 0..) |anchor, anchor_index| {
        try validateAnchor(anchor, target_cursor, source.size, target.size);
        const gap = anchor.target_offset - target_cursor;
        var use_residual = false;
        var candidate_len: usize = 0;
        if (anchor_index != 0 and gap != 0 and gap <= max_residual_gap and
            source_cursor <= source.size and gap <= source.size - source_cursor and
            anchor.source_offset == source_cursor + gap)
        {
            candidate_len = @intCast(gap);
            const target_gap = target_gap_buffer[0..candidate_len];
            const source_gap = source_gap_buffer[0..candidate_len];
            const residual = residual_buffer[0..candidate_len];
            try target.readExact(target_cursor, target_gap);
            try source.readExact(source_cursor, source_gap);
            for (residual, source_gap, target_gap) |*byte, old, new| byte.* = new -% old;
            const context = candidate_context orelse blk: {
                const created = zstd_c.ZSTD_createCCtx() orelse return error.CompressFailed;
                candidate_context = created;
                break :blk created;
            };
            const literal_size = try compressedSize(context, candidate_compressed, target_gap, production_options.zstd_level_patch);
            const residual_size = try compressedSize(context, candidate_compressed, residual, production_options.zstd_level_patch);
            const literal_cost = try std.math.add(
                usize,
                literal_size,
                ulebSize(wire.zigZagEncodeI64(@intCast(gap))),
            );
            const residual_cost = try std.math.add(usize, residual_size, ulebSize(0));
            use_residual = residual_cost < literal_cost;
            stats.residual_candidates += 1;
            stats.residual_candidate_bytes = try checkedAdd(stats.residual_candidate_bytes, gap);
        }

        if (gap > std.math.maxInt(u64) >> 1) return error.InputTooLarge;
        var encoded: [wire.max_uleb128_bytes]u8 = undefined;
        try writer.write(appendUleb(&encoded, (gap << 1) | @intFromBool(use_residual)));
        const source_base = if (use_residual) try checkedAdd(source_cursor, gap) else source_cursor;
        const source_delta_wide = @as(i128, @intCast(anchor.source_offset)) -
            @as(i128, @intCast(source_base));
        const source_delta = std.math.cast(i64, source_delta_wide) orelse
            return error.IntegerOverflow;
        try writer.write(appendUleb(&encoded, wire.zigZagEncodeI64(source_delta)));
        try writer.write(appendUleb(&encoded, anchor.length));

        if (use_residual) {
            try writer.write(residual_buffer[0..candidate_len]);
            try residual_reads.append(allocator, .{ .offset = source_cursor, .length = gap });
            source_cursor = try checkedAdd(source_cursor, gap);
            stats.residual_segments += 1;
            stats.residual_bytes = try checkedAdd(stats.residual_bytes, gap);
        } else if (candidate_len != 0) {
            try writer.write(target_gap_buffer[0..candidate_len]);
            stats.literal_bytes = try checkedAdd(stats.literal_bytes, gap);
        } else {
            var remaining = gap;
            var offset = target_cursor;
            while (remaining != 0) {
                const count: usize = @intCast(@min(@as(u64, target_gap_buffer.len), remaining));
                try target.readExact(offset, target_gap_buffer[0..count]);
                try writer.write(target_gap_buffer[0..count]);
                offset = try checkedAdd(offset, count);
                remaining -= count;
            }
            stats.literal_bytes = try checkedAdd(stats.literal_bytes, gap);
        }

        source_cursor = try checkedAdd(anchor.source_offset, anchor.length);
        target_cursor = try checkedAdd(anchor.target_offset, anchor.length);
        stats.copy_bytes = try checkedAdd(stats.copy_bytes, anchor.length);
    }

    var trailing = target.size - target_cursor;
    var trailing_offset = target_cursor;
    while (trailing != 0) {
        const count: usize = @intCast(@min(@as(u64, target_gap_buffer.len), trailing));
        try target.readExact(trailing_offset, target_gap_buffer[0..count]);
        try writer.write(target_gap_buffer[0..count]);
        trailing_offset = try checkedAdd(trailing_offset, count);
        trailing -= count;
    }
    stats.literal_bytes = try checkedAdd(stats.literal_bytes, target.size - target_cursor);
    try writer.finish();
    stats.plain_body_bytes = writer.plain;
    stats.stored_body_bytes = writer.stored;
    const final_header = encodeHeader(.{
        .source_size = source.size,
        .target_size = target.size,
        .record_count = anchors.len,
        .plain_body_len = writer.plain,
        .stored_body_len = writer.stored,
    });
    try output.writeAll(0, &final_header);
    return .{
        .allocator = allocator,
        .payload_length = try checkedAdd(header_size, writer.stored),
        .stats = stats,
        .residual_reads = try residual_reads.toOwnedSlice(allocator),
    };
}

const BodyReader = struct {
    stream: *zstd_c.ZstdDStream,
    patch: Input,
    input_storage: []u8,
    output_storage: []u8,
    stored_remaining: u64,
    stored_offset: u64 = header_size,
    plain_remaining: u64,
    input: zstd_c.ZstdInBuffer = .{ .src = null, .size = 0, .pos = 0 },
    output_position: usize = 0,
    output_length: usize = 0,
    ended: bool = false,

    fn fill(self: *@This()) !void {
        if (self.output_position != self.output_length) return;
        self.output_position = 0;
        self.output_length = 0;
        while (!self.ended and self.output_length == 0) {
            if (self.input.pos == self.input.size and self.stored_remaining != 0) {
                const count: usize = @intCast(@min(
                    @as(u64, self.input_storage.len),
                    self.stored_remaining,
                ));
                try self.patch.readExact(self.stored_offset, self.input_storage[0..count]);
                self.stored_offset = try checkedAdd(self.stored_offset, count);
                self.stored_remaining -= count;
                self.input = .{ .src = self.input_storage.ptr, .size = count, .pos = 0 };
            }

            // one-byte overflow probe without maxInt(u64) extent addition
            const capacity = if (self.plain_remaining < self.output_storage.len)
                @as(usize, @intCast(self.plain_remaining)) + 1
            else
                self.output_storage.len;
            var output: zstd_c.ZstdOutBuffer = .{
                .dst = self.output_storage.ptr,
                .size = capacity,
                .pos = 0,
            };
            const before_input = self.input.pos;
            const remaining = zstd_c.ZSTD_decompressStream(self.stream, &output, &self.input);
            if (zstd_c.ZSTD_isError(remaining) != 0) return error.DecompressFailed;
            if (output.pos > self.plain_remaining) return error.InvalidBodyExtent;
            self.plain_remaining -= output.pos;
            self.output_length = output.pos;
            if (remaining == 0) {
                if (self.input.pos != self.input.size or self.stored_remaining != 0)
                    return error.TrailingCompressedData;
                self.ended = true;
            }
            if (!self.ended and self.input.pos == before_input and output.pos == 0)
                return error.TruncatedFrame;
            if (!self.ended and self.input.pos == self.input.size and
                self.stored_remaining == 0 and output.pos == 0)
                return error.TruncatedFrame;
        }
    }

    fn readExact(self: *@This(), destination: []u8) !void {
        var copied: usize = 0;
        while (copied < destination.len) {
            try self.fill();
            if (self.output_position == self.output_length) return error.TruncatedBody;
            const count = @min(destination.len - copied, self.output_length - self.output_position);
            @memcpy(
                destination[copied .. copied + count],
                self.output_storage[self.output_position .. self.output_position + count],
            );
            copied += count;
            self.output_position += count;
        }
    }

    fn readByte(self: *@This()) !u8 {
        var byte: [1]u8 = undefined;
        try self.readExact(&byte);
        return byte[0];
    }

    fn finish(self: *@This()) !void {
        if (self.output_position != self.output_length or self.plain_remaining != 0)
            return error.InvalidBodyExtent;
        while (!self.ended) {
            try self.fill();
            if (self.output_position != self.output_length) return error.InvalidBodyExtent;
        }
    }
};

fn readUleb(reader: *BodyReader) !u64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    var count: usize = 0;
    while (count < wire.max_uleb128_bytes) : (count += 1) {
        const byte = try reader.readByte();
        const payload: u64 = byte & 0x7f;
        if (shift == 63 and payload > 1) return error.IntegerOverflow;
        value |= payload << shift;
        if (byte & 0x80 == 0) {
            if (count != 0 and payload == 0) return error.NonCanonicalInteger;
            return value;
        }
        if (shift == 63) return error.IntegerOverflow;
        shift += 7;
    }
    return error.IntegerOverflow;
}

fn writeLiteral(reader: *BodyReader, output: Output, offset: *u64, length: u64) !void {
    var remaining = length;
    while (remaining != 0) {
        try reader.fill();
        const count: usize = @intCast(@min(reader.output_length - reader.output_position, remaining));
        if (count == 0) return error.TruncatedBody;
        try output.writeAll(offset.*, reader.output_storage[reader.output_position..][0..count]);
        reader.output_position += count;
        offset.* = try checkedAdd(offset.*, count);
        remaining -= count;
    }
}

fn writeSource(source: Input, output: Output, buffer: []u8, source_offset: *u64, target_offset: *u64, length: u64) !void {
    var remaining = length;
    while (remaining != 0) {
        const count: usize = @intCast(@min(@as(u64, buffer.len), remaining));
        try source.readExact(source_offset.*, buffer[0..count]);
        try output.writeAll(target_offset.*, buffer[0..count]);
        source_offset.* = try checkedAdd(source_offset.*, count);
        target_offset.* = try checkedAdd(target_offset.*, count);
        remaining -= count;
    }
}

// target_size from container, not patch header
pub fn decode(
    allocator: std.mem.Allocator,
    source: Input,
    patch: Input,
    target_size: u64,
    output: Output,
) !void {
    if (patch.size < header_size) return error.Truncated;
    var header_bytes: [header_size]u8 = undefined;
    try patch.readExact(0, &header_bytes);
    const header = try decodeHeader(&header_bytes);
    if (header.source_size != source.size) return error.SourceSizeMismatch;
    if (header.target_size != target_size) return error.TargetSizeMismatch;
    if (header.record_count > target_size) return error.ImpossibleRecordCount;
    const expected_patch_len = try checkedAdd(header_size, header.stored_body_len);
    if (expected_patch_len != patch.size or header.stored_body_len == 0)
        return error.InvalidExtent;
    const maximum_metadata = std.math.mul(u64, header.record_count, 30) catch
        return error.IntegerOverflow;
    if (header.plain_body_len > try checkedAdd(target_size, maximum_metadata))
        return error.BodyTooLarge;

    const input_end: usize = @intCast(@min(header.stored_body_len, stream_buffer_bytes));
    const decoded_end = input_end + @as(usize, @intCast(@max(1, @min(header.plain_body_len, stream_buffer_bytes))));
    const source_end = decoded_end + @as(usize, @intCast(@min(source.size, stream_buffer_bytes)));
    const work = try allocator.alloc(u8, source_end);
    defer allocator.free(work);
    const input_storage = work[0..input_end];
    const decoded_storage = work[input_end..decoded_end];
    const source_storage = work[decoded_end..source_end];

    const stream = zstd_c.ZSTD_createDStream() orelse return error.DecompressFailed;
    defer _ = zstd_c.ZSTD_freeDStream(stream);
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_DCtx_setParameter(
        stream,
        zstd_c.zstd_d_window_log_max,
        window_log,
    )) != 0 or zstd_c.ZSTD_isError(zstd_c.ZSTD_initDStream(stream)) != 0)
        return error.DecompressFailed;

    var reader: BodyReader = .{
        .stream = stream,
        .patch = patch,
        .input_storage = input_storage,
        .output_storage = decoded_storage,
        .stored_remaining = header.stored_body_len,
        .plain_remaining = header.plain_body_len,
    };
    var source_cursor: u64 = 0;
    var target_cursor: u64 = 0;
    var record: u64 = 0;
    while (record < header.record_count) : (record += 1) {
        const tagged_gap = try readUleb(&reader);
        const residual = tagged_gap & 1 != 0;
        const gap = tagged_gap >> 1;
        if (residual and (gap == 0 or gap > max_residual_gap))
            return error.NonCanonicalResidual;
        const encoded_delta = try readUleb(&reader);
        const source_delta = wire.zigZagDecodeI64(encoded_delta);
        const copy_len = try readUleb(&reader);
        if (copy_len == 0) return error.ZeroCopyLength;
        if (try checkedAdd(target_cursor, gap) > target_size) return error.TargetOutOfRange;

        if (residual) {
            if (try checkedAdd(source_cursor, gap) > source.size) return error.SourceOutOfRange;
            var remaining = gap;
            while (remaining != 0) {
                try reader.fill();
                const count: usize = @intCast(@min(reader.output_length - reader.output_position, remaining));
                if (count == 0) return error.TruncatedBody;
                const bytes = reader.output_storage[reader.output_position..][0..count];
                try source.readExact(source_cursor, source_storage[0..count]);
                for (bytes, source_storage[0..count]) |*byte, old| byte.* +%= old;
                try output.writeAll(target_cursor, bytes);
                reader.output_position += count;
                source_cursor = try checkedAdd(source_cursor, count);
                target_cursor = try checkedAdd(target_cursor, count);
                remaining -= count;
            }
        } else {
            try writeLiteral(&reader, output, &target_cursor, gap);
        }

        const signed_source = @as(i128, @intCast(source_cursor)) + source_delta;
        if (signed_source < 0 or signed_source > std.math.maxInt(u64))
            return error.SourceOutOfRange;
        var copy_source: u64 = @intCast(signed_source);
        if (try checkedAdd(copy_source, copy_len) > source.size or
            try checkedAdd(target_cursor, copy_len) > target_size)
            return error.CopyOutOfRange;
        try writeSource(source, output, source_storage, &copy_source, &target_cursor, copy_len);
        source_cursor = copy_source;
    }
    try writeLiteral(&reader, output, &target_cursor, target_size - target_cursor);
    try reader.finish();
}

const MemoryInput = struct {
    bytes: []const u8,

    fn read(raw: ?*anyopaque, offset: u64, destination: []u8) !void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (offset > self.bytes.len or destination.len > self.bytes.len - offset)
            return error.TestReadOutOfBounds;
        @memcpy(destination, self.bytes[@intCast(offset)..][0..destination.len]);
    }

    fn input(self: *@This()) Input {
        return .{ .context = self, .size = self.bytes.len, .read_at = read };
    }
};

const MemoryOutput = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *@This()) void {
        self.bytes.deinit(self.allocator);
    }

    fn write(raw: ?*anyopaque, offset: u64, source: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        const start = std.math.cast(usize, offset) orelse return error.TestWriteOutOfBounds;
        const end = std.math.add(usize, start, source.len) catch return error.TestWriteOutOfBounds;
        if (start > self.bytes.items.len) return error.TestWriteOutOfBounds;
        if (end > self.bytes.items.len) {
            const old = self.bytes.items.len;
            try self.bytes.resize(self.allocator, end);
            @memset(self.bytes.items[old..], 0);
        }
        @memcpy(self.bytes.items[start..end], source);
    }

    fn output(self: *@This()) Output {
        return .{ .context = self, .write_at = write };
    }
};

fn patternedBytes(allocator: std.mem.Allocator, len: usize, seed: u8) ![]u8 {
    const bytes = try allocator.alloc(u8, len);
    for (bytes, 0..) |*byte, index|
        byte.* = @truncate((index *% 73) ^ (index >> 2) ^ (@as(usize, seed) *% 29));
    return bytes;
}

test "streaming ZAR26 selects residuals and round trips" {
    const allocator = std.testing.allocator;
    const source_bytes = try patternedBytes(allocator, 256 * 1024, 7);
    defer allocator.free(source_bytes);
    const target_bytes = try allocator.dupe(u8, source_bytes);
    defer allocator.free(target_bytes);
    target_bytes[70_000] +%= 9;
    target_bytes[90_000] -%= 3;
    @memset(target_bytes[128 * 1024 - 1 + 32 * 1024 .. 200_000], 0);
    const anchors = [_]merge.Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 64 * 1024 },
        .{ .source_offset = 128 * 1024 - 1, .target_offset = 128 * 1024 - 1, .length = 32 * 1024 },
        .{ .source_offset = 200_000, .target_offset = 200_000, .length = 40_000 },
    };
    var source: MemoryInput = .{ .bytes = source_bytes };
    var target: MemoryInput = .{ .bytes = target_bytes };
    var patch: MemoryOutput = .{ .allocator = allocator };
    defer patch.deinit();
    var result = try encode(allocator, source.input(), target.input(), &anchors, patch.output());
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 1), result.stats.residual_segments);
    try std.testing.expectEqual(@as(u64, max_residual_gap), result.stats.residual_bytes);

    var patch_input: MemoryInput = .{ .bytes = patch.bytes.items };
    var decoded: MemoryOutput = .{ .allocator = allocator };
    defer decoded.deinit();
    try decode(allocator, source.input(), patch_input.input(), target_bytes.len, decoded.output());
    try std.testing.expectEqualSlices(u8, target_bytes, decoded.bytes.items);
}

test "ZAR26 residuals and literals cross decoded blocks within one scratch budget" {
    const allocator = std.testing.allocator;
    const literal_len = stream_buffer_bytes - 16;
    const residual_len = 64;
    const trailing_len = stream_buffer_bytes + 32;
    var source_bytes: [128]u8 = undefined;
    for (&source_bytes, 0..) |*byte, index| byte.* = @truncate(index * 73 + 11);
    var residual_bytes: [residual_len]u8 = undefined;
    for (&residual_bytes, 0..) |*byte, index| byte.* = @truncate(index * 7 + 240);

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    try body.writer.writeAll(&.{ 0xe0, 0xff, 0x0f, 0, 4 });
    try body.writer.splatByteAll(0x31, literal_len);
    try body.writer.writeAll(&.{ 0x81, 1, 0, 4 });
    try body.writer.writeAll(&residual_bytes);
    try body.writer.splatByteAll(0x44, trailing_len);
    const frame = try @import("../compression/frame.zig").compressAlloc(allocator, body.written(), 3);
    defer allocator.free(frame);

    const target_len = literal_len + 4 + residual_len + 4 + trailing_len;
    const expected = try allocator.alloc(u8, target_len);
    defer allocator.free(expected);
    @memset(expected[0..literal_len], 0x31);
    @memcpy(expected[literal_len..][0..4], source_bytes[0..4]);
    const residual_start = literal_len + 4;
    for (expected[residual_start..][0..residual_len], residual_bytes, source_bytes[4..][0..residual_len]) |*byte, addend, old|
        byte.* = old +% addend;
    @memcpy(expected[residual_start + residual_len ..][0..4], source_bytes[4 + residual_len ..][0..4]);
    @memset(expected[residual_start + residual_len + 4 ..], 0x44);

    var header: [header_size]u8 = @splat(0);
    @memcpy(header[0..5], "ZAR26");
    std.mem.writeInt(u64, header[8..16], source_bytes.len, .little);
    std.mem.writeInt(u64, header[16..24], target_len, .little);
    std.mem.writeInt(u64, header[24..32], 2, .little);
    std.mem.writeInt(u64, header[32..40], body.written().len, .little);
    std.mem.writeInt(u64, header[40..48], frame.len, .little);
    var patch_bytes: std.Io.Writer.Allocating = .init(allocator);
    defer patch_bytes.deinit();
    try patch_bytes.writer.writeAll(&header);
    try patch_bytes.writer.writeAll(frame);

    const ExpectedOutput = struct {
        expected: []const u8,
        written: usize = 0,

        fn write(raw: ?*anyopaque, offset: u64, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            try std.testing.expectEqual(@as(u64, self.written), offset);
            try std.testing.expect(bytes.len <= self.expected.len - self.written);
            try std.testing.expectEqualSlices(u8, self.expected[self.written..][0..bytes.len], bytes);
            self.written += bytes.len;
        }
    };
    var source: MemoryInput = .{ .bytes = &source_bytes };
    var patch: MemoryInput = .{ .bytes = patch_bytes.written() };
    var sink: ExpectedOutput = .{ .expected = expected };
    const decode_storage = try allocator.alloc(u8, frame.len + stream_buffer_bytes + source_bytes.len);
    defer allocator.free(decode_storage);
    var decode_allocator = std.heap.FixedBufferAllocator.init(decode_storage);
    try decode(decode_allocator.allocator(), source.input(), patch.input(), target_len, .{ .context = &sink, .write_at = ExpectedOutput.write });
    try std.testing.expectEqual(expected.len, sink.written);
}

test "streaming ZAR26 handles literal-only targets" {
    const allocator = std.testing.allocator;
    var source: MemoryInput = .{ .bytes = "source" };
    for ([_][]const u8{ "an unrelated literal target", "" }) |bytes| {
        var target: MemoryInput = .{ .bytes = bytes };
        var patch: MemoryOutput = .{ .allocator = allocator };
        defer patch.deinit();
        var result = try encode(allocator, source.input(), target.input(), &.{}, patch.output());
        defer result.deinit();
        var patch_input: MemoryInput = .{ .bytes = patch.bytes.items };
        var decoded: MemoryOutput = .{ .allocator = allocator };
        defer decoded.deinit();
        var decode_storage: [128]u8 = undefined;
        var decode_allocator = std.heap.FixedBufferAllocator.init(&decode_storage);
        try decode(decode_allocator.allocator(), source.input(), patch_input.input(), target.bytes.len, decoded.output());
        try std.testing.expectEqualStrings(target.bytes, decoded.bytes.items);
    }
}

test "ZAR26 literal candidates consume each buffered gap once" {
    const allocator = std.testing.allocator;
    var source_bytes: [1280]u8 = undefined;
    var random = std.Random.DefaultPrng.init(0x7a61725f67617073);
    random.random().bytes(&source_bytes);
    var target_bytes = source_bytes;
    @memset(target_bytes[256..512], 0);
    @memset(target_bytes[768..1024], 0);
    const Target = struct {
        bytes: []const u8,
        reads: [2]bool = @splat(false),

        fn read(raw: ?*anyopaque, offset: u64, destination: []u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const index: usize = switch (offset) {
                256 => 0,
                768 => 1,
                else => return error.UnexpectedLiteralRead,
            };
            if (self.reads[index]) return error.RepeatedLiteralRead;
            self.reads[index] = true;
            @memcpy(destination, self.bytes[@intCast(offset)..][0..destination.len]);
        }
    };
    var source: MemoryInput = .{ .bytes = &source_bytes };
    var target: Target = .{ .bytes = &target_bytes };
    const anchors = [_]merge.Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 256 },
        .{ .source_offset = 512, .target_offset = 512, .length = 256 },
        .{ .source_offset = 1024, .target_offset = 1024, .length = 256 },
    };
    var patch: MemoryOutput = .{ .allocator = allocator };
    defer patch.deinit();
    var result = try encode(allocator, source.input(), .{ .context = &target, .size = target_bytes.len, .read_at = Target.read }, &anchors, patch.output());
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 2), result.stats.residual_candidates);
    try std.testing.expectEqual(@as(u64, 0), result.stats.residual_segments);
    try std.testing.expectEqual(@as(u64, 512), result.stats.literal_bytes);
    try std.testing.expectEqual([2]bool{ true, true }, target.reads);
    var patch_input: MemoryInput = .{ .bytes = patch.bytes.items };
    var decoded: MemoryOutput = .{ .allocator = allocator };
    defer decoded.deinit();
    try decode(allocator, source.input(), patch_input.input(), target_bytes.len, decoded.output());
    try std.testing.expectEqualSlices(u8, &target_bytes, decoded.bytes.items);
}

test "streaming ZAR26 rejects corrupt envelope and noncanonical data" {
    const allocator = std.testing.allocator;
    var source: MemoryInput = .{ .bytes = "source" };
    var target: MemoryInput = .{ .bytes = "target" };
    var patch: MemoryOutput = .{ .allocator = allocator };
    defer patch.deinit();
    var result = try encode(allocator, source.input(), target.input(), &.{}, patch.output());
    defer result.deinit();
    var patch_input: MemoryInput = .{ .bytes = patch.bytes.items };
    var decoded: MemoryOutput = .{ .allocator = allocator };
    defer decoded.deinit();
    try std.testing.expectError(
        error.TargetSizeMismatch,
        decode(allocator, source.input(), patch_input.input(), 5, decoded.output()),
    );
    patch.bytes.items[0] = 'X';
    try std.testing.expectError(
        error.InvalidMagic,
        decode(allocator, source.input(), patch_input.input(), 6, decoded.output()),
    );
}

// W26 serialization; raw/zstd candidates in shared output

const std = @import("std");
const core = @import("../encoding.zig");
const w26 = @import("../w26.zig");
const checksum = @import("../w26.zig").Checksum;
const zstd_c = @import("../../compression/zstd_c.zig");
const fs = @import("../../core/fs.zig");
const ids = @import("../../core/ids.zig");
const scan = @import("../../core/scan.zig");
const match = @import("match.zig");
const windows = @import("windows.zig");

pub const Cover = match.Cover;

pub const default_window_bound: u64 = 4 * 1024 * 1024;
pub const default_step_bytes: usize = 64 * 1024;
pub const default_meta_count: usize = 64;
pub const default_io_buffer_bytes: usize = 64 * 1024;
pub const max_window_bound: u64 = 256 * 1024 * 1024;
pub const max_step_bytes: usize = 4 * 1024 * 1024;
pub const max_io_buffer_bytes: usize = 4 * 1024 * 1024;
// retained ADD/target bytes not bounded by encoded cover+rle size
pub const max_retained_step_coverage_bytes: usize = 4 * 1024 * 1024;
pub const max_writer_windows: u64 = 1 << 24;
// upstream reader limit: 64 metadata-ring entries
pub const max_writer_meta_count: usize = 64;
pub const patched_field_width: usize = 9;

const max_fixed_value: u64 = (@as(u64, 1) << 63) - 1;
const zstd_continue: c_int = 0;
const zstd_end: c_int = 2;
const zstd_window_log_min: u8 = 10;
const zstd_window_log_max: u8 = 28;

pub const Compression = enum {
    stored,
    zstd_if_smaller,
};

pub const Options = struct {
    window_bound: u64 = default_window_bound,
    // encoded cover+rle bytes
    step_bytes: usize = default_step_bytes,
    // power of two in [2, 64]
    meta_count: usize = default_meta_count,
    compression: Compression = .zstd_if_smaller,
    compression_level: c_int = 5,
    io_buffer_bytes: usize = default_io_buffer_bytes,
    reader: scan.Reader = .direct,
    // full source identity
    source_reader: scan.Reader = .direct,
    // independent planning identities before suffix retention
    expected_source_digest: ?ids.Digest = null,
    expected_target_digest: ?ids.Digest = null,
};

pub const ConstructionObservation = struct {
    source_digest: ids.Digest = .zero,
    target_digest: ids.Digest = .zero,
    source_bytes: u64 = 0,
    target_bytes: u64 = 0,
};

pub const Stats = struct {
    patch_bytes: u64 = 0,
    windows: u64 = 0,
    // original caller count, preserved in header
    covers: u64 = 0,
    // split fragments and zero-length literal terminators included
    serialized_covers: u64 = 0,
    steps: u64 = 0,
    literal_bytes: u64 = 0,
    covered_bytes: u64 = 0,
    max_step_mem: u64 = 0,
    max_window_old: u64 = 0,
    max_sub_covers: u64 = 0,
    max_retained_covered: u64 = 0,
    uncompressed_body: u64 = 0,
    compressed_body: u64 = 0,
    stored: bool = true,
    construction_observation: ConstructionObservation = .{},
};

const BodyStats = struct {
    windows: u64 = 0,
    serialized_covers: u64 = 0,
    steps: u64 = 0,
    literal_bytes: u64 = 0,
    covered_bytes: u64 = 0,
    max_step_mem: u64 = 0,
    max_window_old: u64 = 0,
    max_sub_covers: u64 = 0,
    max_retained_covered: u64 = 0,

    fn eql(a: BodyStats, b: BodyStats) bool {
        return a.windows == b.windows and
            a.serialized_covers == b.serialized_covers and
            a.steps == b.steps and
            a.literal_bytes == b.literal_bytes and
            a.covered_bytes == b.covered_bytes and
            a.max_step_mem == b.max_step_mem and
            a.max_window_old == b.max_window_old and
            a.max_sub_covers == b.max_sub_covers and
            a.max_retained_covered == b.max_retained_covered;
    }
};

const WindowPlan = struct {
    sub_covers: u64 = 0,
};

const Fragment = struct {
    old_pos: u64,
    new_pos: u64,
    length: u64,
    terminator: bool,
};

const WindowCursor = struct {
    cover_index: usize,
    cover_end: usize,
    cover_consumed: u64 = 0,
    terminator_needed: bool,
    terminator_done: bool = false,
    last_old_end: u64 = 0,
    last_new_end: u64 = 0,

    fn hasNext(self: WindowCursor) bool {
        return self.cover_index < self.cover_end or
            (self.terminator_needed and !self.terminator_done);
    }

    fn peek(
        self: WindowCursor,
        all_covers: []const windows.Cover,
        window: windows.Window,
    ) !Fragment {
        if (self.cover_index < self.cover_end) {
            const cover = all_covers[self.cover_index];
            if (cover.source_offset < window.source_offset or
                cover.target_offset < window.target_offset or
                self.cover_consumed >= cover.length)
                return error.InvalidWindow;
            const old_base = cover.source_offset - window.source_offset;
            const new_base = cover.target_offset - window.target_offset;
            return .{
                .old_pos = try checkedAdd(old_base, self.cover_consumed),
                .new_pos = try checkedAdd(new_base, self.cover_consumed),
                .length = cover.length - self.cover_consumed,
                .terminator = false,
            };
        }
        if (!self.terminator_needed or self.terminator_done)
            return error.InternalPlanMismatch;
        return .{
            // upstream literal terminator: zero source delta
            .old_pos = self.last_old_end,
            .new_pos = window.target_length,
            .length = 0,
            .terminator = true,
        };
    }

    fn consume(self: *WindowCursor, fragment: Fragment, original_length: u64) !void {
        if (fragment.terminator) {
            if (fragment.length != 0 or self.terminator_done)
                return error.InternalPlanMismatch;
            self.terminator_done = true;
        } else {
            const cover_length = try checkedAdd(self.cover_consumed, fragment.length);
            if (cover_length > original_length) return error.InternalPlanMismatch;
            if (cover_length == original_length) {
                self.cover_index += 1;
                self.cover_consumed = 0;
            } else {
                self.cover_consumed = cover_length;
            }
        }
        self.last_old_end = try checkedAdd(fragment.old_pos, fragment.length);
        self.last_new_end = try checkedAdd(fragment.new_pos, fragment.length);
    }
};

const StepPlan = struct {
    fragments: u64 = 0,
    cover_bytes: u64 = 0,
    rle_bytes: u64 = 0,
    covered_bytes: u64 = 0,
    literal_bytes: u64 = 0,

    fn memory(self: StepPlan) !u64 {
        return checkedAdd(self.cover_bytes, self.rle_bytes);
    }
};

const StepMode = enum { covers, target };

const CountSink = struct {
    count: u64 = 0,

    fn bytes(self: *CountSink, data: []const u8) !void {
        self.count = try checkedAdd(self.count, data.len);
    }

    fn literal(self: *CountSink, _: u64, length: u64) !void {
        self.count = try checkedAdd(self.count, length);
    }

    fn covered(_: *CountSink, _: u64, _: u64) !void {}

    fn beginCoveredReplay(_: *CountSink, _: []const u8) !void {}

    fn endCoveredReplay(_: *CountSink) !void {}
};

const BodyWriter = struct {
    io: std.Io,
    output: std.Io.File,
    raw_start: u64,
    raw_position: u64,
    raw_end: u64,
    candidate_position: u64,
    candidate_bytes: u64 = 0,
    stream: ?*zstd_c.ZstdCStream,
    compression_live: bool,
    compressed_buffer: []u8,

    fn write(self: *BodyWriter, data: []const u8) !void {
        if (data.len == 0) return;
        if (self.raw_position > self.raw_end) return error.BodySizeMismatch;
        if (@as(u64, @intCast(data.len)) > self.raw_end - self.raw_position)
            return error.BodySizeMismatch;
        self.output.writePositionalAll(self.io, data, self.raw_position) catch
            return error.WriteFailed;
        self.raw_position = try checkedAdd(self.raw_position, data.len);
        if (self.compression_live) try self.compress(data);
    }

    fn compress(self: *BodyWriter, data: []const u8) !void {
        var input: zstd_c.ZstdInBuffer = .{
            .src = data.ptr,
            .size = data.len,
            .pos = 0,
        };
        while (input.pos < input.size) {
            var output: zstd_c.ZstdOutBuffer = .{
                .dst = self.compressed_buffer.ptr,
                .size = self.compressed_buffer.len,
                .pos = 0,
            };
            const before = input.pos;
            const remaining = zstd_c.ZSTD_compressStream2(
                self.stream orelse return error.CompressionFailed,
                &output,
                &input,
                zstd_continue,
            );
            if (zstd_c.ZSTD_isError(remaining) != 0) return error.CompressionFailed;
            try self.acceptCompressed(self.compressed_buffer[0..output.pos]);
            if (!self.compression_live) return;
            if (input.pos == before and output.pos == 0)
                return error.CompressionMadeNoProgress;
        }
    }

    fn acceptCompressed(self: *BodyWriter, data: []const u8) !void {
        if (data.len == 0 or !self.compression_live) return;
        const candidate = try checkedAdd(self.candidate_bytes, data.len);
        if (candidate >= self.rawBodySize()) {
            self.compression_live = false;
            return;
        }
        self.output.writePositionalAll(self.io, data, self.candidate_position) catch
            return error.WriteFailed;
        self.candidate_position = try checkedAdd(self.candidate_position, data.len);
        self.candidate_bytes = candidate;
    }

    fn rawBodySize(self: BodyWriter) u64 {
        return self.raw_end - self.raw_start;
    }
};

const OutputSink = struct {
    io: std.Io,
    target: std.Io.File,
    reader: scan.Reader,
    buffer: []u8,
    writer: *BodyWriter,
    target_hasher: *std.crypto.hash.Blake3,
    target_checksum_hasher: *checksum.Hasher,
    target_observed: u64 = 0,
    covered_target: []const u8 = "",
    covered_position: usize = 0,

    fn bytes(self: *OutputSink, data: []const u8) !void {
        try self.writer.write(data);
    }

    fn literal(self: *OutputSink, target_offset: u64, length: u64) !void {
        try self.observeTarget(target_offset, length, true);
    }

    fn covered(self: *OutputSink, target_offset: u64, length: u64) !void {
        if (target_offset != self.target_observed)
            return error.InternalPlanMismatch;
        const count = std.math.cast(usize, length) orelse return error.IntegerOverflow;
        if (self.covered_position > self.covered_target.len or
            count > self.covered_target.len - self.covered_position)
            return error.InternalPlanMismatch;
        const observed = self.covered_target[self.covered_position..][0..count];
        self.target_hasher.update(observed);
        self.target_checksum_hasher.update(observed);
        self.covered_position += count;
        self.target_observed = try checkedAdd(self.target_observed, count);
    }

    fn beginCoveredReplay(self: *OutputSink, covered_bytes: []const u8) !void {
        if (self.covered_position != self.covered_target.len)
            return error.InternalPlanMismatch;
        self.covered_target = covered_bytes;
        self.covered_position = 0;
    }

    fn endCoveredReplay(self: *OutputSink) !void {
        if (self.covered_position != self.covered_target.len)
            return error.InternalPlanMismatch;
        self.covered_target = "";
        self.covered_position = 0;
    }

    fn observeTarget(
        self: *OutputSink,
        target_offset: u64,
        length: u64,
        emit_literal: bool,
    ) !void {
        if (target_offset != self.target_observed)
            return error.InternalPlanMismatch;
        var consumed: u64 = 0;
        while (consumed < length) {
            const take: usize = @intCast(@min(
                @as(u64, @intCast(self.buffer.len)),
                length - consumed,
            ));
            const offset = try checkedAdd(target_offset, consumed);
            const count = try self.reader.read(
                self.io,
                self.target,
                self.buffer[0..take],
                offset,
            );
            if (count > take) return error.InvalidReadCount;
            if (count == 0) return error.ShortTargetRead;
            const observed = self.buffer[0..count];
            self.target_hasher.update(observed);
            self.target_checksum_hasher.update(observed);
            self.target_observed = try checkedAdd(self.target_observed, count);
            if (emit_literal) try self.writer.write(observed);
            consumed = try checkedAdd(consumed, count);
        }
    }
};

const StepData = struct {
    io: std.Io,
    source: std.Io.File,
    target_file: std.Io.File,
    source_reader: scan.Reader,
    target_reader: scan.Reader,
    add: []u8,
    target: []u8,
    rle: []u8,
    second: []u8,
    third: []u8,
    used: usize = 0,
    rle_used: usize = 0,

    fn reset(self: *StepData) void {
        self.used = 0;
        self.rle_used = 0;
    }

    fn coveredPair(
        self: *StepData,
        source_offset: u64,
        target_offset: u64,
        length: u64,
    ) !void {
        var consumed: u64 = 0;
        while (consumed < length) {
            const remaining_capacity = self.add.len - self.used;
            if (remaining_capacity == 0) return error.InternalPlanMismatch;
            const take: usize = @intCast(@min(
                @as(u64, @intCast(@min(remaining_capacity, self.second.len))),
                length - consumed,
            ));
            if (take == 0) return error.InternalPlanMismatch;
            const source_slice = self.add[self.used..][0..take];
            const target_slice = self.target[self.used..][0..take];
            try readAdjudicatedAt(
                self.io,
                self.source,
                self.source_reader,
                source_slice,
                self.second[0..take],
                self.third[0..take],
                try checkedAdd(source_offset, consumed),
                error.ShortSourceRead,
            );
            try readAdjudicatedAt(
                self.io,
                self.target_file,
                self.target_reader,
                target_slice,
                self.second[0..take],
                self.third[0..take],
                try checkedAdd(target_offset, consumed),
                error.ShortTargetRead,
            );
            for (source_slice, target_slice) |*addend, target_byte| {
                addend.* = target_byte -% addend.*;
            }
            self.used += take;
            consumed = try checkedAdd(consumed, take);
        }
    }

    fn finish(self: *StepData) ![]const u8 {
        const encoded = try encodeRle0(self.add[0..self.used], self.rle);
        self.rle_used = encoded.len;
        return encoded;
    }

    fn coveredTarget(self: *const StepData) []const u8 {
        return self.target[0..self.used];
    }
};

fn readAdjudicatedAt(
    io: std.Io,
    file: std.Io.File,
    reader: scan.Reader,
    destination: []u8,
    second: []u8,
    third: []u8,
    offset: u64,
    comptime short_error: anyerror,
) !void {
    if (destination.len != second.len or destination.len != third.len)
        return error.InternalAdjudicationBufferMismatch;
    try readObservationAt(io, file, reader, destination, offset, short_error);
    try readObservationAt(io, file, reader, second, offset, short_error);
    if (std.mem.eql(u8, destination, second)) return;
    try readObservationAt(io, file, reader, third, offset, short_error);
    if (std.mem.eql(u8, destination, third)) return;
    if (std.mem.eql(u8, second, third)) {
        @memcpy(destination, second);
        return;
    }
    return error.FileChangedDuringAdd;
}

fn readObservationAt(
    io: std.Io,
    file: std.Io.File,
    reader: scan.Reader,
    destination: []u8,
    offset: u64,
    comptime short_error: anyerror,
) !void {
    var done: usize = 0;
    while (done < destination.len) {
        const count = try reader.read(
            io,
            file,
            destination[done..],
            try checkedAdd(offset, done),
        );
        if (count > destination.len - done) return error.InvalidReadCount;
        if (count == 0) return short_error;
        done += count;
    }
}

// rle0: no trailing zero after value run
fn encodeRle0(add: []const u8, output: []u8) ![]const u8 {
    var input_position: usize = 0;
    var output_position: usize = 0;
    if (add.len == 0) {
        try appendUIntToBuffer(output, &output_position, 0);
        return output[0..output_position];
    }
    while (input_position < add.len) {
        const zero_start = input_position;
        while (input_position < add.len and add[input_position] == 0) : (input_position += 1) {}
        try appendUIntToBuffer(output, &output_position, input_position - zero_start);
        if (input_position == add.len) break;

        const value_start = input_position;
        while (input_position < add.len and add[input_position] != 0) : (input_position += 1) {}
        const value_length = input_position - value_start;
        try appendUIntToBuffer(output, &output_position, value_length);
        if (output_position > output.len or value_length > output.len - output_position)
            return error.StepTooSmall;
        @memcpy(output[output_position..][0..value_length], add[value_start..input_position]);
        output_position += value_length;
    }
    return output[0..output_position];
}

fn appendUIntToBuffer(output: []u8, position: *usize, value: anytype) !void {
    var storage: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    const encoded = core.encodeUIntTagged(@intCast(value), 0, 0, &storage);
    if (position.* > output.len or encoded.len > output.len - position.*)
        return error.StepTooSmall;
    @memcpy(output[position.*..][0..encoded.len], encoded);
    position.* += encoded.len;
}

pub fn write(
    allocator: std.mem.Allocator,
    io: std.Io,
    covers: []const Cover,
    source_path: []const u8,
    source_size: u64,
    target_path: []const u8,
    target_size: u64,
    output_path: []const u8,
    output_offset: u64,
    options: Options,
) !Stats {
    try validateOptions(options);
    const cover_count: u64 = std.math.cast(u64, covers.len) orelse
        return error.TooManyCovers;

    const window_covers = try expandCovers(
        allocator,
        covers,
        source_size,
        target_size,
        options.window_bound,
    );
    defer allocator.free(window_covers);
    const formed = try windows.form(
        allocator,
        window_covers,
        source_size,
        target_size,
        options.window_bound,
    );
    defer allocator.free(formed);
    for (formed) |window| {
        if (window.source_length > options.window_bound or
            window.target_length > options.window_bound)
            return error.InternalPlanMismatch;
    }

    const target_buffer = try allocator.alloc(u8, options.io_buffer_bytes);
    defer allocator.free(target_buffer);
    const second_buffer = try allocator.alloc(u8, options.io_buffer_bytes);
    defer allocator.free(second_buffer);
    const third_buffer = try allocator.alloc(u8, options.io_buffer_bytes);
    defer allocator.free(third_buffer);
    const retained_step_bytes: usize = @intCast(@min(
        options.window_bound,
        @as(u64, max_retained_step_coverage_bytes),
    ));
    const step_add = try allocator.alloc(u8, retained_step_bytes);
    defer allocator.free(step_add);
    const step_target = try allocator.alloc(u8, retained_step_bytes);
    defer allocator.free(step_target);
    const step_rle = try allocator.alloc(u8, options.step_bytes);
    defer allocator.free(step_rle);

    const cwd = std.Io.Dir.cwd();
    var source = fs.openRead(io, cwd, source_path) catch return error.SourceReadFailed;
    defer source.close(io);
    if ((source.length(io) catch return error.SourceReadFailed) != source_size)
        return error.SourceSizeChanged;
    var target = fs.openRead(io, cwd, target_path) catch return error.TargetReadFailed;
    defer target.close(io);
    if ((target.length(io) catch return error.TargetReadFailed) != target_size)
        return error.TargetSizeChanged;

    var step_data: StepData = .{
        .io = io,
        .source = source,
        .target_file = target,
        .source_reader = options.source_reader,
        .target_reader = options.reader,
        .add = step_add,
        .target = step_target,
        .rle = step_rle,
        .second = second_buffer,
        .third = third_buffer,
    };

    var counter: CountSink = .{};
    var planned_stats: BodyStats = .{};
    try encodeBody(
        &counter,
        window_covers,
        formed,
        options.step_bytes,
        options.meta_count,
        &step_data,
        &planned_stats,
    );
    const raw_body_size = counter.count;
    if (raw_body_size > max_fixed_value) return error.BodyTooLarge;
    if (try checkedAdd(planned_stats.literal_bytes, planned_stats.covered_bytes) != target_size)
        return error.TargetSizeChanged;

    const stored_header = try buildHeader(
        allocator,
        .stored,
        raw_body_size,
        target_size,
        source_size,
        cover_count,
        planned_stats,
        options.meta_count,
    );
    defer allocator.free(stored_header.bytes);
    const zstd_header = try buildHeader(
        allocator,
        .zstd_if_smaller,
        raw_body_size,
        target_size,
        source_size,
        cover_count,
        planned_stats,
        options.meta_count,
    );
    defer allocator.free(zstd_header.bytes);
    const staging_header = if (options.compression == .zstd_if_smaller)
        zstd_header
    else
        stored_header;

    const staging_header_size: u64 = @intCast(staging_header.bytes.len);
    const staging_body_start = try checkedAdd(output_offset, staging_header_size);
    const raw_end = try checkedAdd(staging_body_start, raw_body_size);
    // compressed candidate follows the raw body
    _ = try checkedAdd(raw_end, raw_body_size);

    const compressed_buffer = if (options.compression == .zstd_if_smaller and
        raw_body_size != 0)
        try allocator.alloc(u8, default_io_buffer_bytes)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(compressed_buffer);

    const stream: ?*zstd_c.ZstdCStream = if (options.compression == .zstd_if_smaller and
        raw_body_size != 0)
        zstd_c.ZSTD_createCStream()
    else
        null;
    if (options.compression == .zstd_if_smaller and raw_body_size != 0 and stream == null)
        return error.CompressionFailed;
    defer {
        if (stream) |value| _ = zstd_c.ZSTD_freeCStream(value);
    }
    if (stream) |value| try initCompressor(value, raw_body_size, options.compression_level);

    var output = fs.openReadWrite(io, cwd, output_path) catch return error.OutputOpenFailed;
    defer output.close(io);
    if (try fs.sameOpenFile(io, source, output)) return error.SourceOutputAlias;
    if (try fs.sameOpenFile(io, target, output)) return error.TargetOutputAlias;
    if ((output.length(io) catch return error.OutputOpenFailed) != output_offset)
        return error.OutputOffsetMismatch;

    // prefix = retry point; original error over cleanup failure
    errdefer {
        output.setLength(io, output_offset) catch {};
    }
    output.writePositionalAll(io, staging_header.bytes, output_offset) catch
        return error.WriteFailed;

    const source_digest = try observeSource(
        io,
        source,
        options.source_reader,
        target_buffer,
        source_size,
    );
    if (options.expected_source_digest) |expected| {
        if (!source_digest.eql(expected))
            return error.ConstructionSourceDigestMismatch;
    }
    const old_checksum = try checksumSourceWindows(
        io,
        source,
        options.source_reader,
        target_buffer,
        formed,
    );

    var body_writer: BodyWriter = .{
        .io = io,
        .output = output,
        .raw_start = staging_body_start,
        .raw_position = staging_body_start,
        .raw_end = raw_end,
        .candidate_position = raw_end,
        .stream = stream,
        .compression_live = stream != null,
        .compressed_buffer = compressed_buffer,
    };
    var target_hasher = std.crypto.hash.Blake3.init(.{});
    var target_checksum_hasher = checksum.Hasher{};
    var sink: OutputSink = .{
        .io = io,
        .target = target,
        .reader = options.reader,
        .buffer = target_buffer,
        .writer = &body_writer,
        .target_hasher = &target_hasher,
        .target_checksum_hasher = &target_checksum_hasher,
    };
    var emitted_stats: BodyStats = .{};
    try encodeBody(
        &sink,
        window_covers,
        formed,
        options.step_bytes,
        options.meta_count,
        &step_data,
        &emitted_stats,
    );
    if (!BodyStats.eql(planned_stats, emitted_stats) or
        body_writer.raw_position != raw_end)
        return error.InternalPlanMismatch;
    if (sink.target_observed != target_size)
        return error.TargetSizeChanged;
    if ((source.length(io) catch return error.SourceReadFailed) != source_size)
        return error.SourceSizeChanged;
    if ((target.length(io) catch return error.TargetReadFailed) != target_size)
        return error.TargetSizeChanged;

    const compressed_size = try finishCompression(&body_writer);
    const use_compressed = compressed_size != 0 and compressed_size < raw_body_size;
    const final_body_size: u64 = if (use_compressed) compressed_size else raw_body_size;
    const final_header = if (use_compressed) zstd_header else stored_header;
    const final_header_size: u64 = @intCast(final_header.bytes.len);
    const final_body_start = try checkedAdd(output_offset, final_header_size);
    if (use_compressed) {
        try moveCandidate(
            io,
            output,
            target_buffer,
            raw_end,
            final_body_start,
            compressed_size,
        );
        var fixed: [patched_field_width]u8 = undefined;
        try packUIntFixed(&fixed, compressed_size);
        @memcpy(
            zstd_header.bytes[@intCast(zstd_header.compressed_size_offset)..][0..patched_field_width],
            &fixed,
        );
    } else {
        if (final_body_start != staging_body_start) {
            try moveCandidate(
                io,
                output,
                target_buffer,
                staging_body_start,
                final_body_start,
                raw_body_size,
            );
        }
    }
    const final_end = try checkedAdd(final_body_start, final_body_size);
    var target_digest: ids.Digest = undefined;
    target_hasher.final(&target_digest.bytes);
    if (options.expected_target_digest) |expected| {
        if (!target_digest.eql(expected))
            return error.ConstructionTargetDigestMismatch;
    }
    const new_checksum = target_checksum_hasher.final();
    @memcpy(
        final_header.bytes[final_header.old_checksum_offset..][0..checksum.byte_size],
        &old_checksum,
    );
    @memcpy(
        final_header.bytes[final_header.new_checksum_offset..][0..checksum.byte_size],
        &new_checksum,
    );
    const diff_checksum = try checksumStoredPatch(
        io,
        output,
        target_buffer,
        final_body_start,
        final_body_size,
        final_header.bytes[0..final_header.diff_checksum_offset],
    );
    @memcpy(
        final_header.bytes[final_header.diff_checksum_offset..][0..checksum.byte_size],
        &diff_checksum,
    );
    output.writePositionalAll(io, final_header.bytes, output_offset) catch
        return error.WriteFailed;

    output.setLength(io, final_end) catch return error.WriteFailed;
    output.sync(io) catch return error.WriteFailed;

    return .{
        .patch_bytes = final_header_size + final_body_size,
        .windows = planned_stats.windows,
        .covers = cover_count,
        .serialized_covers = planned_stats.serialized_covers,
        .steps = planned_stats.steps,
        .literal_bytes = planned_stats.literal_bytes,
        .covered_bytes = planned_stats.covered_bytes,
        .max_step_mem = planned_stats.max_step_mem,
        .max_window_old = planned_stats.max_window_old,
        .max_sub_covers = planned_stats.max_sub_covers,
        .max_retained_covered = planned_stats.max_retained_covered,
        .uncompressed_body = raw_body_size,
        .compressed_body = if (use_compressed) compressed_size else 0,
        .stored = !use_compressed,
        .construction_observation = .{
            .source_digest = source_digest,
            .target_digest = target_digest,
            .source_bytes = source_size,
            .target_bytes = sink.target_observed,
        },
    };
}

// complete source windows in wire order, repeats included
fn checksumSourceWindows(
    io: std.Io,
    source: std.Io.File,
    reader: scan.Reader,
    buffer: []u8,
    formed: []const windows.Window,
) ![checksum.byte_size]u8 {
    var hasher = checksum.Hasher{};
    for (formed) |window| {
        var consumed: u64 = 0;
        while (consumed < window.source_length) {
            const take: usize = @intCast(@min(
                @as(u64, @intCast(buffer.len)),
                window.source_length - consumed,
            ));
            const offset = try checkedAdd(window.source_offset, consumed);
            const count = try reader.read(io, source, buffer[0..take], offset);
            if (count > take) return error.InvalidReadCount;
            if (count == 0) return error.ShortSourceRead;
            hasher.update(buffer[0..count]);
            consumed = try checkedAdd(consumed, count);
        }
    }
    return hasher.final();
}

// stored body, then header through new checksum
fn checksumStoredPatch(
    io: std.Io,
    output: std.Io.File,
    buffer: []u8,
    body_offset: u64,
    body_size: u64,
    header_before_diff_checksum: []const u8,
) ![checksum.byte_size]u8 {
    var hasher = checksum.Hasher{};
    var consumed: u64 = 0;
    while (consumed < body_size) {
        const take: usize = @intCast(@min(
            @as(u64, @intCast(buffer.len)),
            body_size - consumed,
        ));
        const count = fs.readAllAt(
            io,
            output,
            buffer[0..take],
            try checkedAdd(body_offset, consumed),
        ) catch return error.OutputReadFailed;
        if (count != take) return error.OutputReadFailed;
        hasher.update(buffer[0..count]);
        consumed = try checkedAdd(consumed, count);
    }
    hasher.update(header_before_diff_checksum);
    return hasher.final();
}

fn observeSource(
    io: std.Io,
    source: std.Io.File,
    reader: scan.Reader,
    buffer: []u8,
    source_size: u64,
) !ids.Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    var observed: u64 = 0;
    while (observed < source_size) {
        const take: usize = @intCast(@min(
            @as(u64, @intCast(buffer.len)),
            source_size - observed,
        ));
        const count = try reader.read(io, source, buffer[0..take], observed);
        if (count > take) return error.InvalidReadCount;
        if (count == 0) return error.ShortSourceRead;
        hasher.update(buffer[0..count]);
        observed = try checkedAdd(observed, count);
    }
    var digest: ids.Digest = undefined;
    hasher.final(&digest.bytes);
    return digest;
}

fn validateOptions(options: Options) !void {
    if (options.window_bound == 0 or options.window_bound > max_window_bound)
        return error.InvalidWindowBound;
    if (options.step_bytes == 0 or options.step_bytes > max_step_bytes)
        return error.InvalidStepSize;
    if (options.meta_count < 2 or options.meta_count > max_writer_meta_count or
        (options.meta_count & (options.meta_count - 1)) != 0)
        return error.InvalidMetaCount;
    if (options.io_buffer_bytes == 0 or options.io_buffer_bytes > max_io_buffer_bytes)
        return error.InvalidBufferSize;
}

// header count unchanged by wire-cover splitting
fn expandCovers(
    allocator: std.mem.Allocator,
    covers: []const Cover,
    source_size: u64,
    target_size: u64,
    bound: u64,
) ![]windows.Cover {
    var expanded_count: u64 = 0;
    var previous_target_end: u64 = 0;
    for (covers) |cover| {
        if (cover.length == 0) return error.ZeroLengthCover;
        const source_end = try checkedAdd(cover.source_offset, cover.length);
        const target_end = try checkedAdd(cover.target_offset, cover.length);
        if (source_end > source_size) return error.SourceOutOfRange;
        if (target_end > target_size) return error.TargetOutOfRange;
        if (cover.target_offset < previous_target_end) return error.CoversNotOrdered;
        previous_target_end = target_end;

        const pieces_u64 = try checkedAdd(
            cover.length / bound,
            @intFromBool(cover.length % bound != 0),
        );
        if (pieces_u64 > max_writer_windows - expanded_count)
            return error.TooManyWindows;
        expanded_count += pieces_u64;
    }

    const allocation_count = std.math.cast(usize, expanded_count) orelse
        return error.TooManyWindows;
    const expanded = try allocator.alloc(windows.Cover, allocation_count);
    errdefer allocator.free(expanded);
    var out_index: usize = 0;
    for (covers) |cover| {
        var consumed: u64 = 0;
        while (consumed < cover.length) {
            const length = @min(bound, cover.length - consumed);
            expanded[out_index] = .{
                .source_offset = try checkedAdd(cover.source_offset, consumed),
                .target_offset = try checkedAdd(cover.target_offset, consumed),
                .length = length,
            };
            out_index += 1;
            consumed = try checkedAdd(consumed, length);
        }
    }
    if (out_index != expanded.len) return error.InternalPlanMismatch;
    return expanded;
}

fn encodeBody(
    sink: anytype,
    covers: []const windows.Cover,
    formed: []const windows.Window,
    step_bytes: usize,
    meta_count: usize,
    step_data: *StepData,
    stats: *BodyStats,
) !void {
    stats.* = .{};
    const half = meta_count >> 1;
    var loaded_meta_end: usize = 0;
    var last_meta_old_end: u64 = 0;

    for (formed, 0..) |window, window_index| {
        if ((window_index & (half - 1)) == 0 and loaded_meta_end < formed.len) {
            const saved = if (window_index == 0) meta_count else half;
            const batch = @min(formed.len - loaded_meta_end, saved);
            for (formed[loaded_meta_end..][0..batch]) |meta_window| {
                try emitUInt(sink, meta_window.source_length);
                if (meta_window.source_offset >= last_meta_old_end) {
                    try emitTagged(
                        sink,
                        meta_window.source_offset - last_meta_old_end,
                        false,
                    );
                } else {
                    try emitTagged(
                        sink,
                        last_meta_old_end - meta_window.source_offset,
                        true,
                    );
                }
                last_meta_old_end = try checkedAdd(
                    meta_window.source_offset,
                    meta_window.source_length,
                );
            }
            loaded_meta_end += batch;
        }

        const plan = try planWindow(covers, window, step_bytes, step_data);
        try emitUInt(sink, plan.sub_covers);
        stats.max_sub_covers = @max(stats.max_sub_covers, plan.sub_covers);
        stats.max_window_old = @max(stats.max_window_old, window.source_length);

        var cursor = try startWindow(covers, window);
        var emitted_sub_covers: u64 = 0;
        while (cursor.hasNext()) {
            var after = cursor;
            const step = try planStepWithData(
                &after,
                covers,
                window,
                step_bytes,
                step_data,
            );
            const rle = step_data.rle[0..step_data.rle_used];

            try emitUInt(sink, step.cover_bytes);
            try emitUInt(sink, step.rle_bytes);

            var cover_replay = cursor;
            const cover_step = try replayStep(
                .covers,
                sink,
                &cover_replay,
                after,
                covers,
                window,
            );
            if (!stepPlanEql(step, cover_step)) return error.InternalPlanMismatch;

            try sink.bytes(rle);
            try sink.beginCoveredReplay(step_data.coveredTarget());

            var target_replay = cursor;
            const target_step = try replayStep(
                .target,
                sink,
                &target_replay,
                after,
                covers,
                window,
            );
            if (!stepPlanEql(step, target_step)) return error.InternalPlanMismatch;
            try sink.endCoveredReplay();
            cursor = after;

            stats.steps = try checkedAdd(stats.steps, 1);
            stats.serialized_covers = try checkedAdd(
                stats.serialized_covers,
                step.fragments,
            );
            emitted_sub_covers = try checkedAdd(emitted_sub_covers, step.fragments);
            stats.literal_bytes = try checkedAdd(stats.literal_bytes, step.literal_bytes);
            stats.covered_bytes = try checkedAdd(stats.covered_bytes, step.covered_bytes);
            stats.max_step_mem = @max(stats.max_step_mem, try step.memory());
            stats.max_retained_covered = @max(
                stats.max_retained_covered,
                step.covered_bytes,
            );
            if (stats.max_retained_covered > max_retained_step_coverage_bytes)
                return error.InternalPlanMismatch;
        }
        if (emitted_sub_covers != plan.sub_covers)
            return error.InternalPlanMismatch;
        stats.windows = try checkedAdd(stats.windows, 1);
    }
}

fn startWindow(covers: []const windows.Cover, window: windows.Window) !WindowCursor {
    const cover_end = std.math.add(usize, window.first_cover, window.cover_count) catch
        return error.IntegerOverflow;
    if (cover_end > covers.len) return error.InvalidWindow;
    const window_end = try checkedAdd(window.target_offset, window.target_length);
    const last_cover_end = if (window.cover_count == 0)
        window.target_offset
    else blk: {
        const last = covers[cover_end - 1];
        break :blk try checkedAdd(last.target_offset, last.length);
    };
    if (last_cover_end > window_end) return error.InvalidWindow;
    return .{
        .cover_index = window.first_cover,
        .cover_end = cover_end,
        .terminator_needed = last_cover_end < window_end,
    };
}

fn planWindow(
    covers: []const windows.Cover,
    window: windows.Window,
    step_bytes: usize,
    step_data: *StepData,
) !WindowPlan {
    var cursor = try startWindow(covers, window);
    var result: WindowPlan = .{};
    while (cursor.hasNext()) {
        const step = try planStepWithData(&cursor, covers, window, step_bytes, step_data);
        result.sub_covers = try checkedAdd(result.sub_covers, step.fragments);
    }
    return result;
}

fn planStepWithData(
    cursor: *WindowCursor,
    covers: []const windows.Cover,
    window: windows.Window,
    step_bytes: usize,
    step_data: *StepData,
) !StepPlan {
    step_data.reset();
    var plan: StepPlan = .{};
    while (cursor.hasNext()) {
        var fragment = try cursor.peek(covers, window);
        const original_length = if (fragment.terminator)
            0
        else
            covers[cursor.cover_index].length;
        var chosen_length = fragment.length;

        while (true) {
            fragment.length = chosen_length;
            const triple_bytes = try coverEncodingSize(cursor.*, fragment);
            const next_cover_bytes = try checkedAdd(plan.cover_bytes, triple_bytes);
            const saved_used = step_data.used;
            if (fragment.length > step_data.add.len - saved_used) {
                if (plan.fragments != 0) {
                    const retained_rle = try step_data.finish();
                    plan.rle_bytes = @intCast(retained_rle.len);
                    return plan;
                }
                if (fragment.terminator or chosen_length <= 1)
                    return error.StepTooSmall;
                const quarters = chosen_length / 4;
                const remainder = chosen_length % 4;
                chosen_length = @max(
                    @as(u64, 1),
                    quarters * 3 + (remainder * 3) / 4,
                );
                continue;
            }
            if (fragment.length != 0) {
                const source_absolute = try checkedAdd(window.source_offset, fragment.old_pos);
                const target_absolute = try checkedAdd(window.target_offset, fragment.new_pos);
                try step_data.coveredPair(source_absolute, target_absolute, fragment.length);
            }
            const candidate_rle: ?[]const u8 = step_data.finish() catch |err| switch (err) {
                error.StepTooSmall => null,
                else => |other| return other,
            };
            const fits = if (candidate_rle) |encoded|
                try checkedAdd(next_cover_bytes, encoded.len) <= step_bytes
            else
                false;
            if (fits) break;
            step_data.used = saved_used;
            if (plan.fragments != 0) {
                const retained_rle = try step_data.finish();
                plan.rle_bytes = @intCast(retained_rle.len);
                return plan;
            }
            if (fragment.terminator or chosen_length <= 1)
                return error.StepTooSmall;
            const quarters = chosen_length / 4;
            const remainder = chosen_length % 4;
            chosen_length = @max(
                @as(u64, 1),
                quarters * 3 + (remainder * 3) / 4,
            );
        }

        if (fragment.new_pos < cursor.last_new_end) return error.CoversNotOrdered;
        const gap = fragment.new_pos - cursor.last_new_end;
        plan.cover_bytes = try checkedAdd(
            plan.cover_bytes,
            try coverEncodingSize(cursor.*, fragment),
        );
        plan.covered_bytes = try checkedAdd(plan.covered_bytes, fragment.length);
        plan.literal_bytes = try checkedAdd(plan.literal_bytes, gap);
        plan.fragments = try checkedAdd(plan.fragments, 1);
        plan.rle_bytes = @intCast(step_data.rle_used);
        try cursor.consume(fragment, original_length);
    }
    if (plan.fragments == 0) return error.InternalPlanMismatch;
    return plan;
}

fn replayStep(
    comptime mode: StepMode,
    sink: anytype,
    cursor: *WindowCursor,
    end: WindowCursor,
    covers: []const windows.Cover,
    window: windows.Window,
) !StepPlan {
    var plan: StepPlan = .{};
    while (!cursorEql(cursor.*, end)) {
        var fragment = try cursor.peek(covers, window);
        const original_length = if (fragment.terminator)
            0
        else
            covers[cursor.cover_index].length;
        if (!fragment.terminator and cursor.cover_index == end.cover_index) {
            if (end.cover_consumed <= cursor.cover_consumed)
                return error.InternalPlanMismatch;
            fragment.length = end.cover_consumed - cursor.cover_consumed;
        }
        if (fragment.new_pos < cursor.last_new_end) return error.CoversNotOrdered;
        const gap = fragment.new_pos - cursor.last_new_end;

        if (mode == .covers) {
            if (fragment.old_pos >= cursor.last_old_end) {
                try emitTagged(sink, fragment.old_pos - cursor.last_old_end, false);
            } else {
                try emitTagged(sink, cursor.last_old_end - fragment.old_pos, true);
            }
            try emitUInt(sink, gap);
            try emitUInt(sink, fragment.length);
        } else if (mode == .target) {
            if (gap != 0) {
                const absolute = try checkedAdd(window.target_offset, cursor.last_new_end);
                try sink.literal(absolute, gap);
            }
            if (fragment.length != 0) {
                const absolute = try checkedAdd(window.target_offset, fragment.new_pos);
                try sink.covered(absolute, fragment.length);
            }
        } else {
            @compileError("replayStep supports only cover and Target modes");
        }

        plan.cover_bytes = try checkedAdd(
            plan.cover_bytes,
            try coverEncodingSize(cursor.*, fragment),
        );
        plan.covered_bytes = try checkedAdd(plan.covered_bytes, fragment.length);
        plan.literal_bytes = try checkedAdd(plan.literal_bytes, gap);
        plan.fragments = try checkedAdd(plan.fragments, 1);
        try cursor.consume(fragment, original_length);
    }
    if (plan.fragments == 0) return error.InternalPlanMismatch;
    return plan;
}

fn cursorEql(a: WindowCursor, b: WindowCursor) bool {
    return a.cover_index == b.cover_index and
        a.cover_end == b.cover_end and
        a.cover_consumed == b.cover_consumed and
        a.terminator_needed == b.terminator_needed and
        a.terminator_done == b.terminator_done and
        a.last_old_end == b.last_old_end and
        a.last_new_end == b.last_new_end;
}

fn coverEncodingSize(cursor: WindowCursor, fragment: Fragment) !u64 {
    const old_delta = if (fragment.old_pos >= cursor.last_old_end)
        fragment.old_pos - cursor.last_old_end
    else
        cursor.last_old_end - fragment.old_pos;
    if (fragment.new_pos < cursor.last_new_end) return error.CoversNotOrdered;
    const new_delta = fragment.new_pos - cursor.last_new_end;
    return checkedAdd(
        try checkedAdd(packTaggedSize(old_delta), packUIntSize(new_delta)),
        packUIntSize(fragment.length),
    );
}

fn stepPlanEql(a: StepPlan, b: StepPlan) bool {
    return a.fragments == b.fragments and
        a.cover_bytes == b.cover_bytes and
        a.covered_bytes == b.covered_bytes and
        a.literal_bytes == b.literal_bytes;
}

const HeaderResult = struct {
    bytes: []u8,
    compressed_size_offset: u64,
    old_checksum_offset: usize,
    new_checksum_offset: usize,
    diff_checksum_offset: usize,
};

fn buildHeader(
    allocator: std.mem.Allocator,
    compression: Compression,
    raw_body_size: u64,
    target_size: u64,
    source_size: u64,
    cover_count: u64,
    body: BodyStats,
    meta_count: usize,
) !HeaderResult {
    var region: std.ArrayList(u8) = .empty;
    defer region.deinit(allocator);
    if (compression == .zstd_if_smaller)
        try region.appendSlice(allocator, "zstd");
    try region.append(allocator, '&');
    try region.appendSlice(allocator, checksum.name);
    try region.append(allocator, 0);

    const compressed_region_offset = region.items.len;
    try region.appendNTimes(allocator, 0, patched_field_width);
    const uncompressed_region_offset = region.items.len;
    try region.appendNTimes(allocator, 0, patched_field_width);
    try packUIntFixed(
        region.items[compressed_region_offset..][0..patched_field_width],
        0,
    );
    try packUIntFixed(
        region.items[uncompressed_region_offset..][0..patched_field_width],
        raw_body_size,
    );
    for ([_]u64{
        target_size,
        source_size,
        cover_count,
        body.windows,
        meta_count,
        body.max_step_mem,
        body.max_sub_covers,
        body.max_window_old,
        checksum.byte_size,
        0, // extra data size
    }) |field| try appendUInt(&region, allocator, field);

    const old_checksum_region_offset = region.items.len;
    try region.appendNTimes(allocator, 0, checksum.byte_size);
    const new_checksum_region_offset = region.items.len;
    try region.appendNTimes(allocator, 0, checksum.byte_size);
    const diff_checksum_region_offset = region.items.len;
    try region.appendNTimes(allocator, 0, checksum.byte_size);

    if (region.items.len > std.math.maxInt(u16) or
        region.items.len + w26.head_prefix_size > w26.max_head_size)
        return error.HeaderTooLarge;

    const header = try allocator.alloc(u8, w26.head_prefix_size + region.items.len);
    errdefer allocator.free(header);
    @memcpy(header[0..w26.magic.len], w26.magic);
    header[w26.magic.len] = @intCast(region.items.len & 0xff);
    header[w26.magic.len + 1] = @intCast(region.items.len >> 8);
    @memcpy(header[w26.head_prefix_size..], region.items);
    return .{
        .bytes = header,
        .compressed_size_offset = w26.head_prefix_size + compressed_region_offset,
        .old_checksum_offset = w26.head_prefix_size + old_checksum_region_offset,
        .new_checksum_offset = w26.head_prefix_size + new_checksum_region_offset,
        .diff_checksum_offset = w26.head_prefix_size + diff_checksum_region_offset,
    };
}

fn initCompressor(stream: *zstd_c.ZstdCStream, raw_size: u64, level: c_int) !void {
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_initCStream(stream, level)) != 0)
        return error.CompressionFailed;
    const extent = @max(@as(u64, 1), @min(raw_size, max_window_bound));
    const needed_log: u8 = @intCast(std.math.log2_int_ceil(u64, extent));
    const window_log = std.math.clamp(
        needed_log,
        zstd_window_log_min,
        zstd_window_log_max,
    );
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_CCtx_setParameter(
        stream,
        zstd_c.zstd_c_window_log,
        window_log,
    )) != 0) return error.CompressionFailed;
    if (zstd_c.ZSTD_isError(zstd_c.ZSTD_CCtx_setPledgedSrcSize(stream, raw_size)) != 0)
        return error.CompressionFailed;
}

fn finishCompression(writer: *BodyWriter) !u64 {
    if (!writer.compression_live) return 0;
    var input: zstd_c.ZstdInBuffer = .{ .src = null, .size = 0, .pos = 0 };
    while (true) {
        var output: zstd_c.ZstdOutBuffer = .{
            .dst = writer.compressed_buffer.ptr,
            .size = writer.compressed_buffer.len,
            .pos = 0,
        };
        const remaining = zstd_c.ZSTD_compressStream2(
            writer.stream orelse return error.CompressionFailed,
            &output,
            &input,
            zstd_end,
        );
        if (zstd_c.ZSTD_isError(remaining) != 0) return error.CompressionFailed;
        try writer.acceptCompressed(writer.compressed_buffer[0..output.pos]);
        if (!writer.compression_live) return 0;
        if (remaining == 0) return writer.candidate_bytes;
        if (output.pos == 0) return error.CompressionMadeNoProgress;
    }
}

fn moveCandidate(
    io: std.Io,
    output: std.Io.File,
    buffer: []u8,
    source_offset: u64,
    destination_offset: u64,
    length: u64,
) !void {
    // forward copy: overlap-safe only toward lower offsets
    if (destination_offset > source_offset) return error.InternalPlanMismatch;
    var moved: u64 = 0;
    while (moved < length) {
        const take: usize = @intCast(@min(
            @as(u64, @intCast(buffer.len)),
            length - moved,
        ));
        const source = try checkedAdd(source_offset, moved);
        const count = fs.readAllAt(io, output, buffer[0..take], source) catch
            return error.OutputReadFailed;
        if (count != take) return error.OutputReadFailed;
        const destination = try checkedAdd(destination_offset, moved);
        output.writePositionalAll(io, buffer[0..count], destination) catch
            return error.WriteFailed;
        moved = try checkedAdd(moved, count);
    }
}

fn checkedAdd(a: anytype, b: anytype) !u64 {
    const left: u64 = @intCast(a);
    const right: u64 = @intCast(b);
    return std.math.add(u64, left, right) catch error.IntegerOverflow;
}

fn packUIntSize(value: u64) usize {
    const bits: usize = if (value == 0) 1 else 64 - @clz(value);
    return (bits + 6) / 7;
}

fn packTaggedSize(value: u64) usize {
    const bits: usize = if (value == 0) 0 else 64 - @clz(value);
    return if (bits <= 6) 1 else 1 + (bits - 6 + 6) / 7;
}

fn emitUInt(sink: anytype, value: anytype) !void {
    var storage: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    try sink.bytes(core.encodeUIntTagged(@intCast(value), 0, 0, &storage));
}

fn emitTagged(sink: anytype, value: u64, negative: bool) !void {
    var storage: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    try sink.bytes(core.encodeUIntTagged(value, @intFromBool(negative), 1, &storage));
}

fn appendUInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u64,
) !void {
    var storage: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    try out.appendSlice(allocator, core.encodeUIntTagged(value, 0, 0, &storage));
}

fn packUIntFixed(buffer: []u8, value: u64) !void {
    if (buffer.len != patched_field_width or value > max_fixed_value)
        return error.BodyTooLarge;
    var index: usize = 0;
    while (index + 1 < buffer.len) : (index += 1) {
        const shift: u6 = @intCast(7 * (buffer.len - 1 - index));
        buffer[index] = @as(u8, @intCast((value >> shift) & 0x7f)) | 0x80;
    }
    buffer[buffer.len - 1] = @intCast(value & 0x7f);
}

// tests

const apply = @import("apply.zig");

fn absoluteTmpPath(
    allocator: std.mem.Allocator,
    tmp: *const std.testing.TmpDir,
    leaf: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, leaf });
}

fn readPatchHeader(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    offset: u64,
) ![]u8 {
    var file = try fs.openRead(io, std.Io.Dir.cwd(), path);
    defer file.close(io);
    var prefix: [w26.head_prefix_size]u8 = undefined;
    if (try fs.readAllAt(io, file, &prefix, offset) != prefix.len)
        return error.TestShortRead;
    const remaining = @as(usize, prefix[w26.magic.len]) |
        (@as(usize, prefix[w26.magic.len + 1]) << 8);
    const result = try allocator.alloc(u8, prefix.len + remaining);
    errdefer allocator.free(result);
    if (try fs.readAllAt(io, file, result, offset) != result.len)
        return error.TestShortRead;
    return result;
}

fn expectXxh128Checksums(
    patch: []const u8,
    old_window_stream: []const u8,
    target: []const u8,
) !void {
    const info = try w26.parse(patch);
    try w26.validatePatchExtent(info, @intCast(patch.len));
    try std.testing.expectEqualStrings(checksum.name, info.checksum_type);
    try std.testing.expectEqual(@as(u64, checksum.byte_size), info.checksum_byte_size);

    const expected_old = checksum.hash(old_window_stream);
    const expected_new = checksum.hash(target);
    try std.testing.expectEqualSlices(u8, &expected_old, info.old_checksum);
    try std.testing.expectEqualSlices(u8, &expected_new, info.new_checksum);

    const header_size: usize = @intCast(info.window_data_pos);
    const body_size: usize = @intCast(info.storedBodySize());
    var diff_hasher = checksum.Hasher{};
    diff_hasher.update(patch[header_size..][0..body_size]);
    diff_hasher.update(patch[0 .. header_size - checksum.byte_size]);
    const expected_diff = diff_hasher.final();
    try std.testing.expectEqualSlices(u8, &expected_diff, info.diff_checksum);
}

fn expectRoundTrip(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    target_path: []const u8,
    patch_path: []const u8,
    result_path: []const u8,
    patch_offset: u64,
    patch_length: u64,
    target_bytes: []const u8,
) !apply.Stats {
    const stats = try apply.apply(
        allocator,
        io,
        source_path,
        patch_path,
        patch_offset,
        patch_length,
        result_path,
        .{},
    );
    var result = try fs.openRead(io, std.Io.Dir.cwd(), result_path);
    defer result.close(io);
    const actual = try allocator.alloc(u8, target_bytes.len);
    defer allocator.free(actual);
    try std.testing.expectEqual(target_bytes.len, try fs.readAllAt(io, result, actual, 0));
    try std.testing.expectEqualSlices(u8, target_bytes, actual);

    _ = target_path;
    return stats;
}

test "fixed nine-byte W26 size fields round-trip non-minimally" {
    for ([_]u64{ 0, 1, 127, 128, 300, 1 << 40, max_fixed_value }) |value| {
        var encoded: [patched_field_width]u8 = undefined;
        try packUIntFixed(&encoded, value);
        for (encoded[0 .. encoded.len - 1]) |byte|
            try std.testing.expect((byte & 0x80) != 0);
        var position: usize = 0;
        try std.testing.expectEqual(value, try core.decodeHdiffPackUInt(&encoded, &position));
        try std.testing.expectEqual(encoded.len, position);
    }
    var encoded: [patched_field_width]u8 = undefined;
    try std.testing.expectError(error.BodyTooLarge, packUIntFixed(&encoded, max_fixed_value + 1));
}

test "minimal tagged encoder covers the one-bit tag boundaries" {
    for ([_]u64{ 0, 1, 63, 64, 8191, 8192, 1 << 40 }) |value| {
        for ([_]bool{ false, true }) |negative| {
            var encoded: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
            const bytes = core.encodeUIntTagged(value, @intFromBool(negative), 1, &encoded);
            var position: usize = 0;
            const decoded = try core.decodeHdiffPackUIntWithTag(bytes, &position, 1);
            try std.testing.expectEqual(value, decoded.value);
            try std.testing.expectEqual(@intFromBool(negative), decoded.tag);
            try std.testing.expectEqual(bytes.len, position);
        }
    }
}

test "profile cost model predicts the writer rle0 encoder exactly" {
    var add: [match.collinear_gap_max_gap]u8 = undefined;
    var encoded: [match.collinear_gap_max_gap * 2 + 1]u8 = undefined;
    var decoded: [match.collinear_gap_max_gap]u8 = undefined;
    for (0..add.len + 1) |length| {
        for (add[0..length], 0..) |*byte, index| {
            byte.* = if ((index + length) % 7 == 0)
                0
            else
                @truncate(index *% 37 +% length *% 11 +% 1);
        }
        const rle = try encodeRle0(add[0..length], &encoded);
        try std.testing.expectEqual(
            try match.canonicalRle0Size(add[0..length]),
            @as(u64, @intCast(rle.len)),
        );
        if (length != 0) {
            @memset(decoded[0..length], 0);
            var decoder = core.Rle0.init(rle);
            try decoder.addTo(decoded[0..length]);
            try decoder.finish();
            try std.testing.expectEqualSlices(u8, add[0..length], decoded[0..length]);
        }
    }
}

test "stored writer handles metadata ring backward covers and zero terminator" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source_bytes = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const target_bytes = "xxABCDyy0123zz";
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "PREFIX" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const covers = [_]Cover{
        .{ .source_offset = 10, .target_offset = 2, .length = 4 },
        .{ .source_offset = 0, .target_offset = 8, .length = 4 },
    };
    const stats = try write(
        allocator,
        io,
        &covers,
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        "PREFIX".len,
        .{ .window_bound = 8, .step_bytes = 4, .meta_count = 2, .compression = .stored },
    );
    try std.testing.expect(stats.stored);
    try std.testing.expect(stats.windows >= 3);
    try std.testing.expectEqual(@as(u64, 2), stats.covers);
    try std.testing.expect(stats.serialized_covers > stats.covers);
    try std.testing.expect(stats.construction_observation.source_digest.eql(
        ids.Digest.of(source_bytes),
    ));
    try std.testing.expect(stats.construction_observation.target_digest.eql(
        ids.Digest.of(target_bytes),
    ));
    try std.testing.expectEqual(
        @as(u64, source_bytes.len),
        stats.construction_observation.source_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, target_bytes.len),
        stats.construction_observation.target_bytes,
    );
    const header = try readPatchHeader(allocator, io, patch_path, "PREFIX".len);
    defer allocator.free(header);
    const info = try w26.parse(header);
    try std.testing.expectEqualStrings("", info.compress_type);
    try std.testing.expectEqualStrings(checksum.name, info.checksum_type);
    try std.testing.expectEqual(@as(u64, checksum.byte_size), info.checksum_byte_size);
    try std.testing.expectEqual(@as(u64, 0), info.compressed_size);
    try std.testing.expectEqual(stats.uncompressed_body, info.uncompressed_size);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        "PREFIX".len,
        stats.patch_bytes,
        target_bytes,
    );
}

test "collinear ADD cover is smaller and interoperable at a nonzero offset" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const left = "0123456789abcdefghijklmnopqrstuv";
    const source_gap = "ABCDEFGHIJKLMNOP";
    const target_gap = "BBCDEFGHIJKLMNOP";
    const right = "vwxyz9876543210VWXYZ9876543210Q";
    const source_bytes = left ++ source_gap ++ right;
    const target_bytes = left ++ target_gap ++ right;
    const prefix = "nonzero-W26-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "exact.patch", .data = prefix });
    try tmp.dir.writeFile(io, .{ .sub_path = "profile.patch", .data = prefix });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const exact_path = try std.fs.path.join(allocator, &.{ root, "exact.patch" });
    defer allocator.free(exact_path);
    const profile_path = try std.fs.path.join(allocator, &.{ root, "profile.patch" });
    defer allocator.free(profile_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "profile.out" });
    defer allocator.free(result_path);

    const exact = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = left.len },
        .{
            .source_offset = left.len + source_gap.len,
            .target_offset = left.len + target_gap.len,
            .length = right.len,
        },
    };
    const merged = [_]Cover{.{
        .source_offset = 0,
        .target_offset = 0,
        .length = source_bytes.len,
    }};
    const options: Options = .{
        .window_bound = 128,
        .step_bytes = 128,
        .meta_count = 2,
        .compression = .stored,
        .io_buffer_bytes = 13,
        .expected_source_digest = ids.Digest.of(source_bytes),
        .expected_target_digest = ids.Digest.of(target_bytes),
    };
    const exact_stats = try write(
        allocator,
        io,
        &exact,
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        exact_path,
        prefix.len,
        options,
    );
    const profile_stats = try write(
        allocator,
        io,
        &merged,
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        profile_path,
        prefix.len,
        options,
    );
    try std.testing.expect(profile_stats.patch_bytes < exact_stats.patch_bytes);
    try std.testing.expect(
        profile_stats.max_retained_covered <= max_retained_step_coverage_bytes,
    );
    try std.testing.expectEqual(@as(u64, 0), profile_stats.literal_bytes);
    try std.testing.expectEqual(@as(u64, target_bytes.len), profile_stats.covered_bytes);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        profile_path,
        result_path,
        prefix.len,
        profile_stats.patch_bytes,
        target_bytes,
    );
}

test "successful-wrong ADD seam planning read is adjudicated before emission" {
    const Fault = struct {
        seam: u64,
        fired: bool = false,

        fn read(raw: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const count = try fs.readAllAt(io, file, buffer, offset);
            if (!self.fired and offset <= self.seam and self.seam - offset < count) {
                buffer[@intCast(self.seam - offset)] +%= 113;
                self.fired = true;
            }
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source_bytes = "AAAAAAAA" ++ "abcdefghijklmnop" ++ "BBBBBBBB";
    const target_bytes = "AAAAAAAA" ++ "bbcdefghijklmnop" ++ "BBBBBBBB";
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const merged = [_]Cover{.{ .source_offset = 0, .target_offset = 0, .length = source_bytes.len }};
    var fault: Fault = .{ .seam = 8 };
    const stats = try write(
        allocator,
        io,
        &merged,
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        0,
        .{
            .window_bound = 64,
            .step_bytes = 64,
            .meta_count = 2,
            .compression = .stored,
            .io_buffer_bytes = 7,
            .source_reader = .{ .context = &fault, .read_fn = Fault.read },
            .expected_source_digest = ids.Digest.of(source_bytes),
            .expected_target_digest = ids.Digest.of(target_bytes),
        },
    );
    try std.testing.expect(fault.fired);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        target_bytes,
    );
}

test "dense ADD candidate shrinks after rle capacity overflow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source_bytes: [32]u8 = @splat(0);
    var target_bytes: [32]u8 = undefined;
    for (&target_bytes, 0..) |*byte, index| byte.* = @intCast(index + 1);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = &source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = &target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const merged = [_]Cover{.{ .source_offset = 0, .target_offset = 0, .length = source_bytes.len }};
    const stats = try write(
        allocator,
        io,
        &merged,
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        0,
        .{
            .window_bound = 64,
            .step_bytes = 6,
            .meta_count = 2,
            .compression = .stored,
            .io_buffer_bytes = 11,
            .expected_source_digest = ids.Digest.of(&source_bytes),
            .expected_target_digest = ids.Digest.of(&target_bytes),
        },
    );
    try std.testing.expect(stats.serialized_covers > merged.len);
    try std.testing.expect(stats.max_step_mem <= 6);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        &target_bytes,
    );
}

test "one exact cover may split while the header retains matcher count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bytes: [128]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = &bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = &bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const covers = [_]Cover{.{ .source_offset = 0, .target_offset = 0, .length = bytes.len }};
    const stats = try write(
        allocator,
        io,
        &covers,
        source_path,
        bytes.len,
        target_path,
        bytes.len,
        patch_path,
        0,
        .{ .window_bound = bytes.len, .step_bytes = 4, .meta_count = 2, .compression = .stored },
    );
    try std.testing.expectEqual(@as(u64, 1), stats.covers);
    try std.testing.expect(stats.serialized_covers > stats.covers);
    const applied = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        &bytes,
    );
    try std.testing.expectEqual(@as(u64, 1), applied.header_cover_count);
    try std.testing.expect(applied.real_covers > applied.header_cover_count);
}

test "oversized exact cover is pre-split to the requested window bound" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes_pattern = "bounded-cover-";
    const bytes = std.mem.asBytes(&@as([8][bytes_pattern.len]u8, @splat(bytes_pattern.*)));
    const bound: u64 = 17;
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const covers = [_]Cover{.{ .source_offset = 0, .target_offset = 0, .length = bytes.len }};
    const stats = try write(
        allocator,
        io,
        &covers,
        source_path,
        bytes.len,
        target_path,
        bytes.len,
        patch_path,
        0,
        .{ .window_bound = bound, .meta_count = 2, .compression = .stored },
    );
    try std.testing.expect(stats.windows > 1);
    try std.testing.expect(stats.max_window_old <= bound);
    try std.testing.expectEqual(@as(u64, 1), stats.covers);
    try std.testing.expect(stats.serialized_covers > stats.covers);
    const applied = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        bytes,
    );
    try std.testing.expectEqual(@as(u64, 1), applied.header_cover_count);
    try std.testing.expect(applied.real_covers > applied.header_cover_count);
}

test "zstd candidate wins only when it is strictly smaller" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target_bytes_pattern = "compressible-body-";
    const target_bytes = std.mem.asBytes(&@as([8192][target_bytes_pattern.len]u8, @splat(target_bytes_pattern.*)));
    const prefix = "COMPRESSED-CONTAINER-PREFIX";
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = prefix });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const stats = try write(
        allocator,
        io,
        &.{},
        source_path,
        0,
        target_path,
        target_bytes.len,
        patch_path,
        prefix.len,
        .{ .window_bound = 4096, .meta_count = 4 },
    );
    try std.testing.expect(!stats.stored);
    try std.testing.expect(stats.compressed_body < stats.uncompressed_body);
    const header = try readPatchHeader(allocator, io, patch_path, prefix.len);
    defer allocator.free(header);
    const info = try w26.parse(header);
    try std.testing.expectEqualStrings("zstd", info.compress_type);
    try std.testing.expectEqual(stats.compressed_body, info.compressed_size);
    const container = try tmp.dir.readFileAlloc(
        io,
        "patch.bin",
        allocator,
        .limited(prefix.len + @as(usize, @intCast(stats.patch_bytes)) + 1),
    );
    defer allocator.free(container);
    try expectXxh128Checksums(container[prefix.len..], "", target_bytes);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        prefix.len,
        stats.patch_bytes,
        target_bytes,
    );
}

test "non-beneficial zstd selects canonical empty-codec stored body" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "abXd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    const stats = try write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        patch_path,
        0,
        .{ .window_bound = 4, .meta_count = 2 },
    );
    try std.testing.expect(stats.stored);
    const header = try readPatchHeader(allocator, io, patch_path, 0);
    defer allocator.free(header);
    const info = try w26.parse(header);
    try std.testing.expectEqualStrings("", info.compress_type);
    try std.testing.expectEqual(@as(u64, 0), info.compressed_size);
    const patch = try tmp.dir.readFileAlloc(io, "patch.bin", allocator, .limited(1024));
    defer allocator.free(patch);
    try expectXxh128Checksums(patch, "", "abXd");
    const body_start: usize = @intCast(info.window_data_pos);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 1, 3, 1, 0, 4, 0, 0, 'a', 'b', 'X', 'd' },
        patch[body_start..],
    );
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        "abXd",
    );
}

test "construction observation exposes successful wrong Target payload reads" {
    const Substitute = struct {
        bytes: []const u8,

        fn read(
            raw: ?*anyopaque,
            _: std.Io,
            _: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const start = std.math.cast(usize, offset) orelse return 0;
            if (start >= self.bytes.len) return 0;
            const count = @min(buffer.len, self.bytes.len - start);
            @memcpy(buffer[0..count], self.bytes[start..][0..count]);
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "GOOD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);
    var wrong: Substitute = .{ .bytes = "EVIL" };
    const stats = try write(
        allocator,
        io,
        &.{},
        source_path,
        0,
        target_path,
        4,
        patch_path,
        0,
        .{
            .window_bound = 4,
            .meta_count = 2,
            .compression = .stored,
            .reader = .{ .context = &wrong, .read_fn = Substitute.read },
        },
    );
    const observation = stats.construction_observation;
    try std.testing.expect(observation.source_digest.eql(ids.Digest.of("")));
    try std.testing.expect(observation.target_digest.eql(ids.Digest.of("EVIL")));
    try std.testing.expect(!observation.target_digest.eql(ids.Digest.of("GOOD")));
    try std.testing.expectEqual(@as(u64, 0), observation.source_bytes);
    try std.testing.expectEqual(@as(u64, 4), observation.target_bytes);
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        0,
        stats.patch_bytes,
        "EVIL",
    );
    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(5));
    defer allocator.free(target);
    try std.testing.expectEqualStrings("GOOD", target);
}

test "construction observation exposes successful wrong Source exact-cover reads" {
    const Substitute = struct {
        bytes: []const u8,

        fn read(
            raw: ?*anyopaque,
            _: std.Io,
            _: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const start = std.math.cast(usize, offset) orelse return 0;
            if (start >= self.bytes.len) return 0;
            const count = @min(buffer.len, self.bytes.len - start);
            @memcpy(buffer[0..count], self.bytes[start..][0..count]);
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "GOOD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "GOOD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = "" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);

    var wrong: Substitute = .{ .bytes = "EVIL" };
    const covers = [_]Cover{.{ .source_offset = 0, .target_offset = 0, .length = 4 }};
    const stats = try write(
        allocator,
        io,
        &covers,
        source_path,
        4,
        target_path,
        4,
        patch_path,
        0,
        .{
            .window_bound = 4,
            .meta_count = 2,
            .compression = .stored,
            .source_reader = .{ .context = &wrong, .read_fn = Substitute.read },
        },
    );
    const observation = stats.construction_observation;
    try std.testing.expect(observation.source_digest.eql(ids.Digest.of("EVIL")));
    try std.testing.expect(!observation.source_digest.eql(ids.Digest.of("GOOD")));
    try std.testing.expect(observation.target_digest.eql(ids.Digest.of("GOOD")));
    try std.testing.expectEqual(@as(u64, 4), observation.source_bytes);
    try std.testing.expectEqual(@as(u64, 4), observation.target_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.literal_bytes);
    const header = try readPatchHeader(allocator, io, patch_path, 0);
    defer allocator.free(header);
    const info = try w26.parse(header);
    const expected_old_checksum = checksum.hash("EVIL");
    try std.testing.expectEqualSlices(u8, &expected_old_checksum, info.old_checksum);
}

test "construction authority mismatches roll output back to its exact prefix" {
    const Substitute = struct {
        bytes: []const u8,

        fn read(
            raw: ?*anyopaque,
            _: std.Io,
            _: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const start = std.math.cast(usize, offset) orelse return 0;
            if (start >= self.bytes.len) return 0;
            const count = @min(buffer.len, self.bytes.len - start);
            @memcpy(buffer[0..count], self.bytes[start..][0..count]);
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const prefix = "authority-retry-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "GOOD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "GOOD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = prefix });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);

    var wrong_source: Substitute = .{ .bytes = "EVIL" };
    try std.testing.expectError(error.ConstructionSourceDigestMismatch, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        patch_path,
        prefix.len,
        .{
            .window_bound = 4,
            .meta_count = 2,
            .compression = .stored,
            .source_reader = .{ .context = &wrong_source, .read_fn = Substitute.read },
            .expected_source_digest = ids.Digest.of("GOOD"),
            .expected_target_digest = ids.Digest.of("GOOD"),
        },
    ));
    const after_source = try tmp.dir.readFileAlloc(io, "patch.bin", allocator, .limited(prefix.len + 1));
    defer allocator.free(after_source);
    try std.testing.expectEqualSlices(u8, prefix, after_source);

    var wrong_target: Substitute = .{ .bytes = "EVIL" };
    try std.testing.expectError(error.ConstructionTargetDigestMismatch, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        patch_path,
        prefix.len,
        .{
            .window_bound = 4,
            .meta_count = 2,
            .compression = .stored,
            .reader = .{ .context = &wrong_target, .read_fn = Substitute.read },
            .expected_source_digest = ids.Digest.of("GOOD"),
            .expected_target_digest = ids.Digest.of("GOOD"),
        },
    ));
    const after_target = try tmp.dir.readFileAlloc(io, "patch.bin", allocator, .limited(prefix.len + 1));
    defer allocator.free(after_target);
    try std.testing.expectEqualSlices(u8, prefix, after_target);
}

test "payload read failure rolls output back to its exact retry prefix" {
    const Fault = struct {
        calls: usize = 0,

        fn read(
            raw: ?*anyopaque,
            _: std.Io,
            _: std.Io.File,
            _: []u8,
            _: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.calls += 1;
            return error.InjectedPayloadRead;
        }
    };
    const MutateSource = struct {
        path: []const u8,
        fired: bool = false,

        fn read(
            raw: ?*anyopaque,
            io: std.Io,
            target: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            if (!self.fired) {
                var source = try fs.openReadWrite(io, std.Io.Dir.cwd(), self.path);
                defer source.close(io);
                try source.setLength(io, 0);
                self.fired = true;
            }
            return fs.readAllAt(io, target, buffer, offset);
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const prefix = "retry-prefix-must-survive";
    const source_bytes = "source-size-must-stay-stable";
    const target_bytes_pattern = "literal-only-retry-target";
    const target_bytes = std.mem.asBytes(&@as([64][target_bytes_pattern.len]u8, @splat(target_bytes_pattern.*)));
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch.bin", .data = prefix });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch.bin" });
    defer allocator.free(patch_path);
    const result_path = try std.fs.path.join(allocator, &.{ root, "result.bin" });
    defer allocator.free(result_path);

    var source_fault: Fault = .{};
    try std.testing.expectError(error.InjectedPayloadRead, write(
        allocator,
        io,
        &.{},
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        prefix.len,
        .{
            .window_bound = 128,
            .meta_count = 2,
            .compression = .stored,
            .source_reader = .{ .context = &source_fault, .read_fn = Fault.read },
        },
    ));
    try std.testing.expectEqual(@as(usize, 1), source_fault.calls);
    const source_read_rollback = try tmp.dir.readFileAlloc(
        io,
        "patch.bin",
        allocator,
        .limited(prefix.len + 1),
    );
    defer allocator.free(source_read_rollback);
    try std.testing.expectEqualSlices(u8, prefix, source_read_rollback);

    var fault: Fault = .{};
    try std.testing.expectError(error.InjectedPayloadRead, write(
        allocator,
        io,
        &.{},
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        prefix.len,
        .{
            .window_bound = 128,
            .meta_count = 2,
            .compression = .stored,
            .reader = .{ .context = &fault, .read_fn = Fault.read },
        },
    ));
    try std.testing.expectEqual(@as(usize, 1), fault.calls);
    const rolled_back = try tmp.dir.readFileAlloc(io, "patch.bin", allocator, .limited(prefix.len + 1));
    defer allocator.free(rolled_back);
    try std.testing.expectEqualSlices(u8, prefix, rolled_back);

    var mutation: MutateSource = .{ .path = source_path };
    try std.testing.expectError(error.SourceSizeChanged, write(
        allocator,
        io,
        &.{},
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        prefix.len,
        .{
            .window_bound = 128,
            .meta_count = 2,
            .compression = .stored,
            .reader = .{ .context = &mutation, .read_fn = MutateSource.read },
        },
    ));
    try std.testing.expect(mutation.fired);
    const source_rollback = try tmp.dir.readFileAlloc(io, "patch.bin", allocator, .limited(prefix.len + 1));
    defer allocator.free(source_rollback);
    try std.testing.expectEqualSlices(u8, prefix, source_rollback);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });

    const stats = try write(
        allocator,
        io,
        &.{},
        source_path,
        source_bytes.len,
        target_path,
        target_bytes.len,
        patch_path,
        prefix.len,
        .{
            .window_bound = 128,
            .meta_count = 2,
            .compression = .stored,
        },
    );
    _ = try expectRoundTrip(
        allocator,
        io,
        source_path,
        target_path,
        patch_path,
        result_path,
        prefix.len,
        stats.patch_bytes,
        target_bytes,
    );
}

test "direct Target and Source output aliases are refused before mutation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "same" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    try std.testing.expectError(error.TargetOutputAlias, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        target_path,
        4,
        .{ .compression = .stored },
    ));
    try std.testing.expectError(error.SourceOutputAlias, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        source_path,
        4,
        .{ .compression = .stored },
    ));
    var unchanged = try fs.openRead(io, std.Io.Dir.cwd(), target_path);
    defer unchanged.close(io);
    var bytes: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try fs.readAllAt(io, unchanged, &bytes, 0));
    try std.testing.expectEqualStrings("same", &bytes);
}

test "Windows hard-link aliases of either input are refused before mutation" {
    if (@import("builtin").target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "source" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "target" });
    try fs.hardLinkInTmp(allocator, &tmp, "target.bin", "target-link.bin");
    try fs.hardLinkInTmp(allocator, &tmp, "source.bin", "source-link.bin");
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const target_link = try std.fs.path.join(allocator, &.{ root, "target-link.bin" });
    defer allocator.free(target_link);
    const source_link = try std.fs.path.join(allocator, &.{ root, "source-link.bin" });
    defer allocator.free(source_link);
    try std.testing.expectError(error.TargetOutputAlias, write(
        allocator,
        io,
        &.{},
        source_path,
        6,
        target_path,
        6,
        target_link,
        6,
        .{ .compression = .stored },
    ));
    try std.testing.expectError(error.SourceOutputAlias, write(
        allocator,
        io,
        &.{},
        source_path,
        6,
        target_path,
        6,
        source_link,
        6,
        .{ .compression = .stored },
    ));
}

test "invalid options and cover endpoints fail before output mutation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "output.bin", .data = "sentinel" });
    const root = try absoluteTmpPath(allocator, &tmp, "");
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const output_path = try std.fs.path.join(allocator, &.{ root, "output.bin" });
    defer allocator.free(output_path);
    try std.testing.expectError(error.InvalidMetaCount, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        output_path,
        8,
        .{ .meta_count = 3 },
    ));
    try std.testing.expectError(error.InvalidMetaCount, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        output_path,
        8,
        .{ .meta_count = 128 },
    ));
    try std.testing.expectError(error.InvalidBufferSize, write(
        allocator,
        io,
        &.{},
        source_path,
        4,
        target_path,
        4,
        output_path,
        8,
        .{ .io_buffer_bytes = max_io_buffer_bytes + 1 },
    ));
    const huge: u64 = 1 << 40;
    try std.testing.expectError(error.TooManyWindows, write(
        allocator,
        io,
        &.{.{ .source_offset = 0, .target_offset = 0, .length = huge }},
        source_path,
        huge,
        target_path,
        huge,
        output_path,
        8,
        .{ .window_bound = 1, .compression = .stored },
    ));
    try std.testing.expectError(error.TargetOutOfRange, write(
        allocator,
        io,
        &.{.{ .source_offset = 0, .target_offset = 3, .length = 2 }},
        source_path,
        4,
        target_path,
        4,
        output_path,
        8,
        .{},
    ));
    var output = try fs.openRead(io, std.Io.Dir.cwd(), output_path);
    defer output.close(io);
    var bytes: [8]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try fs.readAllAt(io, output, &bytes, 0));
    try std.testing.expectEqualStrings("sentinel", &bytes);
}

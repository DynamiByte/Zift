// HDIFFW26 apply; bounded windows and step buffers

const std = @import("std");
const core = @import("../encoding.zig");
const w26 = @import("../w26.zig");
const checksum = @import("../w26.zig").Checksum;
const clip = @import("../../compression/decoder.zig");
const fs = @import("../../core/fs.zig");
const scan = @import("../../core/scan.zig");

pub const max_step_bytes: usize = 4 * 1024 * 1024;
pub const max_source_window_bytes: usize = 256 * 1024 * 1024;
pub const max_zstd_window_bytes: u64 = 256 * 1024 * 1024;
pub const work_buffer_bytes: usize = 128 * 1024;

pub const Error = core.Error || w26.Error || clip.Error || error{
    CallbackCancelled,
    ChecksumMismatch,
    CoverCountDisagrees,
    CoverCountExhausted,
    InvalidReadCount,
    PatchRangeOutOfBounds,
    SourceReadFailed,
    SourceSizeMismatch,
    StepTooLarge,
    SubCoverCountTooLarge,
    UnsafeTargetAlias,
    UnsupportedChecksum,
    UnsupportedCompression,
    WindowOutOfRange,
    WindowTooLarge,
    WriteFailed,
    ZeroLengthCoverNotLast,
};

pub const OutputHook = @import("../hooks.zig").OutputHook;
pub const ProgressHook = @import("../hooks.zig").ProgressHook;

pub const Options = struct {
    reader: scan.Reader = .direct,
    output: ?OutputHook = null,
    progress: ?ProgressHook = null,
};

pub const Stats = struct {
    windows: u64 = 0,
    // including zero-length trailing-literal covers
    decoded_covers: u64 = 0,
    // positive wire covers, including split fragments beyond original count
    real_covers: u64 = 0,
    header_cover_count: u64 = 0,
    steps: u64 = 0,
    literal_bytes: u64 = 0,
    covered_bytes: u64 = 0,
    source_reads: u64 = 0,
    peak_step_bytes: usize = 0,
    peak_window_bytes: usize = 0,
};

const WindowMeta = struct {
    old_pos: u64 = 0,
    len: u64 = 0,
};

const ShortRead = enum {
    header,
    source,
};

// disposable partial output on failure after target creation
pub fn apply(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    container_path: []const u8,
    patch_offset: u64,
    patch_length: u64,
    target_path: []const u8,
    options: Options,
) !Stats {
    return applyTarget(
        allocator,
        io,
        source_path,
        container_path,
        patch_offset,
        patch_length,
        .{ .path = target_path },
        options,
    );
}

// empty caller-owned staging required
pub fn applyToFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    container_path: []const u8,
    patch_offset: u64,
    patch_length: u64,
    target: std.Io.File,
    options: Options,
) !Stats {
    return applyTarget(
        allocator,
        io,
        source_path,
        container_path,
        patch_offset,
        patch_length,
        .{ .file = target },
        options,
    );
}

// caller-owned handles
pub fn applyFilesToFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: std.Io.File,
    container: std.Io.File,
    patch_offset: u64,
    patch_length: u64,
    target: std.Io.File,
    options: Options,
) !Stats {
    return applyContainerTarget(
        allocator,
        io,
        .{ .file = source },
        container,
        patch_offset,
        patch_length,
        .{ .file = target },
        options,
    );
}

pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    container_path: []const u8,
    patch_offset: u64,
    patch_length: u64,
    options: Options,
) !Stats {
    if (options.output == null) return Error.WriteFailed;
    return applyTarget(
        allocator,
        io,
        source_path,
        container_path,
        patch_offset,
        patch_length,
        .discard,
        options,
    );
}

const Source = union(enum) {
    path: []const u8,
    file: std.Io.File,
};

const Target = union(enum) {
    path: []const u8,
    file: std.Io.File,
    discard,
};

fn applyTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    container_path: []const u8,
    patch_offset: u64,
    patch_length: u64,
    destination: Target,
    options: Options,
) !Stats {
    var container = fs.openRead(io, std.Io.Dir.cwd(), container_path) catch
        return Error.SourceReadFailed;
    defer container.close(io);

    return applyContainerTarget(
        allocator,
        io,
        .{ .path = source_path },
        container,
        patch_offset,
        patch_length,
        destination,
        options,
    );
}

fn applyContainerTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_input: Source,
    container: std.Io.File,
    patch_offset: u64,
    patch_length: u64,
    destination: Target,
    options: Options,
) !Stats {
    const container_size = container.length(io) catch return Error.SourceReadFailed;
    const patch_end = std.math.add(u64, patch_offset, patch_length) catch
        return Error.PatchRangeOutOfBounds;
    if (patch_end > container_size) return Error.PatchRangeOutOfBounds;

    var header_storage: [w26.max_head_size]u8 = undefined;
    const header = try readHeaderExact(
        io,
        container,
        patch_offset,
        patch_length,
        options.reader,
        &header_storage,
    );
    const info = try w26.parse(header);
    try w26.validatePatchExtent(info, patch_length);

    // zstd name valid for stored bytes; no implicit support for other codecs
    if (info.compress_type.len != 0 and
        !std.mem.eql(u8, info.compress_type, "zstd"))
        return Error.UnsupportedCompression;
    if (info.compressed_size != 0 and info.compress_type.len == 0)
        return Error.UnsupportedCompression;

    const checksummed = info.checksum_type.len != 0;
    if (checksummed) {
        if (!std.mem.eql(u8, info.checksum_type, checksum.name) or
            info.checksum_byte_size != checksum.byte_size or
            info.old_checksum.len != checksum.byte_size or
            info.new_checksum.len != checksum.byte_size or
            info.diff_checksum.len != checksum.byte_size)
            return Error.UnsupportedChecksum;
    } else if (info.checksum_byte_size != 0 or info.old_checksum.len != 0 or
        info.new_checksum.len != 0 or info.diff_checksum.len != 0)
    {
        return Error.UnsupportedChecksum;
    }

    // at least one target byte per original cover
    if (info.cover_count > info.new_size) return Error.CoverCountDisagrees;

    const step_capacity = core.checkedU64ToUsize(info.max_step_mem) catch
        return Error.StepTooLarge;
    if (step_capacity > max_step_bytes) return Error.StepTooLarge;
    const window_capacity = core.checkedU64ToUsize(info.max_window_old) catch
        return Error.WindowTooLarge;
    if (window_capacity > max_source_window_bytes) return Error.WindowTooLarge;

    const meta_count = core.checkedU64ToUsize(info.window_meta_count) catch
        return w26.Error.HeaderInconsistent;
    if (meta_count < 2 or meta_count > w26.max_window_meta_count or
        (meta_count & (meta_count - 1)) != 0)
        return w26.Error.HeaderInconsistent;

    var owned_source: ?std.Io.File = null;
    const source = switch (source_input) {
        .path => |source_path| blk: {
            const opened = fs.openRead(io, std.Io.Dir.cwd(), source_path) catch
                return Error.SourceReadFailed;
            owned_source = opened;
            break :blk opened;
        },
        .file => |file| file,
    };
    defer if (owned_source) |file| file.close(io);
    const real_source_size = source.length(io) catch return Error.SourceReadFailed;
    if (real_source_size != info.old_size) return Error.SourceSizeMismatch;

    const body_offset = std.math.add(u64, patch_offset, info.window_data_pos) catch
        return Error.PatchRangeOutOfBounds;
    var body = try clip.Decoder.init(
        allocator,
        io,
        container,
        body_offset,
        info.compressed_size,
        info.uncompressed_size,
        .{ .max_window_bytes = max_zstd_window_bytes, .reader = options.reader },
    );
    defer body.deinit();

    // zero wire limits still need nonempty decoder buffers
    const step_storage = try allocator.alloc(u8, @max(step_capacity, 1));
    defer allocator.free(step_storage);
    const window_storage = try allocator.alloc(u8, @max(window_capacity, 1));
    defer allocator.free(window_storage);
    const work = try allocator.alloc(u8, work_buffer_bytes);
    defer allocator.free(work);
    const metas = try allocator.alloc(WindowMeta, meta_count);
    defer allocator.free(metas);
    @memset(metas, .{});

    // W26 diff checksum: stored body, then header through new checksum
    if (checksummed) {
        try verifyDiffChecksum(
            io,
            container,
            patch_offset,
            header,
            info,
            options.reader,
            work,
        );
    }

    var old_hasher: ?checksum.Hasher = if (checksummed)
        checksum.Hasher{}
    else
        null;
    var new_hasher: ?checksum.Hasher = if (checksummed)
        checksum.Hasher{}
    else
        null;

    try body.skip(info.extra_data_size);

    var owned_target: ?std.Io.File = null;
    const guarded = destination == .file;
    const target: ?std.Io.File = switch (destination) {
        .path => |target_path| blk: {
            const opened = fs.openOrCreateReadWrite(io, std.Io.Dir.cwd(), target_path) catch
                return Error.WriteFailed;
            owned_target = opened;
            break :blk opened;
        },
        .file => |file| file,
        .discard => null,
    };
    defer if (owned_target) |file| file.close(io);
    if (target) |file| {
        if ((fs.sameOpenFile(io, file, source) catch return Error.WriteFailed) or
            (fs.sameOpenFile(io, file, container) catch return Error.WriteFailed))
            return Error.UnsafeTargetAlias;
        if (guarded) {
            fs.validateGuardedOutput(io, file, 0) catch return Error.WriteFailed;
        } else {
            file.setLength(io, 0) catch return Error.WriteFailed;
        }
    }

    var stats: Stats = .{
        .header_cover_count = info.cover_count,
    };
    var meta_last_old_end: u64 = 0;
    var loaded_meta_end: u64 = 0;
    var output_pos: u64 = 0;

    var window_index: u64 = 0;
    while (window_index < info.window_count) : (window_index += 1) {
        const half_meta: u64 = @intCast(meta_count >> 1);
        if ((window_index & (half_meta - 1)) == 0 and
            loaded_meta_end < info.window_count)
        {
            const saved: u64 = if (window_index == 0)
                @intCast(meta_count)
            else
                half_meta;
            const batch = @min(info.window_count - loaded_meta_end, saved);
            const write_index: usize = @intCast(loaded_meta_end & @as(u64, @intCast(meta_count - 1)));
            try readMetaBatch(
                &body,
                &meta_last_old_end,
                info.max_window_old,
                real_source_size,
                metas,
                write_index,
                @intCast(batch),
            );
            loaded_meta_end = try core.checkedAddU64(loaded_meta_end, batch);
        }

        var sub_covers = try core.readUInt(&body);
        if (sub_covers > info.max_sub_cover_count)
            return Error.SubCoverCountTooLarge;

        const meta_index: usize = @intCast(window_index & @as(u64, @intCast(meta_count - 1)));
        const meta = metas[meta_index];
        if (meta.len > info.max_window_old or meta.len > window_capacity)
            return Error.WindowTooLarge;
        if (meta.old_pos > real_source_size or
            meta.len > real_source_size - meta.old_pos)
            return Error.WindowOutOfRange;

        const window_len: usize = @intCast(meta.len);
        const source_calls = try readExactAt(
            io,
            source,
            window_storage[0..window_len],
            meta.old_pos,
            options.reader,
            .source,
        );
        stats.source_reads = try core.checkedAddU64(stats.source_reads, source_calls);
        stats.peak_window_bytes = @max(stats.peak_window_bytes, window_len);
        const window = window_storage[0..window_len];
        if (old_hasher) |*hasher| hasher.update(window);

        // coordinates carried across steps, reset per window
        var last_old_end: u64 = 0;
        var last_new_end: u64 = 0;
        const window_output_base = output_pos;

        while (sub_covers != 0) {
            const cover_bytes_u64 = try core.readUInt(&body);
            const rle_bytes_u64 = try core.readUInt(&body);
            const cover_bytes = core.checkedU64ToUsize(cover_bytes_u64) catch
                return Error.StepTooLarge;
            const rle_bytes = core.checkedU64ToUsize(rle_bytes_u64) catch
                return Error.StepTooLarge;
            if (cover_bytes > step_capacity or rle_bytes > step_capacity or
                rle_bytes > step_capacity - cover_bytes)
                return Error.StepTooLarge;
            const step_len = cover_bytes + rle_bytes;
            try body.readInto(step_storage[0..step_len]);
            stats.steps = try core.checkedAddU64(stats.steps, 1);
            stats.peak_step_bytes = @max(stats.peak_step_bytes, step_len);

            var covers = core.CoverReader.init(
                step_storage[0..cover_bytes],
                last_old_end,
                last_new_end,
            );
            var rle = core.Rle0.init(step_storage[cover_bytes..step_len]);
            var step_covered: u64 = 0;

            while (!covers.atEnd()) {
                if (sub_covers == 0) return Error.CoverCountExhausted;
                const cover = try covers.next();

                const wanted_output = std.math.add(
                    u64,
                    window_output_base,
                    cover.new_pos,
                ) catch return core.Error.TargetOverflow;
                if (wanted_output < output_pos) return core.Error.TargetUnderflow;
                if (wanted_output > info.new_size) return core.Error.TargetOverflow;
                var literal_left = wanted_output - output_pos;
                while (literal_left != 0) {
                    const take: usize = @intCast(@min(@as(u64, work.len), literal_left));
                    try body.readInto(work[0..take]);
                    try emit(target, io, output_pos, work[0..take], options, if (new_hasher) |*hasher| hasher else null);
                    output_pos = try core.checkedAddU64(output_pos, take);
                    stats.literal_bytes = try core.checkedAddU64(stats.literal_bytes, take);
                    literal_left -= take;
                }

                sub_covers -= 1;
                if (cover.length == 0) {
                    if (sub_covers != 0) return Error.ZeroLengthCoverNotLast;
                } else {
                    if (cover.old_pos > meta.len or
                        cover.length > meta.len - cover.old_pos)
                        return core.Error.CoverOutOfRange;
                    if (output_pos > info.new_size or
                        cover.length > info.new_size - output_pos)
                        return core.Error.TargetOverflow;

                    var source_left = cover.length;
                    var window_pos = core.checkedU64ToUsize(cover.old_pos) catch
                        return core.Error.CoverOutOfRange;
                    while (source_left != 0) {
                        const take: usize = @intCast(@min(@as(u64, work.len), source_left));
                        @memcpy(work[0..take], window[window_pos..][0..take]);
                        try rle.addTo(work[0..take]);
                        try emit(target, io, output_pos, work[0..take], options, if (new_hasher) |*hasher| hasher else null);
                        output_pos = try core.checkedAddU64(output_pos, take);
                        stats.covered_bytes = try core.checkedAddU64(stats.covered_bytes, take);
                        window_pos += take;
                        source_left -= take;
                    }
                    stats.real_covers = try core.checkedAddU64(stats.real_covers, 1);
                    step_covered = try core.checkedAddU64(step_covered, cover.length);
                }
                stats.decoded_covers = try core.checkedAddU64(stats.decoded_covers, 1);
            }

            // upstream literal-only terminator: one unused zero run
            // otherwise exact RLE exhaustion per step
            try finishStepRle(&rle, step_covered);
            last_old_end = covers.last_old_end;
            last_new_end = covers.last_new_end;
        }

        stats.windows = try core.checkedAddU64(stats.windows, 1);
    }

    if (output_pos != info.new_size) return core.Error.TargetUnderflow;
    // original cover count: lower bound after splitting
    if (stats.real_covers < info.cover_count) return Error.CoverCountDisagrees;

    try body.finish();

    if (old_hasher) |*hasher| {
        const actual = hasher.final();
        if (!std.mem.eql(u8, &actual, info.old_checksum))
            return Error.ChecksumMismatch;
    }
    if (new_hasher) |*hasher| {
        const actual = hasher.final();
        if (!std.mem.eql(u8, &actual, info.new_checksum))
            return Error.ChecksumMismatch;
    }

    if (target) |file| {
        if (guarded) {
            fs.validateGuardedOutput(io, file, info.new_size) catch return Error.WriteFailed;
        } else {
            file.setLength(io, info.new_size) catch return Error.WriteFailed;
        }
        file.sync(io) catch return Error.WriteFailed;
    }
    return stats;
}

fn finishStepRle(rle: *const core.Rle0, covered: u64) !void {
    if (rle.atEnd()) return;
    if (covered != 0 or rle.pos != 0 or rle.zero_remaining != 0 or
        rle.value_remaining != 0 or !rle.next_is_zero)
        return core.Error.RleOverrun;

    var position: usize = 0;
    const length = core.decodeHdiffPackUInt(rle.code, &position) catch |err| switch (err) {
        core.Error.Truncated => return core.Error.RleOverrun,
        else => |e| return e,
    };
    if (length != 0 or position != rle.code.len) return core.Error.RleOverrun;
}

fn readHeaderExact(
    io: std.Io,
    file: std.Io.File,
    patch_offset: u64,
    patch_length: u64,
    reader: scan.Reader,
    storage: *[w26.max_head_size]u8,
) ![]const u8 {
    if (patch_length < w26.head_prefix_size) return w26.Error.Truncated;
    _ = try readExactAt(
        io,
        file,
        storage[0..w26.head_prefix_size],
        patch_offset,
        reader,
        .header,
    );
    if (!std.mem.eql(u8, storage[0..w26.magic.len], w26.magic))
        return w26.Error.NotW26;

    const remaining = @as(usize, storage[w26.magic.len]) |
        (@as(usize, storage[w26.magic.len + 1]) << 8);
    const header_len = std.math.add(usize, w26.head_prefix_size, remaining) catch
        return w26.Error.HeaderTooLarge;
    if (header_len > storage.len) return w26.Error.HeaderTooLarge;
    if (@as(u64, header_len) > patch_length) return w26.Error.Truncated;

    const rest_offset = std.math.add(u64, patch_offset, w26.head_prefix_size) catch
        return Error.PatchRangeOutOfBounds;
    _ = try readExactAt(
        io,
        file,
        storage[w26.head_prefix_size..header_len],
        rest_offset,
        reader,
        .header,
    );
    return storage[0..header_len];
}

fn readExactAt(
    io: std.Io,
    file: std.Io.File,
    destination: []u8,
    offset: u64,
    reader: scan.Reader,
    short_read: ShortRead,
) !u64 {
    var done: usize = 0;
    var calls: u64 = 0;
    while (done != destination.len) {
        const current_offset = std.math.add(u64, offset, done) catch
            return Error.PatchRangeOutOfBounds;
        const count = try reader.read(io, file, destination[done..], current_offset);
        calls = try core.checkedAddU64(calls, 1);
        if (count > destination.len - done) return Error.InvalidReadCount;
        if (count == 0) return switch (short_read) {
            .header => w26.Error.Truncated,
            .source => Error.SourceReadFailed,
        };
        done += count;
    }
    return calls;
}

fn readMetaBatch(
    body: *clip.Decoder,
    last_old_end: *u64,
    max_window_old: u64,
    source_size: u64,
    metas: []WindowMeta,
    write_index: usize,
    batch: usize,
) !void {
    var candidate_last = last_old_end.*;
    for (0..batch) |index| {
        const len = try core.readUInt(body);
        var sign: u8 = 0;
        const delta = try core.readUIntTagged(body, 1, &sign);
        const old_pos = if (sign == 0)
            std.math.add(u64, candidate_last, delta) catch
                return Error.WindowOutOfRange
        else blk: {
            if (delta > candidate_last) return Error.WindowOutOfRange;
            break :blk candidate_last - delta;
        };
        if (len > max_window_old) return Error.WindowTooLarge;
        if (old_pos > source_size or len > source_size - old_pos)
            return Error.WindowOutOfRange;
        const old_end = std.math.add(u64, old_pos, len) catch
            return Error.WindowOutOfRange;

        metas[(write_index + index) % metas.len] = .{
            .old_pos = old_pos,
            .len = len,
        };
        candidate_last = old_end;
    }
    last_old_end.* = candidate_last;
}

fn emit(
    target: ?std.Io.File,
    io: std.Io,
    offset: u64,
    bytes: []const u8,
    options: Options,
    new_hasher: ?*checksum.Hasher,
) !void {
    if (target) |file|
        file.writePositionalAll(io, bytes, offset) catch return Error.WriteFailed;
    if (new_hasher) |hasher| hasher.update(bytes);
    if (options.output) |hook| {
        if (!try hook.call(offset, bytes)) return Error.CallbackCancelled;
    }
    if (options.progress) |hook| {
        if (!try hook.call(bytes.len)) return Error.CallbackCancelled;
    }
}

fn verifyDiffChecksum(
    io: std.Io,
    container: std.Io.File,
    patch_offset: u64,
    header: []const u8,
    info: w26.Info,
    reader: scan.Reader,
    buffer: []u8,
) !void {
    if (buffer.len == 0 or info.diff_checksum.len != checksum.byte_size)
        return Error.UnsupportedChecksum;
    var hasher = checksum.Hasher{};

    const body_offset = std.math.add(u64, patch_offset, info.window_data_pos) catch
        return Error.PatchRangeOutOfBounds;
    var consumed: u64 = 0;
    const stored_size = info.storedBodySize();
    while (consumed != stored_size) {
        const take: usize = @intCast(@min(@as(u64, buffer.len), stored_size - consumed));
        const offset = std.math.add(u64, body_offset, consumed) catch
            return Error.PatchRangeOutOfBounds;
        _ = try readExactAt(
            io,
            container,
            buffer[0..take],
            offset,
            reader,
            .header,
        );
        hasher.update(buffer[0..take]);
        consumed = try core.checkedAddU64(consumed, take);
    }

    if (header.len < checksum.byte_size) return Error.UnsupportedChecksum;
    hasher.update(header[0 .. header.len - checksum.byte_size]);
    const actual = hasher.final();
    if (!std.mem.eql(u8, &actual, info.diff_checksum))
        return Error.ChecksumMismatch;
}

// tests

const TestCover = struct {
    old_pos: u64,
    new_pos: u64,
    length: u64,
};

const TestStep = struct {
    covers: []const TestCover,
    // null = all-zero ADD stream
    rle: ?[]const u8 = null,
    literals: []const u8 = "",
    declared_cover_bytes: ?u64 = null,
    declared_rle_bytes: ?u64 = null,
};

const TestWindow = struct {
    old_pos: u64,
    old_len: u64,
    steps: []const TestStep,
    sub_cover_count: ?u64 = null,
};

const PatchOptions = struct {
    meta_count: u64 = 2,
    extra_data: []const u8 = "",
    body_tail: []const u8 = "",
    compress: bool = false,
    compress_type: ?[]const u8 = null,
    checksum_type: []const u8 = "",
    checksum_size: usize = 0,
    other_info: []const u8 = "",
    header_cover_count: ?u64 = null,
    header_old_size: ?u64 = null,
    header_new_size: ?u64 = null,
    max_step_mem: ?u64 = null,
    max_sub_cover_count: ?u64 = null,
    max_window_old: ?u64 = null,
};

const BodyStats = struct {
    real_covers: u64 = 0,
    max_step: u64 = 0,
    max_sub_covers: u64 = 0,
    max_window_old: u64 = 0,
};

fn appendPackUInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u64,
) !void {
    var reversed: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    var count: usize = 0;
    var remaining = value;
    while (true) {
        reversed[count] = @intCast(remaining & 0x7f);
        count += 1;
        remaining >>= 7;
        if (remaining == 0) break;
    }
    var index = count;
    while (index != 0) {
        index -= 1;
        var byte = reversed[index];
        if (index != 0) byte |= 0x80;
        try out.append(allocator, byte);
    }
}

fn appendPackUIntSign(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u64,
    negative: bool,
) !void {
    const bits: usize = if (value == 0) 0 else 64 - @clz(value);
    const count: usize = if (bits <= 6) 1 else 1 + (bits - 6 + 6) / 7;
    var encoded: [core.max_hdiff_pack_uint_bytes]u8 = @splat(0);
    var remaining = value;
    var index = count;
    while (index > 1) {
        index -= 1;
        encoded[index] = @intCast(remaining & 0x7f);
        remaining >>= 7;
    }
    encoded[0] = @intCast(remaining);
    if (negative) encoded[0] |= 0x80;
    if (count > 1) {
        encoded[0] |= 0x40;
        for (encoded[1 .. count - 1]) |*byte| byte.* |= 0x80;
    }
    try out.appendSlice(allocator, encoded[0..count]);
}

fn appendMeta(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    window: TestWindow,
    last_old_end: *u64,
) !void {
    try appendPackUInt(out, allocator, window.old_len);
    if (window.old_pos >= last_old_end.*) {
        try appendPackUIntSign(out, allocator, window.old_pos - last_old_end.*, false);
    } else {
        try appendPackUIntSign(out, allocator, last_old_end.* - window.old_pos, true);
    }
    last_old_end.* = try core.checkedAddU64(window.old_pos, window.old_len);
}

fn appendWindowData(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    window: TestWindow,
    stats: *BodyStats,
) !void {
    var actual_sub_covers: u64 = 0;
    for (window.steps) |step| {
        actual_sub_covers = try core.checkedAddU64(actual_sub_covers, step.covers.len);
        for (step.covers) |cover| {
            if (cover.length != 0)
                stats.real_covers = try core.checkedAddU64(stats.real_covers, 1);
        }
    }
    const declared_sub_covers = window.sub_cover_count orelse actual_sub_covers;
    try appendPackUInt(out, allocator, declared_sub_covers);
    stats.max_sub_covers = @max(stats.max_sub_covers, declared_sub_covers);
    stats.max_window_old = @max(stats.max_window_old, window.old_len);

    var last_old_end: u64 = 0;
    var last_new_end: u64 = 0;
    for (window.steps) |step| {
        var cover_data: std.ArrayList(u8) = .empty;
        defer cover_data.deinit(allocator);
        var total_covered: u64 = 0;
        for (step.covers) |cover| {
            if (cover.old_pos >= last_old_end) {
                try appendPackUIntSign(&cover_data, allocator, cover.old_pos - last_old_end, false);
            } else {
                try appendPackUIntSign(&cover_data, allocator, last_old_end - cover.old_pos, true);
            }
            if (cover.new_pos < last_new_end) return error.TestCoversNotOrdered;
            try appendPackUInt(&cover_data, allocator, cover.new_pos - last_new_end);
            try appendPackUInt(&cover_data, allocator, cover.length);
            last_old_end = try core.checkedAddU64(cover.old_pos, cover.length);
            last_new_end = try core.checkedAddU64(cover.new_pos, cover.length);
            total_covered = try core.checkedAddU64(total_covered, cover.length);
        }

        var rle_data: std.ArrayList(u8) = .empty;
        defer rle_data.deinit(allocator);
        if (step.rle) |encoded| {
            try rle_data.appendSlice(allocator, encoded);
        } else {
            // upstream zero run, including literal-only terminator
            try appendPackUInt(&rle_data, allocator, total_covered);
        }

        try appendPackUInt(
            out,
            allocator,
            step.declared_cover_bytes orelse cover_data.items.len,
        );
        try appendPackUInt(
            out,
            allocator,
            step.declared_rle_bytes orelse rle_data.items.len,
        );
        try out.appendSlice(allocator, cover_data.items);
        try out.appendSlice(allocator, rle_data.items);
        try out.appendSlice(allocator, step.literals);
        stats.max_step = @max(
            stats.max_step,
            try core.checkedAddU64(cover_data.items.len, rle_data.items.len),
        );
    }
}

fn buildBody(
    allocator: std.mem.Allocator,
    windows: []const TestWindow,
    options: PatchOptions,
    stats: *BodyStats,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, options.extra_data);

    const meta_count = try core.checkedU64ToUsize(options.meta_count);
    if (meta_count < 2 or (meta_count & (meta_count - 1)) != 0)
        return error.TestBadMetaCount;
    const half = meta_count >> 1;
    var loaded: usize = 0;
    var last_meta_old_end: u64 = 0;
    for (windows, 0..) |window, window_index| {
        if ((window_index & (half - 1)) == 0 and loaded < windows.len) {
            const saved = if (window_index == 0) meta_count else half;
            const batch = @min(windows.len - loaded, saved);
            for (windows[loaded..][0..batch]) |meta_window|
                try appendMeta(&out, allocator, meta_window, &last_meta_old_end);
            loaded += batch;
        }
        try appendWindowData(&out, allocator, window, stats);
    }
    try out.appendSlice(allocator, options.body_tail);
    return out.toOwnedSlice(allocator);
}

fn buildPatch(
    allocator: std.mem.Allocator,
    source_size: u64,
    new_size: u64,
    windows: []const TestWindow,
    options: PatchOptions,
) ![]u8 {
    var stats: BodyStats = .{};
    const raw_body = try buildBody(allocator, windows, options, &stats);
    defer allocator.free(raw_body);
    const stored_body = if (options.compress)
        try @import("../../compression/frame.zig").compressAlloc(allocator, raw_body, 5)
    else
        try allocator.dupe(u8, raw_body);
    defer allocator.free(stored_body);
    if (options.compress and stored_body.len > raw_body.len)
        return error.TestCompressionNotSmaller;

    const compression_name = options.compress_type orelse
        (if (options.compress) "zstd" else "");
    var region: std.ArrayList(u8) = .empty;
    defer region.deinit(allocator);
    try region.appendSlice(allocator, compression_name);
    try region.append(allocator, '&');
    try region.appendSlice(allocator, options.checksum_type);
    try region.append(allocator, 0);

    for ([_]u64{
        if (options.compress) stored_body.len else 0,
        raw_body.len,
        options.header_new_size orelse new_size,
        options.header_old_size orelse source_size,
        options.header_cover_count orelse stats.real_covers,
        windows.len,
        options.meta_count,
        options.max_step_mem orelse stats.max_step,
        options.max_sub_cover_count orelse stats.max_sub_covers,
        options.max_window_old orelse stats.max_window_old,
        options.checksum_size,
        options.extra_data.len,
    }) |field| try appendPackUInt(&region, allocator, field);
    try region.appendSlice(allocator, options.other_info);
    try region.appendNTimes(allocator, 0x11, options.checksum_size);
    try region.appendNTimes(allocator, 0x22, options.checksum_size);
    try region.appendNTimes(allocator, 0x33, options.checksum_size);
    if (region.items.len > std.math.maxInt(u16)) return error.TestHeaderTooLarge;

    var patch: std.ArrayList(u8) = .empty;
    errdefer patch.deinit(allocator);
    try patch.appendSlice(allocator, w26.magic);
    try patch.append(allocator, @intCast(region.items.len & 0xff));
    try patch.append(allocator, @intCast(region.items.len >> 8));
    try patch.appendSlice(allocator, region.items);
    try patch.appendSlice(allocator, stored_body);
    return patch.toOwnedSlice(allocator);
}

fn hashParts(parts: []const []const u8) ![checksum.byte_size]u8 {
    var hasher = checksum.Hasher{};
    for (parts) |part| hasher.update(part);
    return hasher.final();
}

// old_parts: complete source windows in wire order, overlaps/repeats included
fn sealXxh128Patch(
    patch: []u8,
    old_parts: []const []const u8,
    target: []const u8,
) !void {
    const info = try w26.parse(patch);
    if (!std.mem.eql(u8, info.checksum_type, checksum.name) or
        info.checksum_byte_size != checksum.byte_size)
        return error.TestChecksumShape;
    const header_len = try core.checkedU64ToUsize(info.window_data_pos);
    const checksum_extent = 3 * checksum.byte_size;
    if (header_len < checksum_extent or patch.len < header_len)
        return error.TestChecksumShape;
    const old_start = header_len - checksum_extent;
    const new_start = old_start + checksum.byte_size;
    const diff_start = new_start + checksum.byte_size;

    const old_digest = try hashParts(old_parts);
    const target_parts = [_][]const u8{target};
    const new_digest = try hashParts(&target_parts);
    @memcpy(patch[old_start..new_start], &old_digest);
    @memcpy(patch[new_start..diff_start], &new_digest);
    try resealDiffChecksum(patch);
}

fn resealDiffChecksum(patch: []u8) !void {
    const info = try w26.parse(patch);
    if (!std.mem.eql(u8, info.checksum_type, checksum.name) or
        info.checksum_byte_size != checksum.byte_size)
        return error.TestChecksumShape;
    const header_len = try core.checkedU64ToUsize(info.window_data_pos);
    if (header_len < checksum.byte_size or patch.len < header_len)
        return error.TestChecksumShape;
    const diff_start = header_len - checksum.byte_size;
    var hasher = checksum.Hasher{};
    hasher.update(patch[header_len..]);
    hasher.update(patch[0..diff_start]);
    const digest = hasher.final();
    @memcpy(patch[diff_start..header_len], &digest);
}

fn absoluteTmpPath(
    allocator: std.mem.Allocator,
    tmp: *const std.testing.TmpDir,
    leaf: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, leaf });
}

fn makeContainer(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    patch: []const u8,
    suffix: []const u8,
) ![]u8 {
    const result = try allocator.alloc(u8, prefix.len + patch.len + suffix.len);
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..][0..patch.len], patch);
    @memcpy(result[prefix.len + patch.len ..], suffix);
    return result;
}

const CaseFiles = struct {
    allocator: std.mem.Allocator,
    source_path: []u8,
    container_path: []u8,
    target_path: []u8,

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        tmp: *std.testing.TmpDir,
        source_bytes: []const u8,
        container_bytes: []const u8,
        target_initial: ?[]const u8,
    ) !CaseFiles {
        try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
        try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = container_bytes });
        if (target_initial) |bytes|
            try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = bytes });
        const source_path = try absoluteTmpPath(allocator, tmp, "source.bin");
        errdefer allocator.free(source_path);
        const container_path = try absoluteTmpPath(allocator, tmp, "container.bin");
        errdefer allocator.free(container_path);
        const target_path = try absoluteTmpPath(allocator, tmp, "target.bin");
        errdefer allocator.free(target_path);
        return .{
            .allocator = allocator,
            .source_path = source_path,
            .container_path = container_path,
            .target_path = target_path,
        };
    }

    fn deinit(self: *CaseFiles) void {
        self.allocator.free(self.source_path);
        self.allocator.free(self.container_path);
        self.allocator.free(self.target_path);
        self.* = undefined;
    }
};

// handle-scoped source faults, independent of container offsets
const ChecksumSubstituteReader = struct {
    source: std.Io.File,
    container: std.Io.File,
    body_offset: u64,
    corrupt_body_pass: ?u64 = null,
    corrupt_body_relative_offset: u64 = 0,
    corrupt_source_relative_offset: ?u64 = null,
    body_passes: u64 = 0,
    body_corruptions: u64 = 0,
    source_corruptions: u64 = 0,

    fn read(
        raw: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        buffer: []u8,
        offset: u64,
    ) !usize {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        const count = try scan.Reader.direct.read(io, file, buffer, offset);
        const read_end = std.math.add(u64, offset, count) catch
            return error.TestReadOffsetOverflow;

        if (try fs.sameOpenFile(io, file, self.container)) {
            if (offset == self.body_offset)
                self.body_passes = try core.checkedAddU64(self.body_passes, 1);
            if (self.corrupt_body_pass == self.body_passes and
                self.body_corruptions == 0)
            {
                const wanted = std.math.add(
                    u64,
                    self.body_offset,
                    self.corrupt_body_relative_offset,
                ) catch return error.TestReadOffsetOverflow;
                if (wanted >= offset and wanted < read_end) {
                    buffer[@intCast(wanted - offset)] ^= 1;
                    self.body_corruptions = 1;
                }
            }
        } else if (try fs.sameOpenFile(io, file, self.source)) {
            if (self.corrupt_source_relative_offset) |wanted| {
                if (self.source_corruptions == 0 and
                    wanted >= offset and wanted < read_end)
                {
                    buffer[@intCast(wanted - offset)] ^= 1;
                    self.source_corruptions = 1;
                }
            }
        }
        return count;
    }

    fn reader(self: *@This()) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

const HookState = struct {
    bytes: [64]u8 = @splat(0),
    len: usize = 0,
    next_offset: u64 = 0,
    output_calls: usize = 0,
    progress_calls: usize = 0,
    progressed: u64 = 0,
    cancel_after: ?u64 = null,

    fn output(raw: ?*anyopaque, offset: u64, bytes: []const u8) !bool {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (offset != self.next_offset or bytes.len > self.bytes.len - self.len)
            return error.TestBadOutputHook;
        @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
        self.next_offset += bytes.len;
        self.output_calls += 1;
        return true;
    }

    fn progress(raw: ?*anyopaque, count: u64) !bool {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.progress_calls += 1;
        self.progressed = try core.checkedAddU64(self.progressed, count);
        if (self.cancel_after) |limit| return self.progressed < limit;
        return true;
    }
};

test "W26 refuses Source and container Target aliases before truncation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const steps = [_]TestStep{.{ .covers = &covers }};
    const windows = [_]TestWindow{.{
        .old_pos = 0,
        .old_len = source_bytes.len,
        .steps = &steps,
    }};
    const patch = try buildPatch(allocator, source_bytes.len, source_bytes.len, &windows, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    const source_path = try absoluteTmpPath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try absoluteTmpPath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);

    try std.testing.expectError(Error.UnsafeTargetAlias, apply(
        allocator,
        io,
        source_path,
        container_path,
        0,
        patch.len,
        source_path,
        .{},
    ));
    try std.testing.expectError(Error.UnsafeTargetAlias, apply(
        allocator,
        io,
        source_path,
        container_path,
        0,
        patch.len,
        container_path,
        .{},
    ));

    const source_after = try tmp.dir.readFileAlloc(io, "source.bin", allocator, .limited(4));
    defer allocator.free(source_after);
    try std.testing.expectEqualStrings(source_bytes, source_after);
    const container_after = try tmp.dir.readFileAlloc(io, "container.bin", allocator, .limited(patch.len + 1));
    defer allocator.free(container_after);
    try std.testing.expectEqualSlices(u8, patch, container_after);
}

test "W26 refuses a hard-linked Source Target before truncation" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const steps = [_]TestStep{.{ .covers = &covers }};
    const windows = [_]TestWindow{.{
        .old_pos = 0,
        .old_len = source_bytes.len,
        .steps = &steps,
    }};
    const patch = try buildPatch(allocator, source_bytes.len, source_bytes.len, &windows, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    try fs.hardLinkInTmp(allocator, &tmp, "source.bin", "target.bin");
    const source_path = try absoluteTmpPath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try absoluteTmpPath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try absoluteTmpPath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);

    try std.testing.expectError(Error.UnsafeTargetAlias, apply(
        allocator,
        io,
        source_path,
        container_path,
        0,
        patch.len,
        target_path,
        .{},
    ));
    const source_after = try tmp.dir.readFileAlloc(io, "source.bin", allocator, .limited(4));
    defer allocator.free(source_after);
    try std.testing.expectEqualStrings(source_bytes, source_after);
}

test "W26 borrowed handles survive Source and container pathname replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{
        .{ .old_pos = 0, .new_pos = 0, .length = 3 },
        .{ .old_pos = 3, .new_pos = 5, .length = 0 },
    };
    const add_code = [_]u8{ 0, 3, 1, 0, 255 };
    const steps = [_]TestStep{.{
        .covers = &covers,
        .rle = &add_code,
        .literals = "XY",
    }};
    const windows = [_]TestWindow{.{
        .old_pos = 0,
        .old_len = source_bytes.len,
        .steps = &steps,
    }};
    const patch = try buildPatch(allocator, source_bytes.len, 5, &windows, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var container = try fs.openRead(io, tmp.dir, "container.bin");
    defer container.close(io);
    var target = try fs.createGuardedOutputBeneath(io, tmp.dir, "target.bin");
    defer target.close(io);

    try tmp.dir.rename("source.bin", tmp.dir, "retained-source.bin", io);
    try tmp.dir.rename("container.bin", tmp.dir, "retained-container.bin", io);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "XYZ" });
    const hostile_container = try allocator.alloc(u8, patch.len);
    defer allocator.free(hostile_container);
    @memset(hostile_container, 0xa5);
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = hostile_container });

    _ = try applyFilesToFile(
        allocator,
        io,
        source,
        container,
        0,
        patch.len,
        target,
        .{},
    );

    var actual: [5]u8 = undefined;
    try std.testing.expectEqual(actual.len, try target.readPositionalAll(io, &actual, 0));
    try std.testing.expectEqualStrings("bbbXY", &actual);
    try std.testing.expectEqual(@as(u64, source_bytes.len), try source.length(io));
    try std.testing.expectEqual(@as(u64, patch.len), try container.length(io));
}

test "W26 stored apply supports nonzero patch offset ADD and append terminator" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{
        .{ .old_pos = 0, .new_pos = 0, .length = 3 },
        .{ .old_pos = 3, .new_pos = 5, .length = 0 },
    };
    // rle0: zero 0, values 3, ADD {1, 0, 255}
    const add_code = [_]u8{ 0, 3, 1, 0, 255 };
    const steps = [_]TestStep{.{
        .covers = &covers,
        .rle = &add_code,
        .literals = "XY",
    }};
    const windows = [_]TestWindow{.{
        .old_pos = 0,
        .old_len = source_bytes.len,
        .steps = &steps,
    }};
    const patch = try buildPatch(allocator, source_bytes.len, 5, &windows, .{});
    defer allocator.free(patch);
    const prefix = "nonzero-container-prefix";
    const container_bytes = try makeContainer(allocator, prefix, patch, "unrelated-suffix");
    defer allocator.free(container_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, null);
    defer files.deinit();
    var hooks: HookState = .{};
    const stats = try apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        prefix.len,
        patch.len,
        files.target_path,
        .{
            .output = .{ .context = &hooks, .call_fn = HookState.output },
            .progress = .{ .context = &hooks, .call_fn = HookState.progress },
        },
    );

    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(6));
    defer allocator.free(target);
    try std.testing.expectEqualStrings("bbbXY", target);
    try std.testing.expectEqualSlices(u8, target, hooks.bytes[0..hooks.len]);
    try std.testing.expectEqual(@as(u64, 5), hooks.progressed);
    try std.testing.expect(hooks.output_calls >= 2);
    try std.testing.expectEqual(@as(u64, 1), stats.windows);
    try std.testing.expectEqual(@as(u64, 2), stats.decoded_covers);
    try std.testing.expectEqual(@as(u64, 1), stats.real_covers);
    try std.testing.expectEqual(@as(u64, 3), stats.covered_bytes);
    try std.testing.expectEqual(@as(u64, 2), stats.literal_bytes);
}

test "W26 cover backward delta and coordinate ends carry across steps" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abcdefgh";
    const covers0 = [_]TestCover{.{ .old_pos = 4, .new_pos = 0, .length = 2 }};
    const covers1 = [_]TestCover{.{ .old_pos = 1, .new_pos = 2, .length = 3 }};
    const steps = [_]TestStep{
        .{ .covers = &covers0 },
        .{ .covers = &covers1 },
    };
    const windows = [_]TestWindow{.{
        .old_pos = 0,
        .old_len = source_bytes.len,
        .steps = &steps,
    }};
    const patch = try buildPatch(allocator, source_bytes.len, 5, &windows, .{});
    defer allocator.free(patch);
    const container_bytes = try makeContainer(allocator, "P", patch, "S");
    defer allocator.free(container_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, null);
    defer files.deinit();
    const stats = try apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        1,
        patch.len,
        files.target_path,
        .{},
    );
    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(6));
    defer allocator.free(target);
    try std.testing.expectEqualStrings("efbcd", target);
    try std.testing.expectEqual(@as(u64, 2), stats.steps);
    try std.testing.expectEqual(@as(u64, 2), stats.real_covers);
}

test "W26 metadata ring refills by halves with cumulative signed old ends" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abcde";
    const one_cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 1 }};
    const one_step = [_]TestStep{.{ .covers = &one_cover }};
    const windows = [_]TestWindow{
        .{ .old_pos = 0, .old_len = 1, .steps = &one_step },
        .{ .old_pos = 2, .old_len = 1, .steps = &one_step },
        .{ .old_pos = 4, .old_len = 1, .steps = &one_step },
        .{ .old_pos = 1, .old_len = 1, .steps = &one_step },
        .{ .old_pos = 3, .old_len = 1, .steps = &one_step },
    };
    const patch = try buildPatch(allocator, source_bytes.len, 5, &windows, .{ .meta_count = 2 });
    defer allocator.free(patch);
    const container_bytes = try makeContainer(allocator, "ring-prefix", patch, "tail");
    defer allocator.free(container_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, null);
    defer files.deinit();
    const stats = try apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        "ring-prefix".len,
        patch.len,
        files.target_path,
        .{},
    );
    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(6));
    defer allocator.free(target);
    try std.testing.expectEqualStrings("acebd", target);
    try std.testing.expectEqual(@as(u64, windows.len), stats.windows);
    try std.testing.expectEqual(@as(u64, windows.len), stats.source_reads);
}

test "W26 refuses policy caps malformed checksums and unsupported compressed plugins before Target mutation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "a";
    const covers = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 1 }};
    const steps = [_]TestStep{.{ .covers = &covers }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 1, .steps = &steps }};

    const Case = struct {
        patch: []u8,
        expected: anyerror,
    };
    var zeros: [4096]u8 = @splat(0);
    const cases = [_]Case{
        .{
            .patch = try buildPatch(allocator, 1, 1, &windows, .{
                .max_step_mem = max_step_bytes + 1,
            }),
            .expected = Error.StepTooLarge,
        },
        .{
            .patch = try buildPatch(allocator, 1, 1, &windows, .{
                .header_old_size = max_source_window_bytes + 1,
                .max_window_old = max_source_window_bytes + 1,
            }),
            .expected = Error.WindowTooLarge,
        },
        .{
            .patch = try buildPatch(allocator, 1, 1, &windows, .{
                .checksum_type = "xxh128",
                .checksum_size = 1,
            }),
            .expected = Error.UnsupportedChecksum,
        },
        .{
            .patch = try buildPatch(allocator, 1, 1, &windows, .{
                .compress_type = "brotli",
            }),
            .expected = Error.UnsupportedCompression,
        },
        .{
            .patch = try buildPatch(allocator, 1, 1, &windows, .{
                .compress = true,
                .compress_type = "brotli",
                .extra_data = &zeros,
            }),
            .expected = Error.UnsupportedCompression,
        },
    };
    defer for (cases) |case| allocator.free(case.patch);

    for (cases, 0..) |case, index| {
        const container_bytes = try makeContainer(allocator, "off", case.patch, "suffix");
        defer allocator.free(container_bytes);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(
            allocator,
            io,
            &tmp,
            source_bytes,
            container_bytes,
            "sentinel",
        );
        defer files.deinit();
        _ = index;
        try std.testing.expectError(
            case.expected,
            apply(
                allocator,
                io,
                files.source_path,
                files.container_path,
                3,
                case.patch.len,
                files.target_path,
                .{},
            ),
        );
        const untouched = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(9));
        defer allocator.free(untouched);
        try std.testing.expectEqualStrings("sentinel", untouched);
    }
}

test "W26 verifies stored xxh128 with nonzero offset and repeated overlapping Source windows" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abcdef";
    const cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 4 }};
    const step = [_]TestStep{.{ .covers = &cover }};
    const windows = [_]TestWindow{
        .{ .old_pos = 0, .old_len = 4, .steps = &step },
        .{ .old_pos = 2, .old_len = 4, .steps = &step },
    };
    const target_bytes = "abcdcdef";
    const old_parts = [_][]const u8{ source_bytes[0..4], source_bytes[2..6] };
    const patch = try buildPatch(allocator, source_bytes.len, target_bytes.len, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(patch);
    try sealXxh128Patch(patch, &old_parts, target_bytes);
    const prefix = "checksummed-prefix";
    const container = try makeContainer(allocator, prefix, patch, "tail");
    defer allocator.free(container);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container, null);
    defer files.deinit();
    const stats = try apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        prefix.len,
        patch.len,
        files.target_path,
        .{},
    );
    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(target_bytes.len + 1));
    defer allocator.free(target);
    try std.testing.expectEqualStrings(target_bytes, target);
    try std.testing.expectEqual(@as(u64, 2), stats.windows);
}

test "W26 verifies compressed xxh128 bodies" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const step = [_]TestStep{.{ .covers = &cover }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 3, .steps = &step }};
    var zeros: [4096]u8 = @splat(0);
    const old_parts = [_][]const u8{source_bytes};
    const patch = try buildPatch(allocator, source_bytes.len, source_bytes.len, &windows, .{
        .compress = true,
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
        .extra_data = &zeros,
    });
    defer allocator.free(patch);
    try sealXxh128Patch(patch, &old_parts, source_bytes);
    const info = try w26.parse(patch);
    try std.testing.expect(info.compressed_size != 0);

    const prefix = "checksummed-zstd-prefix";
    const container = try makeContainer(allocator, prefix, patch, "unrelated-suffix");
    defer allocator.free(container);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container, null);
    defer files.deinit();
    _ = try apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        prefix.len,
        patch.len,
        files.target_path,
        .{},
    );
    const target = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(4));
    defer allocator.free(target);
    try std.testing.expectEqualStrings(source_bytes, target);
}

test "W26 diff checksum corruption and unknown checksum names cannot mutate Target" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const step = [_]TestStep{.{ .covers = &cover }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 3, .steps = &step }};
    const old_parts = [_][]const u8{source_bytes};

    const corrupt = try buildPatch(allocator, 3, 3, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(corrupt);
    try sealXxh128Patch(corrupt, &old_parts, source_bytes);
    corrupt[corrupt.len - 1] ^= 1;

    const unknown = try buildPatch(allocator, 3, 3, &windows, .{
        .checksum_type = "XXH128",
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(unknown);

    const cases = [_]struct { patch: []const u8, expected: anyerror }{
        .{ .patch = corrupt, .expected = Error.ChecksumMismatch },
        .{ .patch = unknown, .expected = Error.UnsupportedChecksum },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, case.patch, "sentinel");
        defer files.deinit();
        try std.testing.expectError(case.expected, apply(
            allocator,
            io,
            files.source_path,
            files.container_path,
            0,
            case.patch.len,
            files.target_path,
            .{},
        ));
        const untouched = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(9));
        defer allocator.free(untouched);
        try std.testing.expectEqualStrings("sentinel", untouched);
    }
}

test "W26 old and new checksum mismatches remain hard failures after structural apply" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abcd";
    const target_bytes = "abc";
    const cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const step = [_]TestStep{.{ .covers = &cover }};
    // unused window byte: corruption detectable only by old checksum
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 4, .steps = &step }};
    const old_parts = [_][]const u8{source_bytes};
    const base = try buildPatch(allocator, source_bytes.len, target_bytes.len, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(base);
    try sealXxh128Patch(base, &old_parts, target_bytes);

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, "abcX", base, null);
        defer files.deinit();
        try std.testing.expectError(Error.ChecksumMismatch, apply(
            allocator,
            io,
            files.source_path,
            files.container_path,
            0,
            base.len,
            files.target_path,
            .{},
        ));
        const reconstructed = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(4));
        defer allocator.free(reconstructed);
        try std.testing.expectEqualStrings(target_bytes, reconstructed);
    }
    {
        const wrong_new = try allocator.dupe(u8, base);
        defer allocator.free(wrong_new);
        const info = try w26.parse(wrong_new);
        const header_len = try core.checkedU64ToUsize(info.window_data_pos);
        const new_start = header_len - 2 * checksum.byte_size;
        wrong_new[new_start] ^= 1;
        try resealDiffChecksum(wrong_new);

        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, wrong_new, null);
        defer files.deinit();
        try std.testing.expectError(Error.ChecksumMismatch, apply(
            allocator,
            io,
            files.source_path,
            files.container_path,
            0,
            wrong_new.len,
            files.target_path,
            .{},
        ));
    }
}

test "W26 successful-wrong diff preflight read cannot mutate Target" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const target_bytes = "phase-boundary literal payload";
    const cover = [_]TestCover{.{
        .old_pos = 0,
        .new_pos = target_bytes.len,
        .length = 0,
    }};
    const step = [_]TestStep{.{ .covers = &cover, .literals = target_bytes }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 0, .steps = &step }};
    const old_parts = [_][]const u8{""};
    const patch = try buildPatch(allocator, 0, target_bytes.len, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(patch);
    try sealXxh128Patch(patch, &old_parts, target_bytes);
    const info = try w26.parse(patch);
    const header_len = try core.checkedU64ToUsize(info.window_data_pos);
    const literal_offset = std.mem.indexOf(u8, patch[header_len..], target_bytes) orelse
        return error.TestLiteralNotFound;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, "", patch, "sentinel");
    defer files.deinit();
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var container = try fs.openRead(io, tmp.dir, "container.bin");
    defer container.close(io);
    var wrong: ChecksumSubstituteReader = .{
        .source = source,
        .container = container,
        .body_offset = info.window_data_pos,
        .corrupt_body_pass = 1,
        .corrupt_body_relative_offset = literal_offset + 3,
    };

    try std.testing.expectError(Error.ChecksumMismatch, apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        0,
        patch.len,
        files.target_path,
        .{ .reader = wrong.reader() },
    ));
    try std.testing.expectEqual(@as(u64, 1), wrong.body_passes);
    try std.testing.expectEqual(@as(u64, 1), wrong.body_corruptions);
    const untouched = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(9));
    defer allocator.free(untouched);
    try std.testing.expectEqualStrings("sentinel", untouched);
}

test "W26 successful-wrong later body read cannot pass new checksum" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const target_bytes = "phase-boundary literal payload";
    const fault_index: usize = 7;
    const cover = [_]TestCover{.{
        .old_pos = 0,
        .new_pos = target_bytes.len,
        .length = 0,
    }};
    const step = [_]TestStep{.{ .covers = &cover, .literals = target_bytes }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 0, .steps = &step }};
    const old_parts = [_][]const u8{""};
    const patch = try buildPatch(allocator, 0, target_bytes.len, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(patch);
    try sealXxh128Patch(patch, &old_parts, target_bytes);
    const info = try w26.parse(patch);
    const header_len = try core.checkedU64ToUsize(info.window_data_pos);
    const literal_offset = std.mem.indexOf(u8, patch[header_len..], target_bytes) orelse
        return error.TestLiteralNotFound;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, "", patch, "sentinel");
    defer files.deinit();
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var container = try fs.openRead(io, tmp.dir, "container.bin");
    defer container.close(io);
    var wrong: ChecksumSubstituteReader = .{
        .source = source,
        .container = container,
        .body_offset = info.window_data_pos,
        .corrupt_body_pass = 2,
        .corrupt_body_relative_offset = literal_offset + fault_index,
    };

    try std.testing.expectError(Error.ChecksumMismatch, apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        0,
        patch.len,
        files.target_path,
        .{ .reader = wrong.reader() },
    ));
    try std.testing.expectEqual(@as(u64, 2), wrong.body_passes);
    try std.testing.expectEqual(@as(u64, 1), wrong.body_corruptions);
    const reconstructed = try tmp.dir.readFileAlloc(
        io,
        "target.bin",
        allocator,
        .limited(target_bytes.len + 1),
    );
    defer allocator.free(reconstructed);
    try std.testing.expectEqual(target_bytes.len, reconstructed.len);
    try std.testing.expectEqualSlices(u8, target_bytes[0..fault_index], reconstructed[0..fault_index]);
    try std.testing.expectEqual(target_bytes[fault_index] ^ 1, reconstructed[fault_index]);
    try std.testing.expectEqualSlices(u8, target_bytes[fault_index + 1 ..], reconstructed[fault_index + 1 ..]);
}

test "W26 successful-wrong Source window read cannot pass old checksum" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abcd";
    const target_bytes = "abc";
    const cover = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const step = [_]TestStep{.{ .covers = &cover }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 4, .steps = &step }};
    const old_parts = [_][]const u8{source_bytes};
    const patch = try buildPatch(allocator, source_bytes.len, target_bytes.len, &windows, .{
        .checksum_type = checksum.name,
        .checksum_size = checksum.byte_size,
    });
    defer allocator.free(patch);
    try sealXxh128Patch(patch, &old_parts, target_bytes);
    const info = try w26.parse(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, patch, null);
    defer files.deinit();
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var container = try fs.openRead(io, tmp.dir, "container.bin");
    defer container.close(io);
    var wrong: ChecksumSubstituteReader = .{
        .source = source,
        .container = container,
        .body_offset = info.window_data_pos,
        .corrupt_source_relative_offset = 3,
    };

    try std.testing.expectError(Error.ChecksumMismatch, apply(
        allocator,
        io,
        files.source_path,
        files.container_path,
        0,
        patch.len,
        files.target_path,
        .{ .reader = wrong.reader() },
    ));
    try std.testing.expectEqual(@as(u64, 0), wrong.body_corruptions);
    try std.testing.expectEqual(@as(u64, 1), wrong.source_corruptions);
    const reconstructed = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(4));
    defer allocator.free(reconstructed);
    try std.testing.expectEqualStrings(target_bytes, reconstructed);
}

test "W26 rejects short trailing and overlong rle0 step streams exactly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{.{ .old_pos = 0, .new_pos = 0, .length = 3 }};
    const Case = struct { code: []const u8, expected: anyerror };
    const cases = [_]Case{
        .{ .code = &.{2}, .expected = core.Error.RleUnderrun },
        .{ .code = &.{5}, .expected = core.Error.RleOverrun },
        .{ .code = &.{ 3, 0 }, .expected = core.Error.RleOverrun },
    };
    for (cases) |case| {
        const steps = [_]TestStep{.{ .covers = &covers, .rle = case.code }};
        const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 3, .steps = &steps }};
        const patch = try buildPatch(allocator, 3, 3, &windows, .{});
        defer allocator.free(patch);
        const container_bytes = try makeContainer(allocator, "p", patch, "s");
        defer allocator.free(container_bytes);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, null);
        defer files.deinit();
        try std.testing.expectError(
            case.expected,
            apply(
                allocator,
                io,
                files.source_path,
                files.container_path,
                1,
                patch.len,
                files.target_path,
                .{},
            ),
        );
    }
}

test "W26 rejects malformed extents source sizes ranges and cover structure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "ab";
    const bad_cover = [_]TestCover{.{ .old_pos = 1, .new_pos = 0, .length = 2 }};
    const bad_step = [_]TestStep{.{ .covers = &bad_cover }};
    const bad_window = [_]TestWindow{.{ .old_pos = 0, .old_len = 2, .steps = &bad_step }};
    const patch = try buildPatch(allocator, 2, 2, &bad_window, .{});
    defer allocator.free(patch);
    const container_bytes = try makeContainer(allocator, "prefix", patch, "suffix");
    defer allocator.free(container_bytes);

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, "old");
        defer files.deinit();
        try std.testing.expectError(
            w26.Error.PatchExtentMismatch,
            apply(allocator, io, files.source_path, files.container_path, 6, patch.len - 1, files.target_path, .{}),
        );
        try std.testing.expectError(
            Error.PatchRangeOutOfBounds,
            apply(allocator, io, files.source_path, files.container_path, 6, patch.len + 7, files.target_path, .{}),
        );
        const untouched = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(4));
        defer allocator.free(untouched);
        try std.testing.expectEqualStrings("old", untouched);
    }
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, "wrong", container_bytes, "old");
        defer files.deinit();
        try std.testing.expectError(
            Error.SourceSizeMismatch,
            apply(allocator, io, files.source_path, files.container_path, 6, patch.len, files.target_path, .{}),
        );
        const untouched = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(4));
        defer allocator.free(untouched);
        try std.testing.expectEqualStrings("old", untouched);
    }
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, container_bytes, null);
        defer files.deinit();
        try std.testing.expectError(
            core.Error.CoverOutOfRange,
            apply(allocator, io, files.source_path, files.container_path, 6, patch.len, files.target_path, .{}),
        );
    }

    const zero_then_real = [_]TestCover{
        .{ .old_pos = 0, .new_pos = 0, .length = 0 },
        .{ .old_pos = 0, .new_pos = 0, .length = 1 },
    };
    const zero_step = [_]TestStep{.{ .covers = &zero_then_real }};
    const zero_window = [_]TestWindow{.{ .old_pos = 0, .old_len = 1, .steps = &zero_step }};
    const zero_patch = try buildPatch(allocator, 2, 1, &zero_window, .{});
    defer allocator.free(zero_patch);
    const zero_container = try makeContainer(allocator, "z", zero_patch, "");
    defer allocator.free(zero_container);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, zero_container, null);
    defer files.deinit();
    try std.testing.expectError(
        Error.ZeroLengthCoverNotLast,
        apply(allocator, io, files.source_path, files.container_path, 1, zero_patch.len, files.target_path, .{}),
    );
}

test "W26 treats lower header cover count as informational and enforces other final bounds" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_bytes = "abc";
    const covers = [_]TestCover{
        .{ .old_pos = 0, .new_pos = 0, .length = 1 },
        .{ .old_pos = 1, .new_pos = 1, .length = 1 },
        .{ .old_pos = 2, .new_pos = 2, .length = 1 },
    };
    const steps = [_]TestStep{.{ .covers = &covers }};
    const windows = [_]TestWindow{.{ .old_pos = 0, .old_len = 3, .steps = &steps }};
    const excess_patch = try buildPatch(allocator, 3, 3, &windows, .{ .header_cover_count = 0 });
    defer allocator.free(excess_patch);
    const excess_container = try makeContainer(allocator, "x", excess_patch, "");
    defer allocator.free(excess_container);

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, excess_container, null);
        defer files.deinit();
        const stats = try apply(
            allocator,
            io,
            files.source_path,
            files.container_path,
            1,
            excess_patch.len,
            files.target_path,
            .{},
        );
        try std.testing.expectEqual(@as(u64, 3), stats.real_covers);
        try std.testing.expectEqual(@as(u64, 0), stats.header_cover_count);
    }

    const too_many_header = try buildPatch(allocator, 3, 3, &windows, .{ .header_cover_count = 4 });
    defer allocator.free(too_many_header);
    const too_many_container = try makeContainer(allocator, "x", too_many_header, "");
    defer allocator.free(too_many_container);
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, too_many_container, null);
        defer files.deinit();
        try std.testing.expectError(
            Error.CoverCountDisagrees,
            apply(allocator, io, files.source_path, files.container_path, 1, too_many_header.len, files.target_path, .{}),
        );
    }

    const trailing_patch = try buildPatch(allocator, 3, 3, &windows, .{ .body_tail = "X" });
    defer allocator.free(trailing_patch);
    const trailing_container = try makeContainer(allocator, "x", trailing_patch, "");
    defer allocator.free(trailing_container);
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, trailing_container, null);
        defer files.deinit();
        try std.testing.expectError(
            clip.Error.OutputSizeMismatch,
            apply(allocator, io, files.source_path, files.container_path, 1, trailing_patch.len, files.target_path, .{}),
        );
    }

    const normal_patch = try buildPatch(allocator, 3, 3, &windows, .{});
    defer allocator.free(normal_patch);
    const normal_container = try makeContainer(allocator, "x", normal_patch, "");
    defer allocator.free(normal_container);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var files = try CaseFiles.init(allocator, io, &tmp, source_bytes, normal_container, null);
    defer files.deinit();
    var hooks: HookState = .{ .cancel_after = 1 };
    try std.testing.expectError(
        Error.CallbackCancelled,
        apply(
            allocator,
            io,
            files.source_path,
            files.container_path,
            1,
            normal_patch.len,
            files.target_path,
            .{ .progress = .{ .context = &hooks, .call_fn = HookState.progress } },
        ),
    );
}

const encoding = @import("hdiff/encoding.zig");
const streams = @import("hdiff/streams.zig");
const std = @import("std");

const sf20 = @import("hdiff/sf20.zig");
const fs = @import("core/fs.zig");
const ids = @import("core/ids.zig");
const scan = @import("core/scan.zig");
const h13 = @import("hdiff/h13.zig");
const h13_apply = @import("hdiff/h13/apply.zig");
const h13_create = @import("hdiff/h13/create.zig");
const interrupt = @import("interrupt.zig");
const covers = @import("hdiff/w26/match.zig");
const tracker = @import("tracker.zig");
const w26 = @import("hdiff/w26.zig");
const w26_apply = @import("hdiff/w26/apply.zig");
const w26_checksum = @import("hdiff/w26.zig").Checksum;
const w26_write = @import("hdiff/w26/create.zig");

pub const default_match_block_size: usize = 64;
pub const minimum_memory_match_block_size: usize = 16384;

pub fn standardMatchBlockSize(minimum_memory: bool) usize {
    return if (minimum_memory) minimum_memory_match_block_size else covers.default_block_size;
}

pub const GuardedPart = streams.FilePart;
pub const InputPart = streams.FilePart;

pub const Progress = struct {
    tracker: tracker.Tracker = .{},
    // inherited cancellation; rereads excluded from UI byte counts
    cancel_source: ?*const Progress = null,
    output_hash: ?*OutputHash = null,
    output_digest: ?*OutputDigest = null,

    pub fn done(self: *const Progress) u64 {
        return self.tracker.done();
    }

    pub fn cancel(self: *Progress) void {
        self.tracker.cancel();
    }
};

pub const OutputHash = struct {
    size: u64,
    written: u64 = 0,
    hasher: std.crypto.hash.Md5 = std.crypto.hash.Md5.init(.{}),
    failed: bool = false,

    pub fn init(size: u64) OutputHash {
        return .{ .size = size };
    }

    pub fn finish(self: *OutputHash) ![16]u8 {
        if (self.failed or self.written != self.size) return error.HDiffOutputHashFailed;
        var actual: [16]u8 = undefined;
        self.hasher.final(&actual);
        return actual;
    }

    pub fn verify(self: *OutputHash, expected: [16]u8) ![16]u8 {
        const actual = try self.finish();
        if (!std.mem.eql(u8, &actual, &expected)) return error.Md5Mismatch;
        return actual;
    }
};

pub const OutputDigest = struct {
    size: u64,
    written: u64 = 0,
    hasher: std.crypto.hash.Blake3 = std.crypto.hash.Blake3.init(.{}),
    failed: bool = false,

    pub fn init(size: u64) OutputDigest {
        return .{ .size = size };
    }

    pub fn verify(self: *OutputDigest, expected: ids.Digest) !ids.Digest {
        if (self.failed or self.written != self.size)
            return error.HDiffOutputDigestFailed;
        var actual: ids.Digest = undefined;
        self.hasher.final(&actual.bytes);
        if (!actual.eql(expected)) return error.DigestMismatch;
        return actual;
    }
};

fn progressCallback(context: ?*anyopaque, count: u64) !bool {
    const progress: *Progress = @ptrCast(@alignCast(context.?));
    if (progressCancelled(progress)) return false;
    progress.tracker.add(count);
    return true;
}

fn progressCancelled(progress: *const Progress) bool {
    var current: ?*const Progress = progress;
    var depth: u8 = 0;
    while (current) |state| {
        if (state.tracker.isCancelled()) return true;
        current = state.cancel_source;
        depth += 1;
        if (depth == 16 and current != null) return true;
    }
    return interrupt.requested();
}

fn requireProgress(progress: *const Progress) !void {
    if (progressCancelled(progress)) return error.Interrupted;
}

fn outputCallback(context: ?*anyopaque, offset: u64, bytes: []const u8) !bool {
    const progress: *Progress = @ptrCast(@alignCast(context.?));
    return updateOutputHash(progress.output_hash, offset, bytes) and
        updateOutputDigest(progress.output_digest, offset, bytes);
}

fn updateOutputHash(maybe_state: ?*OutputHash, offset: u64, bytes: []const u8) bool {
    const state = maybe_state orelse return true;
    if (state.failed or offset != state.written or bytes.len > state.size - state.written) {
        state.failed = true;
        return false;
    }
    state.hasher.update(bytes);
    state.written += bytes.len;
    return true;
}

fn updateOutputDigest(maybe_state: ?*OutputDigest, offset: u64, bytes: []const u8) bool {
    const state = maybe_state orelse return true;
    if (state.failed or offset != state.written) {
        state.failed = true;
        return false;
    }
    const new_written = std.math.add(u64, state.written, bytes.len) catch {
        state.failed = true;
        return false;
    };
    if (new_written > state.size) {
        state.failed = true;
        return false;
    }
    state.hasher.update(bytes);
    state.written = new_written;
    return true;
}

fn hasOutputObserver(progress: *const Progress) bool {
    return progress.output_hash != null or progress.output_digest != null;
}

pub const FileIdentity = struct {
    path: []const u8,
    size: u64,
    digest: ids.Digest,
};

pub const Format = enum {
    w26,
    h13,
    sf20,

    pub fn parse(text: []const u8) ?Format {
        if (std.ascii.eqlIgnoreCase(text, "w26") or std.ascii.eqlIgnoreCase(text, "hdiffw26")) return .w26;
        if (std.ascii.eqlIgnoreCase(text, "h13") or std.ascii.eqlIgnoreCase(text, "hdiff13")) return .h13;
        if (std.ascii.eqlIgnoreCase(text, "sf20") or std.ascii.eqlIgnoreCase(text, "hdiffsf20")) return .sf20;
        return null;
    }

    pub fn label(self: Format) []const u8 {
        return switch (self) {
            .w26 => "HDIFFW26",
            .h13 => "HDIFF13",
            .sf20 => "HDIFFSF20",
        };
    }
};

pub const CreateOptions = struct {
    format: Format = .w26,
    match_block_size: usize = covers.default_block_size,
    old_window_size: usize = 2 * 1024 * 1024,
    step_mem_size: usize = 256 * 1024,
    compression: w26_write.Compression = .zstd_if_smaller,
    compression_level: c_int = 5,
};

pub const standard_min_match_block_size: usize = 16;
pub const standard_max_match_block_size: usize = 16 * 1024;
pub const standard_min_window_size: usize = 64;
pub const standard_max_window_size: usize = 256 * 1024 * 1024;
pub const standard_min_step_mem_size: usize = 4 * 1024;
pub const standard_max_step_mem_size: usize = 4 * 1024 * 1024;

pub const CreateResult = struct {
    patch_size: u64,
    patch_digest: ids.Digest,
    construction: ?w26_write.ConstructionObservation = null,
};

// digest-sink verification; offset-prefix restore on failure
pub fn createAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: FileIdentity,
    target: FileIdentity,
    output_path: []const u8,
    offset: u64,
    options: CreateOptions,
    progress: *Progress,
) !CreateResult {
    try validateCreateOptions(options);
    try requireOutputOffset(io, output_path, offset);
    return createAtTransaction(
        allocator,
        io,
        source,
        target,
        output_path,
        offset,
        options,
        progress,
    ) catch |err| {
        rollbackOutput(io, output_path, offset) catch
            return error.HDiffRollbackFailed;
        return err;
    };
}

fn createAtTransaction(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: FileIdentity,
    target: FileIdentity,
    output_path: []const u8,
    offset: u64,
    options: CreateOptions,
    progress: *Progress,
) !CreateResult {
    try requireProgress(progress);

    var patch_size: u64 = 0;
    var construction: ?w26_write.ConstructionObservation = null;
    switch (options.format) {
        .w26 => {
            var cancellable_reader: CancellableReader = .{ .progress = progress };
            const source_parts = [_]covers.Part{.{ .path = source.path, .size = source.size }};
            const profiled_covers = try covers.matchExact(
                allocator,
                io,
                &source_parts,
                .{ .path = target.path, .size = target.size },
                .{
                    .block_size = options.match_block_size,
                    .profile = .collinear_gap,
                    .reader = cancellable_reader.reader(),
                },
            );
            defer allocator.free(profiled_covers);
            try requireProgress(progress);
            const stats = w26_write.write(
                allocator,
                io,
                profiled_covers,
                source.path,
                source.size,
                target.path,
                target.size,
                output_path,
                offset,
                .{
                    .window_bound = options.old_window_size,
                    .step_bytes = options.step_mem_size,
                    .compression = options.compression,
                    .compression_level = options.compression_level,
                    .reader = cancellable_reader.reader(),
                    .source_reader = cancellable_reader.reader(),
                    .expected_source_digest = source.digest,
                    .expected_target_digest = target.digest,
                },
            ) catch |err| switch (err) {
                error.ConstructionSourceDigestMismatch => return error.SourceChangedDuringCreate,
                error.ConstructionTargetDigestMismatch => return error.DigestMismatch,
                else => return err,
            };
            patch_size = stats.patch_bytes;
            construction = stats.construction_observation;
            try validateCreatedW26(io, output_path, offset, patch_size, source.size, target.size);
        },
        .h13, .sf20 => {
            const source_file = try fs.openRead(io, .cwd(), source.path);
            defer source_file.close(io);
            const target_file = try fs.openRead(io, .cwd(), target.path);
            defer target_file.close(io);
            const output = try fs.openReadWrite(io, .cwd(), output_path);
            defer output.close(io);
            const source_part: InputPart = .{ .file = source_file, .size = source.size };
            const target_part: InputPart = .{ .file = target_file, .size = target.size };
            const compression_level: ?c_int = if (options.compression == .stored) null else options.compression_level;
            patch_size = if (options.format == .h13)
                try createH13AtGuardedFiles(allocator, io, source_part, target_part, output, offset, options.match_block_size, compression_level, progress)
            else
                try createSf20AtGuardedFiles(io, source_part, target_part, output, offset, options.match_block_size, compression_level, progress);
        },
    }
    try requireProgress(progress);

    const patch_digest = try digestRange(io, output_path, offset, patch_size, progress);
    try requireProgress(progress);

    try verifyCreatedPatch(allocator, io, options.format, source.path, output_path, offset, patch_size, target, progress);

    try confirmRangeDigest(io, output_path, offset, patch_size, patch_digest, progress);
    try requireProgress(progress);

    // source identity includes bytes outside copy ranges
    try confirmSourceIdentity(io, source, progress);
    try requireProgress(progress);

    return .{
        .patch_size = patch_size,
        .patch_digest = patch_digest,
        .construction = construction,
    };
}

fn validateCreateOptions(options: CreateOptions) !void {
    if (options.match_block_size < standard_min_match_block_size or
        options.match_block_size > standard_max_match_block_size)
        return error.InvalidBlockSize;
    if (options.format == .w26) {
        if (options.old_window_size < standard_min_window_size or
            options.old_window_size > standard_max_window_size)
            return error.InvalidWindowSize;
        if (options.step_mem_size < standard_min_step_mem_size or
            options.step_mem_size > standard_max_step_mem_size)
            return error.InvalidStepMemorySize;
    }
}

const CancellableReader = struct {
    progress: *Progress,

    fn read(
        context: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        buffer: []u8,
        offset: u64,
    ) !usize {
        const self: *@This() = @ptrCast(@alignCast(context orelse
            return error.Interrupted));
        try requireProgress(self.progress);
        const count = try scan.Reader.direct.read(io, file, buffer, offset);
        try requireProgress(self.progress);
        self.progress.tracker.add(count);
        return count;
    }

    fn reader(self: *@This()) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

fn verifyCreatedPatch(allocator: std.mem.Allocator, io: std.Io, format: Format, source_path: []const u8, patch_path: []const u8, offset: u64, patch_size: u64, target: FileIdentity, parent_progress: *Progress) !void {
    var digest = OutputDigest.init(target.size);
    var progress: Progress = .{
        .cancel_source = parent_progress,
        .output_digest = &digest,
    };
    switch (format) {
        .w26 => {
            _ = w26_apply.verify(allocator, io, source_path, patch_path, offset, patch_size, .{
                .output = .{ .context = &progress, .call_fn = outputCallback },
                .progress = .{ .context = &progress, .call_fn = progressCallback },
            }) catch |err| return mapApplyError(err);
        },
        .h13, .sf20 => {
            const source_file = try fs.openRead(io, .cwd(), source_path);
            defer source_file.close(io);
            const patch_file = try fs.openRead(io, .cwd(), patch_path);
            defer patch_file.close(io);
            if (format == .h13) {
                _ = h13_apply.verifyFiles(allocator, io, source_file, patch_file, offset, patch_size, .{
                    .output = .{ .context = &progress, .call_fn = outputCallback },
                    .progress = .{ .context = &progress, .call_fn = progressCallback },
                }) catch |err| return mapApplyError(err);
            } else {
                const input = try streams.Input.init(io, &.{.{ .file = source_file, .size = try source_file.length(io) }});
                sf20.apply(io, &input, patch_file, offset, patch_size, .{
                    .io = io,
                    .observer = .{ .context = &progress, .call_fn = outputCallback },
                    .progress = .{ .context = &progress, .call_fn = progressCallback },
                }) catch |err| return mapApplyError(err);
            }
        },
    }
    _ = try digest.verify(target.digest);
}

fn confirmSourceIdentity(io: std.Io, source: FileIdentity, progress: *Progress) !void {
    const actual = digestRange(io, source.path, 0, source.size, progress) catch |err| switch (err) {
        error.Interrupted => return err,
        else => return error.SourceChangedDuringCreate,
    };
    if (!actual.eql(source.digest)) return error.SourceChangedDuringCreate;
}

pub fn createSf20AtGuardedFiles(
    io: std.Io,
    source: InputPart,
    target: InputPart,
    output: std.Io.File,
    offset: u64,
    match_block_size: usize,
    compression_level: ?c_int,
    progress: *Progress,
) !u64 {
    const sources = [_]InputPart{source};
    const targets = [_]InputPart{target};
    return createSf20Parts(io, &sources, &targets, output, offset, match_block_size, compression_level, progress);
}

pub fn createH13AtGuardedFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: InputPart,
    target: InputPart,
    output: std.Io.File,
    offset: u64,
    match_block_size: usize,
    compression_level: ?c_int,
    progress: *Progress,
) !u64 {
    try requireProgress(progress);
    return h13_create.create(allocator, io, source, target, output, offset, match_block_size, compression_level, .{
        .context = progress,
        .call_fn = progressCallback,
    }) catch |err| return mapNativeCreateError(err, progress);
}

fn createSf20Parts(io: std.Io, source_parts: []const InputPart, target_parts: []const InputPart, output: std.Io.File, offset: u64, block: usize, compression_level: ?c_int, progress: *Progress) !u64 {
    try requireProgress(progress);
    var source = streams.Input.init(io, source_parts) catch |err| return mapNativeCreateError(err, progress);
    var target = streams.Input.init(io, target_parts) catch |err| return mapNativeCreateError(err, progress);
    source.progress = .{ .context = progress, .call_fn = progressCallback };
    target.progress = source.progress;
    return sf20.create(io, &source, &target, output, offset, block, compression_level) catch |err| return mapNativeCreateError(err, progress);
}

fn requireOutputOffset(io: std.Io, path: []const u8, offset: u64) !void {
    var output = try fs.openReadWrite(io, std.Io.Dir.cwd(), path);
    defer output.close(io);
    if (try output.length(io) != offset) return error.OutputOffsetMismatch;
}

fn rollbackOutput(io: std.Io, path: []const u8, offset: u64) !void {
    var output = try fs.openReadWrite(io, std.Io.Dir.cwd(), path);
    defer output.close(io);
    try output.setLength(io, offset);
    try output.sync(io);
    if (try output.length(io) != offset) return error.HDiffRollbackFailed;
}

fn validateCreatedW26(
    io: std.Io,
    path: []const u8,
    offset: u64,
    patch_size: u64,
    source_size: u64,
    target_size: u64,
) !void {
    var file = try fs.openRead(io, std.Io.Dir.cwd(), path);
    defer file.close(io);
    const expected_end = std.math.add(u64, offset, patch_size) catch
        return error.InvalidCreatedHDiff;
    if (try file.length(io) != expected_end) return error.InvalidCreatedHDiff;
    const wanted: usize = @intCast(@min(@as(u64, w26.max_head_size), patch_size));
    var prefix: [w26.max_head_size]u8 = undefined;
    if (try fs.readAllAt(io, file, prefix[0..wanted], offset) != wanted)
        return error.InvalidCreatedHDiff;
    const info = w26.parse(prefix[0..wanted]) catch return error.InvalidCreatedHDiff;
    w26.validatePatchExtent(info, patch_size) catch return error.InvalidCreatedHDiff;
    if (info.old_size != source_size or info.new_size != target_size)
        return error.InvalidCreatedHDiff;
    if (!std.mem.eql(u8, info.checksum_type, w26_checksum.name) or
        info.checksum_byte_size != w26_checksum.byte_size)
        return error.InvalidCreatedHDiff;
}

fn confirmRangeDigest(
    io: std.Io,
    path: []const u8,
    offset: u64,
    size: u64,
    expected: ids.Digest,
    progress: *Progress,
) !void {
    const actual = try digestRange(io, path, offset, size, progress);
    if (!actual.eql(expected)) return error.PatchChangedDuringVerification;
}

fn digestRange(
    io: std.Io,
    path: []const u8,
    offset: u64,
    size: u64,
    progress: ?*Progress,
) !ids.Digest {
    var file = try fs.openRead(io, std.Io.Dir.cwd(), path);
    defer file.close(io);
    const expected_end = std.math.add(u64, offset, size) catch return error.InvalidHDiffRange;
    if (try file.length(io) != expected_end) return error.InvalidHDiffRange;
    var hasher = std.crypto.hash.Blake3.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var position: u64 = 0;
    while (position < size) {
        if (progress) |state| try requireProgress(state);
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - position));
        const count = try fs.readAllAt(io, file, buffer[0..wanted], offset + position);
        if (count != wanted) return error.InvalidHDiffRange;
        if (progress) |state| try requireProgress(state);
        hasher.update(buffer[0..count]);
        position += count;
    }
    var digest: ids.Digest = undefined;
    hasher.final(&digest.bytes);
    return digest;
}

pub const Info = struct {
    source_size: u64,
    target_size: u64,
};

pub const info_prefix_size = 4096;

pub fn infoPrefix(bytes: []const u8) !Info {
    if (std.mem.startsWith(u8, bytes, w26.magic)) {
        const parsed = w26.parse(bytes) catch return error.InvalidHDiff;
        return .{ .source_size = parsed.old_size, .target_size = parsed.new_size };
    }
    if (std.mem.startsWith(u8, bytes, h13.magic)) {
        const parsed = h13.parse(bytes) catch return error.InvalidHDiff;
        return .{ .source_size = parsed.old_size, .target_size = parsed.new_size };
    }

    var pos: usize = 0;
    if (std.mem.startsWith(u8, bytes, sf20.magic)) {
        pos = sf20.magic.len;
    } else {
        return error.InvalidHDiff;
    }
    const compression_end = std.mem.indexOfScalarPos(u8, bytes, pos, 0) orelse return error.InvalidHDiff;
    pos = compression_end + 1;
    const target_size = encoding.decodeHdiffPackUInt(bytes, &pos) catch return error.InvalidHDiff;
    const source_size = encoding.decodeHdiffPackUInt(bytes, &pos) catch return error.InvalidHDiff;
    return .{ .source_size = source_size, .target_size = target_size };
}

pub fn infoAt(io: std.Io, container_path: []const u8, offset: u64, size: u64) !Info {
    const file = fs.openRead(io, .cwd(), container_path) catch return error.InvalidHDiff;
    defer file.close(io);
    return infoFile(io, file, offset, size) catch return error.InvalidHDiff;
}

fn infoFile(io: std.Io, file: std.Io.File, offset: u64, size: u64) !Info {
    const length = try file.length(io);
    if (offset > length or size > length - offset) return error.InvalidHDiff;
    var prefix: [info_prefix_size]u8 = undefined;
    const take: usize = @intCast(@min(size, prefix.len));
    if (try fs.readAllAt(io, file, prefix[0..take], offset) != take) return error.InvalidHDiff;
    const bytes = prefix[0..take];
    if (std.mem.startsWith(u8, bytes, w26.magic)) {
        const header = try w26.parse(bytes);
        try w26.validatePatchExtent(header, size);
        return .{ .source_size = header.old_size, .target_size = header.new_size };
    }
    if (std.mem.startsWith(u8, bytes, h13.magic)) {
        const header = try h13.parse(bytes);
        try h13.validatePatchExtent(header, size);
        return .{ .source_size = header.old_size, .target_size = header.new_size };
    }
    const header = try sf20.info(io, file, offset, size);
    return .{ .source_size = header.old_size, .target_size = header.new_size };
}

pub fn applyAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    container_path: []const u8,
    offset: u64,
    size: u64,
    target_path: []const u8,
    progress: *Progress,
) !void {
    const kind = detectPatchKind(io, container_path, offset, size) catch
        return error.HDiffApplyFailed;
    switch (kind) {
        .w26 => {
            const options: w26_apply.Options = .{
                .output = if (hasOutputObserver(progress)) .{
                    .context = progress,
                    .call_fn = outputCallback,
                } else null,
                .progress = .{
                    .context = progress,
                    .call_fn = progressCallback,
                },
            };
            _ = w26_apply.apply(
                allocator,
                io,
                source_path,
                container_path,
                offset,
                size,
                target_path,
                options,
            ) catch |err| return mapApplyError(err);
            return;
        },
        .h13 => {
            const options: h13_apply.Options = .{
                .output = if (hasOutputObserver(progress)) .{
                    .context = progress,
                    .call_fn = outputCallback,
                } else null,
                .progress = .{
                    .context = progress,
                    .call_fn = progressCallback,
                },
            };
            _ = h13_apply.apply(
                allocator,
                io,
                source_path,
                container_path,
                offset,
                size,
                target_path,
                options,
            ) catch |err| return mapApplyError(err);
            return;
        },
        .sf20 => {},
    }

    applySf20Path(io, source_path, container_path, offset, size, target_path, progress) catch |err| return mapApplyError(err);
}

fn applySf20Path(io: std.Io, source_path: []const u8, container_path: []const u8, offset: u64, size: u64, target_path: []const u8, progress: *Progress) !void {
    const source_file = try fs.openRead(io, .cwd(), source_path);
    defer source_file.close(io);
    const container = try fs.openRead(io, .cwd(), container_path);
    defer container.close(io);
    const target = fs.openReadWrite(io, .cwd(), target_path) catch |err| switch (err) {
        error.FileNotFound => try fs.createGuardedOutput(io, .cwd(), target_path),
        else => return err,
    };
    defer target.close(io);
    _ = try fs.validateGuardedOutputAuthority(io, target);
    if (try fs.sameOpenFile(io, target, source_file) or try fs.sameOpenFile(io, target, container)) return error.UnsafeOutput;
    try target.setLength(io, 0);
    const parts = [_]InputPart{.{ .file = source_file, .size = try source_file.length(io) }};
    const source = try streams.Input.init(io, &parts);
    const header = try sf20.info(io, container, offset, size);
    const targets = [_]GuardedPart{.{ .file = target, .size = header.new_size }};
    try sf20.apply(io, &source, container, offset, size, sf20Output(io, &targets, progress));
}

fn sf20Output(io: std.Io, parts: []const GuardedPart, progress: *Progress) streams.Output {
    return .{
        .io = io,
        .parts = parts,
        .progress = .{ .context = progress, .call_fn = progressCallback },
        .observer = if (hasOutputObserver(progress)) .{ .context = progress, .call_fn = outputCallback } else null,
    };
}

pub fn applyAtGuardedFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: InputPart,
    container: InputPart,
    offset: u64,
    size: u64,
    target: std.Io.File,
    progress: *Progress,
) !void {
    validateInputPart(io, source) catch return error.HDiffApplyFailed;
    validateInputPart(io, container) catch return error.HDiffApplyFailed;
    const kind = detectPatchKindFile(io, container, offset, size) catch
        return error.HDiffApplyFailed;
    switch (kind) {
        .w26 => {
            const options: w26_apply.Options = .{
                .output = if (hasOutputObserver(progress)) .{
                    .context = progress,
                    .call_fn = outputCallback,
                } else null,
                .progress = .{
                    .context = progress,
                    .call_fn = progressCallback,
                },
            };
            _ = w26_apply.applyFilesToFile(
                allocator,
                io,
                source.file,
                container.file,
                offset,
                size,
                target,
                options,
            ) catch |err| return mapApplyError(err);
            return;
        },
        .h13 => {
            const options: h13_apply.Options = .{
                .output = if (hasOutputObserver(progress)) .{
                    .context = progress,
                    .call_fn = outputCallback,
                } else null,
                .progress = .{
                    .context = progress,
                    .call_fn = progressCallback,
                },
            };
            _ = h13_apply.applyFilesToFile(
                allocator,
                io,
                source.file,
                container.file,
                offset,
                size,
                target,
                options,
            ) catch |err| return mapApplyError(err);
            return;
        },
        .sf20 => {},
    }

    const sources = [_]InputPart{source};
    const input = streams.Input.init(io, &sources) catch |err| return mapApplyError(err);
    const header = sf20.info(io, container.file, offset, size) catch |err| return mapApplyError(err);
    const targets = [_]GuardedPart{.{ .file = target, .size = header.new_size }};
    sf20.apply(io, &input, container.file, offset, size, sf20Output(io, &targets, progress)) catch |err| return mapApplyError(err);
}

fn validateInputPart(io: std.Io, input: InputPart) !void {
    const stat = try input.file.stat(io);
    if (stat.kind != .file or stat.size != input.size) return error.InvalidHDiffInput;
}

fn mapNativeCreateError(err: anyerror, progress: *Progress) anyerror {
    requireProgress(progress) catch |cancel| return cancel;
    return switch (err) {
        error.HDiffConstructionVerificationFailed, error.HDiffRollbackFailed, error.OutOfMemory => err,
        else => error.HDiffCreateFailed,
    };
}

test "native creation errors preserve failure authority" {
    var progress: Progress = .{};
    try std.testing.expectEqual(error.HDiffConstructionVerificationFailed, mapNativeCreateError(error.HDiffConstructionVerificationFailed, &progress));
    try std.testing.expectEqual(error.HDiffRollbackFailed, mapNativeCreateError(error.HDiffRollbackFailed, &progress));
    try std.testing.expectEqual(error.HDiffCreateFailed, mapNativeCreateError(error.ShortRead, &progress));
    progress.cancel();
    try std.testing.expectEqual(error.Interrupted, mapNativeCreateError(error.HDiffRollbackFailed, &progress));
}

const dispatch_prefix_size = sf20.magic.len;

fn detectPatchKind(io: std.Io, container_path: []const u8, offset: u64, size: u64) !Format {
    var container = try fs.openRead(io, std.Io.Dir.cwd(), container_path);
    defer container.close(io);

    return detectPatchKindFile(
        io,
        .{ .file = container, .size = try container.length(io) },
        offset,
        size,
    );
}

fn detectPatchKindFile(io: std.Io, container: InputPart, offset: u64, size: u64) !Format {
    const container_size = try container.file.length(io);
    if (container_size != container.size) return error.InvalidHDiff;

    const range_end = std.math.add(u64, offset, size) catch return error.InvalidHDiff;
    if (range_end > container_size) return error.InvalidHDiff;

    const wanted: usize = @intCast(@min(@as(u64, dispatch_prefix_size), size));
    var prefix: [dispatch_prefix_size]u8 = undefined;
    const count = try container.file.readPositionalAll(io, prefix[0..wanted], offset);
    if (count != wanted) return error.InvalidHDiff;
    const bytes = prefix[0..count];

    if (bytes.len >= w26.magic.len and std.mem.eql(u8, bytes[0..w26.magic.len], w26.magic))
        return .w26;
    if (bytes.len >= h13.magic.len and std.mem.eql(u8, bytes[0..h13.magic.len], h13.magic))
        return .h13;
    if (bytes.len >= sf20.magic.len and std.mem.eql(u8, bytes[0..sf20.magic.len], sf20.magic))
        return .sf20;
    return error.InvalidHDiff;
}

fn mapApplyError(err: anyerror) anyerror {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StepTooLarge, error.WindowTooLarge => error.InvalidHDiffMemoryRequirement,
        else => error.HDiffApplyFailed,
    };
}

test "SF20 guarded creator retains inputs and owns exact suffix rollback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var source_data: [48 * 1024]u8 = undefined;
    for (&source_data, 0..) |*byte, index|
        byte.* = @intCast((index * 31 + 9) % 251);
    var target_data = source_data;
    @memset(target_data[7000..11000], 0xa6);
    @memset(target_data[33000..35000], 0x3d);
    const prefix = "guarded-sf20-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "create-source.bin", .data = &source_data });
    try tmp.dir.writeFile(io, .{ .sub_path = "create-target.bin", .data = &target_data });
    try tmp.dir.writeFile(io, .{ .sub_path = "create-container.ziff", .data = prefix });

    var source = try fs.openRead(io, tmp.dir, "create-source.bin");
    defer source.close(io);
    var target = try fs.openRead(io, tmp.dir, "create-target.bin");
    defer target.close(io);
    var construction = try fs.openReadWrite(io, tmp.dir, "create-container.ziff");
    defer construction.close(io);
    const source_input: InputPart = .{ .file = source, .size = source_data.len };
    const target_input: InputPart = .{ .file = target, .size = target_data.len };

    var rejected_progress: Progress = .{};
    try std.testing.expectError(
        error.HDiffCreateFailed,
        createSf20AtGuardedFiles(
            io,
            .{ .file = source, .size = source_data.len + 1 },
            target_input,
            construction,
            prefix.len,
            default_match_block_size,
            5,
            &rejected_progress,
        ),
    );
    try std.testing.expectError(
        error.HDiffCreateFailed,
        createSf20AtGuardedFiles(
            io,
            source_input,
            .{ .file = target, .size = target_data.len + 1 },
            construction,
            prefix.len,
            default_match_block_size,
            5,
            &rejected_progress,
        ),
    );
    try std.testing.expectError(
        error.HDiffCreateFailed,
        createSf20AtGuardedFiles(
            io,
            source_input,
            target_input,
            construction,
            prefix.len + 1,
            default_match_block_size,
            5,
            &rejected_progress,
        ),
    );

    try std.testing.expectError(
        error.HDiffCreateFailed,
        createSf20AtGuardedFiles(
            io,
            source_input,
            target_input,
            source,
            source_data.len,
            default_match_block_size,
            5,
            &rejected_progress,
        ),
    );
    var source_after_alias: [source_data.len]u8 = undefined;
    try std.testing.expectEqual(
        source_after_alias.len,
        try source.readPositionalAll(io, &source_after_alias, 0),
    );
    try std.testing.expectEqualSlices(u8, &source_data, &source_after_alias);

    const untouched = try tmp.dir.readFileAlloc(
        io,
        "create-container.ziff",
        allocator,
        .limited(prefix.len + 1),
    );
    defer allocator.free(untouched);
    try std.testing.expectEqualStrings(prefix, untouched);

    // windows: refused rename still valid for borrowed-object test
    if (tmp.dir.rename("create-source.bin", tmp.dir, "retained-create-source.bin", io)) |_| {
        var hostile: [source_data.len]u8 = undefined;
        @memset(&hostile, 0x51);
        try tmp.dir.writeFile(io, .{ .sub_path = "create-source.bin", .data = &hostile });
    } else |err| switch (err) {
        error.FileBusy, error.AccessDenied => {},
        else => return err,
    }
    if (tmp.dir.rename("create-target.bin", tmp.dir, "retained-create-target.bin", io)) |_| {
        var hostile: [target_data.len]u8 = undefined;
        @memset(&hostile, 0xe4);
        try tmp.dir.writeFile(io, .{ .sub_path = "create-target.bin", .data = &hostile });
    } else |err| switch (err) {
        error.FileBusy, error.AccessDenied => {},
        else => return err,
    }

    sf20.TestFault.enabled = true;
    defer sf20.TestFault.enabled = false;
    var corrupt_progress: Progress = .{};
    try std.testing.expectError(
        error.HDiffConstructionVerificationFailed,
        createSf20AtGuardedFiles(
            io,
            source_input,
            target_input,
            construction,
            prefix.len,
            default_match_block_size,
            5,
            &corrupt_progress,
        ),
    );
    const rolled_back = try tmp.dir.readFileAlloc(
        io,
        "create-container.ziff",
        allocator,
        .limited(prefix.len + 1),
    );
    defer allocator.free(rolled_back);
    try std.testing.expectEqualStrings(prefix, rolled_back);

    sf20.TestFault.enabled = false;
    var create_progress: Progress = .{};
    const diff_size = try createSf20AtGuardedFiles(
        io,
        source_input,
        target_input,
        construction,
        prefix.len,
        default_match_block_size,
        5,
        &create_progress,
    );
    try std.testing.expect(diff_size > 0);

    var retained_target: [target_data.len]u8 = undefined;
    try std.testing.expectEqual(
        retained_target.len,
        try target.readPositionalAll(io, &retained_target, 0),
    );
    try std.testing.expectEqualSlices(u8, &target_data, &retained_target);

    var container = try fs.openRead(io, tmp.dir, "create-container.ziff");
    defer container.close(io);
    var output = try fs.createGuardedOutputBeneath(io, tmp.dir, "create-output.bin");
    defer output.close(io);
    var apply_progress: Progress = .{};
    try applyAtGuardedFiles(
        allocator,
        io,
        source_input,
        .{ .file = container, .size = try container.length(io) },
        prefix.len,
        diff_size,
        output,
        &apply_progress,
    );
    var actual: [target_data.len]u8 = undefined;
    try std.testing.expectEqual(actual.len, try output.readPositionalAll(io, &actual, 0));
    try std.testing.expectEqualSlices(u8, &target_data, &actual);
}

test "group guarded creator pins more than eight Source and Target inputs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    const part_count = 9;
    const part_size = 3072;
    var source_data: [part_count][part_size]u8 = undefined;
    var target_data: [part_count][part_size]u8 = undefined;
    var source_names: [part_count][]const u8 = undefined;
    var target_names: [part_count][]const u8 = undefined;
    for (0..part_count) |index| {
        source_names[index] = try scratch.print("group-create-source-{d}.bin", .{index});
        target_names[index] = try scratch.print("group-create-target-{d}.bin", .{index});
        for (&source_data[index], 0..) |*byte, byte_index|
            byte.* = @intCast((index * 47 + byte_index * 23 + 13) % 251);
        target_data[index] = source_data[index];
        @memset(target_data[index][333..777], @as(u8, @intCast(0x80 + index)));
        try tmp.dir.writeFile(io, .{
            .sub_path = source_names[index],
            .data = &source_data[index],
        });
        try tmp.dir.writeFile(io, .{
            .sub_path = target_names[index],
            .data = &target_data[index],
        });
    }
    const prefix = "group-guarded-prefix";
    try tmp.dir.writeFile(io, .{
        .sub_path = "group-create-container.ziff",
        .data = prefix,
    });
    var source_inputs: [part_count]InputPart = undefined;
    var target_inputs: [part_count]InputPart = undefined;
    var source_opened: usize = 0;
    var target_opened: usize = 0;
    defer for (source_inputs[0..source_opened]) |part| part.file.close(io);
    defer for (target_inputs[0..target_opened]) |part| part.file.close(io);
    for (0..part_count) |index| {
        const source = try fs.openRead(io, tmp.dir, source_names[index]);
        source_inputs[index] = .{ .file = source, .size = part_size };
        source_opened += 1;
        const target = try fs.openRead(io, tmp.dir, target_names[index]);
        target_inputs[index] = .{ .file = target, .size = part_size };
        target_opened += 1;
    }

    var hostile: [part_size]u8 = undefined;
    @memset(&hostile, 0x5a);
    for (0..part_count) |index| {
        const saved_source = try scratch.print("saved-group-create-source-{d}.bin", .{index});
        if (tmp.dir.rename(source_names[index], tmp.dir, saved_source, io)) |_| {
            try tmp.dir.writeFile(io, .{
                .sub_path = source_names[index],
                .data = &hostile,
            });
        } else |err| switch (err) {
            error.FileBusy, error.AccessDenied => {},
            else => return err,
        }

        const saved_target = try scratch.print("saved-group-create-target-{d}.bin", .{index});
        if (tmp.dir.rename(target_names[index], tmp.dir, saved_target, io)) |_| {
            try tmp.dir.writeFile(io, .{
                .sub_path = target_names[index],
                .data = &hostile,
            });
        } else |err| switch (err) {
            error.FileBusy, error.AccessDenied => {},
            else => return err,
        }
    }

    var create_progress: Progress = .{};
    var construction = try fs.openReadWrite(io, tmp.dir, "group-create-container.ziff");
    defer construction.close(io);
    const diff_size = try createSf20Parts(
        io,
        &source_inputs,
        &target_inputs,
        construction,
        prefix.len,
        default_match_block_size,
        5,
        &create_progress,
    );
    try std.testing.expect(diff_size > 0);

    for (target_inputs, target_data) |part, expected| {
        var retained_prefix: [32]u8 = undefined;
        try std.testing.expectEqual(
            retained_prefix.len,
            try part.file.readPositionalAll(io, &retained_prefix, 0),
        );
        try std.testing.expectEqualSlices(u8, expected[0..retained_prefix.len], &retained_prefix);
    }

    var container = try fs.openRead(io, tmp.dir, "group-create-container.ziff");
    defer container.close(io);
    var output_parts: [part_count]GuardedPart = undefined;
    var output_opened: usize = 0;
    defer for (output_parts[0..output_opened]) |part| part.file.close(io);
    for (&output_parts, 0..) |*part, index| {
        const name = try scratch.print("group-create-output-{d}.bin", .{index});
        const file = try fs.createGuardedOutputBeneath(io, tmp.dir, name);
        part.* = .{ .file = file, .size = part_size };
        output_opened += 1;
    }
    var apply_progress: Progress = .{};
    const input = try streams.Input.init(io, &source_inputs);
    try sf20.apply(io, &input, container, prefix.len, diff_size, sf20Output(io, &output_parts, &apply_progress));
    for (output_parts, target_data) |part, expected| {
        var actual: [part_size]u8 = undefined;
        try std.testing.expectEqual(
            actual.len,
            try part.file.readPositionalAll(io, &actual, 0),
        );
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "standard HDiff compression modes reconstruct and bind the exact appended range" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var source_data: [96 * 1024]u8 = undefined;
    for (&source_data, 0..) |*byte, index| byte.* = @intCast((index * 29 + 7) % 251);
    var target_data = source_data;
    @memset(target_data[13000..13777], 0xa5);
    @memset(target_data[71000..71888], 0x3c);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = &source_data });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = &target_data });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const source_identity: FileIdentity = .{
        .path = source_path,
        .size = source_data.len,
        .digest = ids.Digest.of(&source_data),
    };
    const target_identity: FileIdentity = .{
        .path = target_path,
        .size = target_data.len,
        .digest = ids.Digest.of(&target_data),
    };
    const prefix = "preserved-standard-prefix";
    const cases = [_]struct {
        compression: w26_write.Compression,
        level: c_int = 5,
        container: []const u8,
    }{
        .{ .compression = .stored, .container = "stored.patch" },
        .{ .compression = .zstd_if_smaller, .level = 1, .container = "fast.patch" },
        .{ .compression = .zstd_if_smaller, .level = 3, .container = "default.patch" },
        .{ .compression = .zstd_if_smaller, .container = "zig.patch" },
        .{ .compression = .zstd_if_smaller, .level = 22, .container = "best.patch" },
    };

    for ([_]Format{ .w26, .h13, .sf20 }) |format| {
        for (cases) |case| {
            try tmp.dir.writeFile(io, .{ .sub_path = case.container, .data = prefix });
            const container_path = try std.fs.path.join(allocator, &.{ root, case.container });
            defer allocator.free(container_path);

            var progress: Progress = .{};
            const result = try createAt(
                allocator,
                io,
                source_identity,
                target_identity,
                container_path,
                prefix.len,
                .{ .format = format, .compression = case.compression, .compression_level = case.level },
                &progress,
            );
            try std.testing.expect(result.patch_size != 0);
            try std.testing.expectEqual(format == .w26, result.construction != null);
            if (result.construction) |observed| {
                try std.testing.expect(observed.source_digest.eql(source_identity.digest));
                try std.testing.expect(observed.target_digest.eql(target_identity.digest));
            }

            const bytes = try tmp.dir.readFileAlloc(
                io,
                case.container,
                allocator,
                .limited(prefix.len + result.patch_size + 1),
            );
            defer allocator.free(bytes);
            try std.testing.expectEqual(prefix.len + result.patch_size, bytes.len);
            try std.testing.expectEqualStrings(prefix, bytes[0..prefix.len]);
            try std.testing.expect(result.patch_digest.eql(ids.Digest.of(bytes[prefix.len..])));
            try std.testing.expect(std.mem.startsWith(u8, bytes[prefix.len..], format.label()));
            if (format == .w26) {
                const info = try w26.parse(bytes[prefix.len..]);
                try w26.validatePatchExtent(info, result.patch_size);
                try std.testing.expectEqualStrings(w26_checksum.name, info.checksum_type);
                try std.testing.expectEqual(@as(u64, w26_checksum.byte_size), info.checksum_byte_size);
            }
        }
    }
}

test "standard HDiff wrong Target authority restores exact prefix" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var source_data: [32 * 1024]u8 = undefined;
    for (&source_data, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var target_data = source_data;
    @memset(target_data[4096..4608], 0x51);
    const prefix = "transaction-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = &source_data });
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = &target_data });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch", .data = prefix });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target" });
    defer allocator.free(target_path);
    const patch_path = try std.fs.path.join(allocator, &.{ root, "patch" });
    defer allocator.free(patch_path);

    for ([_]Format{ .w26, .h13, .sf20 }) |format| {
        var progress: Progress = .{};
        try std.testing.expectError(error.DigestMismatch, createAt(
            allocator,
            io,
            .{ .path = source_path, .size = source_data.len, .digest = ids.Digest.of(&source_data) },
            .{ .path = target_path, .size = target_data.len, .digest = ids.Digest.of("not the Target") },
            patch_path,
            prefix.len,
            .{ .format = format },
            &progress,
        ));
        var source_progress: Progress = .{};
        try std.testing.expectError(error.SourceChangedDuringCreate, createAt(
            allocator,
            io,
            .{ .path = source_path, .size = source_data.len, .digest = ids.Digest.of("not the Source") },
            .{ .path = target_path, .size = target_data.len, .digest = ids.Digest.of(&target_data) },
            patch_path,
            prefix.len,
            .{ .format = format },
            &source_progress,
        ));
        const got = try tmp.dir.readFileAlloc(io, "patch", allocator, .limited(prefix.len + 1));
        defer allocator.free(got);
        try std.testing.expectEqualStrings(prefix, got);
    }
}

test "pre-cancelled standard HDiff creators cannot mutate the append point" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source_bytes = "cancelled Source bytes";
    const target_bytes = "cancelled Target bytes";
    const prefix = "cancel-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = target_bytes });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target" });
    defer allocator.free(target_path);
    const cases = [_]struct {
        compression: w26_write.Compression,
        patch: []const u8,
    }{
        .{ .compression = .stored, .patch = "stored-cancel.patch" },
        .{ .compression = .zstd_if_smaller, .patch = "zig-cancel.patch" },
    };
    for ([_]Format{ .w26, .h13, .sf20 }) |format| {
        for (cases) |case| {
            try tmp.dir.writeFile(io, .{ .sub_path = case.patch, .data = prefix });
            const patch_path = try std.fs.path.join(allocator, &.{ root, case.patch });
            defer allocator.free(patch_path);
            var progress: Progress = .{};
            progress.cancel();
            try std.testing.expectError(error.Interrupted, createAt(
                allocator,
                io,
                .{ .path = source_path, .size = source_bytes.len, .digest = ids.Digest.of(source_bytes) },
                .{ .path = target_path, .size = target_bytes.len, .digest = ids.Digest.of(target_bytes) },
                patch_path,
                prefix.len,
                .{ .format = format, .compression = case.compression },
                &progress,
            ));
            const got = try tmp.dir.readFileAlloc(io, case.patch, allocator, .limited(prefix.len + 1));
            defer allocator.free(got);
            try std.testing.expectEqualStrings(prefix, got);
        }
    }
}

test "standard W26 creation profiles are validated before file access" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const missing: FileIdentity = .{ .path = "does-not-exist", .size = 0, .digest = .zero };
    var progress: Progress = .{};
    try std.testing.expectError(error.InvalidBlockSize, createAt(
        allocator,
        io,
        missing,
        missing,
        "missing-output",
        0,
        .{ .compression = .zstd_if_smaller, .match_block_size = standard_max_match_block_size + 1 },
        &progress,
    ));
    try std.testing.expectError(error.InvalidBlockSize, createAt(
        allocator,
        io,
        missing,
        missing,
        "missing-output",
        0,
        .{ .match_block_size = standard_min_match_block_size - 1 },
        &progress,
    ));
    try std.testing.expectError(error.InvalidWindowSize, createAt(
        allocator,
        io,
        missing,
        missing,
        "missing-output",
        0,
        .{ .old_window_size = standard_min_window_size - 1 },
        &progress,
    ));
    try std.testing.expectError(error.InvalidStepMemorySize, createAt(
        allocator,
        io,
        missing,
        missing,
        "missing-output",
        0,
        .{ .step_mem_size = standard_min_step_mem_size - 1 },
        &progress,
    ));
}

test "pure HDIFF13 facade applies and drives progress and output hashing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const patch = [_]u8{ 72, 68, 73, 70, 70, 49, 51, 38, 0, 4, 4, 0, 0, 0, 1, 0, 0, 0, 4, 0, 3, 97, 98, 88, 100 };
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch", .data = &patch });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source = try std.fs.path.join(allocator, &.{ root, "source" });
    defer allocator.free(source);
    const diff = try std.fs.path.join(allocator, &.{ root, "patch" });
    defer allocator.free(diff);
    const output = try std.fs.path.join(allocator, &.{ root, "output" });
    defer allocator.free(output);

    const prefix_info = try infoPrefix(&patch);
    try std.testing.expectEqual(@as(u64, 4), prefix_info.source_size);
    try std.testing.expectEqual(@as(u64, 4), prefix_info.target_size);
    const info = try infoAt(io, diff, 0, patch.len);
    try std.testing.expectEqual(prefix_info.source_size, info.source_size);
    try std.testing.expectEqual(prefix_info.target_size, info.target_size);

    var output_hash = OutputHash.init(4);
    var progress: Progress = .{ .output_hash = &output_hash };
    try applyAt(allocator, io, source, diff, 0, patch.len, output, &progress);
    try std.testing.expectEqual(@as(u64, 4), progress.done());
    var expected: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("abXd", &expected, .{});
    _ = try output_hash.verify(expected);
    const got = try tmp.dir.readFileAlloc(io, "output", allocator, .limited(5));
    defer allocator.free(got);
    try std.testing.expectEqualStrings("abXd", got);

    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, "guarded-output");
    defer guarded.close(io);
    var guarded_hash = OutputHash.init(4);
    var guarded_progress: Progress = .{ .output_hash = &guarded_hash };
    var source_file = try fs.openRead(io, tmp.dir, "source");
    defer source_file.close(io);
    var patch_file = try fs.openRead(io, tmp.dir, "patch");
    defer patch_file.close(io);
    try applyAtGuardedFiles(
        allocator,
        io,
        .{ .file = source_file, .size = 4 },
        .{ .file = patch_file, .size = patch.len },
        0,
        patch.len,
        guarded,
        &guarded_progress,
    );
    _ = try guarded_hash.verify(expected);
    var guarded_bytes: [4]u8 = undefined;
    try std.testing.expectEqual(
        guarded_bytes.len,
        try guarded.readPositionalAll(io, &guarded_bytes, 0),
    );
    try std.testing.expectEqualStrings("abXd", &guarded_bytes);
    try guarded.sync(io);
}

const stored_w26_fixture = [_]u8{
    0x48, 0x44, 0x49, 0x46, 0x46, 0x57, 0x32, 0x36, 0x0e, 0x00, 0x26, 0x00, 0x00, 0x0d, 0x04, 0x04,
    0x00, 0x01, 0x40, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01, 0x00, 0x04, 0x00,
    0x00, 0x61, 0x62, 0x58, 0x64,
};

test "pure HDIFFW26 facade applies an exact nonzero range with hooks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const prefix_info = try infoPrefix(&stored_w26_fixture);
    try std.testing.expectEqual(@as(u64, 4), prefix_info.source_size);
    try std.testing.expectEqual(@as(u64, 4), prefix_info.target_size);

    var container: std.ArrayList(u8) = .empty;
    defer container.deinit(allocator);
    try container.appendSlice(allocator, "prefix!");
    try container.appendSlice(allocator, &stored_w26_fixture);
    try container.appendSlice(allocator, "suffix!");
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container", .data = container.items });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source = try std.fs.path.join(allocator, &.{ root, "source" });
    defer allocator.free(source);
    const diff = try std.fs.path.join(allocator, &.{ root, "container" });
    defer allocator.free(diff);
    const output = try std.fs.path.join(allocator, &.{ root, "output" });
    defer allocator.free(output);

    var output_hash = OutputHash.init(4);
    var progress: Progress = .{ .output_hash = &output_hash };
    try applyAt(
        allocator,
        io,
        source,
        diff,
        "prefix!".len,
        stored_w26_fixture.len,
        output,
        &progress,
    );
    try std.testing.expectEqual(@as(u64, 4), progress.done());
    var expected: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("abXd", &expected, .{});
    _ = try output_hash.verify(expected);
    const got = try tmp.dir.readFileAlloc(io, "output", allocator, .limited(5));
    defer allocator.free(got);
    try std.testing.expectEqualStrings("abXd", got);

    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, "guarded-output");
    defer guarded.close(io);
    var guarded_hash = OutputHash.init(4);
    var guarded_progress: Progress = .{ .output_hash = &guarded_hash };
    var source_file = try fs.openRead(io, tmp.dir, "source");
    defer source_file.close(io);
    var container_file = try fs.openRead(io, tmp.dir, "container");
    defer container_file.close(io);
    try applyAtGuardedFiles(
        allocator,
        io,
        .{ .file = source_file, .size = 4 },
        .{ .file = container_file, .size = container.items.len },
        "prefix!".len,
        stored_w26_fixture.len,
        guarded,
        &guarded_progress,
    );
    _ = try guarded_hash.verify(expected);
    var guarded_bytes: [4]u8 = undefined;
    try std.testing.expectEqual(
        guarded_bytes.len,
        try guarded.readPositionalAll(io, &guarded_bytes, 0),
    );
    try std.testing.expectEqualStrings("abXd", &guarded_bytes);
    try guarded.sync(io);
}

test "checksummed HDIFFW26 is rejected without bundled SF20 fallback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // unsupported checksum name for dispatch validation
    const patch = [_]u8{
        0x48, 0x44, 0x49, 0x46, 0x46, 0x57, 0x32, 0x36, 0x12, 0x00,
        0x26, 0x78, 0x00, 0x00, 0x0d, 0x04, 0x04, 0x00, 0x01, 0x40,
        0x04, 0x01, 0x00, 0x01, 0x00, 0xaa, 0xbb, 0xcc, 0x00, 0x00,
        0x01, 0x03, 0x01, 0x00, 0x04, 0x00, 0x00, 0x61, 0x62, 0x58,
        0x64,
    };
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = "abcd" });
    try tmp.dir.writeFile(io, .{ .sub_path = "patch", .data = &patch });
    try tmp.dir.writeFile(io, .{ .sub_path = "output", .data = "sentinel" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source = try std.fs.path.join(allocator, &.{ root, "source" });
    defer allocator.free(source);
    const diff = try std.fs.path.join(allocator, &.{ root, "patch" });
    defer allocator.free(diff);
    const output = try std.fs.path.join(allocator, &.{ root, "output" });
    defer allocator.free(output);

    var progress: Progress = .{};
    try std.testing.expectError(
        error.HDiffApplyFailed,
        applyAt(allocator, io, source, diff, 0, patch.len, output, &progress),
    );
    const got = try tmp.dir.readFileAlloc(io, "output", allocator, .limited(9));
    defer allocator.free(got);
    try std.testing.expectEqualStrings("sentinel", got);
    try std.testing.expectEqual(@as(u64, 0), progress.done());
}

const Interop = struct {
    const allocator = std.heap.smp_allocator;
    const root = ".zig-cache/codec-interop";
    const old_path = root ++ "/old";
    const new_path = root ++ "/new";
    const patch_path = root ++ "/patch";
    const out_path = root ++ "/out";

    fn external(io: std.Io, argv: []const []const u8) !void {
        const result = try std.process.run(allocator, io, .{ .argv = argv, .stdout_limit = .limited(64 * 1024), .stderr_limit = .limited(64 * 1024) });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code == 0) return,
            else => {},
        }
        std.debug.print("external HDiff failure: {s}\n{s}\n", .{ result.stdout, result.stderr });
        return error.ExternalHDiffFailed;
    }
    fn reset(io: std.Io, dir: std.Io.Dir) !void {
        for ([_][]const u8{ "patch", "out" }) |name|
            try dir.writeFile(io, .{ .sub_path = name, .data = "" });
    }
    fn check(io: std.Io, expected: []const u8) !void {
        const file = try fs.openRead(io, .cwd(), out_path);
        defer file.close(io);
        if (try file.length(io) != expected.len) return error.OutputSizeMismatch;
        var buffer: [64 * 1024]u8 = undefined;
        var pos: usize = 0;
        while (pos < expected.len) {
            const take = @min(buffer.len, expected.len - pos);
            if (try fs.readAllAt(io, file, buffer[0..take], pos) != take or
                !std.mem.eql(u8, buffer[0..take], expected[pos..][0..take])) return error.OutputMismatch;
            pos += take;
        }
    }

    fn run(io: std.Io) !void {
        try std.Io.Dir.cwd().createDirPath(io, root);
        const dir = try std.Io.Dir.cwd().openDir(io, root, .{});
        defer dir.close(io);
        defer for ([_][]const u8{ "old", "new", "patch", "out" }) |name| {
            dir.deleteFile(io, name) catch {};
        };
        var random = std.Random.DefaultPrng.init(0x7a69675f706f7274);
        for ([_]usize{ 0, 1, 3, 16, 63, 256, 4096, 262145, 1048593, 4194305 }) |length| {
            const source = try allocator.alloc(u8, length);
            defer allocator.free(source);
            random.random().bytes(source);
            for (0..3) |kind| {
                if (kind == 2) @memset(source, 0x51);
                const target = try allocator.alloc(u8, length + (if (kind == 1) @as(usize, 97) else 0));
                defer allocator.free(target);
                if (kind == 1) {
                    random.random().bytes(target[0..97]);
                    @memcpy(target[97..], source);
                } else @memcpy(target, source);
                if (kind != 0 and target.len > 73) {
                    var pos: usize = 0;
                    const stride: usize = if (length == 4194305) 192 else 4096;
                    while (pos < target.len) : (pos += stride) {
                        for (target[pos..@min(target.len, pos + 73)]) |*byte| byte.* +%= 41;
                    }
                }
                try dir.writeFile(io, .{ .sub_path = "old", .data = source });
                try dir.writeFile(io, .{ .sub_path = "new", .data = target });
                // upstream SF20: ADD/RLE coverage beyond exact-copy writer
                for ([_]bool{ false, true }) |compressed| {
                    try reset(io, dir);
                    const old = try fs.openRead(io, dir, "old");
                    defer old.close(io);
                    const new = try fs.openRead(io, dir, "new");
                    defer new.close(io);
                    const patch = try fs.openReadWrite(io, dir, "patch");
                    defer patch.close(io);
                    var progress: Progress = .{};
                    _ = try createSf20AtGuardedFiles(io, .{ .file = old, .size = source.len }, .{ .file = new, .size = target.len }, patch, 0, 64, if (compressed) 5 else null, &progress);
                    try external(io, &.{ "../hdiffpatch/hpatchz", "-f", old_path, patch_path, out_path });
                    try check(io, target);
                    try reset(io, dir);
                    var h13_progress: Progress = .{};
                    _ = try createH13AtGuardedFiles(allocator, io, .{ .file = old, .size = source.len }, .{ .file = new, .size = target.len }, patch, 0, 64, if (compressed) 5 else null, &h13_progress);
                    if (length == 4194305 and kind == 1) {
                        var prefix: [512]u8 = undefined;
                        const size = try fs.readAllAt(io, patch, &prefix, 0);
                        try std.testing.expect((try h13.parse(prefix[0..size])).covers.raw > 64 * 1024);
                    }
                    try external(io, &.{ "../hdiffpatch/hpatchz", "-f", old_path, patch_path, out_path });
                    try check(io, target);
                    for ([_][]const u8{ "-SD-4k", "-m" }) |format| {
                        try reset(io, dir);
                        try external(io, &.{ "../hdiffpatch/hdiffz", "-f", format, if (compressed) "-c-zstd-5" else "-c-no", old_path, new_path, patch_path });
                        var apply_progress: Progress = .{};
                        try applyAt(allocator, io, old_path, patch_path, 0, try patch.length(io), out_path, &apply_progress);
                        try check(io, target);
                    }
                    try reset(io, dir);
                    var standard_progress: Progress = .{};
                    _ = try createAt(allocator, io, .{ .path = old_path, .size = source.len, .digest = ids.Digest.of(source) }, .{ .path = new_path, .size = target.len, .digest = ids.Digest.of(target) }, patch_path, 0, .{ .compression = if (compressed) .zstd_if_smaller else .stored }, &standard_progress);
                    try external(io, &.{ "../hdiffpatch/hpatchz", "-f", "-C-all", old_path, patch_path, out_path });
                    try check(io, target);
                }
            }
        }
    }
};

test "independent HDiff interoperability" {
    if (!@import("test_options").codec_interop) return error.SkipZigTest;
    try Interop.run(std.testing.io);
}

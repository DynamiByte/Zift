// ziff payload construction and resumable finalization

const std = @import("std");
const Thread = std.Thread;
const tree = @import("../tree.zig");
const content = @import("../core/content.zig");
const zstd_c = @import("../compression/zstd_c.zig");
const match_index = @import("../match/index.zig");
const dirscan = @import("../core/dirscan.zig");
const fs = @import("../core/fs.zig");
const ids = @import("../core/ids.zig");
const ranges = @import("../core/ranges.zig");
const scan = @import("../core/scan.zig");
const merge_mod = @import("../match/merge.zig");
const zar26 = @import("../format/zar26.zig");
const production_options = @import("../production_options.zig");
const profile = @import("../profile.zig");
const ziff = @import("../format/ziff.zig");
const ziff_file = @import("../format/ziff_file.zig");
const ui = @import("../ui.zig");
const interrupt = @import("../interrupt.zig");
const manifest_mod = @import("../core/manifest.zig");

pub const default_buffer_bytes: usize = 1024 * 1024;
pub const max_buffer_bytes: usize = 64 * 1024 * 1024;
pub const default_serializer_memory_bytes: usize = 256 * 1024 * 1024;
pub const minimum_serializer_memory_bytes: usize = 64 * 1024 * 1024;
const zstd_output_buffer_bytes: usize = 128 * 1024;

// slice-major covers retained across units
const max_family_cover_bytes: usize = 512 * 1024 * 1024;
const max_singleton_batch_families: usize = 128;
const max_singleton_batch_source_parts: usize = 512;
// leave CPU headroom for indexing
const max_singleton_pipeline_workers: usize = 4;
const zstd_continue: c_int = 0;
const zstd_end: c_int = 2;
const zstd_window_log_min: u8 = 10;
const zstd_window_log_max: u8 = if (@bitSizeOf(usize) == 32) 30 else 31;

pub const Bindings = struct {
    source_root: []const u8,
    target_root: []const u8,
    container_path: []const u8,
    // same exclusion policy as source planning
    source_ignore: ?dirscan.IgnorePath = null,
    source_manifest: ?[]const ziff.FileEntry = null,
};

pub const Options = struct {
    target_metadata: []const manifest_mod.MetadataFile = &.{},
    target_size_problem: ?*TargetSizeProblem = null,
    progress: ?*ui.Operation = null,
    // borrowed through finalization
    target_observations: ?*tree.Tree = null,
    buffer_bytes: usize = default_buffer_bytes,
    source_reader: scan.Reader = .direct,
    payload_reader: scan.Reader = .direct,
    matcher_reader: scan.Reader = .direct,
    // 0 = whole-family index; otherwise per-source-slice bound
    slice_budget: u64 = production_options.matcher_slice_budget,
    // 0 = automatic worker counts
    matcher_threads: usize = 0,
    matcher_search_workers: usize = 0,
    serializer_workers: usize = 0,
    // oversized units: direct streaming outside buffer pool
    serializer_memory_bytes: usize = default_serializer_memory_bytes,
};

pub const TargetSizeProblem = struct {
    pub const Details = struct { path: []const u8, expected: u64, actual: u64 };

    details: ?Details = null,
    mutex: std.Io.Mutex = .init,

    fn record(problem: *TargetSizeProblem, io: std.Io, details: Details) void {
        problem.mutex.lockUncancelable(io);
        defer problem.mutex.unlock(io);
        if (problem.details == null) problem.details = details;
    }
};

pub const Stats = struct {
    payload_start: u64,
    payload_end: u64,
    raw_units: u32,
    zstd_units: u32,
    zar26_units: u32,
    zar26: zar26.Stats = .{},
    identity_completion_bytes: u64 = 0,
};

const FullStats = struct {
    payload_length: u64,
    target_digest: ?ids.Digest,
};

fn addZar26Stats(total: *zar26.Stats, value: zar26.Stats) void {
    inline for (@typeInfo(zar26.Stats).@"struct".field_names) |name|
        @field(total, name) += @field(value, name);
}

const SourceSnapshot = struct {
    allocator: std.mem.Allocator,
    files: []const ziff.FileEntry,
    owns_files: bool = false,
    index: std.StringHashMapUnmanaged(usize) = .empty,

    fn borrowed(allocator: std.mem.Allocator, files: []const ziff.FileEntry) !SourceSnapshot {
        var index: std.StringHashMapUnmanaged(usize) = .empty;
        errdefer index.deinit(allocator);
        try index.ensureTotalCapacity(allocator, @intCast(files.len));
        for (files, 0..) |file, position| {
            const got = index.getOrPutAssumeCapacity(file.path);
            if (got.found_existing) return error.DuplicateSourcePath;
            got.value_ptr.* = position;
        }
        return .{ .allocator = allocator, .files = files, .index = index };
    }

    fn observed(allocator: std.mem.Allocator, entries: []scan.Entry) !SourceSnapshot {
        const files = try allocator.alloc(ziff.FileEntry, entries.len);
        errdefer allocator.free(files);
        for (entries, files) |entry, *file| file.* = .{
            .path = entry.path,
            .size = entry.size,
            .digest = entry.digest,
        };
        var snapshot = try borrowed(allocator, files);
        snapshot.owns_files = true;
        allocator.free(entries);
        return snapshot;
    }

    fn find(snapshot: *const SourceSnapshot, path: []const u8) ?*const ziff.FileEntry {
        const position = snapshot.index.get(path) orelse return null;
        return &snapshot.files[position];
    }

    fn deinit(snapshot: *SourceSnapshot) void {
        snapshot.index.deinit(snapshot.allocator);
        if (snapshot.owns_files) {
            for (snapshot.files) |file| snapshot.allocator.free(file.path);
            snapshot.allocator.free(snapshot.files);
        }
        snapshot.* = undefined;
    }
};

test "source snapshots preserve borrowed manifests and clean up ownership transfers" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const manifest = [_]ziff.FileEntry{
                .{ .path = "b", .size = 2, .digest = ids.Digest.of("bb") },
                .{ .path = "a", .size = 1, .digest = ids.Digest.of("a") },
            };
            var borrowed = try SourceSnapshot.borrowed(allocator, &manifest);
            defer borrowed.deinit();
            try std.testing.expectEqual(manifest[1].digest, borrowed.find("a").?.digest);
            try std.testing.expectEqual(manifest[0..].ptr, borrowed.files.ptr);
            var empty = try SourceSnapshot.borrowed(allocator, &.{});
            defer empty.deinit();
            try std.testing.expect(empty.find("absent") == null);

            const entries = try allocator.alloc(scan.Entry, manifest.len);
            var initialized: usize = 0;
            var owns_entries = true;
            defer if (owns_entries) {
                for (entries[0..initialized]) |entry| allocator.free(entry.path);
                allocator.free(entries);
            };
            for (manifest, entries) |file, *entry| {
                entry.* = .{ .path = try allocator.dupe(u8, file.path), .size = file.size, .digest = file.digest };
                initialized += 1;
            }
            var observed = try SourceSnapshot.observed(allocator, entries);
            owns_entries = false;
            defer observed.deinit();
            try std.testing.expectEqual(manifest[0].size, observed.find("b").?.size);
            try std.testing.expectEqual(manifest[1].digest, observed.find("a").?.digest);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

fn checkedAdd(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch return error.IntegerOverflow;
}

// write-callback budget enforcement, independent of allocator growth
fn bufferedPayloadLimit(target_size: u64) !usize {
    const doubled = std.math.mul(u64, target_size, 2) catch return error.OutputTooLarge;
    const with_overhead = std.math.add(u64, doubled, 1024 * 1024) catch return error.OutputTooLarge;
    return std.math.cast(usize, with_overhead) orelse error.OutputTooLarge;
}

fn digestOpenInput(
    io: std.Io,
    input: struct { file: std.Io.File, size: u64 },
    buffer: []u8,
    reader: scan.Reader,
) !ids.Digest {
    if (buffer.len == 0) return error.InvalidBufferSize;
    if (try input.file.length(io) != input.size) return error.SourceChangedDuringCreate;

    var hasher = std.crypto.hash.Blake3.init(.{});
    var offset: u64 = 0;
    while (offset < input.size) {
        try interrupt.check();
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), input.size - offset));
        const count = try reader.read(io, input.file, buffer[0..wanted], offset);
        if (count > wanted) return error.InvalidReadCount;
        if (count != wanted) return error.SourceChangedDuringCreate;
        hasher.update(buffer[0..count]);
        offset = try checkedAdd(offset, @intCast(count));
    }
    if (try input.file.length(io) != input.size) return error.SourceChangedDuringCreate;

    var digest: ids.Digest = undefined;
    hasher.final(&digest.bytes);
    return digest;
}

fn compressionWindowLog(plain_size: u64) c_int {
    const extent = @max(plain_size, 1);
    const needed: u8 = @intCast(std.math.log2_int_ceil(u64, extent));
    return std.math.clamp(needed, zstd_window_log_min, zstd_window_log_max);
}

fn joinedPath(allocator: std.mem.Allocator, root: []const u8, path: []const u8) ![]u8 {
    if (root.len == 0) return allocator.dupe(u8, path);
    return std.fs.path.join(allocator, &.{ root, path });
}

fn plannedTarget(directory: ziff.Directory, unit: ziff.Unit) !struct { index: u32, file: ziff.FileEntry } {
    const file_index = unit.target;
    if (file_index >= directory.files.len) return error.OutputFileIndexOutOfRange;
    return .{ .index = file_index, .file = directory.files[file_index] };
}

fn requireTargetSize(io: std.Io, file: std.Io.File, entry: ziff.FileEntry, problem: ?*TargetSizeProblem) !void {
    const actual = try file.length(io);
    if (actual == entry.size) return;
    if (problem) |value| value.record(io, .{ .path = entry.path, .expected = entry.size, .actual = actual });
    return error.TargetSizeChanged;
}

fn openTarget(io: std.Io, root: std.Io.Dir, entry: ziff.FileEntry, problem: ?*TargetSizeProblem) !std.Io.File {
    var file = try fs.openReadAuthorityBeneath(io, root, entry.path);
    errdefer file.close(io);
    try requireTargetSize(io, file, entry, problem);
    return file;
}

fn prevalidatePlan(
    allocator: std.mem.Allocator,
    header: ziff.Header,
    directory: ziff.Directory,
) !u64 {
    if (header.unit_count != directory.units.len) return error.UnitCountMismatch;
    for (directory.units) |unit| {
        if (unit.payload_offset != 0 or unit.payload_len != 0) {
            return error.PayloadMetadataAlreadySet;
        }
    }

    const encoded_header = try ziff.encodeHeader(allocator, header);
    defer allocator.free(encoded_header);
    const payload_start = try checkedAdd(ziff.preamble_size, encoded_header.len);
    const temporary_units = try allocator.dupe(ziff.Unit, directory.units);
    defer allocator.free(temporary_units);
    var cursor = payload_start;
    for (temporary_units) |*unit| {
        unit.payload_offset = cursor;
        unit.payload_len = switch (unit.kind) {
            .raw => directory.files[unit.target].size,
            .zstd, .patch_zar26 => 1,
        };
        cursor = try checkedAdd(cursor, unit.payload_len);
    }
    const temporary_directory: ziff.Directory = .{
        .files = directory.files,
        .ops = directory.ops,
        .units = temporary_units,
        .sources = directory.sources,
        .removed = directory.removed,
        .replays = directory.replays,
    };
    try ziff.validate(allocator, header, temporary_directory, payload_start, cursor);
    return payload_start;
}

fn validateSourceIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    header: ziff.Header,
    bindings: Bindings,
    options: Options,
) !SourceSnapshot {
    if (bindings.source_manifest) |manifest| {
        // manifest: logical membership; family use: physical validation
        if (!ziff.logicalFingerprint(manifest).eql(header.source_fingerprint))
            return error.SourceFingerprintMismatch;
        var total: u64 = 0;
        for (manifest) |entry| total = try checkedAdd(total, entry.size);
        if (total != header.source_bytes) return error.SourceBytesMismatch;
        return SourceSnapshot.borrowed(allocator, manifest);
    }
    const entries = try scan.enumerate(allocator, io, bindings.source_root, bindings.source_ignore);
    var owns_entries = true;
    defer if (owns_entries) scan.deinitEntries(allocator, entries);
    const observed = try scan.hashAll(allocator, io, bindings.source_root, entries, .{
        .buffer_bytes = options.buffer_bytes,
        .reader = options.source_reader,
    });
    if (observed.bytes != header.source_bytes) return error.SourceBytesMismatch;
    var snapshot = try SourceSnapshot.observed(allocator, entries);
    owns_entries = false;
    errdefer snapshot.deinit();
    if (!ziff.logicalFingerprint(snapshot.files).eql(header.source_fingerprint))
        return error.SourceFingerprintMismatch;
    return snapshot;
}

fn validatePhysicalBindings(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    bindings: Bindings,
    target_size_problem: ?*TargetSizeProblem,
) !void {
    const cwd = std.Io.Dir.cwd();
    const checked = try allocator.alloc(?u64, directory.files.len);
    defer allocator.free(checked);
    @memset(checked, null);
    for (directory.units) |unit| {
        const target = try plannedTarget(directory, unit);
        const target_path = try joinedPath(allocator, bindings.target_root, target.file.path);
        defer allocator.free(target_path);
        var target_file = try fs.openRead(io, cwd, target_path);
        defer target_file.close(io);
        try requireTargetSize(io, target_file, target.file, target_size_problem);

        const first: usize = unit.source_first;
        const count: usize = unit.source_count;
        if (first > directory.sources.len or count > directory.sources.len - first) {
            return error.SourceSliceOutOfRange;
        }
        for (directory.sources[first..][0..count]) |source| {
            if (source.offset != 0) return error.PartialSourceUnsupported;
            if (source.file >= directory.files.len) return error.SourceFileIndexOutOfRange;
            // shared file entry may hold the target's size
            if (checked[source.file]) |validated| {
                if (validated == source.length) continue;
            }
            const source_path = try joinedPath(allocator, bindings.source_root, directory.files[source.file].path);
            defer allocator.free(source_path);
            var source_file = try fs.openRead(io, cwd, source_path);
            defer source_file.close(io);
            if (try source_file.length(io) != source.length) return error.PartialSourceUnsupported;
            checked[source.file] = source.length;
        }
    }
}

fn writeCompressedInput(
    io: std.Io,
    output: std.Io.File,
    stream: *zstd_c.ZstdCStream,
    input_bytes: []const u8,
    output_buffer: []u8,
    output_position: *u64,
) !void {
    var input: zstd_c.ZstdInBuffer = .{
        .src = if (input_bytes.len == 0) null else input_bytes.ptr,
        .size = input_bytes.len,
        .pos = 0,
    };
    while (input.pos < input.size) {
        try interrupt.check();
        var compressed: zstd_c.ZstdOutBuffer = .{
            .dst = output_buffer.ptr,
            .size = output_buffer.len,
            .pos = 0,
        };
        const before = input.pos;
        const remaining = zstd_c.ZSTD_compressStream2(stream, &compressed, &input, zstd_continue);
        if (zstd_c.ZSTD_isError(remaining) != 0) return error.ZstdCompressFailed;
        if (compressed.pos != 0) {
            try output.writePositionalAll(io, output_buffer[0..compressed.pos], output_position.*);
            output_position.* = try checkedAdd(output_position.*, compressed.pos);
        }
        if (input.pos == before and compressed.pos == 0) return error.ZstdMadeNoProgress;
    }
}

fn finishCompressed(
    io: std.Io,
    output: std.Io.File,
    stream: *zstd_c.ZstdCStream,
    output_buffer: []u8,
    output_position: *u64,
) !void {
    var input: zstd_c.ZstdInBuffer = .{ .src = null, .size = 0, .pos = 0 };
    while (true) {
        try interrupt.check();
        var compressed: zstd_c.ZstdOutBuffer = .{
            .dst = output_buffer.ptr,
            .size = output_buffer.len,
            .pos = 0,
        };
        const remaining = zstd_c.ZSTD_compressStream2(stream, &compressed, &input, zstd_end);
        if (zstd_c.ZSTD_isError(remaining) != 0) return error.ZstdCompressFailed;
        if (compressed.pos != 0) {
            try output.writePositionalAll(io, output_buffer[0..compressed.pos], output_position.*);
            output_position.* = try checkedAdd(output_position.*, compressed.pos);
        }
        if (remaining == 0) return;
        if (compressed.pos == 0) return error.ZstdMadeNoProgress;
    }
}

fn writeFullUnit(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_path: []const u8,
    target_entry: ziff.FileEntry,
    output: std.Io.File,
    output_offset: u64,
    kind: ziff.UnitKind,
    options: Options,
) !FullStats {
    const target_size = target_entry.size;
    const cwd = std.Io.Dir.cwd();
    var target = try fs.openRead(io, cwd, target_path);
    defer target.close(io);
    try requireTargetSize(io, target, target_entry, options.target_size_problem);
    if (try output.length(io) != output_offset) return error.OutputOffsetMismatch;

    const input_buffer = try allocator.alloc(u8, options.buffer_bytes);
    defer allocator.free(input_buffer);
    const output_buffer = if (kind == .zstd)
        try allocator.alloc(u8, zstd_output_buffer_bytes)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(output_buffer);
    const stream: ?*zstd_c.ZstdCStream = if (kind == .zstd) zstd_c.ZSTD_createCStream() else null;
    if (kind == .zstd and stream == null) return error.ZstdCompressFailed;
    defer if (stream) |value| {
        _ = zstd_c.ZSTD_freeCStream(value);
    };
    if (stream) |value| {
        if (zstd_c.ZSTD_isError(zstd_c.ZSTD_initCStream(value, production_options.zstd_level_full)) != 0) {
            return error.ZstdCompressFailed;
        }
        // pledged size + bounded history against excess decoder allocation
        if (zstd_c.ZSTD_isError(zstd_c.ZSTD_CCtx_setParameter(
            value,
            zstd_c.zstd_c_window_log,
            compressionWindowLog(target_size),
        )) != 0) return error.ZstdCompressFailed;
        if (zstd_c.ZSTD_isError(zstd_c.ZSTD_CCtx_setPledgedSrcSize(value, target_size)) != 0) {
            return error.ZstdCompressFailed;
        }
    }

    var local_state: content.State = .{ .size = target_size };
    const state = if (try observationFor(allocator, options.target_observations, target_entry)) |observed|
        observed
    else
        &local_state;
    try state.bindVerification(target_entry.verification);
    var target_position: u64 = 0;
    var output_position = output_offset;
    while (target_position < target_size) {
        try interrupt.check();
        const wanted: usize = @intCast(@min(@as(u64, input_buffer.len), target_size - target_position));
        const count = try options.payload_reader.read(io, target, input_buffer[0..wanted], target_position);
        if (count > wanted) return error.InvalidReadCount;
        if (count != wanted) return error.ShortTargetRead;
        const bytes = input_buffer[0..count];
        try state.observe(target_position, bytes);
        switch (kind) {
            .raw => {
                try output.writePositionalAll(io, bytes, output_position);
                output_position = try checkedAdd(output_position, count);
            },
            .zstd => try writeCompressedInput(io, output, stream.?, bytes, output_buffer, &output_position),
            else => return error.UnsupportedProductionUnit,
        }
        target_position = try checkedAdd(target_position, count);
        if (options.progress) |progress| progress.advanceWork(count, 0);
    }
    if (stream) |value| try finishCompressed(io, output, value, output_buffer, &output_position);
    try requireTargetSize(io, target, target_entry, options.target_size_problem);
    if (try output.length(io) != output_position) return error.OutputSizeMismatch;
    const digest = try state.finish(io, target, input_buffer, options.payload_reader);
    const deferred = options.target_observations != null and target_entry.digest.eql(content.pending_digest);
    if (digest) |value| if (!deferred and !target_entry.digest.eql(.zero) and !value.eql(target_entry.digest))
        return error.TargetDigestMismatch;
    return .{ .payload_length = output_position - output_offset, .target_digest = digest };
}

fn truncateContainerSuffix(io: std.Io, file: std.Io.File, offset: u64) !void {
    if (try file.length(io) < offset) return error.OutputOffsetMismatch;
    try file.setLength(io, offset);
    if (try file.length(io) != offset) return error.OutputSizeMismatch;
}

const LogicalPart = struct {
    file: std.Io.File,
    logical_start: u64,
    size: u64,
    observation: ?*content.State = null,
};

const LogicalInput = struct {
    io: std.Io,
    reader: scan.Reader,
    parts: []const LogicalPart,
    size: u64,

    fn readCallback(context: *anyopaque, offset: u64, destination: []u8) !void {
        const self: *LogicalInput = @ptrCast(@alignCast(context));
        try self.readExact(destination, offset);
    }

    fn readExact(self: *LogicalInput, destination: []u8, offset: u64) !void {
        try interrupt.check();
        if (destination.len == 0) return;
        const end = std.math.add(u64, offset, destination.len) catch return error.ReadOutOfBounds;
        if (end > self.size) return error.ReadOutOfBounds;
        var done: usize = 0;
        var position = offset;
        while (done < destination.len) {
            // ordered contiguous parts required by binary search
            var low: usize = 0;
            var high: usize = self.parts.len;
            var found: ?LogicalPart = null;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const part = self.parts[middle];
                if (position < part.logical_start) {
                    high = middle;
                } else if (position >= part.logical_start + part.size) {
                    low = middle + 1;
                } else {
                    found = part;
                    break;
                }
            }
            const part = found orelse return error.ReadOutOfBounds;
            const relative = position - part.logical_start;
            const available = part.size - relative;
            const want: usize = @intCast(@min(@as(u64, destination.len - done), available));
            const got = try self.reader.read(self.io, part.file, destination[done .. done + want], relative);
            if (got != want) return error.ShortRead;
            if (part.observation) |state| try state.observe(relative, destination[done .. done + want]);
            done += want;
            position += want;
        }
    }

    fn matchInput(self: *LogicalInput) match_index.Input {
        return .{ .context = self, .size = self.size, .read_at = LogicalInput.readCallback };
    }

    fn zarRead(context: ?*anyopaque, offset: u64, destination: []u8) !void {
        const self: *LogicalInput = @ptrCast(@alignCast(context.?));
        try self.readExact(destination, offset);
    }

    fn zarInput(self: *LogicalInput) zar26.Input {
        return .{ .context = self, .size = self.size, .read_at = zarRead };
    }
};

const SourcePart = struct {
    path: []const u8,
    logical_start: u64,
    size: u64,
    identity: fs.ObjectIdentity,
    mtime: std.Io.Timestamp,
    ctime: std.Io.Timestamp,

    fn capture(io: std.Io, file: std.Io.File, path: []const u8, logical_start: u64, size: u64) !SourcePart {
        const stat = try file.stat(io);
        if (stat.size != size) return error.SourceChangedDuringCreate;
        return .{
            .path = path,
            .logical_start = logical_start,
            .size = size,
            .identity = try fs.openFileIdentity(file),
            .mtime = stat.mtime,
            .ctime = stat.ctime,
        };
    }

    fn validate(self: SourcePart, io: std.Io, file: std.Io.File) !void {
        const stat = try file.stat(io);
        if (stat.size != self.size or stat.mtime.nanoseconds != self.mtime.nanoseconds or
            stat.ctime.nanoseconds != self.ctime.nanoseconds or
            !(try fs.openFileIdentity(file)).eql(self.identity))
            return error.SourceChangedDuringCreate;
    }
};

const SourceInput = struct {
    io: std.Io,
    root: std.Io.Dir,
    reader: scan.Reader,
    parts: []const SourcePart,
    size: u64,
    base: u64 = 0,
};

const SourceHandle = struct { part: usize, file: std.Io.File };

// index callbacks serialized by Index; serializers own separate readers
const SourceReader = struct {
    input: SourceInput,
    handles: []SourceHandle,
    opened: usize = 0,

    fn deinit(self: *SourceReader) void {
        for (self.handles[0..self.opened]) |handle| handle.file.close(self.input.io);
        self.opened = 0;
    }

    fn openPart(self: *SourceReader, index: usize) !std.Io.File {
        for (self.handles[0..self.opened], 0..) |handle, position| {
            if (handle.part != index) continue;
            std.mem.copyBackwards(SourceHandle, self.handles[1 .. position + 1], self.handles[0..position]);
            self.handles[0] = handle;
            return handle.file;
        }
        if (self.opened == self.handles.len) {
            self.opened -= 1;
            self.handles[self.opened].file.close(self.input.io);
        }
        const part = self.input.parts[index];
        const file = try fs.openReadAuthorityBeneath(self.input.io, self.input.root, part.path);
        errdefer file.close(self.input.io);
        try part.validate(self.input.io, file);
        std.mem.copyBackwards(SourceHandle, self.handles[1 .. self.opened + 1], self.handles[0..self.opened]);
        self.handles[0] = .{ .part = index, .file = file };
        self.opened += 1;
        return file;
    }

    fn readExact(self: *SourceReader, destination: []u8, offset: u64) !void {
        try interrupt.check();
        if (destination.len == 0) return;
        if (offset > self.input.size or destination.len > self.input.size - offset)
            return error.ReadOutOfBounds;
        var done: usize = 0;
        var position = self.input.base + offset;
        while (done < destination.len) {
            var low: usize = 0;
            var high = self.input.parts.len;
            var found: ?usize = null;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const part = self.input.parts[middle];
                if (position < part.logical_start) {
                    high = middle;
                } else if (position >= part.logical_start + part.size) {
                    low = middle + 1;
                } else {
                    found = middle;
                    break;
                }
            }
            const index = found orelse return error.ReadOutOfBounds;
            const part = self.input.parts[index];
            const relative = position - part.logical_start;
            const want: usize = @intCast(@min(destination.len - done, part.size - relative));
            const file = try self.openPart(index);
            const got = try self.input.reader.read(self.input.io, file, destination[done .. done + want], relative);
            if (got != want) return error.ShortRead;
            done += want;
            position += want;
        }
    }

    fn matchRead(raw: *anyopaque, offset: u64, bytes: []u8) !void {
        const self: *SourceReader = @ptrCast(@alignCast(raw));
        try self.readExact(bytes, offset);
    }

    fn matchInput(self: *SourceReader) match_index.Input {
        return .{ .context = self, .size = self.input.size, .read_at = matchRead };
    }

    fn zarRead(raw: ?*anyopaque, offset: u64, bytes: []u8) !void {
        const self: *SourceReader = @ptrCast(@alignCast(raw.?));
        try self.readExact(bytes, offset);
    }

    fn zarInput(self: *SourceReader) zar26.Input {
        return .{ .context = self, .size = self.input.size, .read_at = zarRead };
    }
};

test "source readers reopen unchanged files and reject changed bindings" {
    const io = std.testing.io;
    for ([_]enum { replacement, modified }{ .replacement, .modified }) |change| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const paths = [_][]const u8{ "a.bin", "empty.bin", "b.bin", "c.bin" };
        const contents = [_][]const u8{ "abcd", "", "EFGH", "ijkl" };
        var parts: [paths.len]SourcePart = undefined;
        var size: u64 = 0;
        for (paths, contents, &parts) |path, bytes, *part| {
            try tmp.dir.writeFile(io, .{ .sub_path = path, .data = bytes });
            const file = try fs.openReadAuthorityBeneath(io, tmp.dir, path);
            defer file.close(io);
            part.* = try SourcePart.capture(io, file, path, size, bytes.len);
            size += bytes.len;
        }
        var handles: [1]SourceHandle = undefined;
        var reader: SourceReader = .{
            .input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = &parts, .size = size },
            .handles = &handles,
        };
        defer reader.deinit();
        var bytes: [8]u8 = undefined;
        try reader.readExact(&bytes, 2);
        try std.testing.expectEqualStrings("cdEFGHij", &bytes);
        try reader.readExact(bytes[0..4], 0);
        try std.testing.expectEqualStrings("abcd", bytes[0..4]);

        var slice_handles: [1]SourceHandle = undefined;
        var slice: SourceReader = .{
            .input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = parts[1..], .size = 8, .base = 4 },
            .handles = &slice_handles,
        };
        defer slice.deinit();
        try slice.readExact(&bytes, 0);
        try std.testing.expectEqualStrings("EFGHijkl", &bytes);
        try std.testing.expectError(error.ReadOutOfBounds, slice.readExact(bytes[0..1], 8));

        try reader.readExact(bytes[0..4], 4);
        switch (change) {
            .replacement => {
                try tmp.dir.rename("a.bin", tmp.dir, "original.bin", io);
                try tmp.dir.writeFile(io, .{ .sub_path = "a.bin", .data = "WXYZ" });
            },
            .modified => {
                const file = try tmp.dir.openFile(io, "a.bin", .{ .mode = .read_write });
                defer file.close(io);
                try std.testing.expect((try fs.openFileIdentity(file)).eql(parts[0].identity));
                try file.writePositionalAll(io, "WXYZ", 0);
                try file.setTimestamps(io, .{ .modify_timestamp = .{ .new = parts[0].mtime.addDuration(.fromSeconds(1)) } });
            },
        }
        try std.testing.expectError(error.SourceChangedDuringCreate, reader.readExact(bytes[0..4], 0));
    }
}

fn observationFor(allocator: std.mem.Allocator, maybe_tree: ?*tree.Tree, entry: ziff.FileEntry) !?*content.State {
    const value = maybe_tree orelse return null;
    const index = value.findIndex(entry.path) orelse return error.MissingTargetObservation;
    const state = try tree.contentState(allocator, &value.files[index]);
    try state.bindVerification(entry.verification);
    return state;
}

fn completeObservation(io: std.Io, directory: ziff.Directory, unit: ziff.Unit, part: LogicalPart, buffer: []u8, options: Options) !void {
    const value = options.target_observations orelse return;
    const target = try plannedTarget(directory, unit);
    const state = part.observation orelse return error.MissingTargetObservation;
    const digest = try state.finish(io, part.file, buffer, options.payload_reader);
    const index = value.findIndex(target.file.path) orelse return error.MissingTargetObservation;
    if (digest) |value_digest| {
        value.files[index].digest = value_digest;
        directory.files[target.index].digest = value_digest;
    } else if (!target.file.verification.isPresent()) return error.IncompleteTargetObservation;
}

fn finalizeObservations(header: *ziff.Header, directory: *ziff.Directory, value: *tree.Tree) !u64 {
    var target_fingerprint = std.crypto.hash.Blake3.init(.{});
    var completion_bytes: u64 = 0;
    for (directory.ops) |*op| {
        const file = &directory.files[op.target];
        const index = value.findIndex(file.path) orelse return error.MissingTargetObservation;
        const observed = value.files[index];
        file.digest = if (file.verification.isPresent())
            .zero
        else
            observed.digest orelse return error.IncompleteTargetObservation;
        if (observed.content_state) |state| completion_bytes += state.completion_bytes;
        ziff.updateLogicalFingerprint(&target_fingerprint, file.*);
    }
    target_fingerprint.final(&header.target_fingerprint.bytes);
    return completion_bytes;
}

const SourceFamily = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    matcher_threads: usize,
    progress: ?*ui.Operation = null,
    refs: []const ziff.SourceRef = &.{},
    parts: []SourcePart = &.{},
    input: SourceInput = undefined,
    index: ?*match_index.Index = null,
    slice_handles: []SourceHandle = &.{},
    slice_reader: SourceReader = undefined,
    slice_start: usize = 0,
    slice_stop: usize = 0,

    fn dropIndex(self: *SourceFamily) void {
        if (self.index) |index| {
            index.deinit();
            self.index = null;
        }
        if (self.slice_handles.len != 0) {
            self.slice_reader.deinit();
            self.allocator.free(self.slice_handles);
            self.slice_handles = &.{};
        }
        self.slice_start = 0;
        self.slice_stop = 0;
    }

    fn release(self: *SourceFamily) void {
        self.dropIndex();
        if (self.parts.len != 0) self.allocator.free(self.parts);
        self.parts = &.{};
        self.refs = &.{};
    }

    fn matches(self: *const SourceFamily, refs: []const ziff.SourceRef) bool {
        if (self.refs.len != refs.len or self.refs.len == 0) return false;
        for (self.refs, refs) |a, b| {
            if (a.file != b.file or a.offset != b.offset or a.length != b.length) return false;
        }
        return true;
    }
};

fn openSourceFamily(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    refs: []const ziff.SourceRef,
    source_snapshot: *const SourceSnapshot,
    source_root: std.Io.Dir,
    authentication_buffer: []u8,
    reader: scan.Reader,
    family: *SourceFamily,
    verify_content: bool,
) !void {
    var span = profile.begin(io, if (verify_content) "create: open+verify source family" else "create: open source family");
    defer span.end(io);
    const matcher_threads = family.matcher_threads;
    const progress = family.progress;
    family.release();
    family.* = .{ .allocator = allocator, .io = io, .matcher_threads = matcher_threads, .progress = progress };
    errdefer family.release();

    family.parts = try allocator.alloc(SourcePart, refs.len);
    var logical: u64 = 0;
    for (refs, family.parts) |ref, *part| {
        if (ref.offset != 0) return error.PartialSourceUnsupported;
        if (ref.file >= directory.files.len) return error.SourceFileIndexOutOfRange;
        const path = directory.files[ref.file].path;
        const expected = source_snapshot.find(path) orelse return error.SourceChangedDuringCreate;
        if (expected.size != ref.length) return error.SourceChangedDuringCreate;

        const file = try fs.openReadAuthorityBeneath(io, source_root, path);
        defer file.close(io);
        part.* = try SourcePart.capture(io, file, path, logical, ref.length);
        if (verify_content) {
            const observed = try digestOpenInput(io, .{ .file = file, .size = ref.length }, authentication_buffer, reader);
            if (!observed.eql(expected.digest)) return error.SourceChangedDuringCreate;
            try part.validate(io, file);
        }
        logical = try checkedAdd(logical, ref.length);
    }
    family.refs = refs;
    family.input = .{ .io = io, .root = source_root, .reader = reader, .parts = family.parts, .size = logical };
}

fn selectSlice(
    family: *SourceFamily,
    start: usize,
    stop: usize,
    block_size: usize,
    emit_alternates: bool,
    reader: scan.Reader,
    source_handles: usize,
) !void {
    if (family.index != null and family.slice_start == start and family.slice_stop == stop) return;
    family.dropIndex();

    const parts = family.parts[start..stop];
    const base = if (parts.len == 0) 0 else parts[0].logical_start;
    const size = if (parts.len == 0) 0 else parts[parts.len - 1].logical_start + parts[parts.len - 1].size - base;
    family.slice_handles = try family.allocator.alloc(SourceHandle, @min(parts.len, @max(1, source_handles)));
    family.slice_reader = .{
        .input = .{ .io = family.io, .root = family.input.root, .reader = reader, .parts = parts, .size = size, .base = base },
        .handles = family.slice_handles,
    };
    errdefer family.dropIndex();
    var index_span = profile.begin(family.io, "create: build match index");
    defer index_span.end(family.io);
    if (family.progress) |progress| progress.phase("Indexing source", 0, 0);
    family.index = try match_index.Index.init(
        family.io,
        family.slice_reader.matchInput(),
        block_size,
        emit_alternates,
        family.matcher_threads,
    );
    family.slice_start = start;
    family.slice_stop = stop;
}

const FamilyCovers = struct {
    allocator: std.mem.Allocator,
    per_unit: []std.ArrayList(merge_mod.Cover),

    fn init(allocator: std.mem.Allocator, count: usize) !FamilyCovers {
        const per_unit = try allocator.alloc(std.ArrayList(merge_mod.Cover), count);
        for (per_unit) |*list| list.* = .empty;
        return .{ .allocator = allocator, .per_unit = per_unit };
    }

    fn deinit(self: *FamilyCovers) void {
        for (self.per_unit) |*list| list.deinit(self.allocator);
        self.allocator.free(self.per_unit);
        self.* = undefined;
    }

    fn bytes(self: *const FamilyCovers) usize {
        var total: usize = 0;
        for (self.per_unit) |list| total += list.items.len * @sizeOf(merge_mod.Cover);
        return total;
    }
};

fn familyRunLength(directory: ziff.Directory, first: usize) usize {
    const head = directory.units[first];
    const head_refs = directory.sources[head.source_first..][0..head.source_count];
    var count: usize = 1;
    while (first + count < directory.units.len) : (count += 1) {
        const next = directory.units[first + count];
        if (next.kind != .patch_zar26) break;
        if (next.source_count != head.source_count) break;
        const next_refs = directory.sources[next.source_first..][0..next.source_count];
        var same = true;
        for (head_refs, next_refs) |a, b| {
            if (a.file != b.file or a.offset != b.offset or a.length != b.length) {
                same = false;
                break;
            }
        }
        if (!same) break;
    }
    return count;
}

const ParallelMatchShared = struct {
    io: std.Io,
    directory: ziff.Directory,
    units: []const ziff.Unit,
    family: *SourceFamily,
    target_root: std.Io.Dir,
    observations: []const ?*content.State,
    covers: *FamilyCovers,
    reader: scan.Reader,
    target_size_problem: ?*TargetSizeProblem,
    results: []?anyerror,
    next: std.atomic.Value(usize) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),
};

fn matchParallelUnit(shared: *ParallelMatchShared, index: usize, authentication_buffer: []u8) !void {
    const unit = shared.units[index];
    const target = try plannedTarget(shared.directory, unit);
    var file = try openTarget(shared.io, shared.target_root, target.file, shared.target_size_problem);
    defer file.close(shared.io);
    var parts = [_]LogicalPart{.{
        .file = file,
        .logical_start = 0,
        .size = target.file.size,
        .observation = shared.observations[index],
    }};

    var reader = shared.reader;
    if (shared.observations[index] == null and
        !try targetMatchesPlan(shared.io, target.file, parts[0], authentication_buffer, reader))
    {
        reader = .direct;
        if (!try targetMatchesPlan(shared.io, target.file, parts[0], authentication_buffer, reader))
            return error.TargetDigestMismatch;
    }

    var target_input: LogicalInput = .{
        .io = shared.io,
        .reader = reader,
        .parts = &parts,
        .size = target.file.size,
    };
    shared.covers.per_unit[index] = .fromOwnedSlice(try shared.family.index.?.search(shared.covers.allocator, target_input.matchInput()));
    if (shared.family.progress) |progress| progress.advanceWork(0, 1);
}

fn parallelMatchWorker(shared: *ParallelMatchShared, authentication_buffer: []u8) void {
    while (!shared.failed.load(.acquire)) {
        const index = shared.next.fetchAdd(1, .monotonic);
        if (index >= shared.units.len) return;
        matchParallelUnit(shared, index, authentication_buffer) catch |err| {
            shared.results[index] = err;
            shared.failed.store(true, .release);
            return;
        };
    }
}

// serialized source callbacks for stateful custom readers
fn matchFamilyParallel(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    units: []const ziff.Unit,
    family: *SourceFamily,
    target_root: std.Io.Dir,
    reader: scan.Reader,
    covers: *FamilyCovers,
    target_observations: ?*tree.Tree,
    requested_workers: usize,
    buffer_bytes: usize,
    target_size_problem: ?*TargetSizeProblem,
) !void {
    const worker_count = @min(@max(@as(usize, 1), requested_workers), units.len);
    try selectSlice(
        family,
        0,
        family.parts.len,
        production_options.matcher_block_size,
        production_options.matcher_alternates,
        reader,
        @max(worker_count, family.matcher_threads),
    );
    defer family.dropIndex();
    if (family.progress) |progress| progress.phase("Matching", 0, units.len);
    var search_span = profile.begin(io, "create: parallel match search");
    defer search_span.end(io);

    const observations = try allocator.alloc(?*content.State, units.len);
    defer allocator.free(observations);
    for (units, observations) |unit, *observation| {
        const target = try plannedTarget(directory, unit);
        observation.* = try observationFor(allocator, target_observations, target.file);
    }
    const results = try allocator.alloc(?anyerror, units.len);
    defer allocator.free(results);
    @memset(results, null);
    const authentication_bytes = if (target_observations == null) buffer_bytes else 0;
    const storage_len = std.math.mul(usize, worker_count, authentication_bytes) catch return error.OutOfMemory;
    const storage = try allocator.alloc(u8, storage_len);
    defer allocator.free(storage);
    var shared: ParallelMatchShared = .{
        .io = io,
        .directory = directory,
        .units = units,
        .family = family,
        .target_root = target_root,
        .observations = observations,
        .covers = covers,
        .reader = reader,
        .target_size_problem = target_size_problem,
        .results = results,
    };

    if (worker_count == 1) {
        parallelMatchWorker(&shared, storage[0..authentication_bytes]);
    } else {
        const threads = try allocator.alloc(Thread, worker_count);
        defer allocator.free(threads);
        var spawned: usize = 0;
        errdefer for (threads[0..spawned]) |thread| thread.join();
        while (spawned < worker_count) : (spawned += 1) {
            const begin = spawned * authentication_bytes;
            threads[spawned] = try Thread.spawn(.{}, parallelMatchWorker, .{
                &shared,
                storage[begin .. begin + authentication_bytes],
            });
        }
        for (threads) |thread| thread.join();
        spawned = 0;
    }

    for (results) |maybe_error| if (maybe_error) |err| return err;
    if (covers.bytes() > max_family_cover_bytes) return error.FamilyCoverBudgetExceeded;
}

fn matchFamilySliceMajor(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    units: []const ziff.Unit,
    family: *SourceFamily,
    target_root: std.Io.Dir,
    slice_budget: u64,
    reader: scan.Reader,
    covers: *FamilyCovers,
    target_observations: ?*tree.Tree,
    target_size_problem: ?*TargetSizeProblem,
) !void {
    const block_size = production_options.matcher_block_size;

    var start: usize = 0;
    while (start < family.parts.len) {
        var stop = start + 1;
        var accumulated: u64 = family.parts[start].size;
        while (stop < family.parts.len) {
            const next = family.parts[stop].size;
            const combined = std.math.add(u64, accumulated, next) catch break;
            if (combined > slice_budget) break;
            accumulated = combined;
            stop += 1;
        }
        try selectSlice(family, start, stop, block_size, production_options.matcher_alternates, reader, family.matcher_threads);
        if (family.progress) |progress| progress.phase("Matching slice", 0, units.len);
        const base = family.parts[start].logical_start;

        for (units, covers.per_unit) |unit, *unit_covers| {
            const target = try plannedTarget(directory, unit);
            var file = try openTarget(io, target_root, target.file, target_size_problem);
            defer file.close(io);
            var parts = [_]LogicalPart{.{
                .file = file,
                .logical_start = 0,
                .size = target.file.size,
                .observation = try observationFor(allocator, target_observations, target.file),
            }};

            var target_input: LogicalInput = .{
                .io = io,
                .reader = reader,
                .parts = &parts,
                .size = target.file.size,
            };
            const found = try family.index.?.search(covers.allocator, target_input.matchInput());
            if (family.progress) |progress| progress.advanceWork(0, 1);
            for (found) |*cover| cover.source_offset += base;
            if (unit_covers.items.len == 0) {
                unit_covers.deinit(covers.allocator);
                unit_covers.* = .fromOwnedSlice(found);
            } else {
                defer covers.allocator.free(found);
                try unit_covers.appendSlice(covers.allocator, found);
            }
        }

        if (covers.bytes() > max_family_cover_bytes) return error.FamilyCoverBudgetExceeded;
        family.dropIndex();
        start = stop;
    }
}

fn recordReplay(
    allocator: std.mem.Allocator,
    directory: ziff.Directory,
    unit_index: usize,
    covers: []const merge_mod.Cover,
    residual_reads: []const ranges.Range,
) !void {
    if (directory.replays.len == 0) return;
    if (unit_index >= directory.units.len or unit_index >= directory.replays.len)
        return error.InvalidReplayUnit;
    const unit = directory.units[unit_index];
    const target = unit.target;
    var reads: std.ArrayList(ranges.Range) = .empty;
    defer reads.deinit(allocator);
    var skips: std.ArrayList(ranges.Range) = .empty;
    defer skips.deinit(allocator);
    const SelfRef = struct { logical: u64, ref: ziff.SourceRef };
    var self_refs: std.ArrayList(SelfRef) = .empty;
    defer self_refs.deinit(allocator);
    var logical: u64 = 0;
    for (directory.sources[unit.source_first..][0..unit.source_count]) |ref| {
        if (ref.file == target) try self_refs.append(allocator, .{ .logical = logical, .ref = ref });
        logical = try checkedAdd(logical, ref.length);
    }
    try reads.appendSlice(allocator, residual_reads);
    for (covers) |cover| {
        const cover_end = try checkedAdd(cover.source_offset, cover.length);
        var cursor = cover.source_offset;
        for (self_refs.items) |self| {
            const start = @max(self.logical, cover.source_offset);
            const stop = @min(try checkedAdd(self.logical, self.ref.length), cover_end);
            if (stop <= start) continue;
            const source_offset = try checkedAdd(self.ref.offset, start - self.logical);
            const target_offset = try checkedAdd(cover.target_offset, start - cover.source_offset);
            if (source_offset == target_offset) {
                if (start > cursor) try reads.append(allocator, .{ .offset = cursor, .length = start - cursor });
                try skips.append(allocator, .{ .offset = target_offset, .length = stop - start });
                cursor = stop;
            }
        }
        if (cursor < cover_end) try reads.append(allocator, .{ .offset = cursor, .length = cover_end - cursor });
    }
    const merged_reads = try ranges.merge(allocator, reads.items);
    errdefer allocator.free(merged_reads);
    const merged_skips = try ranges.merge(allocator, skips.items);
    const replay = &directory.replays[unit_index];
    replay.deinit(allocator);
    replay.* = .{ .reads = merged_reads, .skips = merged_skips };
}

const FilePayloadOutput = struct {
    io: std.Io,
    file: std.Io.File,
    base: u64,

    fn write(raw: ?*anyopaque, offset: u64, bytes: []const u8) !void {
        try interrupt.check();
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        try self.file.writePositionalAll(self.io, bytes, try checkedAdd(self.base, offset));
    }

    fn output(self: *@This()) zar26.Output {
        return .{ .context = self, .write_at = write };
    }
};

fn serializeZar26Unit(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    unit_index: usize,
    unit: ziff.Unit,
    family: *SourceFamily,
    target_root: std.Io.Dir,
    authentication_buffer: []u8,
    covers: []merge_mod.Cover,
    output: std.Io.File,
    output_offset: u64,
    options: Options,
) !Zar26UnitStats {
    const target = try plannedTarget(directory, unit);
    var file = try openTarget(io, target_root, target.file, options.target_size_problem);
    defer file.close(io);
    var parts = [_]LogicalPart{.{
        .file = file,
        .logical_start = 0,
        .size = target.file.size,
        .observation = try observationFor(allocator, options.target_observations, target.file),
    }};

    const merged = try merge_mod.merge(allocator, covers, production_options.matcher_locality);
    defer allocator.free(merged);
    var reader = options.matcher_reader;
    if (options.target_observations == null and !try targetMatchesPlan(io, target.file, parts[0], authentication_buffer, reader)) {
        reader = .direct;
        if (!try targetMatchesPlan(io, target.file, parts[0], authentication_buffer, reader))
            return error.TargetDigestMismatch;
    }

    var target_input: LogicalInput = .{
        .io = io,
        .reader = reader,
        .parts = &parts,
        .size = target.file.size,
    };
    var source_handles: [1]SourceHandle = undefined;
    var source_input: SourceReader = .{ .input = family.input, .handles = &source_handles };
    defer source_input.deinit();
    try truncateContainerSuffix(io, output, output_offset);
    var payload_output: FilePayloadOutput = .{ .io = io, .file = output, .base = output_offset };
    var serialize_span = profile.begin(io, "create: ZAR26 serialize");
    errdefer serialize_span.end(io);
    var result = try zar26.encode(
        allocator,
        source_input.zarInput(),
        target_input.zarInput(),
        merged,
        payload_output.output(),
    );
    serialize_span.end(io);
    defer result.deinit();
    if (result.payload_length == 0) return error.EmptyEncodedPayload;
    try recordReplay(allocator, directory, unit_index, merged, result.residual_reads);
    try completeObservation(io, directory, unit, parts[0], authentication_buffer, options);
    return .{ .payload_length = result.payload_length, .codec = result.stats };
}

const Zar26UnitStats = struct {
    payload_length: u64,
    codec: zar26.Stats,
};

const MemoryPayloadOutput = struct {
    allocator: std.mem.Allocator,
    max_bytes: usize,
    bytes: std.ArrayList(u8) = .empty,

    fn write(raw: ?*anyopaque, offset: u64, data: []const u8) !void {
        try interrupt.check();
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        const start = std.math.cast(usize, offset) orelse return error.OutputTooLarge;
        const end = std.math.add(usize, start, data.len) catch return error.OutputTooLarge;
        if (start > self.bytes.items.len) return error.InvalidOutputOffset;
        if (end > self.max_bytes) return error.PayloadMemoryBudgetExceeded;
        if (end > self.bytes.items.len) {
            try self.bytes.ensureTotalCapacityPrecise(self.allocator, end);
            self.bytes.items.len = end;
        }
        @memcpy(self.bytes.items[start..end], data);
    }

    fn output(self: *@This()) zar26.Output {
        return .{ .context = self, .write_at = write };
    }
};

const EncodedPayload = struct {
    bytes: []u8 = &.{},
    codec: zar26.Stats = .{},
    failed: ?anyerror = null,
};

test "parallel payload buffering enforces its byte cap" {
    var output: MemoryPayloadOutput = .{
        .allocator = std.testing.allocator,
        .max_bytes = 4,
    };
    defer output.bytes.deinit(std.testing.allocator);
    try std.testing.expectError(error.PayloadMemoryBudgetExceeded, MemoryPayloadOutput.write(&output, 0, "12345"));
    try std.testing.expectEqual(@as(usize, 0), output.bytes.items.len);
    try MemoryPayloadOutput.write(&output, 0, "12");
    try MemoryPayloadOutput.write(&output, 1, "34");
    try MemoryPayloadOutput.write(&output, 0, "X");
    try MemoryPayloadOutput.write(&output, 3, "Y");
    try std.testing.expectEqualStrings("X34Y", output.bytes.items);
    try std.testing.expectError(error.InvalidOutputOffset, MemoryPayloadOutput.write(&output, 5, ""));
    try std.testing.expectEqualStrings("X34Y", output.bytes.items);
}

const SerializeJob = struct {
    unit_index: usize,
    unit: ziff.Unit,
    covers: []merge_mod.Cover,
    family: *SourceFamily,
    observation: *content.State,
    max_payload_bytes: usize,
};

const ParallelSerializeShared = struct {
    io: std.Io,
    directory: ziff.Directory,
    jobs: []SerializeJob,
    target_root: std.Io.Dir,
    options: Options,
    results: []EncodedPayload,
    recipe_allocator: std.mem.Allocator,
    recipe_mutex: std.Io.Mutex = .init,
    next: std.atomic.Value(usize) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),
};

fn serializeMemoryUnit(shared: *ParallelSerializeShared, index: usize, authentication_buffer: []u8) !void {
    const allocator = std.heap.smp_allocator;
    const job = &shared.jobs[index];
    const unit = job.unit;
    const target = try plannedTarget(shared.directory, unit);
    var file = try openTarget(shared.io, shared.target_root, target.file, shared.options.target_size_problem);
    defer file.close(shared.io);
    var parts = [_]LogicalPart{.{
        .file = file,
        .logical_start = 0,
        .size = target.file.size,
        .observation = job.observation,
    }};
    var source_handles: [1]SourceHandle = undefined;
    var source_input: SourceReader = .{ .input = job.family.input, .handles = &source_handles };
    defer source_input.deinit();
    const merged = try merge_mod.merge(
        allocator,
        job.covers,
        production_options.matcher_locality,
    );
    defer allocator.free(merged);

    var target_input: LogicalInput = .{
        .io = shared.io,
        .reader = shared.options.matcher_reader,
        .parts = &parts,
        .size = target.file.size,
    };
    var output: MemoryPayloadOutput = .{ .allocator = allocator, .max_bytes = job.max_payload_bytes };
    defer output.bytes.deinit(allocator);
    var result = try zar26.encode(
        allocator,
        source_input.zarInput(),
        target_input.zarInput(),
        merged,
        output.output(),
    );
    defer result.deinit();
    if (result.payload_length == 0 or result.payload_length != output.bytes.items.len)
        return error.InvalidEncodedPayloadLength;
    shared.recipe_mutex.lockUncancelable(shared.io);
    const replay_result = recordReplay(
        shared.recipe_allocator,
        shared.directory,
        job.unit_index,
        merged,
        result.residual_reads,
    );
    shared.recipe_mutex.unlock(shared.io);
    try replay_result;
    try completeObservation(
        shared.io,
        shared.directory,
        unit,
        parts[0],
        authentication_buffer,
        shared.options,
    );
    shared.results[index].bytes = try output.bytes.toOwnedSlice(allocator);
    shared.results[index].codec = result.stats;
    if (shared.options.progress) |progress| progress.advanceWork(0, 1);
}

test "ZAR26 serialization propagates reader failures without switching readers" {
    const Failure = struct {
        calls: usize = 0,
        fn read(raw: ?*anyopaque, _: std.Io, _: std.Io.File, _: []u8, _: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.calls += 1;
            return error.InjectedEncodeReadFailure;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = "literal target bytes";
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = bytes });
    var files = [_]ziff.FileEntry{.{ .path = "target.bin", .size = bytes.len, .digest = ids.Digest.of(bytes) }};
    var units = [_]ziff.Unit{.{ .kind = .patch_zar26, .target = 0, .payload_offset = 0, .payload_len = 0, .source_first = 0, .source_count = 0 }};
    var replays = [_]ziff.Replay{.{}};
    const directory: ziff.Directory = .{ .files = &files, .units = &units, .ops = &.{}, .sources = &.{}, .removed = &.{}, .replays = &replays };
    defer replays[0].deinit(allocator);
    var family: SourceFamily = .{ .allocator = allocator, .io = io, .matcher_threads = 1 };
    family.input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = &.{}, .size = 0 };
    var observation: content.State = .{ .size = bytes.len };
    var jobs = [_]SerializeJob{.{ .unit_index = 0, .unit = units[0], .covers = &.{}, .family = &family, .observation = &observation, .max_payload_bytes = 1024 * 1024 }};
    var results = [_]EncodedPayload{.{}};
    defer if (results[0].bytes.len != 0) std.heap.smp_allocator.free(results[0].bytes);
    var failure: Failure = .{};
    var shared: ParallelSerializeShared = .{
        .io = io,
        .directory = directory,
        .jobs = &jobs,
        .target_root = tmp.dir,
        .options = .{ .matcher_reader = .{ .context = &failure, .read_fn = Failure.read } },
        .results = &results,
        .recipe_allocator = allocator,
    };
    var buffer: [64]u8 = undefined;
    try std.testing.expectError(error.InjectedEncodeReadFailure, serializeMemoryUnit(&shared, 0, &buffer));
    try std.testing.expectEqual(@as(usize, 1), failure.calls);
    try std.testing.expectEqual(@as(usize, 0), results[0].bytes.len);
}

fn parallelSerializeWorker(shared: *ParallelSerializeShared, authentication_buffer: []u8) void {
    while (!shared.failed.load(.acquire)) {
        const index = shared.next.fetchAdd(1, .monotonic);
        if (index >= shared.jobs.len) return;
        serializeMemoryUnit(shared, index, authentication_buffer) catch |err| {
            shared.results[index].failed = err;
            shared.failed.store(true, .release);
            return;
        };
    }
}

const PipelinedSerializeShared = struct {
    serialize: *ParallelSerializeShared,
    available: *std.Io.Semaphore,
    published: *std.atomic.Value(usize),
    producer_done: *std.atomic.Value(bool),
};

fn pipelinedSerializeWorker(shared: *PipelinedSerializeShared, authentication_buffer: []u8) void {
    const serialize = shared.serialize;
    while (true) {
        shared.available.waitUncancelable(serialize.io);
        if (serialize.failed.load(.acquire)) return;
        const index = serialize.next.fetchAdd(1, .monotonic);
        if (index >= shared.published.load(.acquire)) {
            std.debug.assert(shared.producer_done.load(.acquire));
            return;
        }
        serializeMemoryUnit(serialize, index, authentication_buffer) catch |err| {
            serialize.results[index].failed = err;
            serialize.failed.store(true, .release);
            return;
        };
    }
}

fn serializeJobsParallel(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    jobs: []SerializeJob,
    target_root: std.Io.Dir,
    options: Options,
    requested_workers: usize,
    span_name: []const u8,
) ![]EncodedPayload {
    var span = profile.begin(io, span_name);
    defer span.end(io);
    const results = try allocator.alloc(EncodedPayload, jobs.len);
    errdefer allocator.free(results);
    for (results) |*result| result.* = .{};
    errdefer for (results) |result| if (result.bytes.len != 0)
        std.heap.smp_allocator.free(result.bytes);

    const worker_count = @min(@max(@as(usize, 1), requested_workers), jobs.len);
    const storage_len = std.math.mul(usize, worker_count, options.buffer_bytes) catch return error.OutOfMemory;
    const storage = try std.heap.smp_allocator.alloc(u8, storage_len);
    defer std.heap.smp_allocator.free(storage);
    var shared: ParallelSerializeShared = .{
        .io = io,
        .directory = directory,
        .jobs = jobs,
        .target_root = target_root,
        .options = options,
        .results = results,
        .recipe_allocator = allocator,
    };
    if (worker_count == 1) {
        parallelSerializeWorker(&shared, storage[0..options.buffer_bytes]);
    } else {
        const threads = try allocator.alloc(Thread, worker_count);
        defer allocator.free(threads);
        var spawned: usize = 0;
        errdefer for (threads[0..spawned]) |thread| thread.join();
        while (spawned < worker_count) : (spawned += 1) {
            const begin = spawned * options.buffer_bytes;
            threads[spawned] = try Thread.spawn(.{}, parallelSerializeWorker, .{
                &shared,
                storage[begin .. begin + options.buffer_bytes],
            });
        }
        for (threads) |thread| thread.join();
        spawned = 0;
    }
    for (results) |result| if (result.failed) |err| return err;
    return results;
}

fn serializeFamilyParallel(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    units: []const ziff.Unit,
    covers: *const FamilyCovers,
    family: *SourceFamily,
    target_root: std.Io.Dir,
    options: Options,
    requested_workers: usize,
    first_unit: usize,
) ![]EncodedPayload {
    const jobs = try allocator.alloc(SerializeJob, units.len);
    defer allocator.free(jobs);
    for (units, covers.per_unit, jobs, 0..) |unit, unit_covers, *job, offset| {
        const target = try plannedTarget(directory, unit);
        job.* = .{
            .unit_index = first_unit + offset,
            .unit = unit,
            .covers = unit_covers.items,
            .family = family,
            .observation = (try observationFor(allocator, options.target_observations, target.file)) orelse
                return error.MissingTargetObservation,
            .max_payload_bytes = try bufferedPayloadLimit(target.file.size),
        };
    }
    return serializeJobsParallel(
        allocator,
        io,
        directory,
        jobs,
        target_root,
        options,
        requested_workers,
        "create: parallel family serialize",
    );
}

fn deinitEncodedPayloads(allocator: std.mem.Allocator, payloads: []EncodedPayload) void {
    for (payloads) |payload| if (payload.bytes.len != 0)
        std.heap.smp_allocator.free(payload.bytes);
    allocator.free(payloads);
}

const SingletonFamily = struct {
    family: *SourceFamily,
    covers: FamilyCovers,

    fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.covers.deinit();
        self.family.release();
        allocator.destroy(self.family);
        self.* = undefined;
    }
};

fn deinitSingletonFamilies(allocator: std.mem.Allocator, families: []SingletonFamily) void {
    for (families) |*family| family.deinit(allocator);
}

fn prepareSingletonFamily(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    unit_index: usize,
    source_snapshot: *const SourceSnapshot,
    source_root: std.Io.Dir,
    target_root: std.Io.Dir,
    authentication_buffer: []u8,
    options: Options,
    matcher_threads: usize,
    matcher_search_workers: usize,
) !SingletonFamily {
    const unit = directory.units[unit_index];
    const refs = directory.sources[unit.source_first..][0..unit.source_count];
    const family = try allocator.create(SourceFamily);
    family.* = .{ .allocator = allocator, .io = io, .matcher_threads = matcher_threads };
    errdefer {
        family.release();
        allocator.destroy(family);
    }
    var covers = try FamilyCovers.init(std.heap.smp_allocator, 1);
    errdefer covers.deinit();
    try openSourceFamily(
        allocator,
        io,
        directory,
        refs,
        source_snapshot,
        source_root,
        authentication_buffer,
        options.source_reader,
        family,
        false,
    );
    const units = directory.units[unit_index..][0..1];
    if (options.slice_budget != 0) {
        try matchFamilySliceMajor(
            allocator,
            io,
            directory,
            units,
            family,
            target_root,
            options.slice_budget,
            options.matcher_reader,
            &covers,
            options.target_observations,
            options.target_size_problem,
        );
    } else {
        try matchFamilyParallel(
            allocator,
            io,
            directory,
            units,
            family,
            target_root,
            options.matcher_reader,
            &covers,
            options.target_observations,
            matcher_search_workers,
            options.buffer_bytes,
            options.target_size_problem,
        );
    }
    return .{ .family = family, .covers = covers };
}

fn serializeSingletonsPipelined(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: ziff.Directory,
    first_unit: usize,
    unit_count: usize,
    source_snapshot: *const SourceSnapshot,
    source_root: std.Io.Dir,
    target_root: std.Io.Dir,
    authentication_buffer: []u8,
    options: Options,
    matcher_threads: usize,
    matcher_search_workers: usize,
    requested_workers: usize,
) ![]EncodedPayload {
    var span = profile.begin(io, "create: singleton match+serialize pipeline");
    defer span.end(io);

    const families = try allocator.alloc(SingletonFamily, unit_count);
    var prepared: usize = 0;
    defer {
        deinitSingletonFamilies(allocator, families[0..prepared]);
        allocator.free(families);
    }
    const jobs = try allocator.alloc(SerializeJob, unit_count);
    defer allocator.free(jobs);
    const results = try allocator.alloc(EncodedPayload, unit_count);
    errdefer allocator.free(results);
    for (results) |*result| result.* = .{};
    errdefer for (results) |result| if (result.bytes.len != 0)
        std.heap.smp_allocator.free(result.bytes);

    const worker_count = @min(@max(@as(usize, 1), requested_workers), unit_count);
    const storage_len = std.math.mul(usize, worker_count, options.buffer_bytes) catch
        return error.OutOfMemory;
    const storage = try std.heap.smp_allocator.alloc(u8, storage_len);
    defer std.heap.smp_allocator.free(storage);
    var serialize: ParallelSerializeShared = .{
        .io = io,
        .directory = directory,
        .jobs = jobs,
        .target_root = target_root,
        .options = options,
        .results = results,
        .recipe_allocator = allocator,
    };
    var available: std.Io.Semaphore = .{};
    var published: std.atomic.Value(usize) = .init(0);
    var producer_done: std.atomic.Value(bool) = .init(false);
    var shared: PipelinedSerializeShared = .{
        .serialize = &serialize,
        .available = &available,
        .published = &published,
        .producer_done = &producer_done,
    };
    const threads = try allocator.alloc(Thread, worker_count);
    defer allocator.free(threads);
    var spawned: usize = 0;
    errdefer {
        serialize.failed.store(true, .release);
        producer_done.store(true, .release);
        for (0..spawned) |_| available.post(io);
        for (threads[0..spawned]) |thread| thread.join();
    }
    while (spawned < worker_count) : (spawned += 1) {
        const begin = spawned * options.buffer_bytes;
        threads[spawned] = try Thread.spawn(.{}, pipelinedSerializeWorker, .{
            &shared,
            storage[begin .. begin + options.buffer_bytes],
        });
    }

    var producer_error: ?anyerror = null;
    while (prepared < unit_count) {
        try interrupt.check();
        if (serialize.failed.load(.acquire)) break;
        const family = prepareSingletonFamily(
            allocator,
            io,
            directory,
            first_unit + prepared,
            source_snapshot,
            source_root,
            target_root,
            authentication_buffer,
            options,
            matcher_threads,
            matcher_search_workers,
        ) catch |err| {
            producer_error = err;
            serialize.failed.store(true, .release);
            break;
        };
        families[prepared] = family;
        prepared += 1;
        if (serialize.failed.load(.acquire)) break;

        const position = prepared - 1;
        const unit = directory.units[first_unit + position];
        const target = plannedTarget(directory, unit) catch |err| {
            producer_error = err;
            serialize.failed.store(true, .release);
            break;
        };
        const observation = observationFor(
            allocator,
            options.target_observations,
            target.file,
        ) catch |err| {
            producer_error = err;
            serialize.failed.store(true, .release);
            break;
        };
        jobs[position] = .{
            .unit_index = first_unit + position,
            .unit = unit,
            .covers = family.covers.per_unit[0].items,
            .family = family.family,
            .observation = observation orelse {
                producer_error = error.MissingTargetObservation;
                serialize.failed.store(true, .release);
                break;
            },
            .max_payload_bytes = try bufferedPayloadLimit(target.file.size),
        };
        published.store(position + 1, .release);
        available.post(io);
    }

    producer_done.store(true, .release);
    for (0..worker_count) |_| available.post(io);
    for (threads) |thread| thread.join();
    spawned = 0;

    if (producer_error) |err| return err;
    for (results) |result| if (result.failed) |err| return err;
    if (prepared != unit_count) return error.Zar26SerializeFailed;
    return results;
}

fn collateEncodedPayloads(
    io: std.Io,
    output: std.Io.File,
    units: []ziff.Unit,
    payloads: []const EncodedPayload,
    cursor: *u64,
    stats: *Stats,
) !void {
    var span = profile.begin(io, "create: collate payloads");
    defer span.end(io);
    for (units, payloads) |*unit, payload| {
        unit.payload_offset = cursor.*;
        try output.writePositionalAll(io, payload.bytes, cursor.*);
        unit.payload_len = payload.bytes.len;
        stats.zar26_units += 1;
        addZar26Stats(&stats.zar26, payload.codec);
        cursor.* = try checkedAdd(cursor.*, payload.bytes.len);
    }
}

fn targetMatchesPlan(
    io: std.Io,
    entry: ziff.FileEntry,
    part: LogicalPart,
    authentication_buffer: []u8,
    reader: scan.Reader,
) !bool {
    var span = profile.begin(io, "create: target identity hash");
    defer span.end(io);
    if (entry.verification.isPresent()) {
        var state: content.State = .{ .size = entry.size };
        try state.bindVerification(entry.verification);
        var offset: u64 = 0;
        while (offset < entry.size) {
            try interrupt.check();
            const wanted: usize = @intCast(@min(@as(u64, authentication_buffer.len), entry.size - offset));
            const count = try reader.read(io, part.file, authentication_buffer[0..wanted], offset);
            if (count > wanted) return error.InvalidReadCount;
            if (count != wanted) return false;
            state.observe(offset, authentication_buffer[0..count]) catch |err| switch (err) {
                error.TargetIdentityMismatch => return false,
                else => return err,
            };
            offset += count;
        }
        _ = state.finish(io, part.file, authentication_buffer, reader) catch |err| switch (err) {
            error.TargetIdentityMismatch => return false,
            else => return err,
        };
    } else {
        const observed = try digestOpenInput(
            io,
            .{ .file = part.file, .size = entry.size },
            authentication_buffer,
            reader,
        );
        if (!observed.eql(entry.digest)) return false;
    }
    return true;
}

fn createToFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    header: *ziff.Header,
    directory: *ziff.Directory,
    bindings: Bindings,
    output: std.Io.File,
    options: Options,
) !Stats {
    if (options.buffer_bytes == 0 or options.buffer_bytes > max_buffer_bytes) return error.InvalidBufferSize;
    if (options.serializer_memory_bytes == 0) return error.InvalidBufferSize;
    if (options.matcher_threads > 64 or options.matcher_search_workers > 64 or
        options.serializer_workers > 64)
        return error.InvalidWorkerCount;
    if (directory.replays.len != 0) return error.ReplayAlreadyConstructed;
    var has_patch = false;
    for (directory.units) |unit| has_patch = has_patch or unit.kind == .patch_zar26;
    if (has_patch) {
        directory.replays = try allocator.alloc(ziff.Replay, directory.units.len);
        @memset(directory.replays, .{});
        header.required_features |= ziff.Feature.inplace_recipe;
    }
    defer if (directory.replays.len != 0) {
        ziff.freeReplays(allocator, directory.replays);
        directory.replays = &.{};
    };
    const matcher_threads = if (options.matcher_threads != 0)
        options.matcher_threads
    else
        @max(1, @min(@as(usize, 64), Thread.getCpuCount() catch 1));
    const matcher_search_workers = if (options.matcher_search_workers != 0)
        options.matcher_search_workers
    else
        @max(1, @min(@as(usize, 16), Thread.getCpuCount() catch 1));
    const serializer_workers = if (options.serializer_workers != 0)
        options.serializer_workers
    else
        @max(1, @min(@as(usize, 16), Thread.getCpuCount() catch 1));
    const planned_payload_start = try prevalidatePlan(allocator, header.*, directory.*);
    var identity_span = profile.begin(io, "create: source identity snapshot");
    var source_snapshot = try validateSourceIdentity(allocator, io, header.*, bindings, options);
    identity_span.end(io);
    defer source_snapshot.deinit();
    var bindings_span = profile.begin(io, "create: physical binding check");
    if (options.target_observations == null) try validatePhysicalBindings(allocator, io, directory.*, bindings, options.target_size_problem);
    bindings_span.end(io);

    const payload_start = try ziff_file.beginFile(allocator, io, output, header.*);
    if (payload_start != planned_payload_start) return error.PayloadStartChanged;

    var cursor = payload_start;
    var stats: Stats = .{
        .payload_start = payload_start,
        .payload_end = payload_start,
        .raw_units = 0,
        .zstd_units = 0,
        .zar26_units = 0,
    };

    const cwd = std.Io.Dir.cwd();
    const source_root_owned = bindings.source_root.len != 0;
    var unit_source_root = if (source_root_owned)
        try cwd.openDir(io, bindings.source_root, .{ .access_sub_paths = true })
    else
        cwd;
    defer if (source_root_owned) unit_source_root.close(io);
    const target_root_owned = bindings.target_root.len != 0;
    var unit_target_root = if (target_root_owned)
        try cwd.openDir(io, bindings.target_root, .{ .access_sub_paths = true })
    else
        cwd;
    defer if (target_root_owned) unit_target_root.close(io);
    const unit_buffer = try allocator.alloc(u8, options.buffer_bytes);
    defer allocator.free(unit_buffer);
    var family: SourceFamily = .{
        .allocator = allocator,
        .io = io,
        .matcher_threads = matcher_threads,
        .progress = options.progress,
    };
    defer family.release();

    var unit_cursor: usize = 0;
    while (unit_cursor < directory.units.len) : (unit_cursor += 1) {
        try interrupt.check();
        const unit = &directory.units[unit_cursor];
        unit.payload_offset = cursor;
        if (unit.kind == .patch_zar26) {
            var singleton_count: usize = 0;
            var singleton_source_parts: usize = 0;
            var singleton_payload_bytes: usize = 0;
            if (options.target_observations != null and serializer_workers > 1) {
                while (singleton_count < max_singleton_batch_families and
                    unit_cursor + singleton_count < directory.units.len)
                {
                    const candidate = directory.units[unit_cursor + singleton_count];
                    if (candidate.kind != .patch_zar26 or
                        familyRunLength(directory.*, unit_cursor + singleton_count) != 1)
                        break;
                    const candidate_limit = try bufferedPayloadLimit(directory.files[candidate.target].size);
                    if (candidate_limit > options.serializer_memory_bytes) break;
                    const next_payload_bytes = std.math.add(
                        usize,
                        singleton_payload_bytes,
                        candidate_limit,
                    ) catch break;
                    if (next_payload_bytes > options.serializer_memory_bytes) break;
                    const next_parts = std.math.add(usize, singleton_source_parts, candidate.source_count) catch break;
                    if (next_parts > max_singleton_batch_source_parts) break;
                    singleton_source_parts = next_parts;
                    singleton_payload_bytes = next_payload_bytes;
                    singleton_count += 1;
                }
            }
            if (singleton_count > 1) {
                family.release();
                const singleton_units = directory.units[unit_cursor..][0..singleton_count];
                if (options.progress) |progress| progress.phase("Index/match/encode", 0, singleton_count);
                const payloads = serializeSingletonsPipelined(
                    allocator,
                    io,
                    directory.*,
                    unit_cursor,
                    singleton_count,
                    &source_snapshot,
                    unit_source_root,
                    unit_target_root,
                    unit_buffer,
                    options,
                    matcher_threads,
                    matcher_search_workers,
                    @min(serializer_workers, max_singleton_pipeline_workers),
                ) catch |err| {
                    truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                        return rollback_error;
                    return err;
                };
                defer deinitEncodedPayloads(allocator, payloads);
                if (options.progress) |progress| progress.phase("Writing payloads", 0, singleton_count);
                collateEncodedPayloads(
                    io,
                    output,
                    singleton_units,
                    payloads,
                    &cursor,
                    &stats,
                ) catch |err| {
                    truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                        return rollback_error;
                    return err;
                };
                if (options.progress) |progress| for (singleton_units) |completed| {
                    progress.complete(directory.files[completed.target].size, 1);
                    progress.advanceWork(0, 1);
                };
                unit_cursor += singleton_count - 1;
                continue;
            }
            const refs = directory.sources[unit.source_first..][0..unit.source_count];
            if (!family.matches(refs)) {
                if (options.progress) |progress| progress.phase("Opening source", 0, 0);
                try openSourceFamily(
                    allocator,
                    io,
                    directory.*,
                    refs,
                    &source_snapshot,
                    unit_source_root,
                    unit_buffer,
                    options.source_reader,
                    &family,
                    options.target_observations == null,
                );
            }
            const run = familyRunLength(directory.*, unit_cursor);
            const run_units = directory.units[unit_cursor..][0..run];
            // caller's allocator may not support concurrent appends
            var covers = try FamilyCovers.init(std.heap.smp_allocator, run);
            defer covers.deinit();
            if (options.slice_budget != 0) {
                matchFamilySliceMajor(
                    allocator,
                    io,
                    directory.*,
                    run_units,
                    &family,
                    unit_target_root,
                    options.slice_budget,
                    options.matcher_reader,
                    &covers,
                    options.target_observations,
                    options.target_size_problem,
                ) catch |err| {
                    truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                        return rollback_error;
                    return err;
                };
            } else {
                matchFamilyParallel(
                    allocator,
                    io,
                    directory.*,
                    run_units,
                    &family,
                    unit_target_root,
                    options.matcher_reader,
                    &covers,
                    options.target_observations,
                    matcher_search_workers,
                    options.buffer_bytes,
                    options.target_size_problem,
                ) catch |err| {
                    truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                        return rollback_error;
                    return err;
                };
            }
            if (options.progress) |progress| progress.phase("Encoding", 0, run);
            var run_offset: usize = 0;
            while (run_offset < run) {
                var batch_count: usize = 0;
                var batch_bytes: usize = 0;
                if (options.target_observations != null and serializer_workers > 1) {
                    while (run_offset + batch_count < run) {
                        const candidate = run_units[run_offset + batch_count];
                        const limit = try bufferedPayloadLimit(directory.files[candidate.target].size);
                        if (limit > options.serializer_memory_bytes) break;
                        const next_bytes = std.math.add(usize, batch_bytes, limit) catch break;
                        if (next_bytes > options.serializer_memory_bytes) break;
                        batch_bytes = next_bytes;
                        batch_count += 1;
                    }
                }
                if (batch_count > 1) {
                    const batch_units = run_units[run_offset..][0..batch_count];
                    const batch_cover_lists = covers.per_unit[run_offset..][0..batch_count];
                    const batch_covers: FamilyCovers = .{
                        .allocator = covers.allocator,
                        .per_unit = batch_cover_lists,
                    };
                    const payloads = serializeFamilyParallel(
                        allocator,
                        io,
                        directory.*,
                        batch_units,
                        &batch_covers,
                        &family,
                        unit_target_root,
                        options,
                        serializer_workers,
                        unit_cursor + run_offset,
                    ) catch |err| {
                        truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                            return rollback_error;
                        return err;
                    };
                    collateEncodedPayloads(io, output, batch_units, payloads, &cursor, &stats) catch |err| {
                        deinitEncodedPayloads(allocator, payloads);
                        truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                            return rollback_error;
                        return err;
                    };
                    deinitEncodedPayloads(allocator, payloads);
                    if (options.progress) |progress| for (batch_units) |completed| {
                        progress.complete(directory.files[completed.target].size, 1);
                    };
                    run_offset += batch_count;
                    continue;
                }

                const run_unit = &run_units[run_offset];
                run_unit.payload_offset = cursor;
                const produced = serializeZar26Unit(
                    allocator,
                    io,
                    directory.*,
                    unit_cursor + run_offset,
                    run_unit.*,
                    &family,
                    unit_target_root,
                    unit_buffer,
                    covers.per_unit[run_offset].items,
                    output,
                    cursor,
                    options,
                ) catch |err| {
                    truncateContainerSuffix(io, output, cursor) catch |rollback_error|
                        return rollback_error;
                    return err;
                };
                run_unit.payload_len = produced.payload_length;
                stats.zar26_units += 1;
                addZar26Stats(&stats.zar26, produced.codec);
                cursor = try checkedAdd(cursor, produced.payload_length);
                if (options.progress) |progress| {
                    progress.complete(directory.files[run_unit.target].size, 1);
                    progress.advanceWork(0, 1);
                }
                run_offset += 1;
            }
            unit_cursor += run - 1;
            continue;
        }

        if (options.progress != null and
            (unit_cursor == 0 or directory.units[unit_cursor - 1].kind.isPatch()))
        {
            var full_count: usize = 0;
            var full_bytes: u64 = 0;
            for (directory.units[unit_cursor..]) |full_unit| {
                if (full_unit.kind.isPatch()) break;
                full_count += 1;
                full_bytes +|= directory.files[full_unit.target].size;
            }
            options.progress.?.phase("Archiving", full_bytes, full_count);
        }
        const target = try plannedTarget(directory.*, unit.*);
        for (options.target_metadata) |metadata| {
            if (!std.mem.eql(u8, metadata.path, target.file.path)) continue;
            if (metadata.bytes.len != target.file.size) return error.TargetSizeChanged;
            const digest = ids.Digest.of(metadata.bytes);
            if (!target.file.digest.eql(digest)) return error.TargetDigestMismatch;
            switch (unit.kind) {
                .zstd => {
                    var encoder = try @import("../compression/zstd.zig").Encoder.init(io, output, cursor, production_options.zstd_level_full, 0, metadata.bytes.len);
                    defer encoder.deinit();
                    try encoder.write(metadata.bytes);
                    try encoder.finish();
                    unit.payload_len = encoder.position - cursor;
                    stats.zstd_units += 1;
                },
                .raw => {
                    try output.writePositionalAll(io, metadata.bytes, cursor);
                    unit.payload_len = metadata.bytes.len;
                    stats.raw_units += 1;
                },
                .patch_zar26 => return error.InvalidMetadataUnit,
            }
            if (options.progress) |progress| progress.advanceWork(metadata.bytes.len, 0);
            break;
        } else {
            const target_path = try joinedPath(allocator, bindings.target_root, target.file.path);
            defer allocator.free(target_path);
            switch (unit.kind) {
                .patch_zar26 => unreachable,
                .raw, .zstd => {
                    const built = try writeFullUnit(
                        allocator,
                        io,
                        target_path,
                        target.file,
                        output,
                        cursor,
                        unit.kind,
                        options,
                    );
                    if (options.target_observations) |observations| {
                        const index = observations.findIndex(target.file.path) orelse return error.MissingTargetObservation;
                        if (built.target_digest) |digest| {
                            observations.files[index].digest = digest;
                            directory.files[target.index].digest = digest;
                        }
                    } else if (built.target_digest) |digest| {
                        if (!digest.eql(target.file.digest)) return error.TargetDigestMismatch;
                    } else if (!target.file.verification.isPresent()) return error.MissingFileIdentity;
                    unit.payload_len = built.payload_length;
                    if (unit.kind == .raw) stats.raw_units += 1 else stats.zstd_units += 1;
                },
            }
        }
        cursor = try checkedAdd(cursor, unit.payload_len);
        if (options.progress) |progress| {
            progress.complete(target.file.size, 1);
            progress.advanceWork(0, 1);
        }
    }
    stats.payload_end = cursor;
    if (options.progress) |progress| progress.phase("Finalizing", 0, 0);

    if (options.target_observations) |observations| {
        const planned_fingerprint = header.target_fingerprint;
        stats.identity_completion_bytes = try finalizeObservations(header, directory, observations);
        if (!header.target_fingerprint.eql(planned_fingerprint)) {
            try ziff_file.rewriteTargetFingerprintFile(allocator, io, output, header.*);
        }
    }
    _ = try fs.validateGuardedOutputAuthority(io, output);
    ziff_file.finishFile(allocator, io, output, directory.*) catch |err| {
        ziff_file.revokeFinalizedFile(io, output) catch |revoke_error|
            return revoke_error;
        return err;
    };
    _ = fs.validateGuardedOutputAuthority(io, output) catch |err| {
        try ziff_file.revokeFinalizedFile(io, output);
        return err;
    };
    return stats;
}

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    header: *ziff.Header,
    directory: *ziff.Directory,
    bindings: Bindings,
    options: Options,
) !Stats {
    try interrupt.check();
    if (options.progress) |progress| {
        var total_bytes: u64 = 0;
        for (directory.units) |unit| total_bytes +|= directory.files[unit.target].size;
        progress.totals(total_bytes, directory.units.len);
        progress.phase(if (bindings.source_manifest != null) "Preparing" else "Reading source", 0, 0);
    }
    const parent_path = std.fs.path.dirname(bindings.container_path) orelse ".";
    const final_name = std.fs.path.basename(bindings.container_path);
    if (final_name.len == 0) return error.InvalidOutputPath;

    var parent = try std.Io.Dir.cwd().openDir(io, parent_path, .{});
    defer parent.close(io);
    var construction = try fs.PrivateConstructionOutput.create(allocator, io, parent);
    defer construction.deinit();
    const output = try construction.file();
    try construction.requireBinding(0);

    const stats = try createToFile(allocator, io, header, directory, bindings, output, options);
    if (options.progress) |progress| progress.phase("Publishing", 0, 0);
    const final_size = try output.length(io);
    try construction.requireBinding(final_size);
    var checked = try ziff_file.openFile(allocator, io, output);
    checked.deinit();
    try construction.requireBinding(final_size);
    try interrupt.check();
    try construction.publish(final_name, final_size);
    return stats;
}

fn fixturePath(allocator: std.mem.Allocator, tmp: *const std.testing.TmpDir, path: []const u8) ![]u8 {
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    return std.fs.path.join(allocator, &.{ root, path });
}

test "full units reject settled digests and unresolved placeholders" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "target", .default_dir);
    const bytes = "full-unit bytes";
    try tmp.dir.writeFile(io, .{ .sub_path = "target/full.bin", .data = bytes });
    const target_root = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(target_root);
    const target_path = try fixturePath(allocator, &tmp, "target/full.bin");
    defer allocator.free(target_path);
    var observations = try tree.inventory(allocator, io, target_root, null, null);
    defer tree.deinitOwnedTree(allocator, observations);
    var output = try fs.createGuardedOutput(io, tmp.dir, "payload");
    defer output.close(io);
    for ([_]ziff.UnitKind{ .raw, .zstd }) |kind| {
        try output.setLength(io, 0);
        try std.testing.expectError(error.TargetDigestMismatch, writeFullUnit(
            allocator,
            io,
            target_path,
            .{ .path = "full.bin", .size = bytes.len, .digest = ids.Digest.of("wrong bytes") },
            output,
            0,
            kind,
            .{ .target_observations = &observations, .buffer_bytes = 7 },
        ));
        try output.setLength(io, 0);
        try std.testing.expectError(error.TargetDigestMismatch, writeFullUnit(
            allocator,
            io,
            target_path,
            .{ .path = "full.bin", .size = bytes.len, .digest = content.pending_digest },
            output,
            0,
            kind,
            .{ .buffer_bytes = 7 },
        ));
    }
}

test "full-unit extent failures retain the target path and actual size" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "full.bin", .data = "old" });
    const target_path = try fixturePath(allocator, &tmp, "full.bin");
    defer allocator.free(target_path);
    var output = try fs.createGuardedOutput(io, tmp.dir, "payload");
    defer output.close(io);
    for ([_]ziff.UnitKind{ .raw, .zstd }) |kind| {
        var problem: TargetSizeProblem = .{};
        try std.testing.expectError(error.TargetSizeChanged, writeFullUnit(
            allocator,
            io,
            target_path,
            .{ .path = "full.bin", .size = 4, .digest = ids.Digest.of("new!") },
            output,
            0,
            kind,
            .{ .target_size_problem = &problem },
        ));
        try std.testing.expect(problem.details != null);
        try std.testing.expectEqualStrings("full.bin", problem.details.?.path);
        try std.testing.expectEqual(@as(u64, 4), problem.details.?.expected);
        try std.testing.expectEqual(@as(u64, 3), problem.details.?.actual);
        try std.testing.expectEqual(@as(u64, 0), try output.length(io));
    }
}

test "parallel matching returns a coherent target-size failure context" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "source bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.bin", .data = "aa" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.bin", .data = "bbbb" });
    var source = try fs.openReadAuthorityBeneath(io, tmp.dir, "source.bin");
    defer source.close(io);
    var parts = [_]SourcePart{try SourcePart.capture(io, source, "source.bin", 0, "source bytes".len)};
    var family: SourceFamily = .{
        .allocator = allocator,
        .io = io,
        .matcher_threads = 2,
        .parts = &parts,
        .input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = &parts, .size = parts[0].size },
    };
    defer family.dropIndex();
    var files = [_]ziff.FileEntry{
        .{ .path = "a.bin", .size = 3, .digest = ids.Digest.of("aaa") },
        .{ .path = "b.bin", .size = 3, .digest = ids.Digest.of("bbb") },
        .{ .path = "source.bin", .size = parts[0].size, .digest = ids.Digest.of("source bytes") },
    };
    var units = [_]ziff.Unit{
        .{ .kind = .patch_zar26, .target = 0, .source_first = 0, .source_count = 1, .payload_offset = 0, .payload_len = 0 },
        .{ .kind = .patch_zar26, .target = 1, .source_first = 0, .source_count = 1, .payload_offset = 0, .payload_len = 0 },
    };
    var ops = [_]ziff.Op{
        .{ .kind = .patch, .target = 0, .arg = 0 },
        .{ .kind = .patch, .target = 1, .arg = 1 },
    };
    var sources = [_]ziff.SourceRef{.{ .file = 2, .offset = 0, .length = parts[0].size }};
    var removed = [_][]const u8{"source.bin"};
    const directory: ziff.Directory = .{ .files = &files, .units = &units, .ops = &ops, .sources = &sources, .removed = &removed };
    var covers = try FamilyCovers.init(std.heap.smp_allocator, units.len);
    defer covers.deinit();
    var problem: TargetSizeProblem = .{};
    try std.testing.expectError(error.TargetSizeChanged, matchFamilyParallel(
        allocator,
        io,
        directory,
        &units,
        &family,
        tmp.dir,
        .direct,
        &covers,
        null,
        2,
        32,
        &problem,
    ));
    try std.testing.expect(problem.details != null);
    const details = problem.details.?;
    try std.testing.expectEqual(@as(u64, 3), details.expected);
    if (std.mem.eql(u8, details.path, "a.bin")) {
        try std.testing.expectEqual(@as(u64, 2), details.actual);
    } else {
        try std.testing.expectEqualStrings("b.bin", details.path);
        try std.testing.expectEqual(@as(u64, 4), details.actual);
    }
    for (covers.per_unit) |unit_covers| try std.testing.expectEqual(@as(usize, 0), unit_covers.items.len);
}

test "T2 disagreement leaves the container durably unfinalized" {
    const Wrong = struct {
        fired: bool = false,
        fn read(raw_context: ?*anyopaque, io_inner: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            const count = try fs.readAllAt(io_inner, file, buffer, offset);
            if (!self.fired and count != 0) {
                self.fired = true;
                buffer[0] ^= 0xff;
            }
            return count;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);
    const bytes = "planned bytes";
    try target_dir.writeFile(io, .{ .sub_path = "raw.bin", .data = bytes });
    const source_root = try fixturePath(allocator, &tmp, "source");
    defer allocator.free(source_root);
    const target_root = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(target_root);
    const container = try fixturePath(allocator, &tmp, "wrong.ziff");
    defer allocator.free(container);

    const digest = ids.Digest.of(bytes);
    var files = [_]ziff.FileEntry{.{ .path = "raw.bin", .size = bytes.len, .digest = digest }};
    var ops = [_]ziff.Op{.{ .kind = .full, .target = 0, .arg = 0 }};
    var units = [_]ziff.Unit{.{
        .kind = .raw,
        .payload_offset = 0,
        .payload_len = 0,
        .target = 0,
        .source_first = 0,
        .source_count = 0,
    }};
    var directory: ziff.Directory = .{
        .files = &files,
        .ops = &ops,
        .units = &units,
        .sources = &.{},
        .removed = &.{},
    };
    var header: ziff.Header = .{
        .source_identity = "source",
        .target_identity = "target",
        .source_fingerprint = ziff.logicalFingerprint(&.{}),
        .target_fingerprint = ziff.logicalFingerprint(&files),
        .target_bytes = bytes.len,
        .source_bytes = 0,
        .unit_count = 1,
    };
    var wrong: Wrong = .{};
    try std.testing.expectError(error.TargetDigestMismatch, create(
        allocator,
        io,
        &header,
        &directory,
        .{ .source_root = source_root, .target_root = target_root, .container_path = container },
        .{ .payload_reader = .{ .context = &wrong, .read_fn = Wrong.read } },
    ));
    try std.testing.expect(wrong.fired);
    try std.testing.expectError(error.FileNotFound, fs.openRead(io, std.Io.Dir.cwd(), container));
}

test "Ziff create keeps construction private and publishes the retained object" {
    const Swap = struct {
        dir: std.Io.Dir,
        progress: *ui.Operation,
        attempted: bool = false,
        final_was_private: bool = false,
        moved: bool = false,

        fn read(raw: ?*anyopaque, io_inner: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const count = try scan.Reader.direct.read(io_inner, file, buffer, offset);
            if (self.attempted or count == 0) return count;
            try std.testing.expectEqualStrings("Archiving", self.progress.work.?.label);
            try std.testing.expectEqual(@as(usize, 0), self.progress.overall.done_files);
            self.attempted = true;
            self.dir.rename(
                "retained-output.ziff",
                self.dir,
                "moved-output.ziff",
                io_inner,
            ) catch |err| {
                if (err == error.FileNotFound) {
                    self.final_was_private = true;
                    return count;
                }
                return err;
            };
            self.moved = true;
            try self.dir.writeFile(io_inner, .{
                .sub_path = "retained-output.ziff",
                .data = "hostile replacement sentinel",
            });
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);
    const target_bytes = "retained Ziff output payload";
    try target_dir.writeFile(io, .{ .sub_path = "raw.bin", .data = target_bytes });

    const source_root = try fixturePath(allocator, &tmp, "source");
    defer allocator.free(source_root);
    const target_root = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(target_root);
    const container = try fixturePath(allocator, &tmp, "retained-output.ziff");
    defer allocator.free(container);
    const digest = ids.Digest.of(target_bytes);
    var files = [_]ziff.FileEntry{.{
        .path = "raw.bin",
        .size = target_bytes.len,
        .digest = digest,
    }};
    var ops = [_]ziff.Op{.{ .kind = .full, .target = 0, .arg = 0 }};
    var units = [_]ziff.Unit{.{
        .kind = .raw,
        .payload_offset = 0,
        .payload_len = 0,
        .target = 0,
        .source_first = 0,
        .source_count = 0,
    }};
    var directory: ziff.Directory = .{
        .files = &files,
        .ops = &ops,
        .units = &units,
        .sources = &.{},
        .removed = &.{},
    };
    var header: ziff.Header = .{
        .source_identity = "source",
        .target_identity = "target",
        .source_fingerprint = ziff.logicalFingerprint(&.{}),
        .target_fingerprint = ziff.logicalFingerprint(&files),
        .target_bytes = target_bytes.len,
        .source_bytes = 0,
        .unit_count = 1,
    };
    var messages: std.Io.Writer.Allocating = .init(allocator);
    defer messages.deinit();
    var progress: ui.Operation = .{ .io = io, .writer = &messages.writer };
    progress.start("Creating");
    defer progress.stop();
    var swap: Swap = .{ .dir = tmp.dir, .progress = &progress };
    const bindings: Bindings = .{
        .source_root = source_root,
        .target_root = target_root,
        .container_path = container,
    };
    const options: Options = .{
        .payload_reader = .{ .context = &swap, .read_fn = Swap.read },
        .progress = &progress,
    };

    _ = try create(allocator, io, &header, &directory, bindings, options);
    try std.testing.expect(swap.attempted);
    try std.testing.expect(swap.final_was_private);
    try std.testing.expect(!swap.moved);
    var opened = try ziff_file.open(allocator, io, tmp.dir, "retained-output.ziff");
    defer opened.deinit();
    try std.testing.expectError(error.FileNotFound, fs.openRead(io, tmp.dir, "moved-output.ziff"));
    try std.testing.expectEqualStrings("Publishing", progress.work.?.label);
    try std.testing.expectEqual(@as(u64, target_bytes.len), progress.overall.done_bytes);
    try std.testing.expectEqual(@as(usize, 1), progress.overall.done_files);
    progress.finish();
    try std.testing.expect(std.mem.indexOf(u8, messages.written(), "Archiving") == null);

    var failed_progress: std.Io.Writer = .fixed(&.{});
    var silent_progress: ui.Operation = .{ .io = io, .writer = &failed_progress };
    silent_progress.start("Creating");
    defer silent_progress.stop();
    units[0].payload_offset = 0;
    units[0].payload_len = 0;
    const silent_container = try fixturePath(allocator, &tmp, "silent-output.ziff");
    defer allocator.free(silent_container);
    _ = try create(allocator, io, &header, &directory, .{
        .source_root = source_root,
        .target_root = target_root,
        .container_path = silent_container,
    }, .{ .progress = &silent_progress });
    var silent_opened = try ziff_file.open(allocator, io, tmp.dir, "silent-output.ziff");
    defer silent_opened.deinit();
}

const PatchFamilyFixture = struct {
    header: ziff.Header,
    files: [5]ziff.FileEntry,
    ops: [2]ziff.Op,
    units: [1]ziff.Unit,
    sources: [3]ziff.SourceRef,
    removed: [3][]const u8,

    fn init(
        source_a: []const u8,
        source_b: []const u8,
        source_c: []const u8,
        target: []const u8,
    ) PatchFamilyFixture {
        const target_digest = ids.Digest.of(target);
        return .{
            .header = .{
                .required_features = ziff.Feature.zar26_codec,
                .source_identity = "source",
                .target_identity = "target",
                .source_fingerprint = .zero,
                .target_fingerprint = .zero,
                .target_bytes = target.len,
                .source_bytes = source_a.len + source_b.len + source_c.len + 5,
                .unit_count = 1,
            },
            .files = .{
                .{ .path = "blocks/a.blk", .size = source_a.len, .digest = ids.Digest.of(source_a) },
                .{ .path = "blocks/b.blk", .size = source_b.len, .digest = ids.Digest.of(source_b) },
                .{ .path = "blocks/c.blk", .size = source_c.len, .digest = ids.Digest.of(source_c) },
                .{ .path = "blocks/new.blk", .size = target.len, .digest = target_digest },
                .{ .path = "keep.txt", .size = 5, .digest = ids.Digest.of("same\n") },
            },
            .ops = .{
                .{ .kind = .patch, .target = 3, .arg = 0 },
                .{ .kind = .keep, .target = 4, .arg = 0 },
            },
            .units = .{
                .{
                    .kind = .patch_zar26,
                    .payload_offset = 0,
                    .payload_len = 0,
                    .target = 3,
                    .source_first = 0,
                    .source_count = 3,
                },
            },
            .sources = .{
                .{ .file = 0, .offset = 0, .length = source_a.len },
                .{ .file = 1, .offset = 0, .length = source_b.len },
                .{ .file = 2, .offset = 0, .length = source_c.len },
            },
            .removed = .{ "blocks/a.blk", "blocks/b.blk", "blocks/c.blk" },
        };
    }

    fn directory(fixture: *PatchFamilyFixture) ziff.Directory {
        return .{
            .files = &fixture.files,
            .ops = &fixture.ops,
            .units = &fixture.units,
            .sources = &fixture.sources,
            .removed = &fixture.removed,
        };
    }
};

test "parallel singleton-family serialization is canonical" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var random = std.Random.DefaultPrng.init(0x73696e676c65746f);
    const source_a = try allocator.alloc(u8, 384 * 1024);
    defer allocator.free(source_a);
    const source_b = try allocator.alloc(u8, 320 * 1024);
    defer allocator.free(source_b);
    random.random().bytes(source_a);
    random.random().bytes(source_b);
    const target_a = try allocator.dupe(u8, source_a);
    defer allocator.free(target_a);
    const target_b = try allocator.dupe(u8, source_b);
    defer allocator.free(target_b);
    @memset(target_a[40 * 1024 .. 44 * 1024], 0xa5);
    @memset(target_b[190 * 1024 .. 196 * 1024], 0x5a);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "source/old", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.createDir(io, "target/new", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/old/a.bin", .data = source_a });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/old/b.bin", .data = source_b });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/new/a.bin", .data = target_a });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/new/b.bin", .data = target_b });

    const source_root = try fixturePath(allocator, &tmp, "source");
    defer allocator.free(source_root);
    const target_root = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(target_root);
    const serial_path = try fixturePath(allocator, &tmp, "serial.ziff");
    defer allocator.free(serial_path);
    const parallel_path = try fixturePath(allocator, &tmp, "parallel.ziff");
    defer allocator.free(parallel_path);

    const base_files = [_]ziff.FileEntry{
        .{ .path = "new/a.bin", .size = target_a.len, .digest = ids.Digest.of(target_a) },
        .{ .path = "new/b.bin", .size = target_b.len, .digest = ids.Digest.of(target_b) },
        .{ .path = "old/a.bin", .size = source_a.len, .digest = ids.Digest.of(source_a) },
        .{ .path = "old/b.bin", .size = source_b.len, .digest = ids.Digest.of(source_b) },
    };
    const source_manifest = [_]ziff.FileEntry{ base_files[2], base_files[3] };
    const target_manifest = [_]ziff.FileEntry{ base_files[0], base_files[1] };
    const base_ops = [_]ziff.Op{
        .{ .kind = .patch, .target = 0, .arg = 0 },
        .{ .kind = .patch, .target = 1, .arg = 1 },
    };
    const base_units = [_]ziff.Unit{
        .{ .kind = .patch_zar26, .payload_offset = 0, .payload_len = 0, .target = 0, .source_first = 0, .source_count = 1 },
        .{ .kind = .patch_zar26, .payload_offset = 0, .payload_len = 0, .target = 1, .source_first = 1, .source_count = 1 },
    };
    var sources = [_]ziff.SourceRef{
        .{ .file = 2, .offset = 0, .length = source_a.len },
        .{ .file = 3, .offset = 0, .length = source_b.len },
    };
    var removed = [_][]const u8{ "old/a.bin", "old/b.bin" };
    const base_header: ziff.Header = .{
        .required_features = ziff.Feature.zar26_codec,
        .source_identity = "source",
        .target_identity = "target",
        .source_fingerprint = ziff.logicalFingerprint(&source_manifest),
        .target_fingerprint = ziff.logicalFingerprint(&target_manifest),
        .target_bytes = target_a.len + target_b.len,
        .source_bytes = source_a.len + source_b.len,
        .unit_count = base_units.len,
    };

    var serial_target = try tree.inventory(allocator, io, target_root, null, null);
    defer tree.deinitOwnedTree(allocator, serial_target);
    var serial_files = base_files;
    var serial_ops = base_ops;
    var serial_units = base_units;
    var serial_header = base_header;
    var serial_directory: ziff.Directory = .{
        .files = &serial_files,
        .ops = &serial_ops,
        .units = &serial_units,
        .sources = &sources,
        .removed = &removed,
    };
    _ = try create(
        allocator,
        io,
        &serial_header,
        &serial_directory,
        .{
            .source_root = source_root,
            .target_root = target_root,
            .container_path = serial_path,
            .source_manifest = &source_manifest,
        },
        .{ .target_observations = &serial_target, .serializer_workers = 1 },
    );

    var parallel_target = try tree.inventory(allocator, io, target_root, null, null);
    defer tree.deinitOwnedTree(allocator, parallel_target);
    var parallel_files = base_files;
    var parallel_ops = base_ops;
    var parallel_units = base_units;
    var parallel_header = base_header;
    var parallel_directory: ziff.Directory = .{
        .files = &parallel_files,
        .ops = &parallel_ops,
        .units = &parallel_units,
        .sources = &sources,
        .removed = &removed,
    };
    _ = try create(
        allocator,
        io,
        &parallel_header,
        &parallel_directory,
        .{
            .source_root = source_root,
            .target_root = target_root,
            .container_path = parallel_path,
            .source_manifest = &source_manifest,
        },
        .{ .target_observations = &parallel_target, .serializer_workers = 2 },
    );

    var serial_file = try fs.openRead(io, std.Io.Dir.cwd(), serial_path);
    defer serial_file.close(io);
    var parallel_file = try fs.openRead(io, std.Io.Dir.cwd(), parallel_path);
    defer parallel_file.close(io);
    const serial_size = try serial_file.length(io);
    try std.testing.expectEqual(serial_size, try parallel_file.length(io));
    const serial_bytes = try allocator.alloc(u8, @intCast(serial_size));
    defer allocator.free(serial_bytes);
    const parallel_bytes = try allocator.alloc(u8, serial_bytes.len);
    defer allocator.free(parallel_bytes);
    try std.testing.expectEqual(serial_bytes.len, try serial_file.readPositionalAll(io, serial_bytes, 0));
    try std.testing.expectEqual(parallel_bytes.len, try parallel_file.readPositionalAll(io, parallel_bytes, 0));
    try std.testing.expectEqualSlices(u8, serial_bytes, parallel_bytes);
}

test "with a settled manifest, same-length Source drift is refused at the family open" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prng = std.Random.DefaultPrng.init(0x5E11);
    const rand = prng.random();
    const a = try allocator.alloc(u8, 96 * 1024);
    defer allocator.free(a);
    const b = try allocator.alloc(u8, 96 * 1024);
    defer allocator.free(b);
    const c = try allocator.alloc(u8, 96 * 1024);
    defer allocator.free(c);
    rand.bytes(a);
    rand.bytes(b);
    rand.bytes(c);
    var target_builder: std.ArrayList(u8) = .empty;
    defer target_builder.deinit(allocator);
    try target_builder.appendSlice(allocator, b[0..40000]);
    try target_builder.appendSlice(allocator, c[10000..60000]);
    try target_builder.appendSlice(allocator, a[20000..80000]);
    const target = target_builder.items;

    const drifted = try allocator.alloc(u8, b.len);
    defer allocator.free(drifted);
    rand.bytes(drifted);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "source/blocks", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.createDir(io, "target/blocks", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/blocks/a.blk", .data = a });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/blocks/b.blk", .data = drifted });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/blocks/c.blk", .data = c });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/keep.txt", .data = "same\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/blocks/new.blk", .data = target });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/keep.txt", .data = "same\n" });

    const source_root = try fixturePath(allocator, &tmp, "source");
    defer allocator.free(source_root);
    const target_root = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(target_root);
    const container_path = try fixturePath(allocator, &tmp, "drift.ziff");
    defer allocator.free(container_path);

    var fixture = PatchFamilyFixture.init(a, b, c, target);
    const manifest = [_]ziff.FileEntry{
        fixture.files[0], fixture.files[1], fixture.files[2], fixture.files[4],
    };
    fixture.header.source_fingerprint = ziff.logicalFingerprint(&manifest);
    const target_entries = [_]ziff.FileEntry{ fixture.files[3], fixture.files[4] };
    fixture.header.target_fingerprint = ziff.logicalFingerprint(&target_entries);
    fixture.header.target_bytes = target.len + "same\n".len;
    var directory = fixture.directory();

    try std.testing.expectError(error.SourceChangedDuringCreate, create(
        allocator,
        io,
        &fixture.header,
        &directory,
        .{
            .source_root = source_root,
            .target_root = target_root,
            .container_path = container_path,
            .source_ignore = null,
            .source_manifest = &manifest,
        },
        .{},
    ));
    try std.testing.expectError(error.FileNotFound, fs.openRead(io, std.Io.Dir.cwd(), container_path));
}

test "observed target matching needs no authentication scratch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bytes: [2048]u8 = undefined;
    var random = std.Random.DefaultPrng.init(0xc011ec7);
    random.random().bytes(&bytes);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = &bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.bin", .data = &bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.bin", .data = &bytes });
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var parts = [_]SourcePart{try SourcePart.capture(io, source, "source.bin", 0, bytes.len)};
    var files = [_]ziff.FileEntry{
        .{ .path = "a.bin", .size = bytes.len, .digest = content.pending_digest },
        .{ .path = "b.bin", .size = bytes.len, .digest = content.pending_digest },
    };
    var units = [_]ziff.Unit{
        .{ .kind = .patch_zar26, .payload_offset = 0, .payload_len = 0, .target = 0, .source_first = 0, .source_count = 1 },
        .{ .kind = .patch_zar26, .payload_offset = 0, .payload_len = 0, .target = 1, .source_first = 0, .source_count = 1 },
    };
    var observed_files = [_]tree.File{
        .{ .path = "a.bin", .size = bytes.len },
        .{ .path = "b.bin", .size = bytes.len },
    };
    var observations: tree.Tree = .{ .root = "", .files = &observed_files, .map = .empty };
    defer observations.map.deinit(allocator);
    try observations.map.put(allocator, "a.bin", 0);
    try observations.map.put(allocator, "b.bin", 1);
    const expected_digest = ids.Digest.of(&bytes);

    for ([_]usize{ 1, 2 }) |worker_count| {
        var states = [_]content.State{ .{ .size = bytes.len }, .{ .size = bytes.len } };
        for (&observed_files, &states) |*file, *state| file.content_state = state;
        var scratch: [16 * 1024]u8 = undefined;
        var bounded = std.heap.FixedBufferAllocator.init(&scratch);
        var family: SourceFamily = .{
            .allocator = bounded.allocator(),
            .io = io,
            .matcher_threads = 2,
            .parts = &parts,
            .input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = &parts, .size = bytes.len },
        };
        var covers = try FamilyCovers.init(allocator, worker_count);
        defer covers.deinit();
        const directory: ziff.Directory = .{ .files = &files, .ops = &.{}, .units = units[0..worker_count], .sources = &.{}, .removed = &.{} };
        try matchFamilyParallel(
            bounded.allocator(),
            io,
            directory,
            directory.units,
            &family,
            tmp.dir,
            .direct,
            &covers,
            &observations,
            worker_count,
            default_buffer_bytes,
            null,
        );
        for (covers.per_unit, states[0..worker_count]) |unit_covers, state| {
            try std.testing.expectEqualSlices(merge_mod.Cover, &.{.{ .source_offset = 0, .target_offset = 0, .length = bytes.len }}, unit_covers.items);
            try std.testing.expectEqual(expected_digest, state.digest.?);
        }
    }
}

test "serializer worker scratch is not retained with replay recipes" {
    const Memory = struct {
        bytes: []const u8,
        written: usize = 0,

        fn read(raw: ?*anyopaque, offset: u64, destination: []u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const start: usize = @intCast(offset);
            @memcpy(destination, self.bytes[start..][0..destination.len]);
        }

        fn expectWrite(raw: ?*anyopaque, offset: u64, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            try std.testing.expectEqual(@as(u64, self.written), offset);
            try std.testing.expectEqualSlices(u8, self.bytes[self.written..][0..bytes.len], bytes);
            self.written += bytes.len;
        }
    };
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes_pattern = "source bytes retained by the replay recipe";
    const bytes = std.mem.asBytes(&@as([8][bytes_pattern.len]u8, @splat(bytes_pattern.*)));
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.bin", .data = bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.bin", .data = bytes });
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var parts = [_]SourcePart{try SourcePart.capture(io, source, "source.bin", 0, bytes.len)};
    var family: SourceFamily = .{
        .allocator = allocator,
        .io = io,
        .matcher_threads = 1,
        .parts = &parts,
        .input = .{ .io = io, .root = tmp.dir, .reader = .direct, .parts = &parts, .size = bytes.len },
    };
    var files = [_]ziff.FileEntry{
        .{ .path = "source.bin", .size = bytes.len, .digest = ids.Digest.of(bytes) },
        .{ .path = "a.bin", .size = bytes.len, .digest = content.pending_digest },
        .{ .path = "b.bin", .size = bytes.len, .digest = content.pending_digest },
    };
    var units = [_]ziff.Unit{
        .{ .kind = .patch_zar26, .target = 1, .payload_offset = 0, .payload_len = 0, .source_first = 0, .source_count = 1 },
        .{ .kind = .patch_zar26, .target = 2, .payload_offset = 0, .payload_len = 0, .source_first = 0, .source_count = 1 },
    };
    var refs = [_]ziff.SourceRef{.{ .file = 0, .offset = 0, .length = bytes.len }};
    var replays = [_]ziff.Replay{ .{}, .{} };
    const directory: ziff.Directory = .{ .files = &files, .ops = &.{}, .units = &units, .sources = &refs, .removed = &.{}, .replays = &replays };
    var matched = [_]merge_mod.Cover{.{ .source_offset = 0, .target_offset = 0, .length = bytes.len }};
    for (0..4) |_| {
        var states = [_]content.State{ .{ .size = bytes.len }, .{ .size = bytes.len } };
        var jobs: [2]SerializeJob = undefined;
        for (&jobs, units, &states, 0..) |*job, unit, *state, index| job.* = .{
            .unit_index = index,
            .unit = unit,
            .covers = &matched,
            .family = &family,
            .observation = state,
            .max_payload_bytes = try bufferedPayloadLimit(bytes.len),
        };
        const payloads = try serializeJobsParallel(allocator, io, directory, &jobs, tmp.dir, .{}, 2, "test serialize scratch");
        defer deinitEncodedPayloads(allocator, payloads);
        for (payloads, replays) |payload, replay| {
            var patch: Memory = .{ .bytes = payload.bytes };
            var expected: Memory = .{ .bytes = bytes };
            var source_handles: [1]SourceHandle = undefined;
            var source_input: SourceReader = .{ .input = family.input, .handles = &source_handles };
            defer source_input.deinit();
            try zar26.decode(std.testing.allocator, source_input.zarInput(), .{ .context = &patch, .size = payload.bytes.len, .read_at = Memory.read }, bytes.len, .{ .context = &expected, .write_at = Memory.expectWrite });
            try std.testing.expectEqual(bytes.len, expected.written);
            try std.testing.expectEqualSlices(ranges.Range, &.{.{ .offset = 0, .length = bytes.len }}, replay.reads);
        }
    }
    try std.testing.expect(arena.queryCapacity() < default_buffer_bytes);
}

test "full-unit cancellation stops between chunks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes: [4096]u8 = @splat('x');
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = &bytes });
    const path = try fixturePath(allocator, &tmp, "target");
    defer allocator.free(path);
    var output = try fs.createGuardedOutput(io, tmp.dir, "payload");
    defer output.close(io);
    const Reader = struct {
        calls: usize = 0,
        fn read(raw: ?*anyopaque, read_io: std.Io, file: std.Io.File, data: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.calls += 1;
            const count = try file.readPositionalAll(read_io, data, offset);
            interrupt.request();
            return count;
        }
    };
    defer interrupt.reset();
    for ([_]ziff.UnitKind{ .raw, .zstd }) |kind| {
        interrupt.reset();
        try output.setLength(io, 0);
        var reader: Reader = .{};
        try std.testing.expectError(error.Interrupted, writeFullUnit(allocator, io, path, .{
            .path = "target",
            .size = bytes.len,
            .digest = ids.Digest.of(&bytes),
        }, output, 0, kind, .{
            .buffer_bytes = 64,
            .payload_reader = .{ .context = &reader, .read_fn = Reader.read },
        }));
        try std.testing.expectEqual(@as(usize, 1), reader.calls);
        try std.testing.expect(try output.length(io) < bytes.len);
    }
}

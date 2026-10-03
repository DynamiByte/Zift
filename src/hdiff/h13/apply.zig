// HDIFF13 apply: separate cover, RLE control/code, literal streams

const std = @import("std");
const core = @import("../encoding.zig");
const h13 = @import("../h13.zig");
const clip = @import("../../compression/decoder.zig");
const fs = @import("../../core/fs.zig");
const scan = @import("../../core/scan.zig");

pub const max_zstd_window_bytes: u64 = 256 * 1024 * 1024;
pub const work_buffer_bytes: usize = 128 * 1024;
pub const max_header_bytes: usize = h13.magic.len + h13.max_plugin_name_len + 1 +
    11 * core.max_hdiff_pack_uint_bytes;

pub const Error = core.Error || h13.Error || clip.Error || error{
    CallbackCancelled,
    ContainerReadFailed,
    InvalidReadCount,
    PatchRangeOutOfBounds,
    RleNotFinished,
    SourceReadFailed,
    SourceSizeMismatch,
    UnsafeTargetAlias,
    UnsupportedCompression,
    WriteFailed,
    ZeroLengthCover,
};

pub const OutputHook = @import("../hooks.zig").OutputHook;
pub const ProgressHook = @import("../hooks.zig").ProgressHook;

pub const Options = struct {
    reader: scan.Reader = .direct,
    output: ?OutputHook = null,
    progress: ?ProgressHook = null,
};

pub const Stats = struct {
    covers: u64 = 0,
    literal_bytes: u64 = 0,
    covered_bytes: u64 = 0,
    source_reads: u64 = 0,
};

const Cover = struct {
    old_pos: u64,
    new_pos: u64,
    length: u64,
};

const CoverReader = struct {
    stream: *clip.Decoder,
    old_end: u64 = 0,
    new_end: u64 = 0,

    fn next(self: *CoverReader) !Cover {
        var sign: u8 = 0;
        const old_delta = try core.readUIntTagged(self.stream, 1, &sign);
        const old_pos = if (sign == 0)
            std.math.add(u64, self.old_end, old_delta) catch
                return core.Error.CoverOutOfRange
        else blk: {
            if (old_delta > self.old_end) return core.Error.CoverOutOfRange;
            break :blk self.old_end - old_delta;
        };
        const new_delta = try core.readUInt(self.stream);
        const length = try core.readUInt(self.stream);
        const new_pos = std.math.add(u64, self.new_end, new_delta) catch
            return core.Error.TargetOverflow;
        const next_old_end = std.math.add(u64, old_pos, length) catch
            return core.Error.CoverOutOfRange;
        const next_new_end = std.math.add(u64, new_pos, length) catch
            return core.Error.TargetOverflow;

        self.old_end = next_old_end;
        self.new_end = next_new_end;
        return .{ .old_pos = old_pos, .new_pos = new_pos, .length = length };
    }
};

const RleType = enum(u2) {
    zero = 0,
    ff = 1,
    repeated = 2,
    bytes = 3,
};

// literals: logical RLE consumption without ADD
const Rle = struct {
    control: *clip.Decoder,
    code: *clip.Decoder,
    set_remaining: u64 = 0,
    set_value: u8 = 0,
    copy_remaining: u64 = 0,

    fn addTo(self: *Rle, bytes: []u8) !void {
        try self.consume(bytes, bytes.len);
    }

    fn skip(self: *Rle, count: usize) !void {
        try self.consume(null, count);
    }

    fn consume(self: *Rle, output: ?[]u8, count: usize) !void {
        if (output) |bytes| std.debug.assert(bytes.len == count);
        var consumed: usize = 0;
        while (consumed != count) {
            if (self.set_remaining != 0) {
                const take_u64 = @min(self.set_remaining, @as(u64, count - consumed));
                const take: usize = @intCast(take_u64);
                if (output) |bytes| {
                    if (self.set_value != 0) {
                        for (bytes[consumed..][0..take]) |*byte| byte.* +%= self.set_value;
                    }
                }
                self.set_remaining -= take_u64;
                consumed += take;
                continue;
            }

            if (self.copy_remaining != 0) {
                const take_u64 = @min(self.copy_remaining, @as(u64, count - consumed));
                const take: usize = @intCast(take_u64);
                if (output) |bytes| {
                    var scratch: [4096]u8 = undefined;
                    var copied: usize = 0;
                    while (copied != take) {
                        const piece = @min(scratch.len, take - copied);
                        try self.code.readInto(scratch[0..piece]);
                        for (bytes[consumed + copied ..][0..piece], scratch[0..piece]) |*byte, addend| {
                            byte.* +%= addend;
                        }
                        copied += piece;
                    }
                } else {
                    try self.code.skip(take_u64);
                }
                self.copy_remaining -= take_u64;
                consumed += take;
                continue;
            }

            var tag: u8 = 0;
            const encoded_length = try core.readUIntTagged(self.control, 2, &tag);
            const length = std.math.add(u64, encoded_length, 1) catch
                return core.Error.IntegerOverflow;
            switch (@as(RleType, @fromBackingInt(@as(u2, @truncate(tag))))) {
                .zero => {
                    self.set_remaining = length;
                    self.set_value = 0;
                },
                .ff => {
                    self.set_remaining = length;
                    self.set_value = 0xff;
                },
                .repeated => {
                    self.set_value = try self.code.byte();
                    self.set_remaining = length;
                },
                .bytes => self.copy_remaining = length,
            }
        }
    }

    fn finish(self: *Rle) !void {
        if (self.set_remaining != 0 or self.copy_remaining != 0)
            return Error.RleNotFinished;
        try self.control.finish();
        try self.code.finish();
    }
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

pub fn verifyFiles(allocator: std.mem.Allocator, io: std.Io, source: std.Io.File, container: std.Io.File, offset: u64, size: u64, options: Options) !Stats {
    return applyContainerTarget(allocator, io, .{ .file = source }, container, offset, size, .discard, options);
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
        return Error.ContainerReadFailed;
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
    const container_size = container.length(io) catch return Error.ContainerReadFailed;
    const patch_end = std.math.add(u64, patch_offset, patch_length) catch
        return Error.PatchRangeOutOfBounds;
    if (patch_end > container_size) return Error.PatchRangeOutOfBounds;

    var header_storage: [max_header_bytes]u8 = undefined;
    const header = try readHeaderPrefix(
        io,
        container,
        patch_offset,
        patch_length,
        options.reader,
        &header_storage,
    );
    const info = try h13.parse(header);
    try h13.validatePatchExtent(info, patch_length);
    try validateApplyHeader(info);

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
    const source_size = source.length(io) catch return Error.SourceReadFailed;
    if (source_size != info.old_size) return Error.SourceSizeMismatch;

    var covers = try initStream(
        allocator,
        io,
        container,
        patch_offset,
        info.covers_extent,
        info.covers,
        options.reader,
    );
    defer covers.deinit();
    var control = try initStream(
        allocator,
        io,
        container,
        patch_offset,
        info.rle_ctrl_extent,
        info.rle_ctrl,
        options.reader,
    );
    defer control.deinit();
    var code = try initStream(
        allocator,
        io,
        container,
        patch_offset,
        info.rle_code_extent,
        info.rle_code,
        options.reader,
    );
    defer code.deinit();
    var literals = try initStream(
        allocator,
        io,
        container,
        patch_offset,
        info.literals_extent,
        info.literals,
        options.reader,
    );
    defer literals.deinit();

    const work = try allocator.alloc(u8, work_buffer_bytes);
    defer allocator.free(work);

    var owned_target: ?std.Io.File = null;
    const guarded = switch (destination) {
        .path, .discard => false,
        .file => true,
    };
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
            (fs.sameOpenFile(io, file, container) catch return Error.WriteFailed)) return Error.UnsafeTargetAlias;
        if (guarded) {
            fs.validateGuardedOutput(io, file, 0) catch return Error.WriteFailed;
        } else {
            file.setLength(io, 0) catch return Error.WriteFailed;
        }
    }

    var stats: Stats = .{};
    var cover_reader: CoverReader = .{ .stream = &covers };
    var rle: Rle = .{ .control = &control, .code = &code };
    var output_pos: u64 = 0;

    var cover_index: u64 = 0;
    while (cover_index != info.cover_count) : (cover_index += 1) {
        const cover = try cover_reader.next();
        if (cover.length == 0) return Error.ZeroLengthCover;
        if (cover.new_pos < output_pos) return core.Error.TargetUnderflow;
        if (cover.new_pos > info.new_size or
            cover.length > info.new_size - cover.new_pos)
            return core.Error.TargetOverflow;
        if (cover.old_pos > source_size or
            cover.length > source_size - cover.old_pos)
            return core.Error.CoverOutOfRange;

        var literal_left = cover.new_pos - output_pos;
        while (literal_left != 0) {
            const take: usize = @intCast(@min(@as(u64, work.len), literal_left));
            try literals.readInto(work[0..take]);
            try rle.skip(take);
            try emit(target, io, output_pos, work[0..take], options);
            output_pos = try core.checkedAddU64(output_pos, take);
            stats.literal_bytes = try core.checkedAddU64(stats.literal_bytes, take);
            literal_left -= take;
        }

        var source_left = cover.length;
        var source_pos = cover.old_pos;
        while (source_left != 0) {
            const take: usize = @intCast(@min(@as(u64, work.len), source_left));
            const calls = try readExactAt(
                io,
                source,
                work[0..take],
                source_pos,
                options.reader,
                .source,
            );
            stats.source_reads = try core.checkedAddU64(stats.source_reads, calls);
            try rle.addTo(work[0..take]);
            try emit(target, io, output_pos, work[0..take], options);
            output_pos = try core.checkedAddU64(output_pos, take);
            source_pos = try core.checkedAddU64(source_pos, take);
            source_left -= take;
            stats.covered_bytes = try core.checkedAddU64(stats.covered_bytes, take);
        }
        stats.covers = try core.checkedAddU64(stats.covers, 1);
    }

    var trailing_literals = info.new_size - output_pos;
    while (trailing_literals != 0) {
        const take: usize = @intCast(@min(@as(u64, work.len), trailing_literals));
        try literals.readInto(work[0..take]);
        try rle.skip(take);
        try emit(target, io, output_pos, work[0..take], options);
        output_pos = try core.checkedAddU64(output_pos, take);
        stats.literal_bytes = try core.checkedAddU64(stats.literal_bytes, take);
        trailing_literals -= take;
    }

    if (output_pos != info.new_size) return core.Error.TargetUnderflow;
    try covers.finish();
    try rle.finish();
    try literals.finish();

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

fn validateApplyHeader(info: h13.Info) !void {
    if (info.compress_type.len == 0) {
        if (info.compressedCount() != 0) return Error.UnsupportedCompression;
    } else if (!std.mem.eql(u8, info.compress_type, "zstd")) {
        return Error.UnsupportedCompression;
    }

    if (info.cover_count > info.new_size) return h13.Error.HeaderInconsistent;
    if (exceedsProduct(info.covers.raw, info.cover_count, 3 * core.max_hdiff_pack_uint_bytes) or
        exceedsProduct(info.rle_ctrl.raw, info.new_size, core.max_hdiff_pack_uint_bytes) or
        info.rle_code.raw > info.new_size or
        info.literals.raw > info.new_size)
        return h13.Error.HeaderInconsistent;
}

fn exceedsProduct(value: u64, count: u64, factor: u64) bool {
    const bound = std.math.mul(u64, count, factor) catch std.math.maxInt(u64);
    return value > bound;
}

fn initStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    patch_offset: u64,
    extent: h13.StreamExtent,
    spec: h13.StreamSpec,
    reader: scan.Reader,
) !clip.Decoder {
    const absolute = std.math.add(u64, patch_offset, extent.offset) catch
        return Error.PatchRangeOutOfBounds;
    return clip.Decoder.init(
        allocator,
        io,
        file,
        absolute,
        spec.compressed,
        spec.raw,
        .{ .max_window_bytes = max_zstd_window_bytes, .reader = reader },
    );
}

const ShortRead = enum { header, source };

fn readHeaderPrefix(
    io: std.Io,
    file: std.Io.File,
    patch_offset: u64,
    patch_length: u64,
    reader: scan.Reader,
    storage: *[max_header_bytes]u8,
) ![]const u8 {
    const wanted: usize = @intCast(@min(@as(u64, storage.len), patch_length));
    _ = try readExactAt(
        io,
        file,
        storage[0..wanted],
        patch_offset,
        reader,
        .header,
    );
    return storage[0..wanted];
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
            .header => h13.Error.Truncated,
            .source => Error.SourceReadFailed,
        };
        done += count;
    }
    return calls;
}

fn emit(
    target: ?std.Io.File,
    io: std.Io,
    offset: u64,
    bytes: []const u8,
    options: Options,
) !void {
    if (target) |file| file.writePositionalAll(io, bytes, offset) catch return Error.WriteFailed;
    if (options.output) |hook| {
        if (!try hook.call(offset, bytes)) return Error.CallbackCancelled;
    }
    if (options.progress) |hook| {
        if (!try hook.call(bytes.len)) return Error.CallbackCancelled;
    }
}

// tests

const FixtureOptions = struct {
    plugin: []const u8 = "",
    new_size: u64 = 8,
    old_size: u64 = 8,
    cover_count: u64 = 2,
    covers_raw: u64 = 6,
    covers_compressed: u64 = 0,
    control_raw: u64 = 5,
    control_compressed: u64 = 0,
    code_raw: u64 = 4,
    code_compressed: u64 = 0,
    literals_raw: u64 = 3,
    literals_compressed: u64 = 0,
    covers_body: []const u8 = &.{ 2, 2, 3, 0x85, 1, 2 },
    control_body: []const u8 = &.{ 1, 0xc2, 0, 0x80, 0 },
    code_body: []const u8 = &.{ 0, 1, 0xff, 2 },
    literals_body: []const u8 = "xyz",
};

fn appendPackUInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
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

fn buildFixture(allocator: std.mem.Allocator, options: FixtureOptions) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, h13.magic);
    try out.appendSlice(allocator, options.plugin);
    try out.append(allocator, 0);
    for ([_]u64{
        options.new_size,
        options.old_size,
        options.cover_count,
        options.covers_raw,
        options.covers_compressed,
        options.control_raw,
        options.control_compressed,
        options.code_raw,
        options.code_compressed,
        options.literals_raw,
        options.literals_compressed,
    }) |value| try appendPackUInt(&out, allocator, value);
    try out.appendSlice(allocator, options.covers_body);
    try out.appendSlice(allocator, options.control_body);
    try out.appendSlice(allocator, options.code_body);
    try out.appendSlice(allocator, options.literals_body);
    return out.toOwnedSlice(allocator);
}

const HookState = struct {
    bytes: [32]u8 = undefined,
    length: usize = 0,
    progress: u64 = 0,

    fn output(context: ?*anyopaque, offset: u64, bytes: []const u8) !bool {
        const self: *HookState = @ptrCast(@alignCast(context orelse return false));
        if (offset != self.length or bytes.len > self.bytes.len - self.length) return false;
        @memcpy(self.bytes[self.length..][0..bytes.len], bytes);
        self.length += bytes.len;
        return true;
    }

    fn addProgress(context: ?*anyopaque, count: u64) !bool {
        const self: *HookState = @ptrCast(@alignCast(context orelse return false));
        self.progress = try core.checkedAddU64(self.progress, count);
        return true;
    }
};

const DigestHookState = struct {
    hasher: std.crypto.hash.Blake3 = .init(.{}),
    next_offset: u64 = 0,
    progress: u64 = 0,
    output_calls: u64 = 0,

    fn output(context: ?*anyopaque, offset: u64, bytes: []const u8) !bool {
        const self: *DigestHookState = @ptrCast(@alignCast(context orelse return false));
        if (offset != self.next_offset) return false;
        self.hasher.update(bytes);
        self.next_offset = try core.checkedAddU64(self.next_offset, bytes.len);
        self.output_calls = try core.checkedAddU64(self.output_calls, 1);
        return true;
    }

    fn addProgress(context: ?*anyopaque, count: u64) !bool {
        const self: *DigestHookState = @ptrCast(@alignCast(context orelse return false));
        self.progress = try core.checkedAddU64(self.progress, count);
        return true;
    }

    fn final(self: *DigestHookState) [32]u8 {
        var digest: [32]u8 = undefined;
        self.hasher.final(&digest);
        return digest;
    }
};

const ChunkReader = struct {
    max_chunk: usize,
    calls: u64 = 0,

    fn read(
        context: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        buffer: []u8,
        offset: u64,
    ) !usize {
        const self: *ChunkReader = @ptrCast(@alignCast(context orelse return error.MissingContext));
        self.calls = try core.checkedAddU64(self.calls, 1);
        const take = @min(buffer.len, self.max_chunk);
        return scan.Reader.direct.read(io, file, buffer[0..take], offset);
    }

    fn reader(self: *ChunkReader) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

const ReaderBehavior = union(enum) {
    chunked,
    overcount,
    truncate_at: u64,
};

// test reader distinguishes files by length
const ScopedReader = struct {
    source_length: u64,
    container: ReaderBehavior,
    source: ReaderBehavior,
    max_chunk: usize,
    calls: u64 = 0,

    fn read(
        context: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        buffer: []u8,
        offset: u64,
    ) !usize {
        const self: *ScopedReader = @ptrCast(@alignCast(context orelse return error.MissingContext));
        self.calls = try core.checkedAddU64(self.calls, 1);
        const file_length = try file.length(io);
        const behavior = if (file_length == self.source_length) self.source else self.container;
        return switch (behavior) {
            .chunked => scan.Reader.direct.read(
                io,
                file,
                buffer[0..@min(buffer.len, self.max_chunk)],
                offset,
            ),
            .overcount => buffer.len + 1,
            .truncate_at => |boundary| blk: {
                if (offset >= boundary) break :blk 0;
                const available: usize = @intCast(@min(
                    @as(u64, buffer.len),
                    boundary - offset,
                ));
                break :blk scan.Reader.direct.read(
                    io,
                    file,
                    buffer[0..@min(available, self.max_chunk)],
                    offset,
                );
            },
        };
    }

    fn reader(self: *ScopedReader) scan.Reader {
        return .{ .context = self, .read_fn = read };
    }
};

fn testAbsolutePath(allocator: std.mem.Allocator, tmp: *const std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, name });
}

test "HDIFF13 refuses Source and container Target aliases before truncation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const patch = try buildFixture(allocator, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCDEFGH" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
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

    const source_after = try tmp.dir.readFileAlloc(io, "source.bin", allocator, .limited(9));
    defer allocator.free(source_after);
    try std.testing.expectEqualStrings("ABCDEFGH", source_after);
    const container_after = try tmp.dir.readFileAlloc(io, "container.bin", allocator, .limited(patch.len + 1));
    defer allocator.free(container_after);
    try std.testing.expectEqualSlices(u8, patch, container_after);
}

test "HDIFF13 refuses a hard-linked Source Target before truncation" {
    if (@import("builtin").target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const patch = try buildFixture(allocator, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCDEFGH" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    try fs.hardLinkInTmp(allocator, &tmp, "source.bin", "target.bin");
    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
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
    const source_after = try tmp.dir.readFileAlloc(io, "source.bin", allocator, .limited(9));
    defer allocator.free(source_after);
    try std.testing.expectEqualStrings("ABCDEFGH", source_after);
}

test "HDIFF13 borrowed handles survive Source and container pathname replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const patch = try buildFixture(allocator, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCDEFGH" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var container = try fs.openRead(io, tmp.dir, "container.bin");
    defer container.close(io);
    var target = try fs.createGuardedOutputBeneath(io, tmp.dir, "target.bin");
    defer target.close(io);

    try tmp.dir.rename("source.bin", tmp.dir, "retained-source.bin", io);
    try tmp.dir.rename("container.bin", tmp.dir, "retained-container.bin", io);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "12345678" });
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

    var actual: [8]u8 = undefined;
    try std.testing.expectEqual(actual.len, try target.readPositionalAll(io, &actual, 0));
    try std.testing.expectEqualStrings("xyCEDzCB", &actual);
    try std.testing.expectEqual(@as(u64, 8), try source.length(io));
    try std.testing.expectEqual(@as(u64, patch.len), try container.length(io));
}

fn expectFixtureApplyError(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: FixtureOptions,
    source_bytes: []const u8,
    expected_error: anyerror,
) !void {
    const patch = try buildFixture(allocator, options);
    defer allocator.free(patch);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);
    try std.testing.expectError(
        expected_error,
        apply(allocator, io, source_path, container_path, 0, patch.len, target_path, .{}),
    );
}

test "HDIFF13 stored fixture applies exact range and drives sequential hooks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const patch = try buildFixture(allocator, .{});
    defer allocator.free(patch);
    var container: std.ArrayList(u8) = .empty;
    defer container.deinit(allocator);
    try container.appendSlice(allocator, "prefix!");
    try container.appendSlice(allocator, patch);
    try container.appendSlice(allocator, "suffix!");
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCDEFGH" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = container.items });

    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);

    var hook: HookState = .{};
    const stats = try apply(
        allocator,
        io,
        source_path,
        container_path,
        "prefix!".len,
        patch.len,
        target_path,
        .{
            .output = .{ .context = &hook, .call_fn = HookState.output },
            .progress = .{ .context = &hook, .call_fn = HookState.addProgress },
        },
    );
    try std.testing.expectEqual(@as(u64, 2), stats.covers);
    try std.testing.expectEqual(@as(u64, 3), stats.literal_bytes);
    try std.testing.expectEqual(@as(u64, 5), stats.covered_bytes);
    try std.testing.expectEqual(@as(u64, 8), hook.progress);
    try std.testing.expectEqualSlices(u8, "xyCEDzCB", hook.bytes[0..hook.length]);

    const actual = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(9));
    defer allocator.free(actual);
    try std.testing.expectEqualSlices(u8, "xyCEDzCB", actual);
}

test "HDIFF13 applies four independent zstd streams with every RLE kind" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const pair_count: usize = 256;

    var covers_raw: std.ArrayList(u8) = .empty;
    defer covers_raw.deinit(allocator);
    var control_raw: std.ArrayList(u8) = .empty;
    defer control_raw.deinit(allocator);
    var code_raw: std.ArrayList(u8) = .empty;
    defer code_raw.deinit(allocator);
    var literals_raw: std.ArrayList(u8) = .empty;
    defer literals_raw.deinit(allocator);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(allocator);

    for (0..pair_count) |pair_index| {
        // 0x84: source back four bytes; all covers at source[0..4]
        try covers_raw.appendSlice(allocator, &.{ if (pair_index == 0) 0 else 0x84, 4, 4 });
        try covers_raw.appendSlice(allocator, &.{ 0x84, 4, 4 });

        // swapped roles: every RLE kind applied and skipped
        try control_raw.appendSlice(allocator, &.{
            0x01, 0x41, 0x81, 0xc1,
            0x81, 0xc1, 0x01, 0x41,
        });
        try code_raw.appendSlice(allocator, &.{ 1, 2, 3, 5, 6, 7 });
        try literals_raw.appendSlice(allocator, "xyzwxyzw");
        try expected.appendSlice(allocator, "xyzwBCEGxyzwABBC");
    }

    const covers_frame = try @import("../../compression/frame.zig").compressAlloc(allocator, covers_raw.items, 5);
    defer allocator.free(covers_frame);
    const control_frame = try @import("../../compression/frame.zig").compressAlloc(allocator, control_raw.items, 5);
    defer allocator.free(control_frame);
    const code_frame = try @import("../../compression/frame.zig").compressAlloc(allocator, code_raw.items, 5);
    defer allocator.free(code_frame);
    const literals_frame = try @import("../../compression/frame.zig").compressAlloc(allocator, literals_raw.items, 5);
    defer allocator.free(literals_frame);
    inline for (.{
        .{ covers_frame, covers_raw.items },
        .{ control_frame, control_raw.items },
        .{ code_frame, code_raw.items },
        .{ literals_frame, literals_raw.items },
    }) |pair| try std.testing.expect(pair[0].len < pair[1].len);

    const patch = try buildFixture(allocator, .{
        .plugin = "zstd",
        .new_size = expected.items.len,
        .old_size = 4,
        .cover_count = pair_count * 2,
        .covers_raw = covers_raw.items.len,
        .covers_compressed = covers_frame.len,
        .control_raw = control_raw.items.len,
        .control_compressed = control_frame.len,
        .code_raw = code_raw.items.len,
        .code_compressed = code_frame.len,
        .literals_raw = literals_raw.items.len,
        .literals_compressed = literals_frame.len,
        .covers_body = covers_frame,
        .control_body = control_frame,
        .code_body = code_frame,
        .literals_body = literals_frame,
    });
    defer allocator.free(patch);

    var container: std.ArrayList(u8) = .empty;
    defer container.deinit(allocator);
    try container.appendSlice(allocator, "compressed-prefix");
    try container.appendSlice(allocator, patch);
    try container.appendSlice(allocator, "compressed-suffix");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCD" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = container.items });
    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);

    var reader: ChunkReader = .{ .max_chunk = 7 };
    var hook: DigestHookState = .{};
    const stats = try apply(
        allocator,
        io,
        source_path,
        container_path,
        "compressed-prefix".len,
        patch.len,
        target_path,
        .{
            .reader = reader.reader(),
            .output = .{ .context = &hook, .call_fn = DigestHookState.output },
            .progress = .{ .context = &hook, .call_fn = DigestHookState.addProgress },
        },
    );
    try std.testing.expectEqual(@as(u64, pair_count * 2), stats.covers);
    try std.testing.expectEqual(@as(u64, pair_count * 8), stats.literal_bytes);
    try std.testing.expectEqual(@as(u64, pair_count * 8), stats.covered_bytes);
    try std.testing.expectEqual(@as(u64, expected.items.len), hook.progress);
    try std.testing.expectEqual(@as(u64, expected.items.len), hook.next_offset);
    try std.testing.expect(hook.output_calls > 1);
    try std.testing.expect(reader.calls > 4);

    var expected_hasher = std.crypto.hash.Blake3.init(.{});
    expected_hasher.update(expected.items);
    var expected_digest: [32]u8 = undefined;
    expected_hasher.final(&expected_digest);
    try std.testing.expectEqualSlices(u8, &expected_digest, &(hook.final()));

    const actual = try tmp.dir.readFileAlloc(
        io,
        "target.bin",
        allocator,
        .limited(expected.items.len + 1),
    );
    defer allocator.free(actual);
    try std.testing.expectEqualSlices(u8, expected.items, actual);
}

test "HDIFF13 reader seam distinguishes chunking overcounts and real short boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const patch = try buildFixture(allocator, .{});
    defer allocator.free(patch);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "ABCDEFGH" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);

    const cases = [_]struct {
        name: []const u8,
        container: ReaderBehavior,
        source: ReaderBehavior,
        expected: ?anyerror,
    }{
        .{
            .name = "chunked",
            .container = .chunked,
            .source = .chunked,
            .expected = null,
        },
        .{
            .name = "header-overcount",
            .container = .overcount,
            .source = .chunked,
            .expected = Error.InvalidReadCount,
        },
        .{
            .name = "header-truncated",
            .container = .{ .truncate_at = 5 },
            .source = .chunked,
            .expected = h13.Error.Truncated,
        },
        .{
            .name = "source-overcount",
            .container = .chunked,
            .source = .overcount,
            .expected = Error.InvalidReadCount,
        },
        .{
            .name = "source-truncated",
            .container = .chunked,
            .source = .{ .truncate_at = 4 },
            .expected = Error.SourceReadFailed,
        },
    };

    for (cases, 0..) |case, case_index| {
        var target_name_buffer: [32]u8 = undefined;
        const target_name = try std.fmt.bufPrint(
            &target_name_buffer,
            "reader-{d}.bin",
            .{case_index},
        );
        const target_path = try testAbsolutePath(allocator, &tmp, target_name);
        defer allocator.free(target_path);
        var reader: ScopedReader = .{
            .source_length = 8,
            .container = case.container,
            .source = case.source,
            .max_chunk = 3,
        };
        const result = apply(
            allocator,
            io,
            source_path,
            container_path,
            0,
            patch.len,
            target_path,
            .{ .reader = reader.reader() },
        );
        if (result) |stats| {
            if (case.expected != null) {
                std.debug.print("reader case {s} unexpectedly succeeded\n", .{case.name});
                return error.ExpectedReaderFailure;
            }
            try std.testing.expectEqual(@as(u64, 2), stats.covers);
            const actual = try tmp.dir.readFileAlloc(io, target_name, allocator, .limited(9));
            defer allocator.free(actual);
            try std.testing.expectEqualSlices(u8, "xyCEDzCB", actual);
            try std.testing.expect(reader.calls > 5);
        } else |actual_error| {
            const expected = case.expected orelse {
                std.debug.print(
                    "reader case {s} unexpectedly failed with {s}\n",
                    .{ case.name, @errorName(actual_error) },
                );
                return actual_error;
            };
            try std.testing.expectEqual(expected, actual_error);
        }
    }
}

test "HDIFF13 preflight errors do not touch an existing Target" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);

    const cases = [_]struct {
        options: FixtureOptions,
        source: []const u8 = "ABCDEFGH",
        expected: anyerror,
    }{
        .{ .options = .{}, .source = "short", .expected = Error.SourceSizeMismatch },
        .{ .options = .{ .plugin = "not-zstd", .covers_compressed = 6 }, .expected = Error.UnsupportedCompression },
        .{ .options = .{ .plugin = "not-zstd" }, .expected = Error.UnsupportedCompression },
        .{ .options = .{ .plugin = "zstd", .covers_raw = 61, .covers_compressed = 6 }, .expected = h13.Error.HeaderInconsistent },
    };
    for (cases) |case| {
        const patch = try buildFixture(allocator, case.options);
        defer allocator.free(patch);
        try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = case.source });
        try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });
        try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "sentinel" });

        try std.testing.expectError(
            case.expected,
            apply(allocator, io, source_path, container_path, 0, patch.len, target_path, .{}),
        );
        const actual = try tmp.dir.readFileAlloc(io, "target.bin", allocator, .limited(9));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings("sentinel", actual);
    }
}

test "HDIFF13 rejects noncanonical zero-length covers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const patch = try buildFixture(allocator, .{
        .new_size = 1,
        .old_size = 1,
        .cover_count = 1,
        .covers_raw = 3,
        .covers_body = &.{ 0, 0, 0 },
        .control_raw = 1,
        .control_body = &.{0},
        .code_raw = 0,
        .code_body = &.{},
        .literals_raw = 1,
        .literals_body = "x",
    });
    defer allocator.free(patch);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "A" });
    try tmp.dir.writeFile(io, .{ .sub_path = "container.bin", .data = patch });

    const source_path = try testAbsolutePath(allocator, &tmp, "source.bin");
    defer allocator.free(source_path);
    const container_path = try testAbsolutePath(allocator, &tmp, "container.bin");
    defer allocator.free(container_path);
    const target_path = try testAbsolutePath(allocator, &tmp, "target.bin");
    defer allocator.free(target_path);

    try std.testing.expectError(
        Error.ZeroLengthCover,
        apply(allocator, io, source_path, container_path, 0, patch.len, target_path, .{}),
    );
}

test "HDIFF13 enforces each decoded raw-stream grammar bound" {
    const allocator = std.testing.allocator;
    const zeros: [11]u8 = @splat(0);
    const cases = [_]FixtureOptions{
        .{
            .new_size = 1,
            .old_size = 1,
            .cover_count = 0,
            .covers_raw = 1,
            .covers_body = zeros[0..1],
            .control_raw = 1,
            .control_body = zeros[0..1],
            .code_raw = 0,
            .code_body = &.{},
            .literals_raw = 1,
            .literals_body = "x",
        },
        .{
            .new_size = 1,
            .old_size = 1,
            .cover_count = 0,
            .covers_raw = 0,
            .covers_body = &.{},
            .control_raw = 11,
            .control_body = &zeros,
            .code_raw = 0,
            .code_body = &.{},
            .literals_raw = 1,
            .literals_body = "x",
        },
        .{
            .new_size = 1,
            .old_size = 1,
            .cover_count = 0,
            .covers_raw = 0,
            .covers_body = &.{},
            .control_raw = 1,
            .control_body = zeros[0..1],
            .code_raw = 2,
            .code_body = zeros[0..2],
            .literals_raw = 1,
            .literals_body = "x",
        },
        .{
            .new_size = 1,
            .old_size = 1,
            .cover_count = 0,
            .covers_raw = 0,
            .covers_body = &.{},
            .control_raw = 1,
            .control_body = zeros[0..1],
            .code_raw = 0,
            .code_body = &.{},
            .literals_raw = 2,
            .literals_body = "xy",
        },
    };

    for (cases) |case| {
        const patch = try buildFixture(allocator, case);
        defer allocator.free(patch);
        try std.testing.expectError(
            h13.Error.HeaderInconsistent,
            validateApplyHeader(try h13.parse(patch)),
        );
    }
}

test "HDIFF13 rejects trailing and truncated cover RLE and literal streams" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        options: FixtureOptions,
        expected_error: anyerror,
    }{
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 1,
                .covers_raw = 4,
                .covers_body = &.{ 0, 0, 1, 0 },
                .control_raw = 1,
                .control_body = &.{0},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 0,
                .literals_body = &.{},
            },
            .expected_error = clip.Error.OutputSizeMismatch,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 1,
                .covers_raw = 3,
                .covers_body = &.{ 0, 0, 0x80 },
                .control_raw = 1,
                .control_body = &.{0},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 0,
                .literals_body = &.{},
            },
            .expected_error = clip.Error.OutputBudgetExceeded,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 2,
                .control_body = &.{ 0, 0 },
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = clip.Error.OutputSizeMismatch,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 1,
                .control_body = &.{0x20},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = clip.Error.OutputBudgetExceeded,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 1,
                .control_body = &.{1},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = Error.RleNotFinished,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 1,
                .control_body = &.{0},
                .code_raw = 1,
                .code_body = &.{0},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = clip.Error.OutputSizeMismatch,
        },
        .{
            .options = .{
                .new_size = 1,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 1,
                .control_body = &.{0x80},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = clip.Error.OutputBudgetExceeded,
        },
        .{
            .options = .{
                .new_size = 2,
                .old_size = 1,
                .cover_count = 1,
                .covers_raw = 3,
                .covers_body = &.{ 0, 1, 1 },
                .control_raw = 1,
                .control_body = &.{1},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 2,
                .literals_body = "xy",
            },
            .expected_error = clip.Error.OutputSizeMismatch,
        },
        .{
            .options = .{
                .new_size = 2,
                .old_size = 1,
                .cover_count = 0,
                .covers_raw = 0,
                .covers_body = &.{},
                .control_raw = 1,
                .control_body = &.{1},
                .code_raw = 0,
                .code_body = &.{},
                .literals_raw = 1,
                .literals_body = "x",
            },
            .expected_error = clip.Error.OutputBudgetExceeded,
        },
    };

    for (cases) |case| try expectFixtureApplyError(
        allocator,
        io,
        case.options,
        "A",
        case.expected_error,
    );
}

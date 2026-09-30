// exact target covers over concatenated source

const std = @import("std");
const builtin = @import("builtin");

const match_index = @import("../../match/index.zig");
const fs = @import("../../core/fs.zig");
const scan = @import("../../core/scan.zig");

pub const default_block_size: usize = 256;
pub const minimum_block_size = 16;
pub const maximum_block_size = 16384;
pub const verification_buffer_bytes: usize = 64 * 1024;
pub const collinear_gap_max_gap: u64 = 511;

// collinear_gap: ADD extension only for strictly lower raw W26 cost
pub const Profile = enum {
    exact_anchors,
    collinear_gap,
};

pub const Part = struct {
    path: []const u8,
    size: u64,
};

// borrowed files through synchronous match
pub const InputPart = struct {
    file: std.Io.File,
    size: u64,
};

pub const Cover = match_index.Cover;

pub const Options = struct {
    block_size: usize = default_block_size,
    profile: Profile = .exact_anchors,
    reader: scan.Reader = .direct,
};

fn validateSourceExtent(sources: []const Part) !void {
    var total: u64 = 0;
    for (sources) |source| {
        total = std.math.add(u64, total, source.size) catch
            return error.SourceTooLarge;
    }
}

const OpenPart = struct {
    file: std.Io.File,
    logical_start: u64,
    size: u64,
};

const LogicalInput = struct {
    io: std.Io,
    reader: scan.Reader,
    parts: []const OpenPart,
    size: u64,

    fn readExact(self: *LogicalInput, destination: []u8, offset: u64) !void {
        const length: u64 = @intCast(destination.len);
        const end = std.math.add(u64, offset, length) catch return error.ReadOutOfBounds;
        if (end > self.size) return error.ReadOutOfBounds;
        if (destination.len == 0) return;

        var done: usize = 0;
        var position = offset;
        while (done < destination.len) {
            var selected: ?OpenPart = null;
            for (self.parts) |part| {
                const part_end = part.logical_start + part.size;
                if (position >= part.logical_start and position < part_end) {
                    selected = part;
                    break;
                }
            }
            const part = selected orelse return error.ReadOutOfBounds;
            const relative = position - part.logical_start;
            const available = part.size - relative;
            const wanted: usize = @intCast(@min(@as(u64, destination.len - done), available));
            if (wanted == 0) return error.ReadOutOfBounds;
            const count = try self.reader.read(
                self.io,
                part.file,
                destination[done .. done + wanted],
                relative,
            );
            if (count != wanted) return error.ShortRead;
            done += wanted;
            position += wanted;
        }
    }

    fn readCallback(context: *anyopaque, offset: u64, destination: []u8) !void {
        const self: *LogicalInput = @ptrCast(@alignCast(context));
        try self.readExact(destination, offset);
    }
};

// source offsets in caller concatenation order
pub fn matchExact(
    allocator: std.mem.Allocator,
    io: std.Io,
    sources: []const Part,
    target: Part,
    options: Options,
) ![]Cover {
    if (options.block_size < minimum_block_size or
        options.block_size > maximum_block_size)
        return error.InvalidBlockSize;
    if (sources.len == 0) return error.NoSources;

    try validateSourceExtent(sources);

    const open_sources = try allocator.alloc(InputPart, sources.len);
    defer allocator.free(open_sources);
    var source_count: usize = 0;
    defer for (open_sources[0..source_count]) |part| part.file.close(io);
    for (sources, open_sources) |source, *opened| {
        var file = try fs.openRead(io, std.Io.Dir.cwd(), source.path);
        const actual_size = file.length(io) catch |err| {
            file.close(io);
            return err;
        };
        if (actual_size != source.size) {
            file.close(io);
            return error.FileChangedDuringMatch;
        }
        opened.* = .{ .file = file, .size = source.size };
        source_count += 1;
    }
    var target_file = try fs.openRead(io, std.Io.Dir.cwd(), target.path);
    defer target_file.close(io);
    if (try target_file.length(io) != target.size) return error.FileChangedDuringMatch;

    return matchExactFiles(
        allocator,
        io,
        open_sources,
        .{ .file = target_file, .size = target.size },
        options,
    );
}

pub fn matchExactFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    sources: []const InputPart,
    target: InputPart,
    options: Options,
) ![]Cover {
    if (options.block_size < minimum_block_size or
        options.block_size > maximum_block_size)
        return error.InvalidBlockSize;
    if (sources.len == 0) return error.NoSources;

    var source_size: u64 = 0;
    const open_sources = try allocator.alloc(OpenPart, sources.len);
    defer allocator.free(open_sources);
    var logical_start: u64 = 0;
    for (sources, open_sources) |source, *opened| {
        if (try source.file.length(io) != source.size) return error.FileChangedDuringMatch;
        source_size = std.math.add(u64, source_size, source.size) catch return error.SourceTooLarge;
        opened.* = .{
            .file = source.file,
            .logical_start = logical_start,
            .size = source.size,
        };
        logical_start = source_size;
    }
    if (try target.file.length(io) != target.size) return error.FileChangedDuringMatch;
    const target_parts = [_]OpenPart{.{
        .file = target.file,
        .logical_start = 0,
        .size = target.size,
    }};

    var source_input: LogicalInput = .{
        .io = io,
        .reader = options.reader,
        .parts = open_sources,
        .size = source_size,
    };
    var target_input: LogicalInput = .{
        .io = io,
        .reader = options.reader,
        .parts = &target_parts,
        .size = target.size,
    };
    const source_match: match_index.Input = .{
        .context = &source_input,
        .size = source_size,
        .read_at = LogicalInput.readCallback,
    };
    const target_match: match_index.Input = .{
        .context = &target_input,
        .size = target.size,
        .read_at = LogicalInput.readCallback,
    };
    const index = try match_index.Index.init(io, source_match, options.block_size, false, 1);
    defer index.deinit();
    const exact_covers = try index.search(allocator, target_match);
    errdefer allocator.free(exact_covers);
    try validateForeign(exact_covers, source_size, target.size);
    try validateExact(
        allocator,
        &source_input,
        &target_input,
        exact_covers,
    );
    try validateBorrowedLengths(io, sources, target);
    if (options.profile == .exact_anchors) return exact_covers;

    const profiled = try collinearGap(
        allocator,
        &source_input,
        &target_input,
        exact_covers,
    );
    errdefer allocator.free(profiled);
    try validateBorrowedLengths(io, sources, target);
    allocator.free(exact_covers);
    return profiled;
}

fn validateBorrowedLengths(
    io: std.Io,
    sources: []const InputPart,
    target: InputPart,
) !void {
    for (sources) |source| {
        if (try source.file.length(io) != source.size) return error.FileChangedDuringMatch;
    }
    if (try target.file.length(io) != target.size) return error.FileChangedDuringMatch;
}

// disjoint anchor pairs for independent decisions and bounded memory
fn collinearGap(
    allocator: std.mem.Allocator,
    source: *LogicalInput,
    target: *LogicalInput,
    anchors: []const Cover,
) ![]Cover {
    var result: std.ArrayList(Cover) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, anchors.len);

    var source_bytes: [collinear_gap_max_gap]u8 = undefined;
    var target_bytes: [collinear_gap_max_gap]u8 = undefined;
    var second: [collinear_gap_max_gap]u8 = undefined;
    var third: [collinear_gap_max_gap]u8 = undefined;

    var index: usize = 0;
    while (index < anchors.len) {
        const first = anchors[index];
        if (index + 1 >= anchors.len) {
            result.appendAssumeCapacity(first);
            break;
        }
        const next = anchors[index + 1];
        const source_gap = collinearCandidateGap(first, next) orelse {
            result.appendAssumeCapacity(first);
            index += 1;
            continue;
        };
        const first_source_end = try checkedAdd(first.source_offset, first.length);
        const first_target_end = try checkedAdd(first.target_offset, first.length);

        const gap_len: usize = @intCast(source_gap);
        if (gap_len != 0) {
            try readAdjudicated(
                source,
                source_bytes[0..gap_len],
                second[0..gap_len],
                third[0..gap_len],
                first_source_end,
            );
            try readAdjudicated(
                target,
                target_bytes[0..gap_len],
                second[0..gap_len],
                third[0..gap_len],
                first_target_end,
            );
            for (target_bytes[0..gap_len], source_bytes[0..gap_len]) |*target_byte, source_byte| {
                target_byte.* -%= source_byte;
            }
        }

        if (try collinearPairIsCheaper(first, next, target_bytes[0..gap_len])) {
            result.appendAssumeCapacity(.{
                .source_offset = first.source_offset,
                .target_offset = first.target_offset,
                .length = try checkedAdd(
                    try checkedAdd(first.length, source_gap),
                    next.length,
                ),
            });
            index += 2;
        } else {
            result.appendAssumeCapacity(first);
            index += 1;
        }
    }
    return result.toOwnedSlice(allocator);
}

fn collinearCandidateGap(first: Cover, next: Cover) ?u64 {
    const first_source_end = std.math.add(u64, first.source_offset, first.length) catch return null;
    const first_target_end = std.math.add(u64, first.target_offset, first.length) catch return null;
    if (next.source_offset < first_source_end or next.target_offset < first_target_end) return null;
    const source_gap = next.source_offset - first_source_end;
    const target_gap = next.target_offset - first_target_end;
    if (source_gap != target_gap or source_gap > collinear_gap_max_gap) return null;
    return source_gap;
}

fn readAdjudicated(
    input: *LogicalInput,
    destination: []u8,
    second: []u8,
    third: []u8,
    offset: u64,
) !void {
    if (destination.len != second.len or destination.len != third.len)
        return error.InternalAdjudicationBufferMismatch;
    try input.readExact(destination, offset);
    try input.readExact(second, offset);
    if (std.mem.eql(u8, destination, second)) return;
    try input.readExact(third, offset);
    if (std.mem.eql(u8, destination, third)) return;
    if (std.mem.eql(u8, second, third)) {
        @memcpy(destination, second);
        return;
    }
    return error.FileChangedDuringProfile;
}

// isolated raw steps; shared metadata/first coordinates cancel
fn collinearPairIsCheaper(first: Cover, next: Cover, gap_add: []const u8) !bool {
    const gap: u64 = @intCast(gap_add.len);
    const merged_length = try checkedAdd(try checkedAdd(first.length, gap), next.length);
    const kept_covered = try checkedAdd(first.length, next.length);

    const kept_cover_bytes = try checkedAdd(
        try checkedAdd(
            try checkedAdd(packTaggedSize(0), packUIntSize(0)),
            packUIntSize(first.length),
        ),
        try checkedAdd(
            try checkedAdd(packTaggedSize(gap), packUIntSize(gap)),
            packUIntSize(next.length),
        ),
    );
    const merged_cover_bytes = try checkedAdd(
        try checkedAdd(packTaggedSize(0), packUIntSize(0)),
        packUIntSize(merged_length),
    );
    const kept_rle_bytes = canonicalRle0ZeroSize(kept_covered);
    const merged_rle_bytes = try canonicalPairRle0Size(first.length, gap_add, next.length);

    const kept = try rawStepCost(2, kept_cover_bytes, kept_rle_bytes, gap);
    const merged = try rawStepCost(1, merged_cover_bytes, merged_rle_bytes, 0);
    return merged < kept;
}

fn rawStepCost(sub_covers: u64, cover_bytes: u64, rle_bytes: u64, literals: u64) !u64 {
    var result: u64 = packUIntSize(sub_covers);
    result = try checkedAdd(result, packUIntSize(cover_bytes));
    result = try checkedAdd(result, packUIntSize(rle_bytes));
    result = try checkedAdd(result, cover_bytes);
    result = try checkedAdd(result, rle_bytes);
    return checkedAdd(result, literals);
}

fn canonicalRle0ZeroSize(length: u64) u64 {
    return packUIntSize(length);
}

fn canonicalRle0ValueSize(length: u64) u64 {
    return packUIntSize(length) + length;
}

pub fn canonicalRle0Size(add: []const u8) !u64 {
    if (add.len == 0) return canonicalRle0ZeroSize(0);
    var result: u64 = 0;
    var index: usize = 0;
    while (index < add.len) {
        const zero_start = index;
        while (index < add.len and add[index] == 0) : (index += 1) {}
        result = try checkedAdd(
            result,
            canonicalRle0ZeroSize(@intCast(index - zero_start)),
        );
        if (index == add.len) break;
        const value_start = index;
        while (index < add.len and add[index] != 0) : (index += 1) {}
        result = try checkedAdd(
            result,
            canonicalRle0ValueSize(@intCast(index - value_start)),
        );
    }
    return result;
}

fn canonicalPairRle0Size(prefix_zeros: u64, gap_add: []const u8, suffix_zeros: u64) !u64 {
    var result: u64 = 0;
    var pending_zeros = prefix_zeros;
    var index: usize = 0;
    while (index < gap_add.len) {
        const zero_start = index;
        while (index < gap_add.len and gap_add[index] == 0) : (index += 1) {}
        pending_zeros = try checkedAdd(pending_zeros, index - zero_start);
        if (index == gap_add.len) break;
        result = try checkedAdd(result, canonicalRle0ZeroSize(pending_zeros));
        pending_zeros = 0;

        const value_start = index;
        while (index < gap_add.len and gap_add[index] != 0) : (index += 1) {}
        result = try checkedAdd(
            result,
            canonicalRle0ValueSize(@intCast(index - value_start)),
        );
    }
    pending_zeros = try checkedAdd(pending_zeros, suffix_zeros);
    if (pending_zeros != 0 or result == 0)
        result = try checkedAdd(result, canonicalRle0ZeroSize(pending_zeros));
    return result;
}

fn checkedAdd(a: anytype, b: anytype) !u64 {
    return std.math.add(u64, @intCast(a), @intCast(b)) catch error.IntegerOverflow;
}

fn packUIntSize(value: u64) u64 {
    const bits: usize = if (value == 0) 1 else 64 - @clz(value);
    return @intCast((bits + 6) / 7);
}

fn packTaggedSize(value: u64) u64 {
    const bits: usize = if (value == 0) 0 else 64 - @clz(value);
    return @intCast(if (bits <= 6) 1 else 1 + (bits - 6 + 6) / 7);
}

fn validateForeign(covers: []const Cover, source_size: u64, target_size: u64) !void {
    var last_target_end: u64 = 0;
    for (covers) |cover| {
        if (cover.length == 0 or cover.target_offset < last_target_end) return error.InvalidCover;
        const source_end = std.math.add(u64, cover.source_offset, cover.length) catch return error.InvalidCover;
        const target_end = std.math.add(u64, cover.target_offset, cover.length) catch return error.InvalidCover;
        if (source_end > source_size or target_end > target_size) return error.InvalidCover;
        last_target_end = target_end;
    }
}

// reread exact covers to catch silent read corruption
fn validateExact(
    allocator: std.mem.Allocator,
    source: *LogicalInput,
    target: *LogicalInput,
    covers: []const Cover,
) !void {
    const source_buffer = try allocator.alloc(u8, verification_buffer_bytes);
    defer allocator.free(source_buffer);
    const target_buffer = try allocator.alloc(u8, verification_buffer_bytes);
    defer allocator.free(target_buffer);

    for (covers) |cover| {
        var done: u64 = 0;
        while (done < cover.length) {
            const count: usize = @intCast(@min(
                @as(u64, verification_buffer_bytes),
                cover.length - done,
            ));
            try source.readExact(source_buffer[0..count], cover.source_offset + done);
            try target.readExact(target_buffer[0..count], cover.target_offset + done);
            if (!std.mem.eql(u8, source_buffer[0..count], target_buffer[0..count])) {
                return error.InexactCover;
            }
            done += count;
        }
    }
}

fn fixtureBytes(allocator: std.mem.Allocator, length: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, length);
    for (bytes, 0..) |*byte, index| {
        byte.* = @truncate((index *% 37) ^ (index >> 3) ^ ((index >> 8) *% 17));
    }
    return bytes;
}

test "path matcher covers concatenated Source boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const split = 4096;
    const bytes = try fixtureBytes(allocator, split * 2);
    defer allocator.free(bytes);
    try tmp.dir.writeFile(io, .{ .sub_path = "source-a.bin", .data = bytes[0..split] });
    try tmp.dir.writeFile(io, .{ .sub_path = "source-b.bin", .data = bytes[split..] });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = bytes });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_a = try std.fs.path.join(allocator, &.{ root, "source-a.bin" });
    defer allocator.free(source_a);
    const source_b = try std.fs.path.join(allocator, &.{ root, "source-b.bin" });
    defer allocator.free(source_b);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const sources = [_]Part{
        .{ .path = source_a, .size = split },
        .{ .path = source_b, .size = split },
    };
    const target: Part = .{ .path = target_path, .size = bytes.len };

    const first = try matchExact(allocator, io, &sources, target, .{});
    defer allocator.free(first);
    try std.testing.expect(first.len != 0);
    var crosses_boundary = false;
    for (first) |cover| {
        if (cover.source_offset < split and cover.source_offset + cover.length > split) crosses_boundary = true;
    }
    try std.testing.expect(crosses_boundary);
}

test "borrowed matcher validates exact covers and never closes caller handles" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = try fixtureBytes(allocator, 16 * 1024);
    defer allocator.free(bytes);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = bytes });

    var source = try fs.openRead(io, tmp.dir, "source.bin");
    defer source.close(io);
    var target = try fs.openRead(io, tmp.dir, "target.bin");
    defer target.close(io);
    const matched = try matchExactFiles(
        allocator,
        io,
        &.{.{ .file = source, .size = bytes.len }},
        .{ .file = target, .size = bytes.len },
        .{},
    );
    defer allocator.free(matched);
    try std.testing.expect(matched.len != 0);

    for (matched) |cover| {
        const start: usize = @intCast(cover.target_offset);
        const source_start: usize = @intCast(cover.source_offset);
        const length: usize = @intCast(cover.length);
        try std.testing.expectEqualSlices(u8, bytes[source_start..][0..length], bytes[start..][0..length]);
    }

    try std.testing.expectError(error.FileChangedDuringMatch, matchExactFiles(
        allocator,
        io,
        &.{.{ .file = source, .size = bytes.len }},
        .{ .file = target, .size = bytes.len - 1 },
        .{},
    ));
    var probe: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try source.readPositionalAll(io, &probe, 0));
    try std.testing.expectEqual(bytes[0], probe[0]);
    try std.testing.expectEqual(@as(usize, 1), try target.readPositionalAll(io, &probe, 0));
    try std.testing.expectEqual(bytes[0], probe[0]);
}

test "matcher rejects block profiles outside the current policy" {
    const target: Part = .{ .path = "must-not-open", .size = 0 };
    try std.testing.expectError(error.InvalidBlockSize, matchExact(
        std.testing.allocator,
        std.testing.io,
        &.{},
        target,
        .{ .block_size = minimum_block_size - 1 },
    ));
    try std.testing.expectError(error.InvalidBlockSize, matchExact(
        std.testing.allocator,
        std.testing.io,
        &.{},
        target,
        .{ .block_size = maximum_block_size + 1 },
    ));
}

test "path matcher validates aggregate Source extent before opening paths" {
    const sources = [_]Part{
        .{ .path = "must-not-open-a", .size = std.math.maxInt(u64) },
        .{ .path = "must-not-open-b", .size = 1 },
    };
    try std.testing.expectError(error.SourceTooLarge, matchExact(
        std.testing.allocator,
        std.testing.io,
        &sources,
        .{ .path = "must-not-open-target", .size = 0 },
        .{},
    ));
}

test "matcher preserves an injected read error" {
    const Fault = struct {
        fn read(_: ?*anyopaque, _: std.Io, _: std.Io.File, _: []u8, _: u64) !usize {
            return error.InjectedMatcherReadFailure;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "source bytes" ** 256 });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "source bytes" ** 256 });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    const size = ("source bytes" ** 256).len;
    try std.testing.expectError(error.InjectedMatcherReadFailure, matchExact(
        allocator,
        io,
        &.{.{ .path = source_path, .size = size }},
        .{ .path = target_path, .size = size },
        .{ .reader = .{ .read_fn = Fault.read } },
    ));
}

test "short callback read is fatal" {
    const Fault = struct {
        fired: bool = false,

        fn read(raw: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const count = try fs.readAllAt(io, file, buffer, offset);
            if (!self.fired and count != 0) {
                self.fired = true;
                return count - 1;
            }
            return count;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "abcdefgh" ** 1024 });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "abcdefgh" ** 1024 });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    var fault: Fault = .{};
    const size = ("abcdefgh" ** 1024).len;
    try std.testing.expectError(error.ShortRead, matchExact(
        allocator,
        io,
        &.{.{ .path = source_path, .size = size }},
        .{ .path = target_path, .size = size },
        .{ .reader = .{ .context = &fault, .read_fn = Fault.read } },
    ));
    try std.testing.expect(fault.fired);
}

test "successful wrong matcher read cannot authorize a COPY cover" {
    const Fault = struct {
        fired: bool = false,

        fn read(raw: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const count = try fs.readAllAt(io, file, buffer, offset);
            if (!self.fired and count != 0 and buffer[0] == 0x22) {
                @memset(buffer[0..count], 0x11);
                self.fired = true;
            }
            return count;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source_bytes = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(source_bytes);
    @memset(source_bytes, 0x11);
    const target_bytes = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(target_bytes);
    @memset(target_bytes, 0x22);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = target_bytes });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "target.bin" });
    defer allocator.free(target_path);
    var fault: Fault = .{};
    try std.testing.expectError(error.InexactCover, matchExact(
        allocator,
        io,
        &.{.{ .path = source_path, .size = source_bytes.len }},
        .{ .path = target_path, .size = target_bytes.len },
        .{ .reader = .{ .context = &fault, .read_fn = Fault.read } },
    ));
    try std.testing.expect(fault.fired);
}

test "matcher never follows a final Source or Target reparse point" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "no-follow" ** 1024 });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "no-follow" ** 1024 });
    tmp.dir.symLink(io, "target.bin", "target-link.bin", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => |e| return e,
    };
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const source_path = try std.fs.path.join(allocator, &.{ root, "source.bin" });
    defer allocator.free(source_path);
    const target_link = try std.fs.path.join(allocator, &.{ root, "target-link.bin" });
    defer allocator.free(target_link);
    const size = ("no-follow" ** 1024).len;
    const covers = matchExact(
        allocator,
        io,
        &.{.{ .path = source_path, .size = size }},
        .{ .path = target_link, .size = size },
        .{},
    ) catch return;
    defer allocator.free(covers);
    try std.testing.expectEqual(@as(usize, 0), covers.len);
}

test "collinear_gap freezes eligibility boundaries and strict raw cost" {
    const first: Cover = .{ .source_offset = 10, .target_offset = 20, .length = 32 };
    const adjacent: Cover = .{ .source_offset = 42, .target_offset = 52, .length = 32 };
    try std.testing.expectEqual(@as(?u64, 0), collinearCandidateGap(first, adjacent));
    try std.testing.expect(try collinearPairIsCheaper(first, adjacent, ""));

    var sparse: [collinear_gap_max_gap]u8 = @splat(0);
    sparse[255] = 1;
    const at_limit: Cover = .{
        .source_offset = 42 + collinear_gap_max_gap,
        .target_offset = 52 + collinear_gap_max_gap,
        .length = 32,
    };
    try std.testing.expectEqual(
        @as(?u64, collinear_gap_max_gap),
        collinearCandidateGap(first, at_limit),
    );
    try std.testing.expect(try collinearPairIsCheaper(first, at_limit, &sparse));

    const past_limit: Cover = .{
        .source_offset = at_limit.source_offset + 1,
        .target_offset = at_limit.target_offset + 1,
        .length = 32,
    };
    try std.testing.expectEqual(@as(?u64, null), collinearCandidateGap(first, past_limit));
    const non_collinear: Cover = .{
        .source_offset = 50,
        .target_offset = 61,
        .length = 32,
    };
    try std.testing.expectEqual(@as(?u64, null), collinearCandidateGap(first, non_collinear));
    const source_overlap: Cover = .{ .source_offset = 41, .target_offset = 60, .length = 8 };
    try std.testing.expectEqual(@as(?u64, null), collinearCandidateGap(first, source_overlap));

    const dense: [collinear_gap_max_gap]u8 = @splat(1);
    try std.testing.expect(!(try collinearPairIsCheaper(first, at_limit, &dense)));
}

test "profile rle0 virtual prefix and suffix cost equals material encoding" {
    const cases = [_][]const u8{
        "",
        &.{0},
        &.{1},
        &.{ 0, 1, 0 },
        &.{ 1, 2, 3, 0, 0, 4 },
    };
    for (0..8) |prefix| {
        for (cases) |gap| {
            for (0..8) |suffix| {
                var material: [22]u8 = @splat(0);
                @memcpy(material[prefix..][0..gap.len], gap);
                const bytes = material[0 .. prefix + gap.len + suffix];
                try std.testing.expectEqual(
                    try canonicalRle0Size(bytes),
                    try canonicalPairRle0Size(prefix, gap, suffix),
                );
            }
        }
    }
}

test "collinear_gap adjudicates a successful-wrong seam and is deterministic" {
    const Fault = struct {
        seam_offset: u64,
        fired: bool = false,

        fn read(raw: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const count = try fs.readAllAt(io, file, buffer, offset);
            if (!self.fired and offset == self.seam_offset and count != 0) {
                buffer[0] +%= 97;
                self.fired = true;
            }
            return count;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source_bytes: [80]u8 = undefined;
    for (&source_bytes, 0..) |*byte, index| byte.* = @truncate(index *% 29 +% 7);
    var target_bytes = source_bytes;
    target_bytes[32] +%= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = &source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = &target_bytes });

    var source_file = try tmp.dir.openFile(io, "source.bin", .{});
    defer source_file.close(io);
    var target_file = try tmp.dir.openFile(io, "target.bin", .{});
    defer target_file.close(io);
    const source_parts = [_]OpenPart{.{ .file = source_file, .logical_start = 0, .size = source_bytes.len }};
    const target_parts = [_]OpenPart{.{ .file = target_file, .logical_start = 0, .size = target_bytes.len }};
    var fault: Fault = .{ .seam_offset = 32 };
    var source_input: LogicalInput = .{
        .io = io,
        .reader = .{ .context = &fault, .read_fn = Fault.read },
        .parts = &source_parts,
        .size = source_bytes.len,
    };
    var target_input: LogicalInput = .{
        .io = io,
        .reader = .direct,
        .parts = &target_parts,
        .size = target_bytes.len,
    };
    const anchors = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 32 },
        .{ .source_offset = 48, .target_offset = 48, .length = 32 },
    };

    const first = try collinearGap(allocator, &source_input, &target_input, &anchors);
    defer allocator.free(first);
    try std.testing.expect(fault.fired);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(u64, source_bytes.len), first[0].length);

    source_input.reader = .direct;
    const second = try collinearGap(allocator, &source_input, &target_input, &anchors);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(Cover, first, second);
}

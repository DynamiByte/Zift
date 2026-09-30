const std = @import("std");
const streams = @import("../streams.zig");
const h13 = @import("../h13.zig");
const apply = @import("apply.zig");
const fs = @import("../../core/fs.zig");
const Cover = @import("../../match/index.zig").Cover;
const encoding = @import("../encoding.zig");
const hooks = @import("../hooks.zig");

const Covers = struct {
    values: []const Cover,

    pub fn emit(covers: Covers, sink: *streams.Sink) !void {
        var buffer: [64 * 1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        var old_end: u64 = 0;
        var new_end: u64 = 0;
        for (covers.values) |cover| {
            if (writer.unusedCapacityLen() < 3 * encoding.max_hdiff_pack_uint_bytes) {
                try sink.write(writer.buffered());
                writer.end = 0;
            }
            const negative = cover.source_offset < old_end;
            const delta = if (negative) old_end - cover.source_offset else cover.source_offset - old_end;
            for ([_]u64{ delta, cover.target_offset - new_end, cover.length }, 0..) |value, field| {
                var storage: [encoding.max_hdiff_pack_uint_bytes]u8 = undefined;
                try writer.writeAll(encoding.encodeUIntTagged(value, if (field == 0) @intFromBool(negative) else 0, if (field == 0) 1 else 0, &storage));
            }
            old_end = cover.source_offset + cover.length;
            new_end = cover.target_offset + cover.length;
        }
        try sink.write(writer.buffered());
    }
};

const Control = struct {
    size: u64,

    pub fn emit(control: Control, sink: *streams.Sink) !void {
        if (control.size != 0) try sink.uint(control.size - 1, 0, 2);
    }
};

const Literals = struct {
    target: *const streams.Input,
    covers: []const Cover,

    pub fn emit(literals: Literals, sink: *streams.Sink) !void {
        var work: [128 * 1024]u8 = undefined;
        var position: u64 = 0;
        for (literals.covers) |cover| {
            try streams.copy(literals.target, sink, position, cover.target_offset - position, &work);
            position = cover.target_offset + cover.length;
        }
        try streams.copy(literals.target, sink, position, literals.target.size - position, &work);
    }
};

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: streams.FilePart,
    target: streams.FilePart,
    output: std.Io.File,
    offset: u64,
    block: usize,
    compression_level: ?c_int,
    progress: ?hooks.ProgressHook,
) !u64 {
    var old = try streams.Input.init(io, &.{source});
    var new = try streams.Input.init(io, &.{target});
    old.progress = progress;
    new.progress = progress;
    try fs.validateGuardedOutput(io, output, offset);
    if (try fs.sameOpenFile(io, output, source.file) or try fs.sameOpenFile(io, output, target.file)) return error.UnsafeOutput;
    if (block < 4 or block > 65536) return error.InvalidArgument;
    return createTransaction(allocator, io, &old, &new, output, offset, block, compression_level, progress) catch |err| {
        output.setLength(io, offset) catch return error.HDiffRollbackFailed;
        return err;
    };
}

fn createTransaction(allocator: std.mem.Allocator, io: std.Io, source: *streams.Input, target: *streams.Input, output: std.Io.File, offset: u64, block: usize, compression_level: ?c_int, progress: ?hooks.ProgressHook) !u64 {
    const covers = try streams.match(allocator, source, target, block);
    defer allocator.free(covers);
    const start = try std.math.add(u64, offset, streams.headerSize(h13.magic, compression_level != null, 11));
    const cover_stream = try streams.writeStream(io, output, start, compression_level, Covers{ .values = covers });
    const control_stream = try streams.writeStream(io, output, cover_stream.end, compression_level, Control{ .size = target.size });
    const literal_stream = try streams.writeStream(io, output, control_stream.end, compression_level, Literals{ .target = target, .covers = covers });
    try streams.writeHeader(io, output, offset, h13.magic, compression_level != null, &.{
        target.size,               source.size,               covers.len,
        cover_stream.raw,          cover_stream.compressed,   control_stream.raw,
        control_stream.compressed, 0,                         0,
        literal_stream.raw,        literal_stream.compressed,
    });
    try output.setLength(io, literal_stream.end);
    const size = literal_stream.end - offset;
    var compare: streams.Compare = .{ .target = target };
    _ = apply.verifyFiles(allocator, io, source.parts[0].file, output, offset, size, .{
        .output = .{ .context = &compare, .call_fn = streams.Compare.call },
        .progress = progress,
    }) catch return error.HDiffConstructionVerificationFailed;
    return size;
}

test "H13 creation verifies stored and zstd patches and preserves append prefixes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var old: [8192]u8 = undefined;
    for (&old, 0..) |*byte, index| byte.* = @truncate(index *% 53 + index / 97);
    var new = old;
    @memset(new[1024..2048], 0x71);
    const prefix = "retained-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "old", .data = &old });
    try tmp.dir.writeFile(io, .{ .sub_path = "new", .data = &new });
    const source = try fs.openRead(io, tmp.dir, "old");
    defer source.close(io);
    const target = try fs.openRead(io, tmp.dir, "new");
    defer target.close(io);
    const aliased_output = try fs.openReadWrite(io, tmp.dir, "old");
    defer aliased_output.close(io);
    for ([_]bool{ false, true }) |compress| {
        try tmp.dir.writeFile(io, .{ .sub_path = "patch", .data = prefix });
        const patch = try fs.openReadWrite(io, tmp.dir, "patch");
        defer patch.close(io);
        const size = try create(allocator, io, .{ .file = source, .size = old.len }, .{ .file = target, .size = new.len }, patch, prefix.len, 64, if (compress) 5 else null, null);
        var retained: [prefix.len]u8 = undefined;
        try std.testing.expectEqual(retained.len, try fs.readAllAt(io, patch, &retained, 0));
        try std.testing.expectEqualStrings(prefix, &retained);
        var input = try streams.Input.init(io, &.{.{ .file = target, .size = new.len }});
        var compare: streams.Compare = .{ .target = &input };
        _ = try apply.verifyFiles(allocator, io, source, patch, prefix.len, size, .{ .output = .{ .context = &compare, .call_fn = streams.Compare.call } });
        try std.testing.expectError(error.UnsafeOutput, create(allocator, io, .{ .file = source, .size = old.len }, .{ .file = target, .size = new.len }, aliased_output, old.len, 64, if (compress) 5 else null, null));
    }
}

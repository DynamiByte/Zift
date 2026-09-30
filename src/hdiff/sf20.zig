// streaming HDIFFSF20 over logical file streams

const streams = @import("streams.zig");
const Input = streams.Input;
const Output = streams.Output;
const Compare = streams.Compare;
const std = @import("std");
const match_index = @import("../match/index.zig");
const fs = @import("../core/fs.zig");
const core = @import("encoding.zig");
const clip = @import("../compression/decoder.zig");
const allocator = std.heap.page_allocator;
pub const magic = "HDIFFSF20&";
pub const max_step_bytes = 4 * 1024 * 1024;
pub const TestFault = if (@import("builtin").is_test) struct {
    pub var enabled = false;
} else struct {
    pub const enabled = false;
};

pub const Info = struct {
    old_size: u64,
    new_size: u64,
    covers: u64,
    step_size: u64,
    raw_size: u64,
    compressed_size: u64,
    header_size: usize,
    compressed: bool,
};
pub fn parse(bytes: []const u8) !Info {
    if (!std.mem.startsWith(u8, bytes, magic)) return error.InvalidHeader;
    const end = std.mem.indexOfScalarPos(u8, bytes, magic.len, 0) orelse return error.Truncated;
    const name = bytes[magic.len..end];
    if (name.len > 256) return error.InvalidHeader;
    if (name.len != 0 and !std.mem.eql(u8, name, "zstd")) return error.UnsupportedCompression;
    var pos = end + 1;
    const new_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const old_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const covers = try core.decodeHdiffPackUInt(bytes, &pos);
    const step_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const raw_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const compressed_size = try core.decodeHdiffPackUInt(bytes, &pos);
    if (compressed_size > raw_size or (compressed_size != 0 and name.len == 0) or
        step_size > new_size +| max_step_bytes or step_size > raw_size +| max_step_bytes) return error.InvalidHeader;
    return .{ .old_size = old_size, .new_size = new_size, .covers = covers, .step_size = step_size, .raw_size = raw_size, .compressed_size = compressed_size, .header_size = pos, .compressed = compressed_size != 0 };
}
pub fn info(io: std.Io, file: std.Io.File, offset: u64, size: u64) !Info {
    const length = try file.length(io);
    if (offset > length or size > length - offset) return error.InvalidRange;
    var prefix: [512]u8 = undefined;
    const take: usize = @intCast(@min(size, prefix.len));
    if (try fs.readAllAt(io, file, prefix[0..take], offset) != take) return error.ShortRead;
    const parsed = try parse(prefix[0..take]);
    const body_size = if (parsed.compressed_size == 0) parsed.raw_size else parsed.compressed_size;
    if (parsed.header_size > size or body_size != size - parsed.header_size) return error.InvalidRange;
    return parsed;
}

pub fn apply(io: std.Io, source: *const Input, file: std.Io.File, offset: u64, size: u64, output: Output) !void {
    const header = try info(io, file, offset, size);
    if (source.size != header.old_size) return error.SourceSizeMismatch;
    if (header.step_size > max_step_bytes) return error.StepTooLarge;
    var total: u64 = 0;
    for (output.parts, 0..) |part, i| {
        const target = part.file;
        _ = try fs.validateGuardedOutputAuthority(io, target);
        if (try fs.sameOpenFile(io, target, file)) return error.UnsafeOutput;
        for (source.parts) |input|
            if (try fs.sameOpenFile(io, target, input.file)) return error.UnsafeOutput;
        for (output.parts[0..i]) |prior|
            if (try fs.sameOpenFile(io, target, prior.file)) return error.UnsafeOutput;
        total = try std.math.add(u64, total, part.size);
    }
    if (output.parts.len != 0 and total != header.new_size) return error.OutputSizeMismatch;
    var body = try clip.Decoder.init(allocator, io, file, offset + header.header_size, header.compressed_size, header.raw_size, .{ .max_window_bytes = 256 * 1024 * 1024 });
    defer body.deinit();
    const step = try allocator.alloc(u8, @intCast(header.step_size));
    defer allocator.free(step);
    const work = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(work);
    var left = header.covers;
    var old_end: u64 = 0;
    var new_end: u64 = 0;
    var position: u64 = 0;
    while (left != 0) {
        const cover_size = try core.readUInt(&body);
        const rle_size = try core.readUInt(&body);
        if (cover_size == 0 or cover_size > step.len or rle_size > step.len - cover_size) return error.InvalidStep;
        const count: usize = @intCast(cover_size + rle_size);
        try body.readInto(step[0..count]);
        var covers = core.CoverReader.init(step[0..@intCast(cover_size)], old_end, new_end);
        var rle = core.Rle0.init(step[@intCast(cover_size)..count]);
        var covered: u64 = 0;
        while (!covers.atEnd()) {
            if (left == 0) return error.CoverCountMismatch;
            const cover = try covers.next();
            if (cover.new_pos < position or cover.new_pos > header.new_size or cover.length > header.new_size - cover.new_pos or
                cover.old_pos > source.size or cover.length > source.size - cover.old_pos) return error.InvalidCover;
            while (position < cover.new_pos) {
                const take: usize = @intCast(@min(work.len, cover.new_pos - position));
                try body.readInto(work[0..take]);
                try output.emit(position, work[0..take]);
                position += take;
            }
            left -= 1;
            if (cover.length == 0 and left != 0) return error.InvalidCover;
            var done: u64 = 0;
            while (done < cover.length) {
                const take: usize = @intCast(@min(work.len, cover.length - done));
                try source.read(cover.old_pos + done, work[0..take]);
                try rle.addTo(work[0..take]);
                try output.emit(position, work[0..take]);
                position += take;
                done += take;
            }
            covered += cover.length;
        }
        if (covered == 0 and !rle.atEnd()) {
            var p: usize = 0;
            if (try core.decodeHdiffPackUInt(rle.code, &p) != 0 or p != rle.code.len) return error.RleOverrun;
        } else try rle.finish();
        old_end = covers.last_old_end;
        new_end = covers.last_new_end;
    }
    if (position != header.new_size) return error.OutputSizeMismatch;
    try body.finish();
    for (output.parts) |part| {
        const target = part.file;
        try target.setLength(io, part.size);
        try fs.validateGuardedOutput(io, target, part.size);
    }
}

fn appendUInt(list: *std.ArrayList(u8), value: u64, tag: u8, tag_bits: u3) !void {
    var storage: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
    try list.appendSlice(allocator, core.encodeUIntTagged(value, tag, tag_bits, &storage));
}

pub fn create(io: std.Io, source: *Input, target: *Input, output: std.Io.File, offset: u64, block: usize, compression_level: ?c_int) !u64 {
    try fs.validateGuardedOutput(io, output, offset);
    for (source.parts) |part| if (try fs.sameOpenFile(io, output, part.file)) return error.UnsafeOutput;
    for (target.parts) |part| if (try fs.sameOpenFile(io, output, part.file)) return error.UnsafeOutput;
    if (block < 4 or block > 65536) return error.InvalidArgument;
    return createTransaction(io, source, target, output, offset, block, compression_level) catch |err| {
        output.setLength(io, offset) catch return error.HDiffRollbackFailed;
        return err;
    };
}

const step_bytes = 64 * 1024;

const Body = struct {
    target: *Input,
    covers: []const match_index.Cover,
    max_step: u64 = 0,

    fn coverCount(body: Body) usize {
        const end = if (body.covers.len == 0) 0 else body.covers[body.covers.len - 1].target_offset + body.covers[body.covers.len - 1].length;
        return body.covers.len + @as(usize, @intFromBool(end != body.target.size));
    }

    fn cover(body: Body, index: usize) match_index.Cover {
        if (index < body.covers.len) return body.covers[index];
        const old_end = if (body.covers.len == 0) 0 else body.covers[body.covers.len - 1].source_offset + body.covers[body.covers.len - 1].length;
        return .{ .source_offset = old_end, .target_offset = body.target.size, .length = 0 };
    }

    pub fn emit(body: *Body, sink: *streams.Sink) !void {
        var code: [step_bytes]u8 = undefined;
        var work: [128 * 1024]u8 = undefined;
        var old_end: u64 = 0;
        var new_end: u64 = 0;
        var literal_pos: u64 = 0;
        var index: usize = 0;
        const count = body.coverCount();
        while (index < count) {
            const first = index;
            var used: usize = 0;
            var covered: u64 = 0;
            while (index < count) {
                const current = body.cover(index);
                var record: [3 * core.max_hdiff_pack_uint_bytes]u8 = undefined;
                var record_len: usize = 0;
                const negative = current.source_offset < old_end;
                const delta = if (negative) old_end - current.source_offset else current.source_offset - old_end;
                for ([_]u64{ delta, current.target_offset - new_end, current.length }, 0..) |value, field| {
                    var encoded: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
                    const bytes = core.encodeUIntTagged(value, if (field == 0) @intFromBool(negative) else 0, if (field == 0) 1 else 0, &encoded);
                    @memcpy(record[record_len..][0..bytes.len], bytes);
                    record_len += bytes.len;
                }
                var skip: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
                const skip_len = core.encodeUIntTagged(covered + current.length, 0, 0, &skip).len;
                if (used + record_len + skip_len > code.len) break;
                @memcpy(code[used..][0..record_len], record[0..record_len]);
                used += record_len;
                covered += current.length;
                old_end = current.source_offset + current.length;
                new_end = current.target_offset + current.length;
                index += 1;
            }
            var skip: [core.max_hdiff_pack_uint_bytes]u8 = undefined;
            const rle = core.encodeUIntTagged(covered, 0, 0, &skip);
            body.max_step = @max(body.max_step, used + rle.len);
            try sink.uint(used, 0, 0);
            try sink.uint(rle.len, 0, 0);
            try sink.write(code[0..used]);
            try sink.write(rle);
            for (first..index) |i| {
                const current = body.cover(i);
                try streams.copy(body.target, sink, literal_pos, current.target_offset - literal_pos, &work);
                literal_pos = current.target_offset + current.length;
            }
        }
    }
};

fn createTransaction(io: std.Io, source: *Input, target: *Input, output: std.Io.File, offset: u64, block: usize, compression_level: ?c_int) !u64 {
    const covers = try streams.match(allocator, source, target, block);
    defer allocator.free(covers);
    var body: Body = .{ .target = target, .covers = covers };
    const body_start = try std.math.add(u64, offset, streams.headerSize(magic, compression_level != null, 6));
    const written = try streams.writeStream(io, output, body_start, compression_level, &body);
    try streams.writeHeader(io, output, offset, magic, compression_level != null, &.{ target.size, source.size, body.coverCount(), body.max_step, written.raw, written.compressed });
    try output.setLength(io, written.end);
    const size = written.end - offset;
    if (TestFault.enabled) {
        var byte: [1]u8 = undefined;
        if (try fs.readAllAt(io, output, &byte, written.end - 1) != 1) return error.HDiffConstructionVerificationFailed;
        byte[0] ^= 0x80;
        try output.writePositionalAll(io, &byte, written.end - 1);
    }
    var compare: Compare = .{ .target = target };
    apply(io, source, output, offset, size, .{ .io = io, .observer = .{ .context = &compare, .call_fn = Compare.call } }) catch return error.HDiffConstructionVerificationFailed;
    if (TestFault.enabled) return error.HDiffConstructionVerificationFailed;
    return size;
}

test "SF20 native progress errors restore the append prefix and permit retry" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes: [16384]u8 = @splat(0x35);
    const prefix = "sf20-retry-prefix";
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = &bytes });
    const file = try fs.openRead(io, tmp.dir, "source");
    defer file.close(io);
    const patch = try fs.createGuardedOutput(io, tmp.dir, "patch");
    defer patch.close(io);
    try patch.writePositionalAll(io, prefix, 0);
    const parts = [_]streams.FilePart{.{ .file = file, .size = bytes.len }};
    var source = try Input.init(io, &parts);
    var target = try Input.init(io, &parts);
    const Reject = struct {
        fn advance(_: ?*anyopaque, _: u64) !bool {
            return error.InjectedProgressFailure;
        }
    };
    source.progress = .{ .call_fn = Reject.advance };
    try std.testing.expectError(error.InjectedProgressFailure, create(io, &source, &target, patch, prefix.len, 64, 5));
    var actual: [prefix.len]u8 = undefined;
    try std.testing.expectEqual(@as(u64, prefix.len), try patch.length(io));
    try std.testing.expectEqual(actual.len, try fs.readAllAt(io, patch, &actual, 0));
    try std.testing.expectEqualSlices(u8, prefix, &actual);

    source.progress = null;
    const size = try create(io, &source, &target, patch, prefix.len, 64, 5);
    try std.testing.expect(size > 0);
    try std.testing.expectEqual(prefix.len + size, try patch.length(io));
}

fn testHeader(codec: []const u8, fields: [6]u64) !std.ArrayList(u8) {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, magic);
    try bytes.appendSlice(allocator, codec);
    try bytes.append(allocator, 0);
    for (fields) |value| try appendUInt(&bytes, value, 0, 0);
    return bytes;
}

test "SF20 batches metadata across step boundaries and flushes trailing literals" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var old: [65536]u8 = undefined;
    for (&old, 0..) |*byte, index| byte.* = @truncate(index *% 53 + index / 97);
    var new = old;
    const covers = try std.testing.allocator.alloc(match_index.Cover, old.len / 2);
    defer std.testing.allocator.free(covers);
    for (covers, 0..) |*cover, index| {
        const source_pos = if (index % 2 == 0) index * 2 else old.len - 2 - index * 2;
        cover.* = .{ .source_offset = source_pos, .target_offset = index * 2, .length = 1 };
        new[index * 2] = old[source_pos];
        new[index * 2 + 1] ^= 0x71;
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "old", .data = &old });
    try tmp.dir.writeFile(io, .{ .sub_path = "new", .data = &new });
    const source_file = try fs.openRead(io, tmp.dir, "old");
    defer source_file.close(io);
    const target_file = try fs.openRead(io, tmp.dir, "new");
    defer target_file.close(io);
    var source = try Input.init(io, &.{.{ .file = source_file, .size = old.len }});
    var target = try Input.init(io, &.{.{ .file = target_file, .size = new.len }});
    const patch = try fs.createGuardedOutput(io, tmp.dir, "patch");
    defer patch.close(io);
    const prefix = "retained-prefix";
    try patch.writePositionalAll(io, prefix, 0);
    for ([_]bool{ false, true }) |compress| {
        var body: Body = .{ .target = &target, .covers = covers };
        const written = try streams.writeStream(io, patch, prefix.len + streams.headerSize(magic, compress, 6), if (compress) 5 else null, &body);
        try streams.writeHeader(io, patch, prefix.len, magic, compress, &.{ target.size, source.size, body.coverCount(), body.max_step, written.raw, written.compressed });
        try patch.setLength(io, written.end);
        try std.testing.expect(body.max_step <= step_bytes);
        try std.testing.expect(written.raw > step_bytes);
        var compare: Compare = .{ .target = &target };
        try apply(io, &source, patch, prefix.len, written.end - prefix.len, .{ .io = io, .observer = .{ .context = &compare, .call_fn = Compare.call } });
        var retained: [prefix.len]u8 = undefined;
        try std.testing.expectEqual(retained.len, try fs.readAllAt(io, patch, &retained, 0));
        try std.testing.expectEqualStrings(prefix, &retained);
    }
}

test "SF20 header rejects unsupported codecs and inconsistent lengths" {
    try std.testing.expectError(error.InvalidHeader, parse("bad"));
    try std.testing.expectError(error.Truncated, parse(magic));
    var unsupported = try testHeader("other", @splat(0));
    defer unsupported.deinit(allocator);
    try std.testing.expectError(error.UnsupportedCompression, parse(unsupported.items));
    var bad_lengths = try testHeader("zstd", .{ 1, 0, 0, 0, 1, 2 });
    defer bad_lengths.deinit(allocator);
    try std.testing.expectError(error.InvalidHeader, parse(bad_lengths.items));
    var missing_codec = try testHeader("", .{ 1, 0, 0, 0, 1, 1 });
    defer missing_codec.deinit(allocator);
    try std.testing.expectError(error.InvalidHeader, parse(missing_codec.items));
    var valid = try testHeader("", @splat(0));
    defer valid.deinit(allocator);
    for (magic.len + 1..valid.items.len) |end|
        try std.testing.expectError(error.Truncated, parse(valid.items[0..end]));
}

test "SF20 rejects oversized steps before allocation and checks exact patch extent" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "patch", .{ .read = true });
    defer file.close(io);
    const source = try Input.init(io, &.{});
    var oversized = try testHeader("", .{ max_step_bytes + 1, 0, 0, max_step_bytes + 1, 1, 0 });
    defer oversized.deinit(allocator);
    try oversized.append(allocator, 0);
    try file.writePositionalAll(io, oversized.items, 0);
    try std.testing.expectError(error.StepTooLarge, apply(io, &source, file, 0, oversized.items.len, .{ .io = io }));
    var empty = try testHeader("", @splat(0));
    defer empty.deinit(allocator);
    try file.setLength(io, empty.items.len);
    try file.writePositionalAll(io, empty.items, 0);
    try apply(io, &source, file, 0, empty.items.len, .{ .io = io });
    try file.writePositionalAll(io, &.{0}, empty.items.len);
    try std.testing.expectError(error.InvalidRange, info(io, file, 0, empty.items.len + 1));
    try std.testing.expectError(error.Truncated, info(io, file, 0, empty.items.len - 1));
}

test "SF20 rejects malformed cover steps and unused RLE data" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "patch", .{ .read = true });
    defer file.close(io);
    const source = try Input.init(io, &.{});
    var bad_step = try testHeader("", .{ 0, 0, 1, 4, 2, 0 });
    defer bad_step.deinit(allocator);
    try bad_step.appendSlice(allocator, &.{ 0, 0 });
    try file.writePositionalAll(io, bad_step.items, 0);
    try std.testing.expectError(error.InvalidStep, apply(io, &source, file, 0, bad_step.items.len, .{ .io = io }));
    var bad_rle = try testHeader("", .{ 0, 0, 1, 4, 6, 0 });
    defer bad_rle.deinit(allocator);
    try bad_rle.appendSlice(allocator, &.{ 3, 1, 0, 0, 0, 1 });
    try file.setLength(io, bad_rle.items.len);
    try file.writePositionalAll(io, bad_rle.items, 0);
    try std.testing.expectError(error.RleOverrun, apply(io, &source, file, 0, bad_rle.items.len, .{ .io = io }));
}

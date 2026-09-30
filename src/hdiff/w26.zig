// HDIFFW26 header parsing; borrowed prefix, unchecked checksums

const std = @import("std");
const core = @import("encoding.zig");

pub const magic = "HDIFFW26";
pub const head_prefix_size: usize = magic.len + @sizeOf(u16);

// upstream header cache: hpatch_kStreamCacheSize
pub const max_head_size: usize = 4096;
// upstream hpatch_kMaxPluginTypeLength, minus delimiter
pub const max_plugin_name_len: usize = 263;
pub const max_window_meta_count: u64 = 1024;
// upstream step-buffer slack: 4 MiB
pub const step_mem_safe_limit: u64 = 4 * 1024 * 1024;

pub const Error = core.Error || error{
    NotW26,
    HeaderTooLarge,
    PluginNameTooLong,
    HeaderInconsistent,
    ImpossibleSizes,
    PatchExtentMismatch,
};

pub const Info = struct {
    // empty = stored/no checksum; named plugins checked by applier
    compress_type: []const u8,
    checksum_type: []const u8,

    compressed_size: u64,
    uncompressed_size: u64,
    new_size: u64,
    old_size: u64,
    cover_count: u64,
    window_count: u64,
    window_meta_count: u64,
    max_step_mem: u64,
    max_sub_cover_count: u64,
    max_window_old: u64,
    checksum_byte_size: u64,
    extra_data_size: u64,

    // borrowed extension bytes, uninterpreted
    other_info: []const u8,
    old_checksum: []const u8,
    new_checksum: []const u8,
    diff_checksum: []const u8,

    // patch-relative offsets
    other_info_pos: u64,
    other_info_end_pos: u64,
    window_data_pos: u64,

    pub fn hasChecksums(self: Info) bool {
        return self.checksum_byte_size != 0;
    }

    pub fn storedBodySize(self: Info) u64 {
        return if (self.compressed_size != 0) self.compressed_size else self.uncompressed_size;
    }
};

// bounded prefix only; full-length check in validatePatchExtent
pub fn parse(bytes: []const u8) Error!Info {
    if (bytes.len < head_prefix_size) return Error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return Error.NotW26;

    const remaining: u64 = @as(u64, bytes[magic.len]) |
        (@as(u64, bytes[magic.len + 1]) << 8);
    const header_size_u64 = try core.checkedAddU64(head_prefix_size, remaining);
    if (header_size_u64 > max_head_size) return Error.HeaderTooLarge;
    const header_size = try core.checkedU64ToUsize(header_size_u64);
    if (bytes.len < header_size) return Error.Truncated;

    const region = bytes[head_prefix_size..header_size];
    var pos: usize = 0;

    const compress_end = std.mem.indexOfScalar(u8, region, '&') orelse
        return Error.HeaderInconsistent;
    if (compress_end > max_plugin_name_len) return Error.PluginNameTooLong;
    const compress_type = region[0..compress_end];
    pos = compress_end + 1;

    const checksum_end = std.mem.indexOfScalarPos(u8, region, pos, 0) orelse
        return Error.HeaderInconsistent;
    if (checksum_end - pos > max_plugin_name_len) return Error.PluginNameTooLong;
    const checksum_type = region[pos..checksum_end];
    pos = checksum_end + 1;

    const compressed_size = try core.decodeHdiffPackUInt(region, &pos);
    const uncompressed_size = try core.decodeHdiffPackUInt(region, &pos);
    const new_size = try core.decodeHdiffPackUInt(region, &pos);
    const old_size = try core.decodeHdiffPackUInt(region, &pos);
    const cover_count = try core.decodeHdiffPackUInt(region, &pos);
    const window_count = try core.decodeHdiffPackUInt(region, &pos);
    const window_meta_count = try core.decodeHdiffPackUInt(region, &pos);
    const max_step_mem = try core.decodeHdiffPackUInt(region, &pos);
    const max_sub_cover_count = try core.decodeHdiffPackUInt(region, &pos);
    const max_window_old = try core.decodeHdiffPackUInt(region, &pos);
    const checksum_byte_size = try core.decodeHdiffPackUInt(region, &pos);
    const extra_data_size = try core.decodeHdiffPackUInt(region, &pos);

    const other_info_pos = try core.checkedAddU64(head_prefix_size, pos);
    const twice_checksum = try core.checkedAddU64(checksum_byte_size, checksum_byte_size);
    const checksum_extent = try core.checkedAddU64(twice_checksum, checksum_byte_size);
    if (checksum_extent > header_size_u64) return Error.HeaderInconsistent;
    const checksum_start = header_size_u64 - checksum_extent;
    if (other_info_pos > checksum_start) return Error.HeaderInconsistent;

    if (window_meta_count < 2 or window_meta_count > max_window_meta_count or
        (window_meta_count & (window_meta_count - 1)) != 0)
        return Error.HeaderInconsistent;
    if ((checksum_type.len == 0) != (checksum_byte_size == 0))
        return Error.HeaderInconsistent;
    if (max_window_old > old_size) return Error.ImpossibleSizes;
    if (max_window_old != 0 and window_count == 0) return Error.HeaderInconsistent;
    if (compressed_size != 0 and compressed_size > uncompressed_size)
        return Error.ImpossibleSizes;
    if (extra_data_size > uncompressed_size) return Error.ImpossibleSizes;

    const target_step_bound = try core.checkedAddU64(new_size, step_mem_safe_limit);
    const body_step_bound = try core.checkedAddU64(uncompressed_size, step_mem_safe_limit);
    if (max_step_mem > target_step_bound or max_step_mem > body_step_bound)
        return Error.ImpossibleSizes;

    const checksum_size = try core.checkedU64ToUsize(checksum_byte_size);
    const checksum_start_usize = try core.checkedU64ToUsize(checksum_start);
    const other_info_pos_usize = try core.checkedU64ToUsize(other_info_pos);
    const old_checksum_end = std.math.add(usize, checksum_start_usize, checksum_size) catch
        return Error.IntegerOverflow;
    const new_checksum_end = std.math.add(usize, old_checksum_end, checksum_size) catch
        return Error.IntegerOverflow;
    const diff_checksum_end = std.math.add(usize, new_checksum_end, checksum_size) catch
        return Error.IntegerOverflow;
    if (diff_checksum_end != header_size) return Error.HeaderInconsistent;

    return .{
        .compress_type = compress_type,
        .checksum_type = checksum_type,
        .compressed_size = compressed_size,
        .uncompressed_size = uncompressed_size,
        .new_size = new_size,
        .old_size = old_size,
        .cover_count = cover_count,
        .window_count = window_count,
        .window_meta_count = window_meta_count,
        .max_step_mem = max_step_mem,
        .max_sub_cover_count = max_sub_cover_count,
        .max_window_old = max_window_old,
        .checksum_byte_size = checksum_byte_size,
        .extra_data_size = extra_data_size,
        .other_info = bytes[other_info_pos_usize..checksum_start_usize],
        .old_checksum = bytes[checksum_start_usize..old_checksum_end],
        .new_checksum = bytes[old_checksum_end..new_checksum_end],
        .diff_checksum = bytes[new_checksum_end..diff_checksum_end],
        .other_info_pos = other_info_pos,
        .other_info_end_pos = checksum_start,
        .window_data_pos = header_size_u64,
    };
}

pub fn validatePatchExtent(info: Info, patch_len: u64) Error!void {
    const expected = try core.checkedAddU64(info.window_data_pos, info.storedBodySize());
    if (expected != patch_len) return Error.PatchExtentMismatch;
}

// tests

const Fields = struct {
    compressed_size: u64 = 5,
    uncompressed_size: u64 = 8,
    new_size: u64 = 20,
    old_size: u64 = 30,
    cover_count: u64 = 4,
    window_count: u64 = 2,
    window_meta_count: u64 = 8,
    max_step_mem: u64 = 9,
    max_sub_cover_count: u64 = 5,
    max_window_old: u64 = 10,
    checksum_byte_size: u64 = 2,
    extra_data_size: u64 = 3,
};

const BuildOptions = struct {
    compress_type: []const u8 = "zstd",
    checksum_type: []const u8 = "xxh128",
    fields: Fields = .{},
    other_info_len: usize = 0,
    nonminimal_fields: bool = false,
    materialize_checksums: bool = true,
};

fn appendPackUInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u64,
    nonminimal: bool,
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
    if (nonminimal) try out.append(allocator, 0x80);
    var i = count;
    while (i != 0) {
        i -= 1;
        var byte = reversed[i];
        if (i != 0) byte |= 0x80;
        try out.append(allocator, byte);
    }
}

fn buildHeader(allocator: std.mem.Allocator, options: BuildOptions) ![]u8 {
    var region: std.ArrayList(u8) = .empty;
    defer region.deinit(allocator);

    try region.appendSlice(allocator, options.compress_type);
    try region.append(allocator, '&');
    try region.appendSlice(allocator, options.checksum_type);
    try region.append(allocator, 0);

    const f = options.fields;
    for ([_]u64{
        f.compressed_size,
        f.uncompressed_size,
        f.new_size,
        f.old_size,
        f.cover_count,
        f.window_count,
        f.window_meta_count,
        f.max_step_mem,
        f.max_sub_cover_count,
        f.max_window_old,
        f.checksum_byte_size,
        f.extra_data_size,
    }) |value| try appendPackUInt(&region, allocator, value, options.nonminimal_fields);

    try region.appendNTimes(allocator, 0xa5, options.other_info_len);
    if (options.materialize_checksums) {
        const checksum_size = try core.checkedU64ToUsize(f.checksum_byte_size);
        try region.appendNTimes(allocator, 0x11, checksum_size);
        try region.appendNTimes(allocator, 0x22, checksum_size);
        try region.appendNTimes(allocator, 0x33, checksum_size);
    }
    if (region.items.len > std.math.maxInt(u16)) return error.TestHeaderTooLarge;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, magic);
    try out.append(allocator, @intCast(region.items.len & 0xff));
    try out.append(allocator, @intCast(region.items.len >> 8));
    try out.appendSlice(allocator, region.items);
    return out.toOwnedSlice(allocator);
}

fn expectMalformed(fields: Fields, expected: Error) !void {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .fields = fields });
    defer allocator.free(bytes);
    try std.testing.expectError(expected, parse(bytes));
}

test "W26 golden header exposes every field and borrowed extent" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .other_info_len = 3 });
    defer allocator.free(bytes);

    const info = try parse(bytes);
    try std.testing.expectEqualStrings("zstd", info.compress_type);
    try std.testing.expectEqualStrings("xxh128", info.checksum_type);
    try std.testing.expectEqual(@as(u64, 5), info.compressed_size);
    try std.testing.expectEqual(@as(u64, 8), info.uncompressed_size);
    try std.testing.expectEqual(@as(u64, 20), info.new_size);
    try std.testing.expectEqual(@as(u64, 30), info.old_size);
    try std.testing.expectEqual(@as(u64, 4), info.cover_count);
    try std.testing.expectEqual(@as(u64, 2), info.window_count);
    try std.testing.expectEqual(@as(u64, 8), info.window_meta_count);
    try std.testing.expectEqual(@as(u64, 9), info.max_step_mem);
    try std.testing.expectEqual(@as(u64, 5), info.max_sub_cover_count);
    try std.testing.expectEqual(@as(u64, 10), info.max_window_old);
    try std.testing.expectEqual(@as(u64, 2), info.checksum_byte_size);
    try std.testing.expectEqual(@as(u64, 3), info.extra_data_size);
    try std.testing.expect(info.hasChecksums());
    try std.testing.expectEqual(@as(u64, bytes.len), info.window_data_pos);
    try std.testing.expectEqual(@as(u64, 3), info.other_info_end_pos - info.other_info_pos);
    try std.testing.expectEqualSlices(u8, &.{ 0xa5, 0xa5, 0xa5 }, info.other_info);
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x11 }, info.old_checksum);
    try std.testing.expectEqualSlices(u8, &.{ 0x22, 0x22 }, info.new_checksum);
    try std.testing.expectEqualSlices(u8, &.{ 0x33, 0x33 }, info.diff_checksum);
    try std.testing.expectEqual(@as(u64, 5), info.storedBodySize());
    try validatePatchExtent(info, @as(u64, bytes.len) + 5);
    try std.testing.expectError(Error.PatchExtentMismatch, validatePatchExtent(info, @as(u64, bytes.len) + 4));
    try std.testing.expectError(Error.PatchExtentMismatch, validatePatchExtent(info, @as(u64, bytes.len) + 6));
}

test "W26 header and plugin limits accept their boundaries and reject one beyond" {
    const allocator = std.testing.allocator;

    const base = try buildHeader(allocator, .{});
    defer allocator.free(base);
    const padding = max_head_size - base.len;
    const exact = try buildHeader(allocator, .{ .other_info_len = padding });
    defer allocator.free(exact);
    try std.testing.expectEqual(@as(usize, max_head_size), exact.len);
    _ = try parse(exact);

    const over = try buildHeader(allocator, .{ .other_info_len = padding + 1 });
    defer allocator.free(over);
    try std.testing.expectEqual(@as(usize, max_head_size + 1), over.len);
    try std.testing.expectError(Error.HeaderTooLarge, parse(over));

    const name_263 = try allocator.alloc(u8, max_plugin_name_len);
    defer allocator.free(name_263);
    @memset(name_263, 'x');
    const compress_at_cap = try buildHeader(allocator, .{ .compress_type = name_263 });
    defer allocator.free(compress_at_cap);
    _ = try parse(compress_at_cap);
    const checksum_at_cap = try buildHeader(allocator, .{ .checksum_type = name_263 });
    defer allocator.free(checksum_at_cap);
    _ = try parse(checksum_at_cap);

    const name_264 = try allocator.alloc(u8, max_plugin_name_len + 1);
    defer allocator.free(name_264);
    @memset(name_264, 'y');
    const compress_over_cap = try buildHeader(allocator, .{ .compress_type = name_264 });
    defer allocator.free(compress_over_cap);
    try std.testing.expectError(Error.PluginNameTooLong, parse(compress_over_cap));
    const checksum_over_cap = try buildHeader(allocator, .{ .checksum_type = name_264 });
    defer allocator.free(checksum_over_cap);
    try std.testing.expectError(Error.PluginNameTooLong, parse(checksum_over_cap));
}

test "W26 refuses every proper prefix of its declared header" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .other_info_len = 9 });
    defer allocator.free(bytes);

    for (0..bytes.len) |cut| {
        try std.testing.expectError(Error.Truncated, parse(bytes[0..cut]));
    }
    _ = try parse(bytes);
}

test "W26 fences incomplete and overlong packUInt fields inside the declared region" {
    const incomplete = [_]u8{
        'H', 'D', 'I', 'F', 'F',  'W', '2', '6',
        3,   0,   '&', 0,   0x80,
    };
    try std.testing.expectError(Error.Truncated, parse(&incomplete));

    const overlong = [_]u8{
        'H',  'D',  'I',  'F',  'F',  'W',  '2',  '6',
        12,   0,    '&',  0,    0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    };
    try std.testing.expectError(Error.IntegerOverflow, parse(&overlong));
}

test "W26 refuses wrong magic missing delimiters and checksum overlap" {
    const allocator = std.testing.allocator;
    const good = try buildHeader(allocator, .{});
    defer allocator.free(good);

    var wrong_magic = try allocator.dupe(u8, good);
    defer allocator.free(wrong_magic);
    wrong_magic[0] = 'X';
    try std.testing.expectError(Error.NotW26, parse(wrong_magic));

    var no_compress_end = try allocator.dupe(u8, good);
    defer allocator.free(no_compress_end);
    no_compress_end[head_prefix_size + 4] = 'x';
    try std.testing.expectError(Error.HeaderInconsistent, parse(no_compress_end));

    const huge_checksum = try buildHeader(allocator, .{ .fields = .{ .checksum_byte_size = 2048 } });
    defer allocator.free(huge_checksum);
    // checksum claim overlapping decoded fields
    huge_checksum[magic.len] = @intCast((good.len - head_prefix_size) & 0xff);
    huge_checksum[magic.len + 1] = @intCast((good.len - head_prefix_size) >> 8);
    try std.testing.expectError(Error.HeaderInconsistent, parse(huge_checksum));
}

test "W26 enforces checksum coupling meta ring and window coupling" {
    const allocator = std.testing.allocator;

    const bytes_without_checksum_name = try buildHeader(allocator, .{ .checksum_type = "" });
    defer allocator.free(bytes_without_checksum_name);
    try std.testing.expectError(Error.HeaderInconsistent, parse(bytes_without_checksum_name));

    const bytes_without_checksum_size = try buildHeader(allocator, .{ .fields = .{ .checksum_byte_size = 0 } });
    defer allocator.free(bytes_without_checksum_size);
    try std.testing.expectError(Error.HeaderInconsistent, parse(bytes_without_checksum_size));

    const valid_without_checksums = try buildHeader(allocator, .{
        .checksum_type = "",
        .fields = .{ .checksum_byte_size = 0 },
    });
    defer allocator.free(valid_without_checksums);
    const no_checksums = try parse(valid_without_checksums);
    try std.testing.expect(!no_checksums.hasChecksums());
    try std.testing.expectEqual(@as(usize, 0), no_checksums.old_checksum.len);

    try expectMalformed(.{ .window_meta_count = 1 }, Error.HeaderInconsistent);
    try expectMalformed(.{ .window_meta_count = 3 }, Error.HeaderInconsistent);
    try expectMalformed(.{ .window_meta_count = 2048 }, Error.HeaderInconsistent);
    const meta_min = try buildHeader(allocator, .{ .fields = .{ .window_meta_count = 2 } });
    defer allocator.free(meta_min);
    _ = try parse(meta_min);
    const meta_max = try buildHeader(allocator, .{ .fields = .{ .window_meta_count = 1024 } });
    defer allocator.free(meta_max);
    _ = try parse(meta_max);

    try expectMalformed(.{ .old_size = 0, .max_window_old = 1 }, Error.ImpossibleSizes);
    try expectMalformed(.{ .old_size = 9, .max_window_old = 10 }, Error.ImpossibleSizes);
    try expectMalformed(.{ .window_count = 0, .max_window_old = 1 }, Error.HeaderInconsistent);
    const empty_source = try buildHeader(allocator, .{ .fields = .{
        .old_size = 0,
        .window_count = 0,
        .max_window_old = 0,
    } });
    defer allocator.free(empty_source);
    _ = try parse(empty_source);
}

test "W26 checks compressed extra and step relations without arithmetic wrap" {
    try expectMalformed(.{ .compressed_size = 9, .uncompressed_size = 8 }, Error.ImpossibleSizes);
    try expectMalformed(.{ .uncompressed_size = 8, .extra_data_size = 9 }, Error.ImpossibleSizes);
    try expectMalformed(.{ .new_size = 0, .max_step_mem = step_mem_safe_limit + 1 }, Error.ImpossibleSizes);
    try expectMalformed(.{
        .uncompressed_size = 0,
        .compressed_size = 0,
        .extra_data_size = 0,
        .max_step_mem = step_mem_safe_limit + 1,
    }, Error.ImpossibleSizes);
    try expectMalformed(.{ .new_size = std.math.maxInt(u64) }, Error.IntegerOverflow);
    try expectMalformed(.{
        .compressed_size = 0,
        .uncompressed_size = std.math.maxInt(u64),
        .extra_data_size = 0,
    }, Error.IntegerOverflow);
    const overflowing_checksum = try buildHeader(std.testing.allocator, .{
        .fields = .{ .checksum_byte_size = std.math.maxInt(u64) },
        .materialize_checksums = false,
    });
    defer std.testing.allocator.free(overflowing_checksum);
    try std.testing.expectError(Error.IntegerOverflow, parse(overflowing_checksum));
}

test "W26 accepts non-minimal standard packUInt fields" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .nonminimal_fields = true });
    defer allocator.free(bytes);
    const info = try parse(bytes);
    try std.testing.expectEqual(@as(u64, 5), info.compressed_size);
    try std.testing.expectEqual(@as(u64, 9), info.max_step_mem);
    try std.testing.expectEqual(@as(u64, 2), info.checksum_byte_size);
}

test "W26 patch extent uses checked exact arithmetic for raw and compressed bodies" {
    const allocator = std.testing.allocator;
    const raw_bytes = try buildHeader(allocator, .{ .fields = .{ .compressed_size = 0 } });
    defer allocator.free(raw_bytes);
    const raw = try parse(raw_bytes);
    try std.testing.expectEqual(@as(u64, 8), raw.storedBodySize());
    try validatePatchExtent(raw, raw.window_data_pos + 8);

    var forged = raw;
    forged.compressed_size = std.math.maxInt(u64);
    forged.uncompressed_size = std.math.maxInt(u64);
    try std.testing.expectError(Error.IntegerOverflow, validatePatchExtent(forged, 0));
}

pub const Checksum = struct {
    pub const name = "xxh128";
    pub const byte_size: usize = 16;
    pub const Hasher = struct {
        state: @import("../core/xxh128.zig").Hasher = .{},
        pub fn update(self: *Hasher, bytes: []const u8) void {
            self.state.update(bytes);
        }
        // HDiff xxh128: little-endian low64, high64
        pub fn final(self: *const Hasher) [byte_size]u8 {
            const value = self.state.final();
            var bytes: [byte_size]u8 = undefined;
            std.mem.writeInt(u64, bytes[0..8], value.low, .little);
            std.mem.writeInt(u64, bytes[8..16], value.high, .little);
            return bytes;
        }
    };
    pub fn hash(bytes: []const u8) [byte_size]u8 {
        var hasher: Hasher = .{};
        hasher.update(bytes);
        return hasher.final();
    }
    test "W26 checksum uses upstream low-high little endian" {
        try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x49, 0x8d, 0x46, 0x24, 0xc3, 0x01, 0x60, 0xd8, 0x98, 0x47, 0x01, 0xd3, 0x06, 0xaa, 0x99 }, &hash(""));
    }
};

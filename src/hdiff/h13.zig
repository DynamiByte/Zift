// HDIFF13 header parsing; slices borrowed from prefix

const std = @import("std");
const core = @import("encoding.zig");

pub const magic = "HDIFF13&";
// upstream hpatch_kMaxPluginTypeLength, minus NUL
pub const max_plugin_name_len: usize = 263;

pub const Error = core.Error || error{
    NotH13,
    PluginNameTooLong,
    HeaderInconsistent,
    ImpossibleSizes,
    PatchExtentMismatch,
};

// compressed == 0: stored
pub const StreamSpec = struct {
    raw: u64,
    compressed: u64,

    pub fn onDisk(self: StreamSpec) u64 {
        return if (self.compressed != 0) self.compressed else self.raw;
    }
};

pub const StreamExtent = struct {
    offset: u64,
    end: u64,

    pub fn len(self: StreamExtent) u64 {
        return self.end - self.offset;
    }
};

pub const Info = struct {
    // parsed plugin name != supported compression
    compress_type: []const u8,
    new_size: u64,
    old_size: u64,
    cover_count: u64,

    covers: StreamSpec,
    rle_ctrl: StreamSpec,
    rle_code: StreamSpec,
    literals: StreamSpec,

    header_end: u64,
    covers_extent: StreamExtent,
    rle_ctrl_extent: StreamExtent,
    rle_code_extent: StreamExtent,
    literals_extent: StreamExtent,

    pub fn compressedCount(self: Info) u8 {
        var count: u8 = 0;
        if (self.covers.compressed != 0) count += 1;
        if (self.rle_ctrl.compressed != 0) count += 1;
        if (self.rle_code.compressed != 0) count += 1;
        if (self.literals.compressed != 0) count += 1;
        return count;
    }

    pub fn bodyBytes(self: Info) u64 {
        return self.literals_extent.end - self.header_end;
    }
};

const Extents = struct {
    covers: StreamExtent,
    rle_ctrl: StreamExtent,
    rle_code: StreamExtent,
    literals: StreamExtent,
};

// prefix only; full-length check in validatePatchExtent
pub fn parse(bytes: []const u8) Error!Info {
    if (bytes.len < magic.len) return Error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return Error.NotH13;

    const plugin_start = magic.len;
    const available_name = bytes.len - plugin_start;
    const search_len = @min(available_name, max_plugin_name_len + 1);
    const plugin_end_rel = std.mem.indexOfScalar(u8, bytes[plugin_start..][0..search_len], 0) orelse {
        if (available_name > max_plugin_name_len) return Error.PluginNameTooLong;
        return Error.Truncated;
    };
    if (plugin_end_rel > max_plugin_name_len) return Error.PluginNameTooLong;
    const plugin_end = plugin_start + plugin_end_rel;
    const compress_type = bytes[plugin_start..plugin_end];

    var pos = plugin_end + 1;
    const new_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const old_size = try core.decodeHdiffPackUInt(bytes, &pos);
    const cover_count = try core.decodeHdiffPackUInt(bytes, &pos);
    const covers: StreamSpec = .{
        .raw = try core.decodeHdiffPackUInt(bytes, &pos),
        .compressed = try core.decodeHdiffPackUInt(bytes, &pos),
    };
    const rle_ctrl: StreamSpec = .{
        .raw = try core.decodeHdiffPackUInt(bytes, &pos),
        .compressed = try core.decodeHdiffPackUInt(bytes, &pos),
    };
    const rle_code: StreamSpec = .{
        .raw = try core.decodeHdiffPackUInt(bytes, &pos),
        .compressed = try core.decodeHdiffPackUInt(bytes, &pos),
    };
    const literals: StreamSpec = .{
        .raw = try core.decodeHdiffPackUInt(bytes, &pos),
        .compressed = try core.decodeHdiffPackUInt(bytes, &pos),
    };

    inline for (.{ covers, rle_ctrl, rle_code, literals }) |stream| {
        // upstream: stored fallback when compression fails to shrink
        if (stream.compressed > stream.raw) return Error.ImpossibleSizes;
    }
    // three bytes minimum per cover; division avoids count*3 overflow
    if (cover_count > covers.raw / 3) return Error.HeaderInconsistent;

    const header_end: u64 = @intCast(pos);
    const extents = try computeExtents(header_end, covers, rle_ctrl, rle_code, literals);
    return .{
        .compress_type = compress_type,
        .new_size = new_size,
        .old_size = old_size,
        .cover_count = cover_count,
        .covers = covers,
        .rle_ctrl = rle_ctrl,
        .rle_code = rle_code,
        .literals = literals,
        .header_end = header_end,
        .covers_extent = extents.covers,
        .rle_ctrl_extent = extents.rle_ctrl,
        .rle_code_extent = extents.rle_code,
        .literals_extent = extents.literals,
    };
}

pub fn validatePatchExtent(info: Info, patch_len: u64) Error!void {
    const extents = try computeExtents(
        info.header_end,
        info.covers,
        info.rle_ctrl,
        info.rle_code,
        info.literals,
    );
    if (extents.literals.end != patch_len) return Error.PatchExtentMismatch;
}

fn computeExtents(
    header_end: u64,
    covers: StreamSpec,
    rle_ctrl: StreamSpec,
    rle_code: StreamSpec,
    literals: StreamSpec,
) Error!Extents {
    const covers_end = try core.checkedAddU64(header_end, covers.onDisk());
    const rle_ctrl_end = try core.checkedAddU64(covers_end, rle_ctrl.onDisk());
    const rle_code_end = try core.checkedAddU64(rle_ctrl_end, rle_code.onDisk());
    const literals_end = try core.checkedAddU64(rle_code_end, literals.onDisk());
    return .{
        .covers = .{ .offset = header_end, .end = covers_end },
        .rle_ctrl = .{ .offset = covers_end, .end = rle_ctrl_end },
        .rle_code = .{ .offset = rle_ctrl_end, .end = rle_code_end },
        .literals = .{ .offset = rle_code_end, .end = literals_end },
    };
}

// tests

const Fields = struct {
    new_size: u64 = 100,
    old_size: u64 = 80,
    cover_count: u64 = 2,
    covers: StreamSpec = .{ .raw = 9, .compressed = 5 },
    rle_ctrl: StreamSpec = .{ .raw = 10, .compressed = 0 },
    rle_code: StreamSpec = .{ .raw = 11, .compressed = 7 },
    literals: StreamSpec = .{ .raw = 20, .compressed = 0 },
};

const BuildOptions = struct {
    compress_type: []const u8 = "zstd",
    fields: Fields = .{},
    nonminimal_fields: bool = false,
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
    var index = count;
    while (index != 0) {
        index -= 1;
        var byte = reversed[index];
        if (index != 0) byte |= 0x80;
        try out.append(allocator, byte);
    }
}

fn buildHeader(allocator: std.mem.Allocator, options: BuildOptions) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, magic);
    try out.appendSlice(allocator, options.compress_type);
    try out.append(allocator, 0);

    const fields = options.fields;
    for ([_]u64{
        fields.new_size,
        fields.old_size,
        fields.cover_count,
        fields.covers.raw,
        fields.covers.compressed,
        fields.rle_ctrl.raw,
        fields.rle_ctrl.compressed,
        fields.rle_code.raw,
        fields.rle_code.compressed,
        fields.literals.raw,
        fields.literals.compressed,
    }) |value| try appendPackUInt(&out, allocator, value, options.nonminimal_fields);
    return out.toOwnedSlice(allocator);
}

test "HDIFF13 golden header exposes all four streams and checked extents" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{});
    defer allocator.free(bytes);

    const info = try parse(bytes);
    try std.testing.expectEqualStrings("zstd", info.compress_type);
    try std.testing.expectEqual(@as(u64, 100), info.new_size);
    try std.testing.expectEqual(@as(u64, 80), info.old_size);
    try std.testing.expectEqual(@as(u64, 2), info.cover_count);
    try std.testing.expectEqual(StreamSpec{ .raw = 9, .compressed = 5 }, info.covers);
    try std.testing.expectEqual(StreamSpec{ .raw = 10, .compressed = 0 }, info.rle_ctrl);
    try std.testing.expectEqual(StreamSpec{ .raw = 11, .compressed = 7 }, info.rle_code);
    try std.testing.expectEqual(StreamSpec{ .raw = 20, .compressed = 0 }, info.literals);
    try std.testing.expectEqual(@as(u8, 2), info.compressedCount());

    const head = info.header_end;
    try std.testing.expectEqual(StreamExtent{ .offset = head, .end = head + 5 }, info.covers_extent);
    try std.testing.expectEqual(StreamExtent{ .offset = head + 5, .end = head + 15 }, info.rle_ctrl_extent);
    try std.testing.expectEqual(StreamExtent{ .offset = head + 15, .end = head + 22 }, info.rle_code_extent);
    try std.testing.expectEqual(StreamExtent{ .offset = head + 22, .end = head + 42 }, info.literals_extent);
    try std.testing.expectEqual(@as(u64, 42), info.bodyBytes());
}

test "HDIFF13 all-stored streams may retain a zstd plugin name" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .fields = .{
        .covers = .{ .raw = 6, .compressed = 0 },
        .rle_ctrl = .{ .raw = 2, .compressed = 0 },
        .rle_code = .{ .raw = 3, .compressed = 0 },
        .literals = .{ .raw = 4, .compressed = 0 },
    } });
    defer allocator.free(bytes);

    const info = try parse(bytes);
    try std.testing.expectEqualStrings("zstd", info.compress_type);
    try std.testing.expectEqual(@as(u8, 0), info.compressedCount());
    try std.testing.expectEqual(@as(u64, 15), info.bodyBytes());
    try std.testing.expectEqual(@as(u64, 6), info.covers.onDisk());
}

test "HDIFF13 accepts stored compressed and mixed stream relationships" {
    const allocator = std.testing.allocator;
    const equal_size = try buildHeader(allocator, .{ .fields = .{
        .covers = .{ .raw = 6, .compressed = 6 },
    } });
    defer allocator.free(equal_size);
    const equal = try parse(equal_size);
    try std.testing.expectEqual(@as(u64, 6), equal.covers.onDisk());

    const empty_name = try buildHeader(allocator, .{ .compress_type = "" });
    defer allocator.free(empty_name);
    try std.testing.expectEqualStrings("", (try parse(empty_name)).compress_type);
}

test "HDIFF13 refuses every proper prefix of a complete header" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{ .nonminimal_fields = true });
    defer allocator.free(bytes);

    for (0..bytes.len) |cut| {
        try std.testing.expectError(Error.Truncated, parse(bytes[0..cut]));
    }
    _ = try parse(bytes);
}

test "HDIFF13 enforces exact magic and plugin-name boundary" {
    const allocator = std.testing.allocator;
    const good = try buildHeader(allocator, .{});
    defer allocator.free(good);

    var wrong = try allocator.dupe(u8, good);
    defer allocator.free(wrong);
    wrong[magic.len - 1] = '!';
    try std.testing.expectError(Error.NotH13, parse(wrong));

    const at_limit_name = try allocator.alloc(u8, max_plugin_name_len);
    defer allocator.free(at_limit_name);
    @memset(at_limit_name, 'a');
    const at_limit = try buildHeader(allocator, .{ .compress_type = at_limit_name });
    defer allocator.free(at_limit);
    _ = try parse(at_limit);

    const over_limit_name = try allocator.alloc(u8, max_plugin_name_len + 1);
    defer allocator.free(over_limit_name);
    @memset(over_limit_name, 'b');
    const over_limit = try buildHeader(allocator, .{ .compress_type = over_limit_name });
    defer allocator.free(over_limit);
    try std.testing.expectError(Error.PluginNameTooLong, parse(over_limit));

    var missing_nul: [magic.len + 5]u8 = undefined;
    @memcpy(missing_nul[0..magic.len], magic);
    @memset(missing_nul[magic.len..], 'x');
    try std.testing.expectError(Error.Truncated, parse(&missing_nul));

    var unterminated_over_limit: [magic.len + max_plugin_name_len + 1]u8 = undefined;
    @memcpy(unterminated_over_limit[0..magic.len], magic);
    @memset(unterminated_over_limit[magic.len..], 'y');
    try std.testing.expectError(Error.PluginNameTooLong, parse(&unterminated_over_limit));
}

test "HDIFF13 rejects impossible stream sizes and minimum cover encoding" {
    const allocator = std.testing.allocator;
    inline for (.{ "covers", "rle_ctrl", "rle_code", "literals" }) |which| {
        var fields: Fields = .{};
        @field(fields, which) = .{ .raw = 4, .compressed = 5 };
        const bytes = try buildHeader(allocator, .{ .fields = fields });
        defer allocator.free(bytes);
        try std.testing.expectError(Error.ImpossibleSizes, parse(bytes));
    }

    const too_many = try buildHeader(allocator, .{ .fields = .{
        .cover_count = 2,
        .covers = .{ .raw = 5, .compressed = 0 },
    } });
    defer allocator.free(too_many);
    try std.testing.expectError(Error.HeaderInconsistent, parse(too_many));

    const exact_minimum = try buildHeader(allocator, .{ .fields = .{
        .cover_count = 2,
        .covers = .{ .raw = 6, .compressed = 0 },
    } });
    defer allocator.free(exact_minimum);
    _ = try parse(exact_minimum);
}

test "HDIFF13 offset arithmetic and exact patch extent reject overflow or slack" {
    const allocator = std.testing.allocator;
    const bytes = try buildHeader(allocator, .{});
    defer allocator.free(bytes);
    const info = try parse(bytes);
    const exact_len = info.literals_extent.end;

    try validatePatchExtent(info, exact_len);
    try std.testing.expectError(Error.PatchExtentMismatch, validatePatchExtent(info, exact_len - 1));
    try std.testing.expectError(Error.PatchExtentMismatch, validatePatchExtent(info, exact_len + 1));

    var with_trailing: std.ArrayList(u8) = .empty;
    defer with_trailing.deinit(allocator);
    try with_trailing.ensureTotalCapacity(allocator, bytes.len + 8);
    try with_trailing.appendSlice(allocator, bytes);
    try with_trailing.appendNTimes(allocator, 0xcc, 8);
    const prefix_info = try parse(with_trailing.items);
    try std.testing.expectEqual(info.header_end, prefix_info.header_end);
    try std.testing.expectError(
        Error.PatchExtentMismatch,
        validatePatchExtent(prefix_info, @intCast(with_trailing.items.len)),
    );

    var forged = info;
    forged.covers = .{ .raw = std.math.maxInt(u64), .compressed = 0 };
    try std.testing.expectError(Error.IntegerOverflow, validatePatchExtent(forged, 0));

    const overflowing_header = try buildHeader(allocator, .{ .fields = .{
        .cover_count = 0,
        .covers = .{ .raw = std.math.maxInt(u64), .compressed = 0 },
        .rle_ctrl = .{ .raw = 0, .compressed = 0 },
        .rle_code = .{ .raw = 0, .compressed = 0 },
        .literals = .{ .raw = 0, .compressed = 0 },
    } });
    defer allocator.free(overflowing_header);
    try std.testing.expectError(Error.IntegerOverflow, parse(overflowing_header));
}

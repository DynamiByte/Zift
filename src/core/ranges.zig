// canonical half-open byte ranges
const std = @import("std");
pub const Range = struct {
    offset: u64,
    length: u64,
    pub fn end(r: Range) u64 {
        return r.offset + r.length;
    }
};
fn less(_: void, a: Range, b: Range) bool {
    return if (a.offset == b.offset) a.length < b.length else a.offset < b.offset;
}
pub fn validate(rs: []const Range, limit: u64) !void {
    var previous: u64 = 0;
    for (rs, 0..) |r, i| {
        if (r.length == 0 or r.offset > limit or r.length > limit - r.offset) return error.InvalidByteRange;
        if (i != 0 and r.offset <= previous) return error.NoncanonicalByteRanges;
        previous = r.end();
    }
}
pub fn merge(allocator: std.mem.Allocator, input: []const Range) ![]Range {
    var merged = try allocator.dupe(Range, input);
    errdefer allocator.free(merged);
    for (merged) |r| if (r.length == 0 or r.length > std.math.maxInt(u64) - r.offset) return error.InvalidByteRange;
    std.mem.sortUnstable(Range, merged, {}, less);
    var n: usize = 0;
    for (merged) |r| {
        if (n != 0 and r.offset <= merged[n - 1].end()) {
            merged[n - 1].length = @max(merged[n - 1].end(), r.end()) - merged[n - 1].offset;
        } else {
            merged[n] = r;
            n += 1;
        }
    }
    return allocator.realloc(merged, n);
}
pub fn intersect(a: Range, b: Range) ?Range {
    const start = @max(a.offset, b.offset);
    const stop = @min(a.end(), b.end());
    return if (stop > start) .{ .offset = start, .length = stop - start } else null;
}
pub fn contains(rs: []const Range, at: u64) ?usize {
    var lo: usize = 0;
    var hi = rs.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const r = rs[mid];
        if (at < r.offset) hi = mid else if (at >= r.end()) lo = mid + 1 else return mid;
    }
    return null;
}
test "range canonicalization and boundaries" {
    const a = std.testing.allocator;
    const rs = try merge(a, &.{ .{ .offset = 8, .length = 4 }, .{ .offset = 0, .length = 4 }, .{ .offset = 3, .length = 5 }, .{ .offset = 20, .length = 3 } });
    defer a.free(rs);
    try std.testing.expectEqualSlices(Range, &.{ .{ .offset = 0, .length = 12 }, .{ .offset = 20, .length = 3 } }, rs);
    try validate(rs, 23);
    try std.testing.expectError(error.InvalidByteRange, validate(rs, 22));
    try std.testing.expectError(error.NoncanonicalByteRanges, validate(&.{ .{ .offset = 0, .length = 4 }, .{ .offset = 4, .length = 1 } }, 5));
    try std.testing.expectEqual(@as(?usize, 0), contains(rs, 11));
    try std.testing.expectEqual(@as(?usize, null), contains(rs, 12));
    try std.testing.expectEqual(@as(?usize, 1), contains(rs, 22));
}

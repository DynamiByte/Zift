// exact COPY only; invalid ADD residuals after trimming
// source-local ties for smaller encoded deltas

const std = @import("std");

pub const Cover = @import("index.zig").Cover;

fn lessThan(_: void, a: Cover, b: Cover) bool {
    if (a.target_offset != b.target_offset) return a.target_offset < b.target_offset;
    if (a.length != b.length) return a.length > b.length;
    return a.source_offset < b.source_offset;
}

fn distance(a: u64, b: u64) u64 {
    return if (a > b) a - b else b - a;
}

pub fn merge(gpa: std.mem.Allocator, all: []Cover, locality: bool) ![]Cover {
    std.mem.sortUnstable(Cover, all, {}, lessThan);

    var out: std.ArrayList(Cover) = .empty;
    errdefer out.deinit(gpa);
    var cursor: u64 = 0;
    var index: usize = 0;
    while (index < all.len) {
        var best: ?Cover = null;
        var scan = index;
        while (scan < all.len and all[scan].target_offset <= cursor) : (scan += 1) {
            const candidate = all[scan];
            const end = candidate.target_offset + candidate.length;
            if (end <= cursor) continue;
            if (best) |current| {
                const best_end = current.target_offset + current.length;
                if (end > best_end) {
                    best = candidate;
                } else if (end == best_end) {
                    if (locality and out.items.len > 0) {
                        const previous = out.items[out.items.len - 1];
                        const anchor = previous.source_offset + previous.length;
                        if (distance(candidate.source_offset, anchor) <
                            distance(current.source_offset, anchor)) best = candidate;
                    } else if (candidate.source_offset < current.source_offset) {
                        best = candidate;
                    }
                }
            } else best = candidate;
        }
        if (best == null) {
            if (scan >= all.len) break;
            cursor = all[scan].target_offset;
            index = scan;
            continue;
        }
        const chosen = best.?;
        const trim = cursor - chosen.target_offset;
        const source_offset = chosen.source_offset + trim;
        const length = (chosen.target_offset + chosen.length) - cursor;

        if (out.items.len > 0) {
            const previous = &out.items[out.items.len - 1];
            if (previous.target_offset + previous.length == cursor and
                previous.source_offset + previous.length == source_offset)
            {
                previous.length += length;
                cursor += length;
                index = scan;
                continue;
            }
        }
        try out.append(gpa, .{
            .source_offset = source_offset,
            .target_offset = cursor,
            .length = length,
        });
        cursor += length;
        index = scan;
    }
    return out.toOwnedSlice(gpa);
}

fn coveredSet(gpa: std.mem.Allocator, covers: []const Cover, len: usize) ![]bool {
    const bits = try gpa.alloc(bool, len);
    @memset(bits, false);
    for (covers) |cover| {
        var i: u64 = cover.target_offset;
        while (i < cover.target_offset + cover.length) : (i += 1) bits[@intCast(i)] = true;
    }
    return bits;
}

fn assertWellFormed(merged: []const Cover, source: []const u8, target: []const u8) !void {
    var previous_end: u64 = 0;
    for (merged) |cover| {
        try std.testing.expect(cover.length > 0);
        try std.testing.expect(cover.target_offset >= previous_end);
        try std.testing.expect(cover.target_offset + cover.length <= target.len);
        try std.testing.expect(cover.source_offset + cover.length <= source.len);
        try std.testing.expectEqualSlices(
            u8,
            source[@intCast(cover.source_offset)..@intCast(cover.source_offset + cover.length)],
            target[@intCast(cover.target_offset)..@intCast(cover.target_offset + cover.length)],
        );
        previous_end = cover.target_offset + cover.length;
    }
}

fn assertNoCoverageLost(
    gpa: std.mem.Allocator,
    input: []const Cover,
    merged: []const Cover,
    target_len: usize,
) !void {
    const before = try coveredSet(gpa, input, target_len);
    defer gpa.free(before);
    const after = try coveredSet(gpa, merged, target_len);
    defer gpa.free(after);
    try std.testing.expectEqualSlices(bool, before, after);
}

fn mergeCopy(gpa: std.mem.Allocator, input: []const Cover, locality: bool) ![]Cover {
    const scratch = try gpa.dupe(Cover, input);
    defer gpa.free(scratch);
    return merge(gpa, scratch, locality);
}

test "merge trims an overlapping cover and shifts its source offset" {
    const gpa = std.testing.allocator;
    const source = "ABCDEFGHIJKLMNOP";
    const target = "ABCDEFGHIJKLMNOP";
    const input = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 10 },
        .{ .source_offset = 6, .target_offset = 6, .length = 10 },
    };
    const merged = try mergeCopy(gpa, &input, false);
    defer gpa.free(merged);
    try assertWellFormed(merged, source, target);
    try assertNoCoverageLost(gpa, &input, merged, target.len);
    try std.testing.expectEqual(@as(usize, 1), merged.len);
    try std.testing.expectEqual(@as(u64, 16), merged[0].length);
}

test "merge keeps a gap literal when nothing covers it" {
    const gpa = std.testing.allocator;
    const source = "ABCDEFGHIJKLMNOP";
    const target = "ABCD????IJKLMNOP";
    const input = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 4 },
        .{ .source_offset = 8, .target_offset = 8, .length = 8 },
    };
    const merged = try mergeCopy(gpa, &input, false);
    defer gpa.free(merged);
    try std.testing.expectEqual(@as(usize, 2), merged.len);
    try std.testing.expectEqual(@as(u64, 8), merged[1].target_offset);
    try assertWellFormed(merged, source, target);
    try assertNoCoverageLost(gpa, &input, merged, target.len);
}

test "merge does not coalesce pieces adjacent only in the target" {
    const gpa = std.testing.allocator;
    const source = "ABCDxxxxABCD";
    const target = "ABCDABCD";
    const input = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 4 },
        .{ .source_offset = 8, .target_offset = 4, .length = 4 },
    };
    const merged = try mergeCopy(gpa, &input, false);
    defer gpa.free(merged);
    try std.testing.expectEqual(@as(usize, 2), merged.len);
    try assertWellFormed(merged, source, target);
    try assertNoCoverageLost(gpa, &input, merged, target.len);
}

test "locality tie-break picks the cover continuing the previous one" {
    const gpa = std.testing.allocator;
    // distant low-offset copy against locality tie-break
    const source = "WXYZ????????WXYZWXYZ";
    const target = "WXYZWXYZ";
    const input = [_]Cover{
        .{ .source_offset = 12, .target_offset = 0, .length = 4 },
        .{ .source_offset = 16, .target_offset = 4, .length = 4 },
        .{ .source_offset = 0, .target_offset = 4, .length = 4 },
    };
    const near = try mergeCopy(gpa, &input, true);
    defer gpa.free(near);
    try assertWellFormed(near, source, target);
    try assertNoCoverageLost(gpa, &input, near, target.len);
    try std.testing.expectEqual(@as(usize, 1), near.len);
    try std.testing.expectEqual(@as(u64, 12), near[0].source_offset);
    try std.testing.expectEqual(@as(u64, 8), near[0].length);

    const far = try mergeCopy(gpa, &input, false);
    defer gpa.free(far);
    try std.testing.expectEqual(@as(usize, 2), far.len);
    try std.testing.expectEqual(@as(u64, 0), far[1].source_offset);
    try assertWellFormed(far, source, target);
    try assertNoCoverageLost(gpa, &input, far, target.len);
}

test "locality is inert when there is no competition" {
    const gpa = std.testing.allocator;
    const input = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 4 },
        .{ .source_offset = 40, .target_offset = 10, .length = 6 },
        .{ .source_offset = 90, .target_offset = 30, .length = 5 },
    };
    const with = try mergeCopy(gpa, &input, true);
    defer gpa.free(with);
    const without = try mergeCopy(gpa, &input, false);
    defer gpa.free(without);
    try std.testing.expectEqualSlices(Cover, without, with);
}

test "merge is identical under any permutation of the input" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();
    const input = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 10 },
        .{ .source_offset = 6, .target_offset = 6, .length = 10 },
        .{ .source_offset = 20, .target_offset = 20, .length = 5 },
        .{ .source_offset = 22, .target_offset = 22, .length = 9 },
        .{ .source_offset = 40, .target_offset = 31, .length = 4 },
    };
    for ([_]bool{ false, true }) |locality| {
        const reference = try mergeCopy(gpa, &input, locality);
        defer gpa.free(reference);
        var trial: usize = 0;
        while (trial < 64) : (trial += 1) {
            var shuffled = input;
            rand.shuffle(Cover, &shuffled);
            const merged = try mergeCopy(gpa, &shuffled, locality);
            defer gpa.free(merged);
            try std.testing.expectEqualSlices(Cover, reference, merged);
        }
    }
}

test "randomised competing covers never lose coverage or emit a false match" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rand = prng.random();

    var round: usize = 0;
    while (round < 200) : (round += 1) {
        const source = try gpa.alloc(u8, 4096);
        defer gpa.free(source);
        rand.bytes(source);
        const target = try gpa.alloc(u8, 2048);
        defer gpa.free(target);
        rand.bytes(target);

        var input: std.ArrayList(Cover) = .empty;
        defer input.deinit(gpa);
        var position: u64 = 0;
        while (position < target.len) {
            const remaining = target.len - position;
            const run = @min(remaining, rand.intRangeAtMost(u64, 1, 200));
            if (rand.boolean() and run >= 8) {
                const so = rand.intRangeAtMost(u64, 0, source.len - run);
                @memcpy(
                    target[@intCast(position)..@intCast(position + run)],
                    source[@intCast(so)..@intCast(so + run)],
                );
                const pieces = rand.intRangeAtMost(usize, 1, 4);
                var piece: usize = 0;
                while (piece < pieces) : (piece += 1) {
                    const a = rand.intRangeAtMost(u64, 0, run - 1);
                    const b = rand.intRangeAtMost(u64, a + 1, run);
                    try input.append(gpa, .{
                        .source_offset = so + a,
                        .target_offset = position + a,
                        .length = b - a,
                    });
                }
            }
            position += run;
        }
        if (input.items.len == 0) continue;

        for ([_]bool{ false, true }) |locality| {
            const merged = try mergeCopy(gpa, input.items, locality);
            defer gpa.free(merged);
            try assertWellFormed(merged, source, target);
            try assertNoCoverageLost(gpa, input.items, merged, target.len);
        }
    }
}

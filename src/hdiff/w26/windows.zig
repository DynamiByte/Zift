// bounded W26 windows; ordered target covers, unordered source offsets

const std = @import("std");

pub const Cover = @import("../../match/index.zig").Cover;

pub const Window = struct {
    target_offset: u64,
    target_length: u64,
    source_offset: u64,
    source_length: u64,
    first_cover: usize,
    cover_count: usize,

    pub fn isLiteralOnly(window: Window) bool {
        return window.cover_count == 0;
    }
};

pub fn validate(covers: []const Cover, source_size: u64, target_size: u64) !void {
    var previous_target_end: u64 = 0;
    for (covers) |cover| {
        if (cover.length == 0) return error.ZeroLengthCover;
        const source_end = std.math.add(u64, cover.source_offset, cover.length) catch {
            return error.IntegerOverflow;
        };
        const target_end = std.math.add(u64, cover.target_offset, cover.length) catch {
            return error.IntegerOverflow;
        };
        if (source_end > source_size) return error.SourceOutOfRange;
        if (target_end > target_size) return error.TargetOutOfRange;
        if (cover.target_offset < previous_target_end) return error.CoversNotOrdered;
        previous_target_end = target_end;
    }
}

// oversized cover = unavoidable singleton; literal gaps splittable
pub fn form(
    allocator: std.mem.Allocator,
    covers: []const Cover,
    source_size: u64,
    target_size: u64,
    bound: u64,
) ![]Window {
    return formLimited(
        allocator,
        covers,
        source_size,
        target_size,
        bound,
        std.math.cast(usize, std.math.maxInt(u32)) orelse std.math.maxInt(usize),
    );
}

fn formLimited(
    allocator: std.mem.Allocator,
    covers: []const Cover,
    source_size: u64,
    target_size: u64,
    bound: u64,
    max_windows: usize,
) ![]Window {
    if (bound == 0) return error.InvalidBound;
    try validate(covers, source_size, target_size);

    var windows: std.ArrayList(Window) = .empty;
    errdefer windows.deinit(allocator);

    var target_cursor: u64 = 0;
    var cover_index: usize = 0;
    while (cover_index < covers.len) {
        const first = covers[cover_index];
        const first_target_end = first.target_offset + first.length;
        const gap = first.target_offset - target_cursor;

        const first_span = first_target_end - target_cursor;
        if (gap > bound or first_span > bound) {
            try appendLiteralWindows(allocator, &windows, target_cursor, gap, bound, max_windows);
            target_cursor = first.target_offset;
        }

        const window_target_start = target_cursor;
        var source_low = first.source_offset;
        var source_high = first.source_offset + first.length;
        var target_high = first_target_end;
        var next_cover = cover_index + 1;

        while (next_cover < covers.len) : (next_cover += 1) {
            const candidate = covers[next_cover];
            const candidate_source_end = candidate.source_offset + candidate.length;
            const candidate_target_end = candidate.target_offset + candidate.length;
            const tentative_source_low = @min(source_low, candidate.source_offset);
            const tentative_source_high = @max(source_high, candidate_source_end);
            const tentative_target_high = @max(target_high, candidate_target_end);
            if (tentative_source_high - tentative_source_low > bound or
                tentative_target_high - window_target_start > bound)
            {
                break;
            }
            source_low = tentative_source_low;
            source_high = tentative_source_high;
            target_high = tentative_target_high;
        }

        try ensureWindowRoom(windows.items.len, 1, max_windows);
        try windows.append(allocator, .{
            .target_offset = window_target_start,
            .target_length = target_high - window_target_start,
            .source_offset = source_low,
            .source_length = source_high - source_low,
            .first_cover = cover_index,
            .cover_count = next_cover - cover_index,
        });
        target_cursor = target_high;
        cover_index = next_cover;
    }

    try appendLiteralWindows(
        allocator,
        &windows,
        target_cursor,
        target_size - target_cursor,
        bound,
        max_windows,
    );
    return windows.toOwnedSlice(allocator);
}

fn ensureWindowRoom(current: usize, additional: usize, max_windows: usize) !void {
    if (additional > max_windows -| current) return error.TooManyWindows;
}

fn appendLiteralWindows(
    allocator: std.mem.Allocator,
    windows: *std.ArrayList(Window),
    start: u64,
    length: u64,
    bound: u64,
    max_windows: usize,
) !void {
    if (length == 0) return;

    const whole = length / bound;
    const count_u64 = std.math.add(u64, whole, @intFromBool(length % bound != 0)) catch {
        return error.IntegerOverflow;
    };
    const count: usize = std.math.cast(usize, count_u64) orelse return error.TooManyWindows;
    try ensureWindowRoom(windows.items.len, count, max_windows);
    try windows.ensureUnusedCapacity(allocator, count);

    var cursor = start;
    var remaining = length;
    while (remaining != 0) {
        const take = @min(remaining, bound);
        windows.appendAssumeCapacity(.{
            .target_offset = cursor,
            .target_length = take,
            .source_offset = 0,
            .source_length = 0,
            .first_cover = 0,
            .cover_count = 0,
        });
        cursor += take;
        remaining -= take;
    }
}

fn expectPartition(windows: []const Window, target_size: u64) !void {
    var cursor: u64 = 0;
    for (windows) |window| {
        try std.testing.expectEqual(cursor, window.target_offset);
        try std.testing.expect(window.target_length != 0);
        cursor += window.target_length;
    }
    try std.testing.expectEqual(target_size, cursor);
}

test "no covers form bounded literal-only windows" {
    const allocator = std.testing.allocator;
    const windows = try form(allocator, &.{}, 0, 25, 10);
    defer allocator.free(windows);
    try std.testing.expectEqual(@as(usize, 3), windows.len);
    try std.testing.expectEqual(@as(u64, 10), windows[0].target_length);
    try std.testing.expectEqual(@as(u64, 10), windows[1].target_length);
    try std.testing.expectEqual(@as(u64, 5), windows[2].target_length);
    for (windows) |window| try std.testing.expect(window.isLiteralOnly());
    try expectPartition(windows, 25);
}

test "backwards and overlapping Target covers are rejected" {
    const backwards = [_]Cover{
        .{ .source_offset = 0, .target_offset = 10, .length = 2 },
        .{ .source_offset = 2, .target_offset = 0, .length = 2 },
    };
    try std.testing.expectError(error.CoversNotOrdered, form(std.testing.allocator, &backwards, 20, 20, 10));

    const overlapping = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 10 },
        .{ .source_offset = 20, .target_offset = 9, .length = 2 },
    };
    try std.testing.expectError(error.CoversNotOrdered, form(std.testing.allocator, &overlapping, 30, 20, 10));
}

test "source-backward covers are valid and use the full Source span" {
    const covers = [_]Cover{
        .{ .source_offset = 100, .target_offset = 0, .length = 10 },
        .{ .source_offset = 0, .target_offset = 12, .length = 10 },
    };
    const windows = try form(std.testing.allocator, &covers, 110, 22, 200);
    defer std.testing.allocator.free(windows);
    try std.testing.expectEqual(@as(usize, 1), windows.len);
    try std.testing.expectEqual(@as(u64, 0), windows[0].source_offset);
    try std.testing.expectEqual(@as(u64, 110), windows[0].source_length);
    try std.testing.expectEqual(@as(usize, 2), windows[0].cover_count);
    try expectPartition(windows, 22);
}

test "cover validation checks zero lengths endpoints and bound" {
    try std.testing.expectError(error.InvalidBound, form(std.testing.allocator, &.{}, 0, 0, 0));
    try std.testing.expectError(
        error.ZeroLengthCover,
        form(std.testing.allocator, &.{.{ .source_offset = 0, .target_offset = 0, .length = 0 }}, 0, 0, 1),
    );
    try std.testing.expectError(
        error.IntegerOverflow,
        form(std.testing.allocator, &.{.{ .source_offset = std.math.maxInt(u64), .target_offset = 0, .length = 1 }}, std.math.maxInt(u64), 1, 1),
    );
    try std.testing.expectError(
        error.IntegerOverflow,
        form(std.testing.allocator, &.{.{ .source_offset = 0, .target_offset = std.math.maxInt(u64), .length = 1 }}, 1, std.math.maxInt(u64), 1),
    );
    try std.testing.expectError(
        error.SourceOutOfRange,
        form(std.testing.allocator, &.{.{ .source_offset = 3, .target_offset = 0, .length = 2 }}, 4, 2, 2),
    );
    try std.testing.expectError(
        error.TargetOutOfRange,
        form(std.testing.allocator, &.{.{ .source_offset = 0, .target_offset = 3, .length = 2 }}, 2, 4, 2),
    );
}

test "large leading interior and trailing gaps are split" {
    const covers = [_]Cover{
        .{ .source_offset = 0, .target_offset = 25, .length = 2 },
        .{ .source_offset = 2, .target_offset = 70, .length = 2 },
    };
    const windows = try form(std.testing.allocator, &covers, 4, 100, 10);
    defer std.testing.allocator.free(windows);
    try expectPartition(windows, 100);
    var cover_windows: usize = 0;
    for (windows) |window| {
        try std.testing.expect(window.target_length <= 10);
        if (!window.isLiteralOnly()) cover_windows += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), cover_windows);
}

test "oversized first cover is an unavoidable singleton" {
    const covers = [_]Cover{
        .{ .source_offset = 0, .target_offset = 2, .length = 20 },
        .{ .source_offset = 20, .target_offset = 22, .length = 2 },
    };
    const windows = try form(std.testing.allocator, &covers, 22, 26, 8);
    defer std.testing.allocator.free(windows);
    try expectPartition(windows, 26);
    try std.testing.expect(windows[0].isLiteralOnly());
    try std.testing.expectEqual(@as(u64, 2), windows[0].target_length);
    try std.testing.expectEqual(@as(usize, 1), windows[1].cover_count);
    try std.testing.expectEqual(@as(u64, 20), windows[1].target_length);
    try std.testing.expectEqual(@as(usize, 1), windows[2].cover_count);
}

test "window count limit is enforced before gap and singleton growth" {
    try std.testing.expectError(
        error.TooManyWindows,
        formLimited(std.testing.allocator, &.{}, 0, 3, 1, 2),
    );

    const after_gap = [_]Cover{
        .{ .source_offset = 0, .target_offset = 3, .length = 1 },
    };
    try std.testing.expectError(
        error.TooManyWindows,
        formLimited(std.testing.allocator, &after_gap, 1, 4, 1, 2),
    );

    const singletons = [_]Cover{
        .{ .source_offset = 0, .target_offset = 0, .length = 2 },
        .{ .source_offset = 2, .target_offset = 2, .length = 2 },
        .{ .source_offset = 4, .target_offset = 4, .length = 2 },
    };
    try std.testing.expectError(
        error.TooManyWindows,
        formLimited(std.testing.allocator, &singletons, 6, 6, 1, 2),
    );

    const merged = try formLimited(std.testing.allocator, &singletons, 6, 6, 6, 1);
    defer std.testing.allocator.free(merged);
    try std.testing.expectEqual(@as(usize, 1), merged.len);
    try std.testing.expectEqual(@as(usize, 3), merged[0].cover_count);
}

test "bound sweeps preserve partition covers and both limits" {
    const covers = [_]Cover{
        .{ .source_offset = 25, .target_offset = 3, .length = 4 },
        .{ .source_offset = 3, .target_offset = 9, .length = 2 },
        .{ .source_offset = 40, .target_offset = 20, .length = 5 },
        .{ .source_offset = 0, .target_offset = 27, .length = 3 },
    };
    for (1..33) |bound_usize| {
        const bound: u64 = @intCast(bound_usize);
        const windows = try form(std.testing.allocator, &covers, 45, 37, bound);
        defer std.testing.allocator.free(windows);
        try expectPartition(windows, 37);

        var next_cover: usize = 0;
        for (windows) |window| {
            if (window.isLiteralOnly()) {
                try std.testing.expect(window.target_length <= bound);
                try std.testing.expectEqual(@as(u64, 0), window.source_length);
                continue;
            }
            try std.testing.expectEqual(next_cover, window.first_cover);
            next_cover += window.cover_count;
            if (window.source_length > bound or window.target_length > bound) {
                try std.testing.expectEqual(@as(usize, 1), window.cover_count);
                try std.testing.expect(covers[window.first_cover].length > bound);
            }
        }
        try std.testing.expectEqual(covers.len, next_cover);
    }
}

fn allocationFailureExercise(allocator: std.mem.Allocator) !void {
    const covers = [_]Cover{
        .{ .source_offset = 10, .target_offset = 17, .length = 3 },
        .{ .source_offset = 0, .target_offset = 31, .length = 4 },
    };
    const windows = try form(allocator, &covers, 20, 53, 7);
    defer allocator.free(windows);
    try expectPartition(windows, 53);
}

test "window formation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureExercise, .{});
}

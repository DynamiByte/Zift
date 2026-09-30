const std = @import("std");
const NameSet = std.HashMapUnmanaged([]const u8, void, std.hash_map.StringContext, std.hash_map.default_max_load_percentage);
const ziff = @import("../format/ziff.zig");
const ranges = @import("../core/ranges.zig");
pub const Range = ranges.Range;
pub const Recipe = ziff.Replay;
pub const SavedRange = struct {
    range: Range,
    backup_offset: u64,
};
pub const File = struct {
    observed_size: u64 = 0,
    observed_single_link: bool = false,
    required_length: u64 = 0,
    required: bool = false,
    writer: ?u32 = null,
    last_use: ?u32 = null,
    save: []SavedRange = &.{},
    save_bytes: u64 = 0,
    removed: bool = false,
    displaced: bool = false,
};
pub const Plan = struct {
    files: []File,
    release: [][]u32,
    remove_initial: []u32,
};
fn add(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch error.IntegerOverflow;
}
pub fn fileIndex(directory: ziff.Directory, path: []const u8) ?u32 {
    var lo: usize = 0;
    var hi = directory.files.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, path, directory.files[mid].path)) {
            .lt => hi = mid,
            .gt => lo = mid + 1,
            .eq => return @intCast(mid),
        }
    }
    return null;
}
// validated directory required; returned allocations in caller's arena
pub fn build(a: std.mem.Allocator, directory: ziff.Directory, recipes: []const Recipe) !Plan {
    const scratch = std.heap.smp_allocator;
    if (recipes.len != directory.units.len) return error.MissingInplaceRecipes;
    const files = try a.alloc(File, directory.files.len);
    @memset(files, .{});
    const needed = try scratch.alloc(std.ArrayList(Range), files.len);
    @memset(needed, .empty);
    defer {
        for (needed) |*n| n.deinit(scratch);
        scratch.free(needed);
    }
    var targets: NameSet = .empty;
    defer targets.deinit(scratch);
    var target_parents: NameSet = .empty;
    defer target_parents.deinit(scratch);
    for (directory.ops) |op| {
        const path = directory.files[op.target].path;
        try targets.put(scratch, path, {});
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            try target_parents.put(scratch, path[0..slash], {});
            start = slash + 1;
        }
    }
    for (directory.removed) |path| {
        const f = fileIndex(directory, path) orelse return error.InvalidRemoval;
        files[f].removed = true;
        // nonadjacent prefix conflict: "a", "a-b", "a/x"
        files[f].displaced = targets.contains(path) or target_parents.contains(path);
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            files[f].displaced = files[f].displaced or targets.contains(path[0..slash]);
            start = slash + 1;
        }
    }
    // writers first: originals needed only for uses after overwrite
    for (directory.units, 0..) |unit, index| {
        if (unit.kind != .patch_zar26 and unit.kind != .raw and unit.kind != .zstd) return error.InplaceCodecUnsupported;
        const file = unit.target;
        if (files[file].writer != null) return error.DuplicateWriter;
        files[file].writer = @intCast(index);
        const skips = recipes[index].skips;
        if (skips.len != 0) {
            files[file].required = true;
            files[file].required_length = @max(files[file].required_length, skips[skips.len - 1].end());
        }
    }
    for (directory.units, recipes, 0..) |unit, recipe, index| {
        var logical: u64 = 0;
        var ri: usize = 0;
        for (directory.sources[unit.source_first..][0..unit.source_count]) |ref| {
            const logical_end = try add(logical, ref.length);
            const entry = &files[ref.file];
            while (ri < recipe.reads.len and recipe.reads[ri].end() <= logical) ri += 1;
            var j = ri;
            while (j < recipe.reads.len and recipe.reads[j].offset < logical_end) : (j += 1) {
                const overlap = ranges.intersect(.{ .offset = logical, .length = ref.length }, recipe.reads[j]) orelse continue;
                const physical: Range = .{ .offset = try add(ref.offset, overlap.offset - logical), .length = overlap.length };
                entry.required = true;
                entry.required_length = @max(entry.required_length, try add(ref.offset, ref.length));
                entry.last_use = @max(entry.last_use orelse 0, @as(u32, @intCast(index)));
                if (entry.writer) |writer| if (index >= writer) {
                    try needed[ref.file].append(scratch, physical);
                };
            }
            logical = logical_end;
        }
    }
    for (files, 0..) |*file, index| {
        const writer = file.writer orelse continue;
        const union_ranges = try ranges.merge(scratch, needed[index].items);
        defer scratch.free(union_ranges);
        const skips = recipes[writer].skips;
        var selected: std.ArrayList(Range) = .empty;
        defer selected.deinit(scratch);
        var skip_cursor: usize = 0;
        for (union_ranges) |r| {
            var offset = r.offset;
            while (skip_cursor < skips.len and skips[skip_cursor].end() <= offset) skip_cursor += 1;
            var j = skip_cursor;
            while (j < skips.len and skips[j].offset < r.end()) : (j += 1) {
                if (skips[j].offset > offset) try selected.append(scratch, .{ .offset = offset, .length = skips[j].offset - offset });
                offset = @max(offset, @min(r.end(), skips[j].end()));
            }
            if (offset < r.end()) try selected.append(scratch, .{ .offset = offset, .length = r.end() - offset });
        }
        const saved = try ranges.merge(scratch, selected.items);
        defer scratch.free(saved);
        file.save = try a.alloc(SavedRange, saved.len);
        for (saved, file.save) |r, *span| {
            span.* = .{ .range = r, .backup_offset = file.save_bytes };
            file.save_bytes = try add(file.save_bytes, r.length);
        }
    }
    const releasing = try scratch.alloc(std.ArrayList(u32), directory.units.len);
    @memset(releasing, .empty);
    defer {
        for (releasing) |*list| list.deinit(scratch);
        scratch.free(releasing);
    }
    var initial: std.ArrayList(u32) = .empty;
    defer initial.deinit(scratch);
    for (files, 0..) |file, index| {
        if (file.save_bytes != 0 or (file.removed and file.last_use != null)) {
            const last = file.last_use orelse return error.MissingSourceLifetime;
            try releasing[last].append(scratch, @intCast(index));
        } else if (file.removed) try initial.append(scratch, @intCast(index));
    }
    const release = try a.alloc([]u32, releasing.len);
    for (releasing, release) |list, *slot| slot.* = try a.dupe(u32, list.items);
    return .{
        .files = files,
        .release = release,
        .remove_initial = try a.dupe(u32, initial.items),
    };
}

test "in-place plan saves overwritten future bytes but not already durable earlier dependencies" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ids = @import("../core/ids.zig");
    var files = [_]ziff.FileEntry{
        .{ .path = "a", .size = 8, .digest = ids.Digest.of("BBBBBBBB") },
        .{ .path = "b", .size = 8, .digest = ids.Digest.of("AAAAAAAA") },
    };
    var ops = [_]ziff.Op{ .{ .kind = .patch, .target = 0, .arg = 0 }, .{ .kind = .patch, .target = 1, .arg = 1 } };
    var units = [_]ziff.Unit{
        .{ .kind = .patch_zar26, .payload_offset = 0, .payload_len = 1, .target = 0, .source_first = 0, .source_count = 1 },
        .{ .kind = .patch_zar26, .payload_offset = 1, .payload_len = 1, .target = 1, .source_first = 1, .source_count = 1 },
    };
    var refs = [_]ziff.SourceRef{ .{ .file = 1, .offset = 0, .length = 8 }, .{ .file = 0, .offset = 0, .length = 8 } };
    var read_ranges = [_]Range{.{ .offset = 0, .length = 8 }};
    var recipes = [_]Recipe{ .{ .reads = &read_ranges }, .{ .reads = &read_ranges } };
    const dir: ziff.Directory = .{ .files = &files, .ops = &ops, .units = &units, .sources = &refs, .removed = &.{} };
    const plan = try build(arena.allocator(), dir, &recipes);
    try std.testing.expectEqual(@as(u64, 8), plan.files[0].save_bytes);
    try std.testing.expectEqual(@as(u64, 0), plan.files[1].save_bytes);
    try std.testing.expectEqual(@as(?u32, 1), plan.files[0].last_use);
}

test "shape conflict detection is not hidden by intervening sibling spellings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ids = @import("../core/ids.zig");
    var files = [_]ziff.FileEntry{
        .{ .path = "a", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "a-b", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "a/x", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "z", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "z-b", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "z/x", .size = 1, .digest = ids.Digest.of("a") },
    };
    var ops = [_]ziff.Op{
        .{ .kind = .keep, .target = 1, .arg = 0 }, .{ .kind = .keep, .target = 2, .arg = 0 },
        .{ .kind = .keep, .target = 3, .arg = 0 }, .{ .kind = .keep, .target = 4, .arg = 0 },
    };
    var removed = [_][]const u8{ "a", "z/x" };
    const dir: ziff.Directory = .{ .files = &files, .ops = &ops, .units = &.{}, .sources = &.{}, .removed = &removed };
    const plan = try build(arena.allocator(), dir, &.{});
    try std.testing.expect(plan.files[0].displaced);
    try std.testing.expect(plan.files[5].displaced);
}

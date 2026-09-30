// ziff planning from directory comparison

const std = @import("std");
const ids = @import("../core/ids.zig");
const integrations = @import("../integrations.zig");
const planner = @import("../plan.zig");
const profile = @import("../profile.zig");
const tree = @import("../tree.zig");
const ziff = @import("../format/ziff.zig");
const content = @import("../core/content.zig");

pub const Owned = struct {
    allocator: std.mem.Allocator,
    header: ziff.Header,
    directory: ziff.Directory,
    // separate source membership; target identity in shared union entries
    source_manifest: []ziff.FileEntry,

    pub fn deinit(owned: *Owned) void {
        owned.allocator.free(owned.directory.files);
        owned.allocator.free(owned.directory.ops);
        owned.allocator.free(owned.directory.units);
        owned.allocator.free(owned.directory.sources);
        owned.allocator.free(owned.directory.removed);
        ziff.freeReplays(owned.allocator, owned.directory.replays);
        owned.allocator.free(owned.source_manifest);
        owned.* = undefined;
    }
};

const PlannedUnit = struct {
    target: u32,
    source: union(enum) { family: []const u32, single: [1]u32, none },

    fn sourceIndexes(unit: *const PlannedUnit) []const u32 {
        return switch (unit.source) {
            .family => |indexes| indexes,
            .single => &unit.source.single,
            .none => &.{},
        };
    }
};

fn planTargets(allocator: std.mem.Allocator, source: []const tree.File, target: []const tree.File, plan: planner.Plan, unit_by_target: []?u32) ![]PlannedUnit {
    var units: std.ArrayList(PlannedUnit) = .empty;
    errdefer units.deinit(allocator);
    @memset(unit_by_target, null);
    for (plan.groups) |group| {
        if (group.source.len == 0 or group.target.len == 0) return error.EmptyGroup;
        for (group.source) |index| if (index >= source.len) {
            return error.InvalidSourceIndex;
        };
        for (group.target) |index| {
            if (index >= target.len) return error.InvalidTargetIndex;
            if (unit_by_target[index] != null) return error.DuplicateTargetIndex;
            unit_by_target[index] = std.math.cast(u32, units.items.len) orelse return error.TooManyUnits;
            try units.append(allocator, .{ .target = index, .source = .{ .family = group.source } });
        }
    }
    for (plan.changed) |pair| {
        if (pair.source >= source.len) return error.InvalidSourceIndex;
        if (pair.target >= target.len) return error.InvalidTargetIndex;
        if (unit_by_target[pair.target] != null) continue;
        if (!std.mem.eql(u8, source[pair.source].path, target[pair.target].path)) return error.NotSamePathPair;
        unit_by_target[pair.target] = std.math.cast(u32, units.items.len) orelse return error.TooManyUnits;
        try units.append(allocator, .{ .target = pair.target, .source = if (target[pair.target].bytes != null) .none else .{ .single = .{pair.source} } });
    }
    for (plan.added) |index| {
        if (index >= target.len) return error.InvalidTargetIndex;
        if (unit_by_target[index] != null) continue;
        unit_by_target[index] = std.math.cast(u32, units.items.len) orelse return error.TooManyUnits;
        try units.append(allocator, .{ .target = index, .source = .none });
    }
    return units.toOwnedSlice(allocator);
}

test "Ziff targets share source families and keep single source inline" {
    const a = std.testing.allocator;
    var old = [_]tree.File{.{ .path = "same", .size = 1 }};
    var new = [_]tree.File{ .{ .path = "same", .size = 2 }, .{ .path = "added", .size = 3 }, .{ .path = "family", .size = 4 } };
    const indexes = [_]u32{0};
    var groups = [_]planner.Group{.{ .source = &indexes, .target = &.{2} }};
    var changes = [_]planner.Change{.{ .source = 0, .target = 0 }};
    var added = [_]u32{ 1, 2 };
    var unit_by_target: [new.len]?u32 = undefined;
    const units = try planTargets(a, &old, &new, .{ .changed = &changes, .added = &added, .removed = &.{}, .groups = &groups }, &unit_by_target);
    defer a.free(units);
    try std.testing.expectEqual(@as(usize, 3), units.len);
    try std.testing.expectEqual(@as(u32, 2), units[0].target);
    try std.testing.expectEqual(indexes[0..].ptr, units[0].sourceIndexes().ptr);
    try std.testing.expectEqualSlices(u32, &.{0}, units[1].sourceIndexes());
    try std.testing.expect(units[2].source == .none);
    try std.testing.expectEqualSlices(?u32, &.{ 1, 2, 0 }, &unit_by_target);
    var duplicate_groups = [_]planner.Group{ groups[0], groups[0] };
    try std.testing.expectError(error.DuplicateTargetIndex, planTargets(a, &old, &new, .{ .changed = &.{}, .added = &.{}, .removed = &.{}, .groups = &duplicate_groups }, &unit_by_target));
}

fn checkedAdd(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch return error.IntegerOverflow;
}

fn requireDigest(file: tree.File) !ids.Digest {
    return file.digest orelse error.MissingConstructionDigest;
}

fn plannedDigest(file: tree.File, deferred: bool) !ids.Digest {
    return file.digest orelse if (deferred) content.pending_digest else error.MissingConstructionDigest;
}

fn lessFile(_: void, lhs: ziff.FileEntry, rhs: ziff.FileEntry) bool {
    return std.mem.order(u8, lhs.path, rhs.path) == .lt;
}

fn lessPath(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn fileIndex(files: []const ziff.FileEntry, path: []const u8) !u32 {
    var low: usize = 0;
    var high = files.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, files[middle].path, path)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return std.math.cast(u32, middle) orelse error.TooManyFiles,
        }
    }
    return error.MissingFileEntry;
}

fn hasAuthoritativeClaim(file: tree.File) bool {
    return if (file.claim) |claim| claim.authority == .authoritative else false;
}

fn verificationHash(file: tree.File) !ids.VerificationHash {
    const claim = file.claim orelse return .none;
    if (claim.authority != .authoritative) return .none;
    return ids.VerificationHash.fromVendor(claim.value);
}

fn targetIdentity(file: tree.File, deferred: bool) !struct { digest: ids.Digest, verification: ids.VerificationHash } {
    const verification: ids.VerificationHash = if (deferred) try verificationHash(file) else .none;
    return .{
        .digest = if (verification.isPresent()) .zero else try plannedDigest(file, deferred),
        .verification = verification,
    };
}

test "deferred authoritative files use the vendor identity directly" {
    const md5: [16]u8 = @splat(0x6d);
    const file: tree.File = .{
        .path = "keep.bin",
        .size = 1234,
        .claim = .{
            .authority = .authoritative,
            .value = try ids.VendorHash.init(.hoyo_pkg_version_md5, .hex, md5),
        },
    };
    const keep = try targetIdentity(file, true);
    try std.testing.expect(keep.digest.eql(.zero));
    try std.testing.expect(keep.verification.eql(.md5(md5)));
}

fn observeZeroPayload(
    allocator: std.mem.Allocator,
    io: std.Io,
    value: *tree.Tree,
    unit_by_target: []const ?u32,
) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, value.root, .{ .access_sub_paths = true });
    defer dir.close(io);
    for (value.files, 0..) |file, index| {
        // known keeps: independent comparison reads already available
        if (file.digest != null) continue;
        const corroborate = unit_by_target.len != 0 and unit_by_target[index] == null and
            !hasAuthoritativeClaim(file);
        if (corroborate) {
            _ = try tree.adjudicateDigest(allocator, io, dir, value, @intCast(index), .{});
        } else {
            _ = try tree.observeDigest(allocator, io, dir, value, @intCast(index), .{});
        }
    }
}

fn sourceManifestEntries(
    allocator: std.mem.Allocator,
    files: []const tree.File,
    deferred: bool,
) ![]ziff.FileEntry {
    const result = try allocator.alloc(ziff.FileEntry, files.len);
    errdefer allocator.free(result);
    for (files, result) |file, *entry| {
        entry.* = .{
            .path = file.path,
            .size = file.size,
            .digest = if (deferred) (file.digest orelse .zero) else try plannedDigest(file, false),
            .verification = if (deferred) try verificationHash(file) else .none,
        };
    }
    std.mem.sortUnstable(ziff.FileEntry, result, {}, lessFile);
    return result;
}

pub fn build(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *tree.Tree,
    target: *tree.Tree,
    plan: planner.Plan,
    software: ?integrations.Software,
    source_identity: []const u8,
    target_identity: []const u8,
) !Owned {
    const deferred = source.deferred_content and target.deferred_content;
    const scratch = std.heap.smp_allocator;
    const unit_by_target = try scratch.alloc(?u32, target.files.len);
    defer scratch.free(unit_by_target);
    const planned_units = try planTargets(scratch, source.files, target.files, plan, unit_by_target);
    defer scratch.free(planned_units);
    {
        var observation_arena = std.heap.ArenaAllocator.init(scratch);
        defer observation_arena.deinit();
        const observation_allocator = observation_arena.allocator();
        var source_span = profile.begin(io, "plan: source identity");
        if (!deferred) try observeZeroPayload(observation_allocator, io, source, &.{});
        source_span.end(io);
        var target_span = profile.begin(io, "plan: target identity + keeps");
        if (!deferred) try observeZeroPayload(observation_allocator, io, target, unit_by_target);
        target_span.end(io);
    }

    const source_fingerprint_files = try sourceManifestEntries(allocator, source.files, deferred);
    errdefer allocator.free(source_fingerprint_files);

    var source_bytes: u64 = 0;
    for (source.files) |file| source_bytes = try checkedAdd(source_bytes, file.size);
    var target_bytes: u64 = 0;
    for (target.files) |file| target_bytes = try checkedAdd(target_bytes, file.size);

    const table_count = std.math.add(usize, target.files.len, plan.removed.len) catch
        return error.TooManyFiles;
    const files = try allocator.alloc(ziff.FileEntry, table_count);
    errdefer allocator.free(files);
    var next: usize = 0;
    for (target.files) |file| {
        const identity = try targetIdentity(file, deferred);
        files[next] = .{
            .path = file.path,
            .size = file.size,
            .digest = identity.digest,
            .verification = identity.verification,
        };
        next += 1;
    }
    for (plan.removed) |source_index| {
        if (source_index >= source.files.len) return error.InvalidSourceIndex;
        const file = source.files[source_index];
        if (target.findIndex(file.path) != null) return error.RemovedPathStillTarget;
        files[next] = .{
            .path = file.path,
            .size = file.size,
            .digest = if (deferred) (file.digest orelse .zero) else try requireDigest(file),
            // source-only identity already header-bound
            .verification = .none,
        };
        next += 1;
    }
    std.mem.sortUnstable(ziff.FileEntry, files, {}, lessFile);
    if (files.len > 1) for (files[1..], files[0 .. files.len - 1]) |current, previous| {
        if (std.mem.eql(u8, current.path, previous.path)) return error.DuplicateFilePath;
    };

    var source_ref_count: usize = 0;
    var previous_sources: []const u32 = &.{};
    for (planned_units) |*unit| {
        if (unit.sourceIndexes().len != 0 and !std.mem.eql(u32, previous_sources, unit.sourceIndexes())) {
            source_ref_count = std.math.add(usize, source_ref_count, unit.sourceIndexes().len) catch
                return error.TooManySourceRefs;
        }
        previous_sources = unit.sourceIndexes();
    }
    const units = try allocator.alloc(ziff.Unit, planned_units.len);
    errdefer allocator.free(units);
    const sources = try allocator.alloc(ziff.SourceRef, source_ref_count);
    errdefer allocator.free(sources);
    var source_cursor: usize = 0;
    var needs_native = false;
    previous_sources = &.{};
    var previous_source_first: u32 = 0;
    for (planned_units, 0..) |*planned, unit_index| {
        const target_file = target.files[planned.target];

        const kind: ziff.UnitKind = if (planned.source != .none) .patch_zar26 else .zstd;
        if (kind.isPatch()) needs_native = true;
        const shares_previous = planned.sourceIndexes().len != 0 and
            std.mem.eql(u32, previous_sources, planned.sourceIndexes());
        const source_first = if (shares_previous)
            previous_source_first
        else
            std.math.cast(u32, source_cursor) orelse return error.TooManySourceRefs;
        units[unit_index] = .{
            .kind = kind,
            .payload_offset = 0,
            .payload_len = 0,
            .target = try fileIndex(files, target_file.path),
            .source_first = source_first,
            .source_count = std.math.cast(u32, planned.sourceIndexes().len) orelse return error.TooManySourceRefs,
        };
        if (!shares_previous) {
            for (planned.sourceIndexes()) |source_index| {
                const source_file = source.files[source_index];
                sources[source_cursor] = .{
                    .file = try fileIndex(files, source_file.path),
                    .offset = 0,
                    .length = source_file.size,
                };
                source_cursor += 1;
            }
        }
        previous_sources = planned.sourceIndexes();
        previous_source_first = source_first;
    }

    const ops = try allocator.alloc(ziff.Op, target.files.len);
    errdefer allocator.free(ops);
    for (target.files, 0..) |target_file, target_index| {
        const target_entry = try fileIndex(files, target_file.path);
        if (unit_by_target[target_index]) |unit_index| {
            ops[target_index] = .{
                .kind = if (units[unit_index].kind.isPatch()) .patch else .full,
                .target = target_entry,
                .arg = unit_index,
            };
        } else {
            ops[target_index] = .{
                .kind = .keep,
                .target = target_entry,
                .arg = 0,
            };
        }
    }
    std.mem.sortUnstable(ziff.Op, ops, {}, struct {
        fn lessThan(_: void, lhs: ziff.Op, rhs: ziff.Op) bool {
            return lhs.target < rhs.target;
        }
    }.lessThan);
    var target_hasher = std.crypto.hash.Blake3.init(.{});
    for (ops) |op| ziff.updateLogicalFingerprint(&target_hasher, files[op.target]);
    var target_fingerprint: ids.Digest = undefined;
    target_hasher.final(&target_fingerprint.bytes);

    const removed = try allocator.alloc([]const u8, plan.removed.len);
    errdefer allocator.free(removed);
    for (plan.removed, removed) |source_index, *path| {
        if (source_index >= source.files.len) return error.InvalidSourceIndex;
        path.* = source.files[source_index].path;
    }
    std.mem.sortUnstable([]const u8, removed, {}, lessPath);

    return .{
        .allocator = allocator,
        .header = .{
            .required_features = if (needs_native) ziff.Feature.zar26_codec else 0,
            .software_id = if (software) |value| integrations.integrationId(value) else 0,
            .source_identity = source_identity,
            .target_identity = target_identity,
            .source_fingerprint = ziff.logicalFingerprint(source_fingerprint_files),
            .target_fingerprint = target_fingerprint,
            .target_bytes = target_bytes,
            .source_bytes = source_bytes,
            .unit_count = std.math.cast(u32, units.len) orelse return error.TooManyUnits,
        },
        .directory = .{
            .files = files,
            .ops = ops,
            .units = units,
            .sources = sources,
            .removed = removed,
        },
        .source_manifest = source_fingerprint_files,
    };
}

test "Ziff preparation allocates only owned output through the caller allocator" {
    const Exercise = struct {
        fn run(backing_allocator: std.mem.Allocator, source_root: []const u8, target_root: []const u8) !void {
            var counting = std.testing.FailingAllocator.init(backing_allocator, .{ .resize_fail_index = 0 });
            const allocator = counting.allocator();
            var source_files = [_]tree.File{
                .{ .path = "family/old.blk", .size = 3 },
                .{ .path = "same.bin", .size = 3 },
                .{ .path = "keep.bin", .size = 4 },
            };
            var target_files = [_]tree.File{
                .{ .path = "family/new.blk", .size = 3 },
                .{ .path = "same.bin", .size = 3 },
                .{ .path = "keep.bin", .size = 4 },
            };
            var source: tree.Tree = .{ .root = source_root, .files = &source_files, .map = .empty };
            var target: tree.Tree = .{ .root = target_root, .files = &target_files, .map = .empty };
            var changes = [_]planner.Change{.{ .source = 1, .target = 1 }};
            var added = [_]u32{0};
            var removed = [_]u32{0};
            var groups = [_]planner.Group{.{ .source = &.{0}, .target = &.{0} }};
            var prepared = try build(allocator, std.testing.io, &source, &target, .{
                .changed = &changes,
                .added = &added,
                .removed = &removed,
                .groups = &groups,
            }, null, "old", "new");
            defer prepared.deinit();
            const directory = prepared.directory;
            const owned_bytes = prepared.source_manifest.len * @sizeOf(ziff.FileEntry) +
                directory.files.len * @sizeOf(ziff.FileEntry) +
                directory.ops.len * @sizeOf(ziff.Op) +
                directory.units.len * @sizeOf(ziff.Unit) +
                directory.sources.len * @sizeOf(ziff.SourceRef) +
                directory.removed.len * @sizeOf([]const u8);
            try std.testing.expectEqual(owned_bytes, counting.allocated_bytes);
            try std.testing.expectEqualSlices(ziff.Op, &.{
                .{ .kind = .patch, .target = 0, .arg = 0 },
                .{ .kind = .keep, .target = 2, .arg = 0 },
                .{ .kind = .patch, .target = 3, .arg = 1 },
            }, directory.ops);
            try std.testing.expectEqual(@as(usize, 2), directory.units.len);
            try std.testing.expectEqual(@as(u32, 0), directory.units[0].source_first);
            try std.testing.expectEqual(@as(u32, 1), directory.units[1].source_first);
            try std.testing.expectEqualStrings("family/old.blk", directory.files[directory.sources[0].file].path);
            try std.testing.expectEqualStrings("same.bin", directory.files[directory.sources[1].file].path);
            try std.testing.expect(directory.files[2].digest.eql(ids.Digest.of("same")));
            try std.testing.expect(directory.files[3].digest.eql(ids.Digest.of("new")));
            try std.testing.expectEqualStrings("family/old.blk", directory.removed[0]);
            try std.testing.expect(prepared.header.source_fingerprint.eql(ziff.logicalFingerprint(prepared.source_manifest)));
            const expected = [_]ziff.FileEntry{ directory.files[0], directory.files[2], directory.files[3] };
            try std.testing.expect(prepared.header.target_fingerprint.eql(ziff.logicalFingerprint(&expected)));
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "source/family");
    try tmp.dir.createDirPath(io, "target/family");
    try tmp.dir.writeFile(io, .{ .sub_path = "source/family/old.blk", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/family/new.blk", .data = "new" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/same.bin", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/same.bin", .data = "new" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/keep.bin", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/keep.bin", .data = "same" });
    const source_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "source" });
    defer allocator.free(source_root);
    const target_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "target" });
    defer allocator.free(target_root);
    try std.testing.checkAllAllocationFailures(allocator, Exercise.run, .{ source_root, target_root });
}

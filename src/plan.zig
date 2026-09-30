const std = @import("std");

const ui = @import("ui.zig");
const tree_mod = @import("tree.zig");
const equality = @import("match/equality.zig");
pub const Change = struct { source: u32, target: u32 };
pub const Group = struct { source: []const u32, target: []const u32 };

pub const Plan = struct {
    changed: []Change,
    added: []u32,
    removed: []u32,
    groups: []Group,
    comparison_bytes: u64 = 0,
};

pub const Comparator = struct {
    io: std.Io,
    source: *tree_mod.Tree,
    target: *tree_mod.Tree,
    source_dir: std.Io.Dir,
    target_dir: std.Io.Dir,
    confirmation_buffer: []u8 = &.{},

    pub fn init(io: std.Io, source: *tree_mod.Tree, target: *tree_mod.Tree) !Comparator {
        var source_dir = try std.Io.Dir.cwd().openDir(io, source.root, .{ .access_sub_paths = true });
        errdefer source_dir.close(io);
        return .{ .io = io, .source = source, .target = target, .source_dir = source_dir, .target_dir = try std.Io.Dir.cwd().openDir(io, target.root, .{ .access_sub_paths = true }) };
    }

    pub fn deinit(self: *Comparator) void {
        self.source_dir.close(self.io);
        self.target_dir.close(self.io);
        std.heap.smp_allocator.free(self.confirmation_buffer);
    }

    pub fn differs(self: *Comparator, pair: Change, progress: ?*ui.Progress) !bool {
        const source_file = self.source.files[pair.source];
        const target_file = self.target.files[pair.target];
        if (source_file.bytes) |old| if (target_file.bytes) |new| return !std.mem.eql(u8, old, new);
        if (source_file.size != target_file.size) {
            _ = try tree_mod.ensureHash(self.io, self.target_dir, self.target, pair.target, progress);
            return true;
        }
        _ = try tree_mod.ensureHash(self.io, self.source_dir, self.source, pair.source, progress);
        _ = try tree_mod.ensureHash(self.io, self.target_dir, self.target, pair.target, progress);
        const old = self.source.files[pair.source];
        const new = self.target.files[pair.target];
        if (try metadataDifference(old, new, self.source.deferred_content and self.target.deferred_content)) |different| return different;
        if (self.confirmation_buffer.len == 0) self.confirmation_buffer = try std.heap.smp_allocator.alloc(u8, 4 * 1024 * 1024);
        var source_side = equalitySide(old);
        var target_side = equalitySide(new);
        var reading: ui.ReadProgress = .{ .progress = progress };
        const decision = try equality.confirm(self.io, self.source_dir, self.target_dir, &source_side, &target_side, self.confirmation_buffer, reading.reader());
        adoptObservation(&self.source.files[pair.source], source_side.first);
        adoptObservation(&self.target.files[pair.target], target_side.first);
        return decision == .different;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *tree_mod.Tree,
    target: *tree_mod.Tree,
    detect_groups: bool,
    progress: ?*ui.Progress,
) !Plan {
    var prepared = try prepare(allocator, source, target, progress);
    defer prepared.deinit();
    if (progress) |p| try p.startReading(prepared.work.items.len, prepared.readBytes());
    return prepared.resolve(io, source, target, detect_groups, progress);
}

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    changed: std.ArrayList(Change) = .empty,
    added: std.ArrayList(u32) = .empty,
    removed: std.ArrayList(u32) = .empty,
    work: std.ArrayList(struct { operation: union(enum) { hash: u32, compare: Change }, bytes: u64 }) = .empty,

    pub fn readBytes(self: Prepared) u64 {
        var count: u64 = 0;
        for (self.work.items) |work| count +|= work.bytes;
        return count;
    }

    pub fn deinit(self: *Prepared) void {
        self.changed.deinit(self.allocator);
        self.added.deinit(self.allocator);
        self.removed.deinit(self.allocator);
        self.work.deinit(std.heap.smp_allocator);
    }

    pub fn resolve(self: *Prepared, io: std.Io, source: *tree_mod.Tree, target: *tree_mod.Tree, detect_groups: bool, progress: ?*ui.Progress) !Plan {
        var sink: std.Io.Writer.Discarding = .init(&.{});
        var counter: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Reading contents" };
        const reading = progress orelse &counter;
        if (self.work.items.len != 0) {
            var comparator = try Comparator.init(io, source, target);
            defer comparator.deinit();
            for (self.work.items) |work| {
                const bytes_before = reading.done_bytes;
                switch (work.operation) {
                    .hash => |index| _ = try tree_mod.ensureHash(io, comparator.target_dir, target, index, reading),
                    .compare => |pair| if (try comparator.differs(pair, reading)) try self.changed.append(self.allocator, pair),
                }
                reading.reconcileRead(work.bytes, reading.done_bytes - bytes_before);
                try reading.finishFile();
            }
        }
        const allocator = self.allocator;
        const groups = if (detect_groups)
            try findGroups(allocator, source.*, target.*, self.changed.items, self.added.items, self.removed.items)
        else
            try allocator.alloc(Group, 0);
        errdefer {
            for (groups) |group| {
                allocator.free(group.source);
                allocator.free(group.target);
            }
            allocator.free(groups);
        }
        const changed = try self.changed.toOwnedSlice(allocator);
        errdefer allocator.free(changed);
        const added = try self.added.toOwnedSlice(allocator);
        errdefer allocator.free(added);
        const removed = try self.removed.toOwnedSlice(allocator);
        return .{ .changed = changed, .added = added, .removed = removed, .groups = groups, .comparison_bytes = reading.done_bytes };
    }
};

pub fn prepare(allocator: std.mem.Allocator, source: *tree_mod.Tree, target: *tree_mod.Tree, progress: ?*ui.Progress) !Prepared {
    var result: Prepared = .{ .allocator = allocator };
    errdefer result.deinit();
    for (source.files, 0..) |file, index| {
        if (target.findIndex(file.path) == null) try result.removed.append(allocator, @intCast(index));
    }
    if (progress) |p| {
        p.total_files = target.files.len;
        p.indeterminate = false;
    }
    for (target.files, 0..) |file, index| {
        const target_index: u32 = @intCast(index);
        if (source.findIndex(file.path)) |source_index| {
            const pair: Change = .{ .source = source_index, .target = target_index };
            if (try metadataDifference(source.files[source_index], file, source.deferred_content and target.deferred_content)) |different| {
                if (different) {
                    try result.changed.append(allocator, pair);
                    if (file.md5 == null) try result.work.append(std.heap.smp_allocator, .{ .operation = .{ .hash = target_index }, .bytes = file.size });
                }
            } else {
                const old = source.files[source_index];
                const bytes = file.size *| 2 +|
                    (if (old.md5 == null) old.size else 0) +|
                    (if (file.md5 == null) file.size else 0);
                try result.work.append(std.heap.smp_allocator, .{ .operation = .{ .compare = pair }, .bytes = bytes });
            }
        } else {
            try result.added.append(allocator, target_index);
            if (file.md5 == null) try result.work.append(std.heap.smp_allocator, .{ .operation = .{ .hash = target_index }, .bytes = file.size });
        }
        if (progress) |p| try p.finishFile();
    }
    return result;
}

pub fn metadataDifference(source: tree_mod.File, target: tree_mod.File, trust_claims: bool) !?bool {
    if (source.bytes) |old| if (target.bytes) |new| return !std.mem.eql(u8, old, new);
    if (source.size != target.size) return true;
    if (source.md5 == null or target.md5 == null) return null;
    if (trust_claims and sameAuthoritativeClaim(source, target)) return false;
    if (hasAuthoritativeClaim(source) and hasAuthoritativeClaim(target) and !sameAuthoritativeClaim(source, target)) return true;
    if (!hasAuthoritativeClaim(source) and !hasAuthoritativeClaim(target) and !try tree_mod.candidateEqual(source, target)) return true;
    return null;
}

fn hasAuthoritativeClaim(file: tree_mod.File) bool {
    return if (file.claim) |claim| claim.authority == .authoritative else false;
}

fn sameAuthoritativeClaim(source: tree_mod.File, target: tree_mod.File) bool {
    const source_claim = source.claim orelse return false;
    const target_claim = target.claim orelse return false;
    return source_claim.authority == .authoritative and
        target_claim.authority == .authoritative and
        source_claim.value.sameClaim(target_claim.value);
}

fn equalitySide(file: tree_mod.File) equality.Side {
    const first: ?equality.Observation = if (file.digest) |digest| .{
        .digest = digest,
        .manifest_md5 = file.md5 orelse @splat(0),
        .observed_vendor = file.observed_vendor,
    } else null;
    return .{
        .path = file.path,
        .size = file.size,
        .first = first,
        .claim = file.claim,
    };
}

fn adoptObservation(file: *tree_mod.File, maybe_observation: ?equality.Observation) void {
    const observation = maybe_observation orelse return;
    file.digest = observation.digest;
    file.md5 = observation.manifest_md5;
    file.observed_vendor = observation.observed_vendor;
}

const Family = struct {
    source: std.ArrayList(u32) = .empty,
    target: std.ArrayList(u32) = .empty,
    added: usize = 0,
    removed: usize = 0,
    source_size: u128 = 0,
    target_size: u128 = 0,
};

const FamilyKey = struct {
    directory: []const u8,
    extension: []const u8,
};

const FamilyKeyContext = struct {
    pub fn hash(_: @This(), key: FamilyKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.directory);
        hasher.update("\x00");
        hasher.update(key.extension);
        return hasher.final();
    }

    pub fn eql(_: @This(), a: FamilyKey, b: FamilyKey) bool {
        return std.mem.eql(u8, a.directory, b.directory) and std.mem.eql(u8, a.extension, b.extension);
    }
};

const FamilyMap = std.HashMapUnmanaged(FamilyKey, u32, FamilyKeyContext, std.hash_map.default_max_load_percentage);

pub fn findGroups(
    allocator: std.mem.Allocator,
    source: tree_mod.Tree,
    target: tree_mod.Tree,
    changed: []const Change,
    added: []const u32,
    removed: []const u32,
) ![]Group {
    const scratch = std.heap.smp_allocator;
    var families: std.ArrayList(Family) = .empty;
    defer {
        for (families.items) |*family| {
            family.source.deinit(scratch);
            family.target.deinit(scratch);
        }
        families.deinit(scratch);
    }
    var family_map: FamilyMap = .empty;
    defer family_map.deinit(scratch);

    for (removed) |source_index| {
        const file = source.files[source_index];
        const family = (try getFamily(scratch, &families, &family_map, file.path)) orelse continue;
        try family.source.append(scratch, source_index);
        family.removed += 1;
        family.source_size += file.size;
    }

    for (added) |target_index| {
        const file = target.files[target_index];
        const family = (try getFamily(scratch, &families, &family_map, file.path)) orelse continue;
        try family.target.append(scratch, target_index);
        family.added += 1;
        family.target_size += file.size;
    }

    for (changed) |change| {
        const target_file = target.files[change.target];
        const family = (try getFamily(scratch, &families, &family_map, target_file.path)) orelse continue;
        try family.source.append(scratch, change.source);
        try family.target.append(scratch, change.target);
        family.source_size += source.files[change.source].size;
        family.target_size += target_file.size;
    }

    var groups: std.ArrayList(Group) = .empty;
    errdefer {
        for (groups.items) |group| {
            allocator.free(group.source);
            allocator.free(group.target);
        }
        groups.deinit(allocator);
    }
    for (families.items) |*family| {
        if (family.added == 0 or family.removed == 0) continue;
        if (family.source_size == 0 or family.target_size == 0) continue;
        const smaller = @min(family.source_size, family.target_size);
        const larger = @max(family.source_size, family.target_size);
        if (smaller * 2 < larger) continue;

        sortIndexes(family.source.items, source);
        sortIndexes(family.target.items, target);
        const source_indexes = try allocator.dupe(u32, family.source.items);
        errdefer allocator.free(source_indexes);
        const target_indexes = try allocator.dupe(u32, family.target.items);
        errdefer allocator.free(target_indexes);
        try groups.append(allocator, .{
            .source = source_indexes,
            .target = target_indexes,
        });
    }
    return groups.toOwnedSlice(allocator);
}

fn sortIndexes(indexes: []u32, source: tree_mod.Tree) void {
    std.mem.sortUnstable(u32, indexes, source, struct {
        fn lessThan(context: tree_mod.Tree, a: u32, b: u32) bool {
            return std.mem.order(u8, context.files[a].path, context.files[b].path) == .lt;
        }
    }.lessThan);
}

fn getFamily(
    allocator: std.mem.Allocator,
    families: *std.ArrayList(Family),
    family_map: *FamilyMap,
    path: []const u8,
) !?*Family {
    const key = familyKey(path) orelse return null;
    const got = try family_map.getOrPut(allocator, key);
    if (got.found_existing) return &families.items[got.value_ptr.*];
    got.value_ptr.* = @intCast(families.items.len);
    try families.append(allocator, .{});
    return &families.items[got.value_ptr.*];
}

fn familyKey(path: []const u8) ?FamilyKey {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const directory = if (slash) |i| path[0..i] else "";
    const basename = if (slash) |i| path[i + 1 ..] else path;
    const extension = std.Io.Dir.path.extension(basename);
    if (extension.len == 0) return null;
    return .{ .directory = directory, .extension = extension };
}

test "group outputs own only accepted sorted members through allocation failures" {
    const Exercise = struct {
        fn run(backing_allocator: std.mem.Allocator) !void {
            var relocating = std.testing.FailingAllocator.init(backing_allocator, .{ .resize_fail_index = 0 });
            const allocator = relocating.allocator();
            var source_files = [_]tree_mod.File{
                .{ .path = "blocks/z.blk", .size = 100 },
                .{ .path = "blocks/a.blk", .size = 100 },
                .{ .path = "a/rejected.blk", .size = 100 },
                .{ .path = "blocks/tiny.pak", .size = 1 },
                .{ .path = "blocks/source", .size = 100 },
            };
            var target_files = [_]tree_mod.File{
                .{ .path = "blocks/b.blk", .size = 80 },
                .{ .path = "b/rejected.blk", .size = 100 },
                .{ .path = "blocks/a.blk", .size = 120 },
                .{ .path = "blocks/huge.pak", .size = 100 },
                .{ .path = "blocks/target", .size = 100 },
            };
            const source: tree_mod.Tree = .{ .root = "", .files = &source_files, .map = .empty };
            const target: tree_mod.Tree = .{ .root = "", .files = &target_files, .map = .empty };
            const groups = try findGroups(allocator, source, target, &.{.{ .source = 1, .target = 2 }}, &.{ 0, 1, 3, 4 }, &.{ 0, 2, 3, 4 });
            defer {
                for (groups) |group| {
                    allocator.free(group.source);
                    allocator.free(group.target);
                }
                allocator.free(groups);
            }
            try std.testing.expectEqual(@as(usize, 1), groups.len);
            try std.testing.expectEqualSlices(u32, &.{ 1, 0 }, groups[0].source);
            try std.testing.expectEqualSlices(u32, &.{ 2, 0 }, groups[0].target);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "equal authoritative deferred claims become keep without opening file contents" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const md5: [16]u8 = @splat(0x33);
    const claim: @import("core/ids.zig").VendorClaim = .{
        .authority = .authoritative,
        .value = try @import("core/ids.zig").VendorHash.init(.hoyo_pkg_version_md5, .hex, md5),
    };
    var source_files = [_]tree_mod.File{.{
        .path = "__zift_manifest_keep_that_does_not_exist__.bin",
        .size = 4096,
        .md5 = md5,
        .claim = claim,
    }};
    var target_files = source_files;
    var source_map: std.StringHashMapUnmanaged(u32) = .empty;
    var target_map: std.StringHashMapUnmanaged(u32) = .empty;
    try source_map.put(allocator, source_files[0].path, 0);
    try target_map.put(allocator, target_files[0].path, 0);
    var source: tree_mod.Tree = .{
        .root = ".",
        .files = &source_files,
        .map = source_map,
        .deferred_content = true,
    };
    var target: tree_mod.Tree = .{
        .root = ".",
        .files = &target_files,
        .map = target_map,
        .deferred_content = true,
    };

    const plan = try build(allocator, std.testing.io, &source, &target, false, null);
    try std.testing.expectEqual(@as(usize, 0), plan.changed.len);
    try std.testing.expectEqual(@as(usize, 0), plan.added.len);
    try std.testing.expectEqual(@as(usize, 0), plan.removed.len);
    try std.testing.expectEqual(@as(u64, 0), plan.comparison_bytes);
}

// in-place apply with forward recovery
const std = @import("std");
const Thread = @import("../core/thread.zig").Thread;
const fs = @import("../core/fs.zig");
const content = @import("../core/content.zig");
const ids = @import("../core/ids.zig");
const ziff = @import("../format/ziff.zig");
const ziff_file = @import("../format/ziff_file.zig");
const zstd_frame = @import("../compression/frame.zig");
const zar26 = @import("../format/zar26.zig");
const zstd_c = @import("../compression/zstd_c.zig");
const plan_mod = @import("inplace_plan.zig");
const buffers = @import("stream_buffers.zig");
const profile = @import("../profile.zig");
const ui_mod = @import("../ui.zig");
const generic = @import("../plan/generic.zig");
const tree = @import("../tree.zig");
const ziff_create = @import("../create/ziff.zig");
const ziff_plan = @import("../create/ziff_plan.zig");
const work_name = ".zift-work";
const state_length = 104;
const state_magic = "ZIFTIP00";
const verify_group_bytes: u64 = 512 * 1024 * 1024;

pub const EventFn = *const fn (?*anyopaque, []const u8, u64) anyerror!void;
pub const Preview = struct {
    estimated_extra_bytes: u64,
    available_bytes: ?u64,
    forced: bool,
    resuming: bool,
    already_completed: bool,
};
pub const ConfirmFn = *const fn (?*anyopaque, Preview) anyerror!bool;
pub const Issue = struct {
    path: []const u8,
    action: []const u8,
    err: anyerror,
};
pub const Options = struct {
    progress: ?*ui_mod.Operation = null,
    issue: ?*const fn (?*anyopaque, Issue) void = null,
    issue_context: ?*anyopaque = null,
    available_space: ?u64 = null,
    force_space: bool = false,
    confirm: ?ConfirmFn = null,
    confirm_context: ?*anyopaque = null,
    verify_finished: bool = false,
    // 0 = min(16, logical CPUs)
    verify_workers: usize = 0,
    checkpoint_units: u32 = 32,
    buffer_bytes: usize = 1024 * 1024,
    write_buffer_bytes: usize = 256 * 1024,
    patch_buffer_bytes: usize = 256 * 1024,
    source_handle_capacity: usize = 512,
    batch_directory_sync: bool = true,
    event: ?EventFn = null,
    event_context: ?*anyopaque = null,
    // fault injection only
    split_writes: bool = false,
};
pub const Stats = struct {
    errors: u64 = 0,
    estimated_extra_bytes: u64 = 0,
    estimated_space_forced: bool = false,
    units_decoded: u64 = 0,
    units_recovered: u64 = 0,
    source_bytes: u64 = 0,
    package_bytes: u64 = 0,
    output_bytes: u64 = 0,
    skipped_bytes: u64 = 0,
    preserved_bytes: u64 = 0,
    preserved_read_bytes: u64 = 0,
    preservation_source_bytes: u64 = 0,
    preservation_read_calls: u64 = 0,
    preservation_write_calls: u64 = 0,
    peak_preserved_bytes: u64 = 0,
    journal_bytes: u64 = 0,
    recovery_hash_bytes: u64 = 0,
    final_hash_bytes: u64 = 0,
    final_hash_read_bytes: u64 = 0,
    size_checks: u64 = 0,
    source_opens: u64 = 0,
    source_handle_evictions: u64 = 0,
    source_handle_limit: u64 = 0,
    source_read_calls: u64 = 0,
    preserved_read_calls: u64 = 0,
    package_read_calls: u64 = 0,
    output_write_calls: u64 = 0,
    decoder_source_calls: u64 = 0,
    decoder_patch_calls: u64 = 0,
    decoder_output_calls: u64 = 0,
    old_files_removed: u64 = 0,
    syncs: u64 = 0,
    file_syncs: u64 = 0,
    directory_syncs: u64 = 0,
    events: u64 = 0,
    resumed: bool = false,
    already_completed: bool = false,
};
const State = struct {
    package: ids.Digest,
    units: u64,
    files: u64,
    next: u64 = 0,
    complete: bool = false,
};
fn encodeState(state: State) [state_length]u8 {
    var bytes: [state_length]u8 = @splat(0);
    @memcpy(bytes[0..8], state_magic);
    @memcpy(bytes[8..40], &state.package.bytes);
    std.mem.writeInt(u64, bytes[40..48], state.units, .little);
    std.mem.writeInt(u64, bytes[48..56], state.files, .little);
    std.mem.writeInt(u64, bytes[56..64], state.next, .little);
    std.mem.writeInt(u64, bytes[64..72], @intFromBool(state.complete), .little);
    const hash = ids.Digest.of(bytes[0..72]);
    @memcpy(bytes[72..104], &hash.bytes);
    return bytes;
}
fn decodeState(bytes: []const u8) !State {
    if (bytes.len != state_length or !std.mem.eql(u8, bytes[0..8], state_magic)) return error.InvalidInplaceJournal;
    const digest = ids.Digest.of(bytes[0..72]);
    if (!std.mem.eql(u8, &digest.bytes, bytes[72..104])) return error.InvalidInplaceJournal;
    var package: ids.Digest = undefined;
    @memcpy(&package.bytes, bytes[8..40]);
    const flags = std.mem.readInt(u64, bytes[64..72], .little);
    const result: State = .{ .package = package, .units = std.mem.readInt(u64, bytes[40..48], .little), .files = std.mem.readInt(u64, bytes[48..56], .little), .next = std.mem.readInt(u64, bytes[56..64], .little), .complete = flags == 1 };
    if (flags > 1 or result.units > ziff.max_unit_count or result.files > ziff.max_table_entries or
        result.next > result.units or (result.complete and result.next != result.units)) return error.InvalidInplaceJournal;
    return result;
}
fn exact(io: std.Io, file: std.Io.File, bytes: []u8, offset: u64) !void {
    if (try fs.readAllAt(io, file, bytes, offset) != bytes.len) return error.ShortInplaceRead;
}
fn sourceName(buffer: []u8, index: usize, backup: bool) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{c}{d}", .{ @as(u8, if (backup) 'b' else 'm'), index });
}
fn partialName(buffer: []u8, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "b{d}.part", .{index});
}
fn knownArtifact(name: []const u8, files: u64) bool {
    if (name.len < 2 or (name[0] != 'b' and name[0] != 'm')) return false;
    const digits = if (std.mem.endsWith(u8, name, ".part")) name[1 .. name.len - 5] else name[1..];
    if (digits.len == 0 or (digits.len > 1 and digits[0] == '0')) return false;
    for (digits) |digit| if (!std.ascii.isDigit(digit)) return false;
    if (name[0] == 'm' and std.mem.endsWith(u8, name, ".part")) return false;
    const number = std.fmt.parseInt(u64, digits, 10) catch return false;
    return number < files;
}
// half the FD limit reserved for roots, outputs, and journal handles
fn handleCapacity(requested: usize) usize {
    if (std.posix.rlimit_resource == void) return requested;
    const limit = std.posix.getrlimit(.NOFILE) catch return @min(requested, 64);
    if (limit.cur == std.posix.RLIM.INFINITY) return requested;
    const finite = std.math.cast(usize, limit.cur) orelse return @min(requested, 64);
    return @min(requested, @max(@as(usize, 1), finite / 2));
}
const Cache = struct {
    const Slot = struct { file: std.Io.File, key: usize };
    slots: []?Slot,
    positions: []?usize,
    next: usize = 0,
    fn init(a: std.mem.Allocator, count: usize, capacity: usize) !Cache {
        const positions = try a.alloc(?usize, count * 2);
        @memset(positions, null);
        const slots = try a.alloc(?Slot, @min(capacity, @max(@as(usize, 1), positions.len)));
        @memset(slots, null);
        return .{ .positions = positions, .slots = slots };
    }
    fn deinit(cache: *Cache, io: std.Io) void {
        for (cache.slots) |slot| if (slot) |s| s.file.close(io);
    }
    fn invalidate(cache: *Cache, io: std.Io, key: usize) void {
        if (cache.positions[key]) |i| {
            cache.slots[i].?.file.close(io);
            cache.slots[i] = null;
            cache.positions[key] = null;
        }
    }
    fn get(cache: *Cache, context: *Context, index: usize, backup: bool) !std.Io.File {
        const key = index + if (backup) context.plan.files.len else @as(usize, 0);
        if (cache.positions[key]) |i| return cache.slots[i].?.file;
        var span = profile.begin(context.io, "inplace: Source opens");
        defer span.end(context.io);
        const slot = cache.next;
        cache.next = (slot + 1) % cache.slots.len;
        if (cache.slots[slot]) |old| {
            context.stats.source_handle_evictions += 1;
            old.file.close(context.io);
            cache.positions[old.key] = null;
            cache.slots[slot] = null;
        }
        var buffer: [64]u8 = undefined;
        var file = if (backup or context.plan.files[index].displaced)
            try fs.openRead(context.io, context.work, try sourceName(&buffer, index, backup))
        else
            try fs.openReadBeneath(context.io, context.root, context.directory.files[index].path);
        errdefer file.close(context.io);
        if ((try file.stat(context.io)).kind != .file) return error.UnsafeSourceObject;
        if (try fs.sameOpenFile(context.io, file, context.package)) return error.SourceIsPackage;
        cache.positions[key] = slot;
        cache.slots[slot] = .{ .file = file, .key = key };
        context.stats.source_opens += 1;
        return file;
    }
};

const Context = struct {
    a: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    work: std.Io.Dir,
    package: std.Io.File,
    directory: ziff.Directory,
    recipes: []const ziff.Replay,
    plan: plan_mod.Plan,
    state: State,
    options: Options,
    stats: Stats = .{},
    cache: Cache,
    buffer: []u8,
    write_buffer: []u8,
    patch_buffer: []u8,
    verification_buffer: []u8,
    verified_targets: []bool,
    unavailable_files: []bool,
    blocked_units: []bool,
    preserved_live: u64 = 0,
    release_cursor: usize = 0,
    dirty_directories: std.StringHashMapUnmanaged(void) = .empty,
    output_names_pending: bool = false,
    fn issue(c: *Context, index: usize, action: []const u8, err: anyerror) !void {
        try c.issuePath(c.directory.files[index].path, action, err);
    }
    fn issuePath(c: *Context, path: []const u8, action: []const u8, err: anyerror) !void {
        if (err == error.Interrupted or err == error.Canceled or err == error.OutOfMemory or err == error.Injected) return err;
        c.stats.errors += 1;
        if (c.options.issue) |report| report(c.options.issue_context, .{ .path = path, .action = action, .err = err });
    }
    fn event(c: *Context, name: []const u8) !void {
        c.stats.events += 1;
        if (c.options.event) |f| try f(c.options.event_context, name, c.stats.events);
    }
    fn sync(c: *Context, file: std.Io.File) !void {
        var span = profile.begin(c.io, "inplace: file sync");
        defer span.end(c.io);
        try file.sync(c.io);
        c.stats.syncs += 1;
        c.stats.file_syncs += 1;
    }
    fn syncDir(c: *Context, dir: std.Io.Dir) !void {
        var span = profile.begin(c.io, "inplace: directory sync");
        defer span.end(c.io);
        try fs.syncDirectory(c.io, dir);
        c.stats.syncs += 1;
        c.stats.directory_syncs += 1;
    }

    fn checkpoint(c: *Context) !void {
        // persist output names before permitting source deletion
        try c.flushDirectories();
        const bytes = encodeState(c.state);
        var part = fs.openReadWrite(c.io, c.work, "state.part") catch |err| switch (err) {
            error.FileNotFound => try fs.createGuardedOutput(c.io, c.work, "state.part"),
            else => return err,
        };
        var part_closed = false;
        defer if (!part_closed) part.close(c.io);
        _ = try fs.validateGuardedOutputAuthority(c.io, part);
        try part.setLength(c.io, 0);
        try c.event("journal-part-created");
        if (c.options.split_writes) {
            try part.writePositionalAll(c.io, bytes[0..52], 0);
            c.stats.journal_bytes += 52;
            try c.event("journal-partial-write");
            try part.writePositionalAll(c.io, bytes[52..], 52);
            c.stats.journal_bytes += 52;
        } else {
            try part.writePositionalAll(c.io, &bytes, 0);
            c.stats.journal_bytes += bytes.len;
        }
        try c.event("journal-written");
        try c.sync(part);
        try c.event("journal-synced");
        // windows: closed handle required for this private-file rename
        part.close(c.io);
        part_closed = true;
        try std.Io.Dir.rename(c.work, "state.part", c.work, "state", c.io);
        try c.event("journal-renamed");
        try c.syncDir(c.work);
        try c.event("journal-directory-synced");
    }
    fn workspaceContents(c: *Context, allowed_files: u64, remove_artifacts: bool) !void {
        var iterator = c.work.iterate();
        while (try iterator.next(c.io)) |entry| {
            if (std.mem.eql(u8, entry.name, "state") or std.mem.eql(u8, entry.name, "lock") or std.mem.eql(u8, entry.name, "state.part")) {
                const stat = try c.work.statFile(c.io, entry.name, .{ .follow_symlinks = false });
                if (stat.kind != .file or stat.nlink != 1) return error.UnknownInplaceWorkspaceObject;
                if (remove_artifacts and std.mem.eql(u8, entry.name, "state.part")) {
                    try c.work.deleteFile(c.io, entry.name);
                    try c.event("obsolete-journal-part-removed");
                }
                continue;
            }
            if (entry.kind != .file or !knownArtifact(entry.name, allowed_files)) return error.UnknownInplaceWorkspaceObject;
            if (remove_artifacts) {
                const stat = try c.work.statFile(c.io, entry.name, .{ .follow_symlinks = false });
                if (stat.kind != .file or stat.nlink != 1) return error.UnknownInplaceWorkspaceObject;
                try c.work.deleteFile(c.io, entry.name);
                try c.event("obsolete-workspace-artifact-removed");
            }
        }
    }
    fn checkFresh(c: *Context) !void {
        var span = profile.begin(c.io, "inplace: Source metadata");
        defer span.end(c.io);
        if (c.options.progress) |progress| progress.totals(0, c.plan.files.len);
        for (c.plan.files, 0..) |file, index| {
            defer if (c.options.progress) |progress| progress.complete(0, 1);
            c.checkFile(index) catch |err| {
                try c.issue(index, "Checking source", err);
                c.unavailable_files[index] = true;
                if (file.writer) |writer| c.blocked_units[writer] = true;
            };
        }
    }
    fn checkFile(c: *Context, index: usize) !void {
        const file = c.plan.files[index];
        var object = fs.openReadBeneath(c.io, c.root, c.directory.files[index].path) catch |err| switch (err) {
            error.FileNotFound, error.PathAncestorNotDirectory, error.IsDir, error.NotDir => {
                if (file.required) return error.MissingRequiredSource;
                if (file.writer == null and !file.removed) return error.FinishedSizeMismatch;
                // valid shape changes: empty directory -> file, source-only file -> parent
                if (file.removed and err != error.FileNotFound) return error.UnsafeRemovalObject;
                return;
            },
            else => return err,
        };
        defer object.close(c.io);
        const stat = try object.stat(c.io);
        if (stat.kind != .file) return error.UnsafeSourceObject;
        c.plan.files[index].observed_size = stat.size;
        c.plan.files[index].observed_single_link = stat.nlink == 1;
        if (file.required and stat.size < file.required_length) return error.SourceTooShort;
        if (file.writer == null and !file.removed and stat.size != c.directory.files[index].size)
            try c.issue(index, "Checking unchanged file", error.FinishedSizeMismatch);
        if (file.writer != null and stat.nlink != 1) return error.UnsafeTargetHardlink;
        if (try fs.sameOpenFile(c.io, object, c.package)) return error.InstallObjectIsPackage;
    }
    fn observeForEstimate(c: *Context, index: usize) !void {
        const file = &c.plan.files[index];
        var name_buffer: [64]u8 = undefined;
        var parent = if (file.displaced)
            fs.BeneathParent{ .dir = c.work, .basename = try sourceName(&name_buffer, index, false), .owned = false }
        else
            fs.openParentBeneath(c.io, c.root, c.directory.files[index].path) catch |err| switch (err) {
                error.FileNotFound, error.PathAncestorNotDirectory => return,
                else => return err,
            };
        defer parent.close(c.io);
        const stat = parent.dir.statFile(c.io, parent.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        if (stat.kind == .directory) return;
        if (stat.kind != .file) return error.UnsafeTargetObject;
        file.observed_size = stat.size;
        file.observed_single_link = stat.nlink == 1;
    }
    fn estimateExtra(c: *Context) !u64 {
        if (c.state.complete) return 0;
        // estimate only: sparse/CoW allocation may differ
        const newly_saved = try c.a.alloc(u64, c.plan.files.len);
        @memset(newly_saved, 0);
        defer c.a.free(newly_saved);
        if (c.stats.resumed) {
            var count: usize = 0;
            for (c.plan.files) |file| if (file.writer != null or file.removed) {
                count += 1;
            };
            if (c.options.progress) |progress| progress.totals(0, count);
            for (c.plan.files, 0..) |file, index| if (file.writer != null or file.removed) {
                defer if (c.options.progress) |progress| progress.complete(0, 1);
                c.observeForEstimate(index) catch |err| {
                    try c.issue(index, "Checking resumed file", err);
                    c.unavailable_files[index] = true;
                    if (file.writer) |writer| c.blocked_units[writer] = true;
                };
            };
        }
        const round = struct {
            fn bytes(n: u64) !u64 {
                const sum = std.math.add(u64, n, 4095) catch return error.SpaceEstimateOverflow;
                return sum & ~@as(u64, 4095);
            }
        };
        var balance: i128 = 0;
        var live: u64 = 0;
        var peak: i128 = 0;
        for (c.plan.remove_initial) |index| {
            const file = c.plan.files[index];
            if (file.observed_single_link) balance -= try round.bytes(file.observed_size);
        }
        var release: usize = @intCast(c.state.next);
        var pending_names = false;
        var displaced = false;
        for (c.plan.files) |f| displaced = displaced or f.displaced;
        for (c.directory.units[@intCast(c.state.next)..], @as(usize, @intCast(c.state.next))..) |unit, ui| {
            const index = unit.target;
            const file = &c.plan.files[index];
            if (file.save_bytes != 0 and (!c.stats.resumed or !try c.artifactExists(index, true))) {
                newly_saved[index] = try round.bytes(file.save_bytes);
                live = std.math.add(u64, live, newly_saved[index]) catch return error.SpaceEstimateOverflow;
            }
            peak = @max(peak, balance + live);
            balance += @as(i128, try round.bytes(c.directory.files[index].size)) - @as(i128, try round.bytes(file.observed_size));
            if (file.observed_size == 0) balance += 4096;
            peak = @max(peak, balance + live);
            // single-link estimate invalid after shape changes
            pending_names = pending_names or !file.observed_single_link or displaced or c.stats.resumed;
            const boundary = (ui + 1) % c.options.checkpoint_units == 0 or ui + 1 == c.directory.units.len;
            if (!c.options.batch_directory_sync or boundary or !pending_names) {
                while (release <= ui) : (release += 1) {
                    for (c.plan.release[release]) |released| {
                        live -= newly_saved[released];
                        const old = c.plan.files[released];
                        if (old.removed and old.observed_single_link) balance -= try round.bytes(old.observed_size);
                    }
                }
            }
            if (boundary) pending_names = false;
        }
        if (peak > std.math.maxInt(u64) - 64 * 1024) return error.SpaceEstimateOverflow;
        return @as(u64, @intCast(peak)) + 64 * 1024;
    }
    fn artifactExists(c: *Context, index: usize, backup: bool) !bool {
        var buffer: [64]u8 = undefined;
        const name = try sourceName(&buffer, index, backup);
        const stat = c.work.statFile(c.io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        if (stat.kind != .file or stat.nlink != 1) return error.UnsafePreservedObject;
        if (backup and stat.size != c.plan.files[index].save_bytes) return error.PreservedSizeMismatch;
        return true;
    }
    fn displace(c: *Context) !void {
        for (c.plan.files, 0..) |file, index| if (file.displaced) {
            if (c.unavailable_files[index]) continue;
            c.displaceFile(index) catch |err| {
                try c.issue(index, "Preserving source", err);
                c.unavailable_files[index] = true;
                if (file.writer) |writer| c.blocked_units[writer] = true;
            };
        };
        try c.removeEmptyParents();
    }
    fn displaceFile(c: *Context, index: usize) !void {
        const file = c.plan.files[index];
        if (try c.artifactExists(index, false)) return;
        if (file.last_use) |last| {
            if (last < c.state.next) return;
        }
        var parent = fs.openParentBeneath(c.io, c.root, c.directory.files[index].path) catch |err| switch (err) {
            error.FileNotFound, error.PathAncestorNotDirectory => {
                if (file.required and c.state.next == 0) return error.MissingDisplacedSource;
                return;
            },
            else => return err,
        };
        defer parent.close(c.io);
        const stat = parent.dir.statFile(c.io, parent.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => {
                if (file.required and c.state.next == 0) return error.MissingDisplacedSource;
                return;
            },
            else => return err,
        };
        // recovery: new directory at the old source path
        if (stat.kind == .directory) {
            if (file.last_use == null or file.last_use.? < c.state.next) return;
            return error.MissingDisplacedSource;
        }
        if (stat.kind != .file or stat.nlink != 1) return error.UnsafeDisplacedSource;
        var buffer: [64]u8 = undefined;
        const name = try sourceName(&buffer, index, false);
        try std.Io.Dir.renamePreserve(parent.dir, parent.basename, c.work, name, c.io);
        try c.event("source-displaced");
        try c.syncDir(parent.dir);
        try c.syncDir(c.work);
        try c.event("source-displacement-synced");
    }
    fn removeEmptyParents(c: *Context) !void {
        var parents: std.StringHashMapUnmanaged(void) = .empty;
        defer parents.deinit(c.a);
        for (c.plan.files, 0..) |file, index| if (file.displaced) {
            var p = c.directory.files[index].path;
            while (std.mem.lastIndexOfScalar(u8, p, '/')) |slash| {
                p = p[0..slash];
                try parents.put(c.a, p, {});
            }
        };
        const paths = try c.a.alloc([]const u8, parents.count());
        defer c.a.free(paths);
        var it = parents.keyIterator();
        var n: usize = 0;
        while (it.next()) |p| {
            paths[n] = p.*;
            n += 1;
        }
        std.mem.sortUnstable([]const u8, paths, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return a.len > b.len;
            }
        }.less);
        for (paths) |p| {
            var parent = fs.openParentBeneath(c.io, c.root, p) catch |err| switch (err) {
                error.FileNotFound, error.PathAncestorNotDirectory => continue,
                else => {
                    try c.issuePath(p, "Cleaning source directory", err);
                    continue;
                },
            };
            defer parent.close(c.io);
            parent.dir.deleteDir(c.io, parent.basename) catch |err| switch (err) {
                error.FileNotFound, error.NotDir, error.DirNotEmpty => continue,
                else => {
                    try c.issuePath(p, "Cleaning source directory", err);
                    continue;
                },
            };
            try c.event("empty-source-directory-removed");
            c.syncDir(parent.dir) catch |err| try c.issuePath(p, "Syncing source directory", err);
        }
    }
    const PreservationSink = struct {
        c: *Context,
        file: std.Io.File,
        pub fn writeExact(self: *@This(), bytes: []const u8, offset: u64) !void {
            const c = self.c;
            if (c.options.split_writes and bytes.len > 1) {
                const half = bytes.len / 2;
                try self.file.writePositionalAll(c.io, bytes[0..half], offset);
                c.stats.preserved_bytes += half;
                c.stats.preservation_write_calls += 1;
                try c.event("partial-preservation-write");
                try self.file.writePositionalAll(c.io, bytes[half..], offset + half);
                c.stats.preserved_bytes += bytes.len - half;
                c.stats.preservation_write_calls += 1;
            } else {
                try self.file.writePositionalAll(c.io, bytes, offset);
                c.stats.preserved_bytes += bytes.len;
                c.stats.preservation_write_calls += 1;
            }
            if (c.options.progress) |progress| progress.advanceWork(bytes.len, 0);
            try c.event("preservation-written");
        }
    };
    fn prepare(c: *Context, index: usize) !void {
        var span = profile.begin(c.io, "inplace: preservation");
        defer span.end(c.io);
        const file = c.plan.files[index];
        if (file.save_bytes == 0) return;
        if (try c.artifactExists(index, true)) return;
        if (c.options.progress) |progress| progress.phase("Preserving source", file.save_bytes, 0);
        var temp_buffer: [64]u8 = undefined;
        const temp = try partialName(&temp_buffer, index);
        var backup = fs.openReadWrite(c.io, c.work, temp) catch |err| switch (err) {
            error.FileNotFound => try fs.createGuardedOutput(c.io, c.work, temp),
            else => return err,
        };
        var backup_closed = false;
        defer if (!backup_closed) backup.close(c.io);
        _ = try fs.validateGuardedOutputAuthority(c.io, backup);
        try backup.setLength(c.io, 0);
        try c.event("preservation-started");
        const source = try c.cache.get(c, index, false);
        var sink: PreservationSink = .{ .c = c, .file = backup };
        var pending: buffers.WriteBuffer = .{ .bytes = c.write_buffer };
        for (file.save) |saved| {
            const r = saved.range;
            var offset = r.offset;
            while (offset < r.end()) {
                const n: usize = @intCast(@min(@as(u64, c.buffer.len), r.end() - offset));
                try exact(c.io, source, c.buffer[0..n], offset);
                c.stats.preservation_source_bytes += n;
                c.stats.preservation_read_calls += 1;
                try pending.write(&sink, c.buffer[0..n], saved.backup_offset + (offset - r.offset));
                offset += n;
            }
        }
        try pending.flush(&sink);
        try c.sync(backup);
        try c.event("preservation-synced");
        var name_buffer: [64]u8 = undefined;
        const name = try sourceName(&name_buffer, index, true);
        backup.close(c.io);
        backup_closed = true;
        try std.Io.Dir.renamePreserve(c.work, temp, c.work, name, c.io);
        try c.event("preservation-published");
        try c.syncDir(c.work);
        try c.event("preservation-directory-synced");
        c.preserved_live += file.save_bytes;
        c.stats.peak_preserved_bytes = @max(c.stats.peak_preserved_bytes, c.preserved_live);
    }
    fn reclaim(c: *Context) !void {
        var span = profile.begin(c.io, "inplace: reclamation");
        defer span.end(c.io);
        while (c.release_cursor < c.state.next) : (c.release_cursor += 1) {
            for (c.plan.release[c.release_cursor]) |index| {
                const file = c.plan.files[index];
                if (file.removed) {
                    c.removeSource(index) catch |err| try c.issue(index, "Cleaning", err);
                    continue;
                }
                c.cache.invalidate(c.io, index + c.plan.files.len);
                var buffer: [64]u8 = undefined;
                c.work.deleteFile(c.io, try sourceName(&buffer, index, true)) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => {
                        try c.issue(index, "Cleaning preserved source", err);
                        continue;
                    },
                };
                c.preserved_live -|= file.save_bytes;
                try c.event("preservation-released");
            }
        }
    }

    fn outputParent(c: *Context, path: []const u8) !fs.BeneathParent {
        try fs.createParentPathBeneath(c.io, c.root, path);
        return fs.openParentBeneath(c.io, c.root, path);
    }
    fn markAncestors(c: *Context, path: []const u8) !void {
        try c.dirty_directories.put(c.a, "", {});
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            try c.dirty_directories.put(c.a, path[0..slash], {});
            start = slash + 1;
        }
    }
    fn flushDirectories(c: *Context) !void {
        if (c.dirty_directories.count() == 0) return;
        const paths = try c.a.alloc([]const u8, c.dirty_directories.count());
        defer c.a.free(paths);
        var it = c.dirty_directories.keyIterator();
        var n: usize = 0;
        while (it.next()) |path| : (n += 1) paths[n] = path.*;
        std.mem.sortUnstable([]const u8, paths, {}, struct {
            fn less(_: void, left: []const u8, right: []const u8) bool {
                if (left.len != right.len) return left.len > right.len;
                return std.mem.lessThan(u8, left, right);
            }
        }.less);
        try c.event("directories-before-sync");
        for (paths) |path| {
            if (path.len == 0) {
                try c.syncDir(c.root);
            } else {
                var parent = fs.openParentBeneath(c.io, c.root, path) catch |err| switch (err) {
                    error.FileNotFound, error.PathAncestorNotDirectory => continue,
                    else => return err,
                };
                defer parent.close(c.io);
                var dir = parent.dir.openDir(c.io, parent.basename, .{ .follow_symlinks = false, .access_sub_paths = true }) catch |err| switch (err) {
                    // removed directory: surviving parent already queued
                    error.FileNotFound, error.NotDir => continue,
                    else => return err,
                };
                defer dir.close(c.io);
                try c.syncDir(dir);
            }
            try c.event("directory-batch-entry-synced");
        }
        c.dirty_directories.clearRetainingCapacity();
        c.output_names_pending = false;
        try c.event("output-name-synced");
    }
    fn syncAncestors(c: *Context, path: []const u8) !void {
        try c.syncDir(c.root);
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            var parent = try fs.openParentBeneath(c.io, c.root, path[0..slash]);
            defer parent.close(c.io);
            var dir = try parent.dir.openDir(c.io, parent.basename, .{ .follow_symlinks = false, .access_sub_paths = true });
            defer dir.close(c.io);
            try c.syncDir(dir);
            start = slash + 1;
        }
    }
    fn readOld(c: *Context, file_index: usize, unit_index: usize, offset: u64, bytes: []u8) !void {
        var span = profile.begin(c.io, "inplace: Source reads");
        defer span.end(c.io);
        const info = c.plan.files[file_index];
        var cursor = offset;
        const end = std.math.add(u64, offset, bytes.len) catch return error.SourceRangeOverflow;
        var r_index: usize = 0;
        var lo: usize = 0;
        var hi = info.save.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (info.save[mid].range.end() <= cursor) lo = mid + 1 else hi = mid;
        }
        r_index = lo;
        const overwritten = if (info.writer) |writer| unit_index >= writer else false;
        while (cursor < end) {
            const active = overwritten and r_index < info.save.len and info.save[r_index].range.offset <= cursor;
            var stop = end;
            if (overwritten and r_index < info.save.len) stop = @min(end, if (active) info.save[r_index].range.end() else info.save[r_index].range.offset);
            const view = bytes[@intCast(cursor - offset)..@intCast(stop - offset)];
            if (active) {
                const backup = try c.cache.get(c, file_index, true);
                const saved = info.save[r_index];
                try exact(c.io, backup, view, saved.backup_offset + (cursor - saved.range.offset));
                c.stats.preserved_read_bytes += view.len;
                c.stats.preserved_read_calls += 1;
            } else {
                const source = try c.cache.get(c, file_index, false);
                try exact(c.io, source, view, cursor);
                c.stats.source_bytes += view.len;
                c.stats.source_read_calls += 1;
            }
            cursor = stop;
            if (overwritten and r_index < info.save.len and cursor >= info.save[r_index].range.end()) r_index += 1;
        }
    }
    fn recoveryHashMatches(c: *Context, index: usize) !bool {
        const expected = c.directory.files[index];
        var parent = fs.openParentBeneath(c.io, c.root, expected.path) catch |err| switch (err) {
            error.FileNotFound, error.PathAncestorNotDirectory => return false,
            else => return err,
        };
        defer parent.close(c.io);
        // windows: write access required for recovery flush
        var file = fs.openExisting(c.io, parent.dir, parent.basename, .read_write) catch |err| switch (err) {
            error.FileNotFound, error.IsDir, error.NotDir => return false,
            else => return err,
        };
        defer file.close(c.io);
        const stat = try file.stat(c.io);
        if (stat.kind != .file or stat.size != expected.size) return false;
        if (stat.nlink != 1) return error.UnsafeTargetHardlink;
        if (c.options.progress) |progress| progress.phase("Recovering", expected.size, 0);
        const hashed = try hashOpenExpected(
            c.io,
            file,
            expected,
            c.buffer,
            c.options.progress,
        );
        c.stats.recovery_hash_bytes += hashed.bytes;
        if (!hashed.matches) return false;
        // matching bytes != durable bytes
        try c.sync(file);
        try c.syncAncestors(expected.path);
        return true;
    }
    fn recover(c: *Context) !void {
        while (c.state.next < c.directory.units.len) {
            const unit = c.directory.units[@intCast(c.state.next)];
            const index = unit.target;
            if (!try c.recoveryHashMatches(index)) break;
            c.state.next += 1;
            c.stats.units_recovered += 1;
            try c.event("finished-output-recovered");
        }
        for (c.plan.files, 0..) |file, index| {
            if (file.writer) |writer| if (writer < c.state.next and file.save_bytes != 0 and
                file.last_use != null and file.last_use.? >= c.state.next)
            {
                if (!try c.artifactExists(index, true)) return error.MissingPreservedSource;
            };
        }
        try c.checkpoint();
        try c.reclaim();
    }
    fn execute(c: *Context, index: usize) !void {
        const unit = c.directory.units[index];
        const target_index = unit.target;
        const target = c.directory.files[target_index];
        if (c.options.progress) |progress| progress.phase("Writing", target.size, 0);
        var setup_span = profile.begin(c.io, "inplace: output setup");
        defer setup_span.end(c.io);
        var parent = try c.outputParent(target.path);
        defer parent.close(c.io);
        var created = false;
        var output = fs.openReadWrite(c.io, parent.dir, parent.basename) catch |err| switch (err) {
            error.FileNotFound => blk: {
                if (c.recipes[index].skips.len != 0) return error.MissingSkippedOutput;
                created = true;
                break :blk try fs.createGuardedOutput(c.io, parent.dir, parent.basename);
            },
            error.IsDir => blk: {
                try parent.dir.deleteDir(c.io, parent.basename);
                try c.event("empty-target-directory-removed");
                created = true;
                break :blk try fs.createGuardedOutput(c.io, parent.dir, parent.basename);
            },
            else => return err,
        };
        defer output.close(c.io);
        _ = try fs.validateGuardedOutputAuthority(c.io, output);
        if (try fs.sameOpenFile(c.io, output, c.package)) return error.TargetIsPackage;
        try c.event("output-opened");
        const refs = c.directory.sources[unit.source_first..][0..unit.source_count];
        const starts = try c.a.alloc(u64, refs.len + 1);
        defer c.a.free(starts);
        starts[0] = 0;
        for (refs, 0..) |ref, i| starts[i + 1] = std.math.add(u64, starts[i], ref.length) catch return error.SourceRangeOverflow;
        const recipe = c.recipes[index];
        if (recipe.skips.len != 0 and try output.length(c.io) < recipe.skips[recipe.skips.len - 1].end()) return error.MissingSkippedOutput;
        var verification: ?content.State = null;
        if (c.options.verify_finished and
            (target.verification.isPresent() or !target.digest.eql(.zero)))
        {
            var state: content.State = .{ .size = target.size };
            try state.bindVerification(target.verification);
            verification = state;
        }
        var decoder: Decoder = .{ .context = c, .unit = unit, .unit_index = index, .output = output, .refs = refs, .starts = starts, .recipe = recipe, .pending = .{ .bytes = c.write_buffer }, .patch_window = .{ .bytes = c.patch_buffer }, .verification = verification };
        setup_span.end(c.io);
        var decode_span = profile.begin(c.io, "inplace: decode+I/O");
        defer decode_span.end(c.io);
        switch (unit.kind) {
            .patch_zar26 => try zar26.decode(
                c.a,
                decoder.zarSourceInput(),
                decoder.zarPatchInput(),
                target.size,
                decoder.zarOutput(),
            ),
            .raw => {
                var offset: u64 = 0;
                while (offset < unit.payload_len) {
                    const n: usize = @intCast(@min(@as(u64, c.buffer.len), unit.payload_len - offset));
                    try exact(c.io, c.package, c.buffer[0..n], unit.payload_offset + offset);
                    c.stats.package_bytes += n;
                    c.stats.package_read_calls += 1;
                    try decoder.write(offset, c.buffer[0..n]);
                    offset += n;
                }
            },
            .zstd => try decoder.decodeZstd(),
        }
        try decoder.pending.flush(&decoder);
        decode_span.end(c.io);
        if (decoder.written != target.size) return error.OutputSizeMismatch;
        if (try decoder.finishVerification()) {
            c.verified_targets[target_index] = true;
            c.stats.final_hash_bytes += target.size;
        }
        try c.event("output-decoded");
        if (try output.length(c.io) != target.size) {
            try c.event("before-truncate");
            try output.setLength(c.io, target.size);
            try c.event("after-truncate");
        }
        if (c.options.progress) |progress| progress.phase("Syncing", 0, 0);
        try c.sync(output);
        try c.event("output-synced");
        // recovery: existing output, possibly undurable parent entry
        if (created or c.stats.resumed) {
            if (c.options.batch_directory_sync) {
                try c.markAncestors(target.path);
                c.output_names_pending = true;
            } else {
                try c.syncAncestors(target.path);
                try c.event("output-name-synced");
            }
        }
        if (c.state.next == index) c.state.next = index + 1;
        c.stats.units_decoded += 1;
        if (c.options.progress) |progress| progress.complete(target.size, 1);
    }
    fn finishUnit(c: *Context) !void {
        const boundary = c.state.next % c.options.checkpoint_units == 0 or c.state.next == c.directory.units.len;
        if (c.options.batch_directory_sync) {
            if (boundary) {
                try c.checkpoint();
                try c.reclaim();
            } else if (!c.output_names_pending) {
                // early reclaim only for durable names with replayable progress
                try c.reclaim();
            }
        } else {
            try c.reclaim();
            if (boundary) try c.checkpoint();
        }
    }
    fn readsRange(c: *const Context, unit_index: usize, start: u64, end: u64) bool {
        const reads = c.recipes[unit_index].reads;
        const first = std.sort.partitionPoint(plan_mod.Range, reads, start, struct {
            fn before(at: u64, range: plan_mod.Range) bool {
                return range.end() <= at;
            }
        }.before);
        return first < reads.len and reads[first].offset < end;
    }
    fn blocked(c: *const Context, index: usize) bool {
        if (c.blocked_units[index]) return true;
        const unit = c.directory.units[index];
        var start: u64 = 0;
        for (c.directory.sources[unit.source_first..][0..unit.source_count]) |ref| {
            const end = start + ref.length;
            if (c.unavailable_files[ref.file] and c.readsRange(index, start, end)) return true;
            start = end;
        }
        return false;
    }
    fn retainFailedDependencies(c: *Context, index: usize) void {
        const unit = c.directory.units[index];
        var start: u64 = 0;
        for (c.directory.sources[unit.source_first..][0..unit.source_count]) |ref| {
            const end = start + ref.length;
            if (c.plan.files[ref.file].writer) |writer| {
                if (writer > index and c.readsRange(index, start, end)) c.blocked_units[writer] = true;
            }
            start = end;
        }
    }
    fn removeSource(c: *Context, index: usize) !void {
        c.cache.invalidate(c.io, index);
        if (c.plan.files[index].displaced) {
            var buffer: [64]u8 = undefined;
            const name = try sourceName(&buffer, index, false);
            const stat = c.work.statFile(c.io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => return,
                else => return err,
            };
            if (stat.kind != .file or stat.nlink != 1) return error.UnsafeDisplacedSource;
            try c.work.deleteFile(c.io, name);
            c.stats.old_files_removed += 1;
            try c.event("displaced-source-removed");
            return;
        }
        const path = c.directory.files[index].path;
        fs.deleteFileBeneath(c.io, c.root, path) catch |err| switch (err) {
            error.FileNotFound => {
                // resumed deletion may still need its parent synced
                if (c.options.batch_directory_sync and c.stats.resumed) try c.markAncestors(path);
                return;
            },
            else => return err,
        };
        c.stats.old_files_removed += 1;
        try c.event("old-file-removed");
        // durable removals before completed receipt
        if (c.options.batch_directory_sync) try c.markAncestors(path) else try c.syncAncestors(path);
    }
    fn verify(c: *Context) !void {
        if (c.options.progress) |progress| progress.phase("Checking files", 0, c.directory.ops.len);
        var span = profile.begin(c.io, "inplace: final verification");
        defer span.end(c.io);
        var held: ?fs.BeneathParent = null;
        var listing: ?std.Io.Dir = null;
        var held_parent: []const u8 = &.{};
        var have_held = false;
        var hash_groups: std.ArrayList(VerifyGroup) = .empty;
        defer hash_groups.deinit(c.a);
        var hash_targets: std.ArrayList(u32) = .empty;
        defer hash_targets.deinit(c.a);
        var active_hash_group: ?usize = null;
        defer if (held) |*parent| parent.close(c.io);
        defer if (listing) |*dir| dir.close(c.io);
        for (c.directory.ops) |op| {
            defer if (c.options.progress) |progress| progress.advanceWork(0, 1);
            const expected = c.directory.files[op.target];
            const parent_path = parentPath(expected.path);
            if (!have_held or !std.mem.eql(u8, held_parent, parent_path)) {
                if (listing) |*dir| dir.close(c.io);
                listing = null;
                if (held) |*parent| parent.close(c.io);
                held = null;
                have_held = false;
                held = fs.openParentBeneath(c.io, c.root, expected.path) catch |err| {
                    try c.issue(op.target, "Verifying", err);
                    continue;
                };
                // mutation handles lack list access
                listing = held.?.dir.openDir(c.io, ".", .{
                    .iterate = true,
                    .access_sub_paths = true,
                    .follow_symlinks = false,
                }) catch |err| {
                    try c.issue(op.target, "Verifying", err);
                    continue;
                };
                held_parent = parent_path;
                have_held = true;
                active_hash_group = null;
            }
            const entry = fs.queryEntryBeneath(c.io, listing.?, baseName(expected.path)) catch |err| {
                try c.issue(op.target, "Verifying", err);
                continue;
            };
            c.stats.size_checks += 1;
            if (entry.kind != .file or entry.size != expected.size) {
                try c.issue(op.target, "Verifying", error.FinishedSizeMismatch);
                continue;
            }
            if (c.options.verify_finished and !c.verified_targets[op.target] and
                (expected.verification.isPresent() or !expected.digest.eql(.zero)))
            {
                if (active_hash_group) |index| {
                    const group = hash_groups.items[index];
                    const combined = std.math.add(u64, group.planned_bytes, expected.size) catch std.math.maxInt(u64);
                    if (group.count != 0 and combined > verify_group_bytes) active_hash_group = null;
                }
                const group_index = active_hash_group orelse group: {
                    try hash_groups.append(c.a, .{
                        .first = hash_targets.items.len,
                        .count = 0,
                        .representative_path = expected.path,
                        .planned_bytes = 0,
                    });
                    const index = hash_groups.items.len - 1;
                    active_hash_group = index;
                    break :group index;
                };
                try hash_targets.append(c.a, op.target);
                hash_groups.items[group_index].count += 1;
                hash_groups.items[group_index].planned_bytes = std.math.add(
                    u64,
                    hash_groups.items[group_index].planned_bytes,
                    expected.size,
                ) catch return error.IntegerOverflow;
            }
        }
        try runFinalHashes(c, hash_groups.items, hash_targets.items);
    }
};
fn parentPath(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return &.{};
    return path[0..slash];
}

const VerifyGroup = struct {
    first: usize,
    count: usize,
    representative_path: []const u8,
    planned_bytes: u64,
};

const VerifyResult = struct {
    err: ?anyerror = null,
    bytes: u64 = 0,
};

const VerifyShared = struct {
    context: *const Context,
    groups: []const VerifyGroup,
    targets: []const u32,
    results: []VerifyResult,
    next: std.atomic.Value(usize) = .init(0),
};

fn verifyGroup(shared: *const VerifyShared, group: VerifyGroup, buffer: []u8) void {
    const c = shared.context;
    var parent = fs.openParentBeneath(c.io, c.root, group.representative_path) catch |err| {
        for (shared.results[group.first..][0..group.count]) |*result| result.err = err;
        return;
    };
    defer parent.close(c.io);
    for (shared.targets[group.first..][0..group.count], shared.results[group.first..][0..group.count]) |target_index, *result| {
        defer if (c.options.progress) |progress| progress.advanceWork(0, 1);
        result.bytes = verifyTarget(c, parent.dir, c.directory.files[target_index], buffer) catch |err| {
            result.err = err;
            continue;
        };
    }
}
fn verifyTarget(c: *const Context, parent: std.Io.Dir, expected: ziff.FileEntry, buffer: []u8) !u64 {
    const hashed = hash: {
        var file = fs.openExisting(c.io, parent, baseName(expected.path), .read_only) catch |err| switch (err) {
            error.FileNotFound, error.IsDir, error.NotDir => return error.FinishedHashMismatch,
            else => return err,
        };
        defer file.close(c.io);
        const stat = try file.stat(c.io);
        if (stat.kind != .file or stat.size != expected.size) return error.FinishedSizeMismatch;
        break :hash try hashOpenExpected(c.io, file, expected, buffer, c.options.progress);
    };
    if (!hashed.matches) return error.FinishedHashMismatch;
    return hashed.bytes;
}

fn verifyWorker(shared: *VerifyShared, buffer: []u8) void {
    while (true) {
        const index = shared.next.fetchAdd(1, .monotonic);
        if (index >= shared.groups.len) return;
        verifyGroup(shared, shared.groups[index], buffer);
    }
}

fn runFinalHashes(c: *Context, groups: []const VerifyGroup, targets: []const u32) !void {
    if (groups.len == 0) return;
    if (c.options.progress) |progress| {
        var bytes: u64 = 0;
        for (groups) |group| bytes +|= group.planned_bytes;
        progress.phase("Verifying", bytes, targets.len);
    }
    const automatic = @max(1, @min(@as(usize, 16), Thread.getCpuCount() catch 1));
    const requested = if (c.options.verify_workers == 0) automatic else c.options.verify_workers;
    const worker_count = @min(requested, groups.len);
    const storage_len = std.math.mul(usize, worker_count, c.options.buffer_bytes) catch return error.OutOfMemory;
    const storage = try c.a.alloc(u8, storage_len);
    defer c.a.free(storage);
    const threads = try c.a.alloc(Thread, worker_count);
    defer c.a.free(threads);
    const results = try c.a.alloc(VerifyResult, targets.len);
    defer c.a.free(results);
    for (results) |*result| result.* = .{};
    var shared: VerifyShared = .{
        .context = c,
        .groups = groups,
        .targets = targets,
        .results = results,
    };
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |thread| thread.join();
    while (spawned < worker_count) : (spawned += 1) {
        const begin = spawned * c.options.buffer_bytes;
        threads[spawned] = try Thread.spawn(.{}, verifyWorker, .{
            &shared,
            storage[begin .. begin + c.options.buffer_bytes],
        });
    }
    for (threads) |thread| thread.join();
    spawned = 0;

    for (results, targets) |result, target| {
        if (result.err) |err| try c.issue(target, "Verifying", err);
        c.stats.final_hash_bytes = std.math.add(u64, c.stats.final_hash_bytes, result.bytes) catch return error.IntegerOverflow;
        c.stats.final_hash_read_bytes = std.math.add(u64, c.stats.final_hash_read_bytes, result.bytes) catch return error.IntegerOverflow;
    }
}

const HashResult = struct { matches: bool, bytes: u64 };

fn hashOpenExpected(
    io: std.Io,
    file: std.Io.File,
    expected: ziff.FileEntry,
    buffer: []u8,
    progress: ?*ui_mod.Operation,
) !HashResult {
    if (buffer.len == 0) return error.InvalidInplaceOptions;
    switch (expected.verification.algorithm) {
        .md5 => {
            var hasher = std.crypto.hash.Md5.init(.{});
            var offset: u64 = 0;
            while (offset < expected.size) {
                const n: usize = @intCast(@min(@as(u64, buffer.len), expected.size - offset));
                try exact(io, file, buffer[0..n], offset);
                hasher.update(buffer[0..n]);
                offset += n;
                if (progress) |operation| operation.advanceWork(n, 0);
            }
            var hash: [16]u8 = undefined;
            hasher.final(&hash);
            return .{
                .matches = std.mem.eql(u8, &hash, &expected.verification.bytes),
                .bytes = expected.size,
            };
        },
        .xxh64 => {
            var hasher = std.hash.XxHash64.init(0);
            var offset: u64 = 0;
            while (offset < expected.size) {
                const n: usize = @intCast(@min(@as(u64, buffer.len), expected.size - offset));
                try exact(io, file, buffer[0..n], offset);
                hasher.update(buffer[0..n]);
                offset += n;
                if (progress) |operation| operation.advanceWork(n, 0);
            }
            var hash: [8]u8 = undefined;
            std.mem.writeInt(u64, &hash, hasher.final(), .big);
            return .{
                .matches = std.mem.eql(u8, &hash, expected.verification.bytes[0..8]),
                .bytes = expected.size,
            };
        },
        .none => {
            if (expected.digest.eql(.zero)) return .{ .matches = false, .bytes = 0 };
            var hasher = std.crypto.hash.Blake3.init(.{});
            var offset: u64 = 0;
            while (offset < expected.size) {
                const n: usize = @intCast(@min(@as(u64, buffer.len), expected.size - offset));
                try exact(io, file, buffer[0..n], offset);
                hasher.update(buffer[0..n]);
                offset += n;
                if (progress) |operation| operation.advanceWork(n, 0);
            }
            var hash: ids.Digest = undefined;
            hasher.final(&hash.bytes);
            return .{ .matches = hash.eql(expected.digest), .bytes = expected.size };
        },
    }
}

fn baseName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

test "recovery and final verification use the sole authoritative MD5 identity" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = "manifest-backed contents";
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = bytes });
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &md5, .{});
    const expected: ziff.FileEntry = .{
        .path = "file.bin",
        .size = bytes.len,
        .digest = .zero,
        .verification = .md5(md5),
    };
    var buffer: [64]u8 = undefined;
    var file = try tmp.dir.openFile(io, "file.bin", .{});
    const good = try hashOpenExpected(io, file, expected, &buffer, null);
    file.close(io);
    try std.testing.expect(good.matches);
    try std.testing.expectEqual(@as(u64, bytes.len), good.bytes);

    const wrong = "manifest-backed contentX";
    try std.testing.expectEqual(bytes.len, wrong.len);
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = wrong });
    file = try tmp.dir.openFile(io, "file.bin", .{});
    defer file.close(io);
    try std.testing.expect(!(try hashOpenExpected(io, file, expected, &buffer, null)).matches);
}

test "authoritative XXH64 identity verifies directly" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = "xxhash-backed contents";
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = bytes });
    var hasher = std.hash.XxHash64.init(0);
    hasher.update(bytes);
    var hash: [8]u8 = undefined;
    std.mem.writeInt(u64, &hash, hasher.final(), .big);
    const expected: ziff.FileEntry = .{
        .path = "file.bin",
        .size = bytes.len,
        .digest = .zero,
        .verification = .xxh64(hash),
    };
    var buffer: [64]u8 = undefined;
    var file = try tmp.dir.openFile(io, "file.bin", .{});
    defer file.close(io);
    try std.testing.expect((try hashOpenExpected(io, file, expected, &buffer, null)).matches);
}

test "final verification hashes independent directories with bounded workers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "a", .default_dir);
    try tmp.dir.createDir(io, "b", .default_dir);
    const a_bytes = "parallel verification alpha" ** 32;
    const b_bytes = "parallel verification beta" ** 32;
    try tmp.dir.writeFile(io, .{ .sub_path = "a/file.bin", .data = a_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "b/file.bin", .data = b_bytes });
    var files = [_]ziff.FileEntry{
        .{ .path = "a/file.bin", .size = a_bytes.len, .digest = ids.Digest.of(a_bytes) },
        .{ .path = "b/file.bin", .size = b_bytes.len, .digest = ids.Digest.of(b_bytes) },
    };
    var verified = [_]bool{ false, false };
    var context: Context = .{
        .a = allocator,
        .io = io,
        .root = tmp.dir,
        .work = undefined,
        .package = undefined,
        .directory = .{ .files = &files, .ops = &.{}, .units = &.{}, .sources = &.{}, .removed = &.{} },
        .recipes = &.{},
        .plan = undefined,
        .state = .{ .package = .zero, .units = 0, .files = files.len },
        .options = .{ .verify_finished = true, .verify_workers = 8, .buffer_bytes = 64 },
        .cache = undefined,
        .buffer = &.{},
        .write_buffer = &.{},
        .patch_buffer = &.{},
        .verification_buffer = &.{},
        .verified_targets = &verified,
        .unavailable_files = &.{},
        .blocked_units = &.{},
    };
    const groups = [_]VerifyGroup{
        .{ .first = 0, .count = 1, .representative_path = files[0].path, .planned_bytes = a_bytes.len },
        .{ .first = 1, .count = 1, .representative_path = files[1].path, .planned_bytes = b_bytes.len },
    };
    const targets = [_]u32{ 0, 1 };
    try runFinalHashes(&context, &groups, &targets);
    try std.testing.expectEqual(@as(u64, a_bytes.len + b_bytes.len), context.stats.final_hash_bytes);
    try std.testing.expectEqual(context.stats.final_hash_bytes, context.stats.final_hash_read_bytes);
    try tmp.dir.writeFile(io, .{ .sub_path = "a/file.bin", .data = "x" ** a_bytes.len });
    try tmp.dir.writeFile(io, .{ .sub_path = "b/file.bin", .data = "x" ** b_bytes.len });
    try runFinalHashes(&context, &groups, &targets);
    try std.testing.expectEqual(@as(u64, 2), context.stats.errors);
}

test "failed in-place unit retains later source writers while independent units finish and retry" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    const old_a = "old alpha data!" ** 1024;
    const old_b = "original beta!" ** 1024;
    const new_a = old_b ++ "new tail";
    const new_b = "completely different beta content" ** 512;
    const new_c = "independent full output";
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a", .data = old_a });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/b", .data = old_b });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a", .data = new_a });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/b", .data = new_b });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/c", .data = new_c });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/d", .data = old_b });
    const root_path = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source_path = try std.fs.path.join(a, &.{ root_path, "source" });
    const target_path = try std.fs.path.join(a, &.{ root_path, "target" });
    var old = try tree.inventory(a, io, source_path, null, null);
    var new = try tree.inventory(a, io, target_path, null, null);
    var changes = [_]@import("../plan.zig").Change{ .{ .source = 0, .target = 0 }, .{ .source = 1, .target = 1 } };
    var added = [_]u32{ 2, 3 };
    var groups = [_]@import("../plan.zig").Group{.{ .source = &.{ 0, 1 }, .target = &.{ 0, 1, 3 } }};
    var prepared = try ziff_plan.build(a, io, &old, &new, .{ .changed = &changes, .added = &added, .removed = &.{}, .groups = &groups }, null, "old", "new");
    defer prepared.deinit();
    const package_path = try std.fs.path.join(a, &.{ root_path, "delta.ziff" });
    _ = try ziff_create.create(a, io, &prepared.header, &prepared.directory, .{ .source_root = source_path, .target_root = target_path, .source_manifest = prepared.source_manifest, .container_path = package_path }, .{ .target_observations = &new });
    var package = try fs.openRead(io, tmp.dir, "delta.ziff");
    defer package.close(io);
    var opened = try ziff_file.openFile(a, io, package);
    defer opened.deinit();
    try std.testing.expect(opened.directory.replays[0].reads.len != 0);
    var root = try tmp.dir.openDir(io, "source", .{ .iterate = true, .access_sub_paths = true });
    defer root.close(io);
    const Fault = struct {
        fired: bool = false,
        fn event(raw: ?*anyopaque, name: []const u8, _: u64) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            if (!self.fired and std.mem.eql(u8, name, "output-decoded")) {
                self.fired = true;
                return error.AccessDenied;
            }
        }
    };
    var fault: Fault = .{};
    const partial = try run(a, io, package, &opened, root, .{ .event = Fault.event, .event_context = &fault });
    try std.testing.expect(partial.errors != 0);
    try std.testing.expectEqual(@as(u64, 2), partial.units_decoded);
    try std.testing.expectEqualStrings(old_b, try root.readFileAlloc(io, "b", a, .unlimited));
    try std.testing.expectEqualStrings(new_c, try root.readFileAlloc(io, "c", a, .unlimited));
    try std.testing.expectEqualStrings(old_b, try root.readFileAlloc(io, "d", a, .unlimited));
    const incomplete = try root.readFileAlloc(io, ".zift-work/state", a, .unlimited);
    try std.testing.expect(!(try decodeState(incomplete)).complete);
    const retry = try run(a, io, package, &opened, root, .{ .verify_finished = true });
    try std.testing.expectEqual(@as(u64, 0), retry.errors);
    try std.testing.expectEqualStrings(new_a, try root.readFileAlloc(io, "a", a, .unlimited));
    try std.testing.expectEqualStrings(new_b, try root.readFileAlloc(io, "b", a, .unlimited));
    try std.testing.expect((try decodeState(try root.readFileAlloc(io, ".zift-work/state", a, .unlimited))).complete);
}

test "deferred full units finalize their identities and apply in place" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    const fixtures = [_]struct { path: []const u8, bytes: []const u8, kind: ziff.UnitKind }{
        .{ .path = "raw.bin", .bytes = "raw added bytes", .kind = .raw },
        .{ .path = "zstd.bin", .bytes = "compressed added bytes", .kind = .zstd },
        .{ .path = "empty.bin", .bytes = "", .kind = .zstd },
    };
    var expected: [fixtures.len]ziff.FileEntry = undefined;
    for (fixtures, &expected) |fixture, *entry| {
        try tmp.dir.writeFile(io, .{
            .sub_path = try std.fmt.allocPrint(allocator, "target/{s}", .{fixture.path}),
            .data = fixture.bytes,
        });
        entry.* = .{ .path = fixture.path, .size = fixture.bytes.len, .digest = ids.Digest.of(fixture.bytes) };
    }
    std.mem.sortUnstable(ziff.FileEntry, &expected, {}, struct {
        fn less(_: void, a: ziff.FileEntry, b: ziff.FileEntry) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.less);
    const fixture_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source_root = try std.fs.path.join(allocator, &.{ fixture_root, "source" });
    const target_root = try std.fs.path.join(allocator, &.{ fixture_root, "target" });
    const package_path = try std.fs.path.join(allocator, &.{ fixture_root, "full.ziff" });
    var source = try tree.inventory(allocator, io, source_root, null, null);
    var target = try tree.inventory(allocator, io, target_root, null, null);
    const comparison = try generic.build(allocator, io, &source, &target, null, .{});
    var prepared = try ziff_plan.build(allocator, io, &source, &target, comparison, null, "old", "new");
    try std.testing.expectEqual(fixtures.len, prepared.directory.units.len);
    for (prepared.directory.units) |*unit| {
        const entry = prepared.directory.files[unit.target];
        try std.testing.expect(entry.digest.eql(content.pending_digest));
        for (fixtures) |fixture| if (std.mem.eql(u8, entry.path, fixture.path)) {
            unit.kind = fixture.kind;
            break;
        };
    }
    const created = try ziff_create.create(
        allocator,
        io,
        &prepared.header,
        &prepared.directory,
        .{
            .source_root = source_root,
            .target_root = target_root,
            .container_path = package_path,
            .source_manifest = prepared.source_manifest,
        },
        .{ .target_observations = &target, .buffer_bytes = 7 },
    );
    try std.testing.expectEqual(@as(u64, 0), created.identity_completion_bytes);
    var package = try fs.openReadContentAuthority(io, std.Io.Dir.cwd(), package_path);
    defer package.close(io);
    var opened = try ziff_file.openFile(allocator, io, package);
    defer opened.deinit();
    try std.testing.expect(opened.header.target_fingerprint.eql(ziff.logicalFingerprint(&expected)));
    for (opened.directory.files, &expected) |actual, entry| {
        try std.testing.expectEqualStrings(entry.path, actual.path);
        try std.testing.expect(actual.digest.eql(entry.digest));
    }
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_root, .{ .iterate = true, .access_sub_paths = true });
    defer source_dir.close(io);
    _ = try run(allocator, io, package, &opened, source_dir, .{ .verify_finished = true });
    for (fixtures) |fixture| {
        const actual = try source_dir.readFileAlloc(io, fixture.path, allocator, .limited(fixture.bytes.len + 1));
        try std.testing.expectEqualSlices(u8, fixture.bytes, actual);
    }
}

test "created ZAR26 package derives anchors and applies in place" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);

    const byte_count = 128 * 1024;
    const old_bytes = try allocator.alloc(u8, byte_count);
    for (old_bytes, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% index / 97);
    const new_bytes = try allocator.dupe(u8, old_bytes);
    var offset: usize = 512;
    while (offset < new_bytes.len) : (offset += 4096) {
        for (new_bytes[offset..@min(offset + 73, new_bytes.len)]) |*byte| byte.* +%= 41;
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "source/game.bin", .data = old_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/game.bin", .data = new_bytes });

    const fixture_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source_root = try std.fs.path.join(allocator, &.{ fixture_root, "source" });
    const target_root = try std.fs.path.join(allocator, &.{ fixture_root, "target" });
    const package_path = try std.fs.path.join(allocator, &.{ fixture_root, "update.ziff" });
    var source = try tree.inventory(allocator, io, source_root, null, null);
    var target = try tree.inventory(allocator, io, target_root, null, null);
    const comparison = try generic.build(allocator, io, &source, &target, null, .{});
    var prepared = try ziff_plan.build(allocator, io, &source, &target, comparison, null, "old", "new");
    try std.testing.expectEqual(@as(usize, 1), prepared.directory.units.len);
    try std.testing.expectEqual(ziff.UnitKind.patch_zar26, prepared.directory.units[0].kind);
    try std.testing.expectEqual(prepared.directory.ops[0].target, prepared.directory.units[0].target);

    _ = try ziff_create.create(
        allocator,
        io,
        &prepared.header,
        &prepared.directory,
        .{
            .source_root = source_root,
            .target_root = target_root,
            .container_path = package_path,
            .source_manifest = prepared.source_manifest,
        },
        .{ .target_observations = &target, .slice_budget = byte_count / 2 },
    );

    var package = try fs.openReadContentAuthority(io, std.Io.Dir.cwd(), package_path);
    defer package.close(io);
    var opened = try ziff_file.openFile(allocator, io, package);
    defer opened.deinit();
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_root, .{ .iterate = true, .access_sub_paths = true });
    defer source_dir.close(io);
    const stats = try run(allocator, io, package, &opened, source_dir, .{ .verify_finished = true });
    try std.testing.expectEqual(@as(u64, 1), stats.units_decoded);
    try std.testing.expectEqual(@as(u64, byte_count), stats.final_hash_bytes);
    try std.testing.expectEqual(stats.skipped_bytes, stats.final_hash_read_bytes);
    try std.testing.expect(stats.final_hash_read_bytes < stats.final_hash_bytes);
    const actual = try tmp.dir.readFileAlloc(io, "source/game.bin", allocator, .limited(new_bytes.len + 1));
    try std.testing.expectEqualSlices(u8, new_bytes, actual);
}

test "in-place recovery retains packed source spans for later units without verification" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    var root = try tmp.dir.openDir(io, "source", .{ .iterate = true });
    defer root.close(io);
    const old = "1111xxxx2222yyyy";
    const next = "NNNNNNNNNNNNNNNN";
    const copied = "11112222";
    try root.writeFile(io, .{ .sub_path = "a", .data = old });

    var files = [_]ziff.FileEntry{
        .{ .path = "a", .size = next.len, .digest = ids.Digest.of(next) },
        .{ .path = "b", .size = copied.len, .digest = ids.Digest.of(copied) },
    };
    const header: ziff.Header = .{
        .required_features = ziff.Feature.inplace_recipe | ziff.Feature.zar26_codec,
        .source_fingerprint = ziff.logicalFingerprint(&.{.{ .path = "a", .size = old.len, .digest = ids.Digest.of(old) }}),
        .target_fingerprint = ziff.logicalFingerprint(&files),
        .target_bytes = next.len + copied.len,
        .source_bytes = old.len,
        .unit_count = 2,
    };
    var package = try fs.createGuardedOutput(io, tmp.dir, "packed.ziff");
    defer package.close(io);
    const payload_start = try ziff_file.beginFile(allocator, io, package, header);
    try package.writePositionalAll(io, next, payload_start);
    const Memory = struct {
        bytes: []const u8,
        fn read(raw: ?*anyopaque, offset: u64, bytes: []u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            @memcpy(bytes, self.bytes[@intCast(offset)..][0..bytes.len]);
        }
        fn input(self: *@This()) zar26.Input {
            return .{ .context = self, .size = self.bytes.len, .read_at = read };
        }
    };
    const Sink = struct {
        io: std.Io,
        file: std.Io.File,
        base: u64,
        fn write(raw: ?*anyopaque, offset: u64, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            try self.file.writePositionalAll(self.io, bytes, self.base + offset);
        }
    };
    var source_memory: Memory = .{ .bytes = old };
    var target_memory: Memory = .{ .bytes = copied };
    var sink: Sink = .{ .io = io, .file = package, .base = payload_start + next.len };
    var encoded = try zar26.encode(
        allocator,
        source_memory.input(),
        target_memory.input(),
        &.{
            .{ .source_offset = 0, .target_offset = 0, .length = 4 },
            .{ .source_offset = 8, .target_offset = 4, .length = 4 },
        },
        .{ .context = &sink, .write_at = Sink.write },
    );
    defer encoded.deinit();
    var ops = [_]ziff.Op{
        .{ .kind = .full, .target = 0, .arg = 0 },
        .{ .kind = .patch, .target = 1, .arg = 1 },
    };
    var units = [_]ziff.Unit{
        .{ .kind = .raw, .payload_offset = payload_start, .payload_len = next.len, .target = 0, .source_first = 0, .source_count = 0 },
        .{ .kind = .patch_zar26, .payload_offset = sink.base, .payload_len = encoded.payload_length, .target = 1, .source_first = 0, .source_count = 1 },
    };
    var sources = [_]ziff.SourceRef{.{ .file = 0, .offset = 0, .length = old.len }};
    var reads = [_]plan_mod.Range{ .{ .offset = 0, .length = 4 }, .{ .offset = 8, .length = 4 } };
    var recipes = [_]ziff.Replay{ .{}, .{ .reads = &reads } };
    try ziff_file.finishFile(allocator, io, package, .{
        .files = &files,
        .ops = &ops,
        .units = &units,
        .sources = &sources,
        .removed = &.{},
        .replays = &recipes,
    });
    var opened = try ziff_file.openFile(allocator, io, package);
    defer opened.deinit();
    const Interrupt = struct {
        fn event(_: ?*anyopaque, name: []const u8, _: u64) !void {
            if (std.mem.eql(u8, name, "after-output-write")) return error.Injected;
        }
    };
    try std.testing.expectError(error.Injected, run(allocator, io, package, &opened, root, .{
        .buffer_bytes = 32,
        .write_buffer_bytes = 0,
        .event = Interrupt.event,
    }));
    const preserved = try root.readFileAlloc(io, ".zift-work/b0", allocator, .limited(copied.len + 1));
    defer allocator.free(preserved);
    try std.testing.expectEqualStrings(copied, preserved);
    const stats = try run(allocator, io, package, &opened, root, .{
        .buffer_bytes = 5,
        .write_buffer_bytes = 3,
        .patch_buffer_bytes = 7,
        .source_handle_capacity = 1,
    });
    try std.testing.expect(stats.resumed);
    try std.testing.expectEqual(@as(u64, 1), stats.units_recovered);
    try std.testing.expectEqual(@as(u64, 1), stats.units_decoded);
    try std.testing.expectEqual(@as(u64, copied.len), stats.preserved_read_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.source_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.final_hash_bytes);
    const actual_a = try root.readFileAlloc(io, "a", allocator, .limited(next.len + 1));
    defer allocator.free(actual_a);
    const actual_b = try root.readFileAlloc(io, "b", allocator, .limited(copied.len + 1));
    defer allocator.free(actual_b);
    try std.testing.expectEqualStrings(next, actual_a);
    try std.testing.expectEqualStrings(copied, actual_b);
    try std.testing.expectError(error.FileNotFound, root.statFile(io, ".zift-work/b0", .{}));
    const verified = try run(allocator, io, package, &opened, root, .{ .verify_finished = true });
    try std.testing.expect(verified.already_completed);
    try std.testing.expectEqual(@as(u64, next.len + copied.len), verified.final_hash_bytes);
}

const Decoder = struct {
    context: *Context,
    unit: ziff.Unit,
    unit_index: usize,
    output: std.Io.File,
    refs: []const ziff.SourceRef,
    starts: []u64,
    recipe: plan_mod.Recipe,
    pending: buffers.WriteBuffer,
    patch_window: buffers.ReadWindow,
    verification: ?content.State,
    written: u64 = 0,
    fn zarSourceRead(raw: ?*anyopaque, offset: u64, data: []u8) !void {
        const d: *Decoder = @ptrCast(@alignCast(raw.?));
        try d.readSource(offset, data);
    }
    fn zarPatchRead(raw: ?*anyopaque, offset: u64, data: []u8) !void {
        const d: *Decoder = @ptrCast(@alignCast(raw.?));
        if (offset > d.unit.payload_len or data.len > d.unit.payload_len - offset)
            return error.ContainerRangeOutOfBounds;
        d.context.stats.decoder_patch_calls += 1;
        var reader: PatchReader = .{ .d = d };
        try d.patch_window.read(&reader, data, offset, d.unit.payload_len);
    }
    fn zarOutputWrite(raw: ?*anyopaque, offset: u64, data: []const u8) !void {
        const d: *Decoder = @ptrCast(@alignCast(raw.?));
        try d.write(offset, data);
    }
    fn zarSourceInput(d: *Decoder) zar26.Input {
        return .{ .context = d, .size = d.starts[d.refs.len], .read_at = zarSourceRead };
    }
    fn zarPatchInput(d: *Decoder) zar26.Input {
        return .{ .context = d, .size = d.unit.payload_len, .read_at = zarPatchRead };
    }
    fn zarOutput(d: *Decoder) zar26.Output {
        return .{ .context = d, .write_at = zarOutputWrite };
    }
    const PatchReader = struct {
        d: *Decoder,
        pub fn readExact(self: *@This(), out: []u8, offset: u64) !void {
            const c = self.d.context;
            var span = profile.begin(c.io, "inplace: package reads");
            defer span.end(c.io);
            try exact(c.io, c.package, out, self.d.unit.payload_offset + offset);
            c.stats.package_bytes += out.len;
            c.stats.package_read_calls += 1;
        }
    };
    fn readSource(d: *Decoder, offset: u64, bytes: []u8) !void {
        d.context.stats.decoder_source_calls += 1;
        const size = d.starts[d.refs.len];
        if (offset > size or bytes.len > size - offset) return error.SourceRangeOverflow;
        @memset(bytes, 0);
        const end = offset + bytes.len;
        // read-ahead holes excluded from authorized source I/O
        var lo: usize = 0;
        var hi = d.recipe.reads.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (d.recipe.reads[mid].end() <= offset) lo = mid + 1 else hi = mid;
        }
        var range_index = lo;
        while (range_index < d.recipe.reads.len and d.recipe.reads[range_index].offset < end) : (range_index += 1) {
            const r = d.recipe.reads[range_index];
            var cursor = @max(offset, r.offset);
            const stop = @min(end, r.end());
            var low: usize = 0;
            var high = d.refs.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (d.starts[mid + 1] <= cursor) low = mid + 1 else high = mid;
            }
            var ref_index = low;
            while (cursor < stop) {
                if (ref_index >= d.refs.len) return error.SourceRangeOverflow;
                const ref = d.refs[ref_index];
                const piece_end = @min(stop, d.starts[ref_index + 1]);
                const view = bytes[@intCast(cursor - offset)..@intCast(piece_end - offset)];
                try d.context.readOld(ref.file, d.unit_index, ref.offset + cursor - d.starts[ref_index], view);
                cursor = piece_end;
                ref_index += 1;
            }
        }
    }
    fn write(d: *Decoder, offset: u64, bytes: []const u8) !void {
        const c = d.context;
        const target_size = c.directory.files[d.unit.target].size;
        if (offset != d.written or offset > target_size or bytes.len > target_size - offset) return error.NonsequentialOutput;
        c.stats.decoder_output_calls += 1;
        var cursor = offset;
        const end = offset + bytes.len;
        var lo: usize = 0;
        var hi = d.recipe.skips.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (d.recipe.skips[mid].end() <= cursor) lo = mid + 1 else hi = mid;
        }
        var index = lo;
        while (cursor < end) {
            if (index < d.recipe.skips.len and d.recipe.skips[index].offset <= cursor) {
                const stop = @min(end, d.recipe.skips[index].end());
                if (d.verification != null) try d.pending.flush(d);
                try d.observeExisting(cursor, stop);
                c.stats.skipped_bytes += stop - cursor;
                cursor = stop;
                index += 1;
                continue;
            }
            const stop = if (index < d.recipe.skips.len) @min(end, d.recipe.skips[index].offset) else end;
            const part = bytes[@intCast(cursor - offset)..@intCast(stop - offset)];
            try d.pending.write(d, part, cursor);
            cursor = stop;
        }
        d.written = end;
        if (c.options.progress) |progress| progress.advanceWork(bytes.len, 0);
    }
    fn observeExisting(d: *Decoder, start: u64, end: u64) !void {
        const state = if (d.verification) |*value| value else return;
        const c = d.context;
        var offset = start;
        while (offset < end) {
            const n: usize = @intCast(@min(@as(u64, c.verification_buffer.len), end - offset));
            try exact(c.io, d.output, c.verification_buffer[0..n], offset);
            try state.observe(offset, c.verification_buffer[0..n]);
            c.stats.final_hash_read_bytes += n;
            offset += n;
        }
    }
    fn finishVerification(d: *Decoder) !bool {
        const state = if (d.verification) |*value| value else return false;
        const expected = d.context.directory.files[d.unit.target];
        try state.observe(expected.size, &.{});
        if (expected.verification.isPresent()) {
            if (!state.verified) return error.TargetIdentityMismatch;
        } else if (state.digest == null or !state.digest.?.eql(expected.digest)) {
            return error.TargetIdentityMismatch;
        }
        return true;
    }
    pub fn writeExact(d: *Decoder, part: []const u8, cursor: u64) !void {
        const c = d.context;
        var span = profile.begin(c.io, "inplace: output writes");
        defer span.end(c.io);
        try c.event("before-output-write");
        if (c.options.split_writes and part.len > 1) {
            const half = part.len / 2;
            try d.output.writePositionalAll(c.io, part[0..half], cursor);
            if (d.verification) |*state| try state.observe(cursor, part[0..half]);
            c.stats.output_write_calls += 1;
            c.stats.output_bytes += half;
            try c.event("partial-output-write");
            try d.output.writePositionalAll(c.io, part[half..], cursor + half);
            if (d.verification) |*state| try state.observe(cursor + half, part[half..]);
            c.stats.output_write_calls += 1;
            c.stats.output_bytes += part.len - half;
        } else {
            try d.output.writePositionalAll(c.io, part, cursor);
            if (d.verification) |*state| try state.observe(cursor, part);
            c.stats.output_write_calls += 1;
            c.stats.output_bytes += part.len;
        }
        try c.event("after-output-write");
    }
    fn decodeZstd(d: *Decoder) !void {
        const c = d.context;
        const stream = zstd_c.ZSTD_createDStream() orelse return error.DecompressFailed;
        defer _ = zstd_c.ZSTD_freeDStream(stream);
        const target_size = c.directory.files[d.unit.target].size;
        try zstd_frame.initBoundedDStream(stream, target_size);
        const storage = try c.a.alloc(u8, 128 * 1024);
        defer c.a.free(storage);
        var input: zstd_c.ZstdInBuffer = .{ .src = c.buffer.ptr, .size = 0, .pos = 0 };
        var consumed: u64 = 0;
        var overflow: [1]u8 = undefined;
        while (true) {
            if (input.pos == input.size and consumed < d.unit.payload_len) {
                const n: usize = @intCast(@min(@as(u64, c.buffer.len), d.unit.payload_len - consumed));
                try exact(c.io, c.package, c.buffer[0..n], d.unit.payload_offset + consumed);
                consumed += n;
                c.stats.package_bytes += n;
                c.stats.package_read_calls += 1;
                input = .{ .src = c.buffer.ptr, .size = n, .pos = 0 };
            }
            const capacity: usize = @intCast(@min(@as(u64, storage.len), target_size - d.written));
            var decoded: zstd_c.ZstdOutBuffer = if (capacity == 0) .{ .dst = &overflow, .size = 1, .pos = 0 } else .{ .dst = storage.ptr, .size = capacity, .pos = 0 };
            const before = input.pos;
            const remaining = zstd_c.ZSTD_decompressStream(stream, &decoded, &input);
            if (zstd_c.ZSTD_isError(remaining) != 0) return error.DecompressFailed;
            if (decoded.pos > capacity) return error.OutputTooLarge;
            if (decoded.pos != 0) try d.write(d.written, storage[0..decoded.pos]);
            if (remaining == 0) {
                if (input.pos != input.size or consumed != d.unit.payload_len) return error.TrailingCompressedData;
                break;
            }
            if (input.pos == before and decoded.pos == 0) return error.TruncatedFrame;
        }
    }
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, package: std.Io.File, opened: *const ziff_file.Opened, root: std.Io.Dir, options: Options) !Stats {
    if (options.checkpoint_units == 0 or options.buffer_bytes == 0 or options.buffer_bytes > 64 * 1024 * 1024) return error.InvalidInplaceOptions;
    if (options.write_buffer_bytes > 4 * 1024 * 1024 or options.patch_buffer_bytes > 4 * 1024 * 1024)
        return error.InvalidInplaceOptions;
    if (options.source_handle_capacity == 0 or options.source_handle_capacity > 4096) return error.InvalidInplaceOptions;
    if (options.verify_workers > 64) return error.InvalidInplaceOptions;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var has_patch = false;
    for (opened.directory.units) |unit| has_patch = has_patch or unit.kind == .patch_zar26;
    if (has_patch and opened.directory.replays.len == 0) return error.MissingInplaceRecipes;
    const recipes: []const ziff.Replay = if (opened.directory.replays.len != 0)
        opened.directory.replays
    else recipes: {
        const empty = try a.alloc(ziff.Replay, opened.directory.units.len);
        @memset(empty, .{});
        break :recipes empty;
    };
    var plan_span = profile.begin(io, "inplace: dependency plan");
    defer plan_span.end(io);
    const plan = try plan_mod.build(a, opened.directory, recipes);
    plan_span.end(io);
    const header = try ziff.encodeHeader(a, opened.header);
    var footer: [64]u8 = undefined;
    try exact(io, package, &footer, opened.file_size - footer.len);
    var binding = std.crypto.hash.Blake3.init(.{});
    binding.update(header);
    binding.update(&footer);
    var package_id: ids.Digest = undefined;
    binding.final(&package_id.bytes);
    root.createDir(io, work_name, @enumFromInt(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    var work = try root.openDir(io, work_name, .{ .iterate = true, .access_sub_paths = true, .follow_symlinks = false });
    defer work.close(io);
    var lock = fs.openReadWrite(io, work, "lock") catch |err| switch (err) {
        error.FileNotFound => try fs.createGuardedOutput(io, work, "lock"),
        // windows: share denial before tryLock
        error.FileBusy => return error.AnotherApplyRunning,
        else => return err,
    };
    defer lock.close(io);
    _ = try fs.validateGuardedOutputAuthority(io, lock);
    if (!try lock.tryLock(io, .exclusive)) return error.AnotherApplyRunning;
    defer lock.unlock(io);
    const verified_targets: []bool = if (options.verify_finished) try a.alloc(bool, plan.files.len) else &.{};
    @memset(verified_targets, false);
    const unavailable_files = try a.alloc(bool, plan.files.len);
    @memset(unavailable_files, false);
    const blocked_units = try a.alloc(bool, opened.directory.units.len);
    @memset(blocked_units, false);
    var context: Context = .{ .a = a, .io = io, .root = root, .work = work, .package = package, .directory = opened.directory, .recipes = recipes, .plan = plan, .state = .{ .package = package_id, .units = opened.directory.units.len, .files = opened.directory.files.len }, .options = options, .cache = try Cache.init(a, plan.files.len, handleCapacity(options.source_handle_capacity)), .buffer = try a.alloc(u8, options.buffer_bytes), .write_buffer = try a.alloc(u8, options.write_buffer_bytes), .patch_buffer = try a.alloc(u8, options.patch_buffer_bytes), .verification_buffer = if (options.verify_finished) try a.alloc(u8, options.buffer_bytes) else &.{}, .verified_targets = verified_targets, .unavailable_files = unavailable_files, .blocked_units = blocked_units };
    defer context.cache.deinit(io);
    context.stats.source_handle_limit = context.cache.slots.len;
    const previous: ?State = blk: {
        var state_file = fs.openRead(io, work, "state") catch |err| switch (err) {
            error.FileNotFound => break :blk null,
            else => return err,
        };
        defer state_file.close(io);
        if (try state_file.length(io) != state_length) return error.InvalidInplaceJournal;
        var bytes: [state_length]u8 = undefined;
        try exact(io, state_file, &bytes, 0);
        break :blk try decodeState(&bytes);
    };
    var fresh_run = true;
    if (previous) |state| {
        try context.workspaceContents(state.files, false);
        if (!state.package.eql(package_id)) {
            if (!state.complete) return error.DifferentInterruptedPackage;
        } else {
            if (state.units != context.state.units or state.files != context.state.files) return error.InvalidInplaceJournal;
            context.state = state;
            context.stats.resumed = true;
            fresh_run = false;
        }
    } else {
        try context.workspaceContents(0, false);
    }
    if (fresh_run) try context.checkFresh();
    context.stats.estimated_extra_bytes = try context.estimateExtra();
    if (options.available_space) |available| {
        if (available < context.stats.estimated_extra_bytes) {
            if (!options.force_space) return error.InsufficientApplySpace;
            context.stats.estimated_space_forced = true;
        }
    }
    if (options.confirm) |confirm| {
        if (!try confirm(options.confirm_context, .{
            .estimated_extra_bytes = context.stats.estimated_extra_bytes,
            .available_bytes = options.available_space,
            .forced = context.stats.estimated_space_forced,
            .resuming = context.stats.resumed and !context.state.complete,
            .already_completed = context.state.complete,
        })) return error.ApplyNotConfirmed;
    }
    if (fresh_run) {
        if (previous) |state| try context.workspaceContents(state.files, true);
        try context.checkpoint();
    }
    if (options.progress) |progress| {
        var bytes: u64 = 0;
        for (opened.directory.units) |unit| bytes +|= opened.directory.files[unit.target].size;
        progress.totals(bytes, opened.directory.units.len);
        progress.phase("Preparing files", 0, 0);
    }
    try context.syncDir(root);
    try context.event("workspace-ready");
    if (context.state.complete) {
        context.stats.already_completed = true;
        if (options.progress) |progress| progress.totals(0, 0);
        try context.verify();
        if (context.stats.errors != 0) {
            context.state.complete = false;
            try context.checkpoint();
            return context.stats;
        }
        try context.workspaceContents(context.state.files, true);
        return context.stats;
    }
    if (context.stats.resumed) try context.recover();
    if (options.progress) |progress| {
        var bytes: u64 = 0;
        for (opened.directory.units[0..@intCast(context.state.next)]) |unit| bytes +|= opened.directory.files[unit.target].size;
        progress.complete(bytes, @intCast(context.state.next));
    }
    try context.displace();
    if (options.progress) |progress| progress.phase("Cleaning", 0, context.plan.remove_initial.len);
    for (context.plan.remove_initial) |index| {
        defer if (options.progress) |progress| progress.advanceWork(0, 1);
        if (context.unavailable_files[index]) continue;
        context.removeSource(index) catch |err| try context.issue(index, "Cleaning", err);
    }
    const first: usize = @intCast(context.state.next);
    for (first..opened.directory.units.len) |index| {
        const target_index = opened.directory.units[index].target;
        if (!context.unavailable_files[target_index]) context.prepare(target_index) catch |err| {
            try context.issue(target_index, "Preserving source", err);
            context.unavailable_files[target_index] = true;
            context.blocked_units[index] = true;
        };
        if (context.blocked(index)) {
            try context.issue(opened.directory.units[index].target, "Skipping dependent patch", error.SourceUnavailable);
            context.retainFailedDependencies(index);
            continue;
        }
        context.execute(index) catch |err| {
            try context.issue(opened.directory.units[index].target, "Applying", err);
            context.retainFailedDependencies(index);
            continue;
        };
        if (context.state.next == index + 1) try context.finishUnit();
    }
    try context.checkpoint();
    try context.syncDir(work);
    try context.verify();
    if (context.stats.errors != 0) return context.stats;
    context.state.complete = true;
    try context.checkpoint();
    try context.workspaceContents(context.state.files, true);
    try context.syncDir(work);
    return context.stats;
}

test "in-place progress records have bounded fields and checked complete state" {
    const good = encodeState(.{ .package = ids.Digest.of("p"), .units = 5, .files = 9, .next = 3 });
    const read = try decodeState(&good);
    try std.testing.expectEqual(@as(u64, 3), read.next);
    for (0..good.len) |i| {
        var bad = good;
        bad[i] ^= 1;
        try std.testing.expectError(error.InvalidInplaceJournal, decodeState(&bad));
    }
    const invalid = encodeState(.{ .package = ids.Digest.of("p"), .units = 5, .files = 9, .next = 3, .complete = true });
    try std.testing.expectError(error.InvalidInplaceJournal, decodeState(&invalid));
    try std.testing.expect(knownArtifact("b123.part", 124));
    try std.testing.expect(!knownArtifact("b123.part", 123));
    try std.testing.expect(!knownArtifact("b0123.part", 124));
    try std.testing.expect(!knownArtifact("m../x", 124));
}

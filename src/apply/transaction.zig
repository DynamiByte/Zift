const std = @import("std");
const builtin = @import("builtin");

const clean = @import("../clean.zig");
const fs = @import("../core/fs.zig");
const path_util = @import("../path.zig");

pub const default_work_root = ".zift-work";
const work_root_candidates = 1024;

const WorkspaceDirectoryIndex = std.StringHashMapUnmanaged(usize);

const OwnedWorkspaceDirectory = struct {
    path: []u8,
    handle: ?std.Io.Dir,
};

// directory ownership only; staging-file handles disposed first
// windows: exact nonrecursive cleanup; unknown entries preserved
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []u8 = &.{},
    root: ?std.Io.Dir = null,
    directories: std.ArrayList(OwnedWorkspaceDirectory) = .empty,
    directory_index: WorkspaceDirectoryIndex = .empty,
    backups_index: ?usize = null,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        semantic_paths: []const []const u8,
    ) !Workspace {
        var name_buf: [64]u8 = undefined;
        for (0..work_root_candidates) |index| {
            const candidate = if (index == 0)
                default_work_root
            else
                try std.fmt.bufPrint(&name_buf, ".zift-work-{d}", .{index});
            if (workRootConflicts(candidate, semantic_paths)) continue;

            const created_root = fs.createGuardedDirectory(io, dir, candidate) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => |other| return other,
            };
            var self: Workspace = .{
                .allocator = allocator,
                .io = io,
                .root = created_root,
            };
            errdefer self.deinit();
            self.name = try allocator.dupe(u8, candidate);
            try self.ensureDirectory("backups");
            self.backups_index = self.directory_index.get("backups") orelse
                return error.WorkspaceContaminated;
            return self;
        }
        return error.NoAvailableWorkRoot;
    }

    pub fn rootDir(self: *const Workspace) !std.Io.Dir {
        return self.root orelse error.WorkspaceClosed;
    }

    pub fn backupsDir(self: *const Workspace) !std.Io.Dir {
        const index = self.backups_index orelse return error.WorkspaceClosed;
        if (index >= self.directories.items.len) return error.WorkspaceClosed;
        return self.directories.items[index].handle orelse error.WorkspaceClosed;
    }

    pub fn validateAt(self: *const Workspace, install_dir: std.Io.Dir) !void {
        const root = try self.rootDir();
        var rebound_root = install_dir.openDir(self.io, self.name, .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch return error.WorkspaceBindingChanged;
        defer rebound_root.close(self.io);
        if (!(try fs.openDirIdentity(root)).eql(try fs.openDirIdentity(rebound_root)))
            return error.WorkspaceBindingChanged;

        const backups = try self.backupsDir();
        var rebound_backups = root.openDir(self.io, "backups", .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch return error.WorkspaceBindingChanged;
        defer rebound_backups.close(self.io);
        if (!(try fs.openDirIdentity(backups)).eql(try fs.openDirIdentity(rebound_backups)))
            return error.WorkspaceBindingChanged;
    }

    // existing untracked component = contamination, not cleanup ownership
    pub fn ensureDirectory(self: *Workspace, path: []const u8) !void {
        try path_util.validate(path);
        var parent = try self.rootDir();
        var start: usize = 0;
        while (start < path.len) {
            const end = std.mem.indexOfScalarPos(u8, path, start, '/') orelse path.len;
            const prefix = path[0..end];
            if (self.directory_index.get(prefix)) |owned_index| {
                if (owned_index >= self.directories.items.len) return error.WorkspaceClosed;
                parent = self.directories.items[owned_index].handle orelse
                    return error.WorkspaceClosed;
                start = end + 1;
                continue;
            }

            const owned_path = try self.allocator.dupe(u8, prefix);
            errdefer self.allocator.free(owned_path);
            try self.directories.ensureUnusedCapacity(self.allocator, 1);
            try self.directory_index.ensureUnusedCapacity(self.allocator, 1);

            var created: ?std.Io.Dir = fs.createGuardedDirectory(
                self.io,
                parent,
                path[start..end],
            ) catch |err| switch (err) {
                error.PathAlreadyExists => return error.WorkspaceContaminated,
                else => |other| return other,
            };
            errdefer if (created) |directory| {
                if (builtin.target.os.tag == .windows)
                    fs.deleteOpenDirectoryWindows(directory) catch {};
                directory.close(self.io);
            };

            const owned_index = self.directories.items.len;
            self.directories.appendAssumeCapacity(.{
                .path = owned_path,
                .handle = created.?,
            });
            self.directory_index.putAssumeCapacity(
                self.directories.items[owned_index].path,
                owned_index,
            );
            created = null;
            parent = self.directories.items[owned_index].handle.?;
            start = end + 1;
        }
    }

    pub fn ensureParent(self: *Workspace, file_path: []const u8) !void {
        try path_util.validate(file_path);
        const slash = std.mem.lastIndexOfScalar(u8, file_path, '/') orelse return;
        if (slash != 0) try self.ensureDirectory(file_path[0..slash]);
    }

    pub fn cleanup(self: *Workspace) void {
        var index = self.directories.items.len;
        while (index != 0) {
            index -= 1;
            const owned = &self.directories.items[index];
            const directory = owned.handle orelse continue;
            if (builtin.target.os.tag == .windows)
                fs.deleteOpenDirectoryWindows(directory) catch {};
            directory.close(self.io);
            owned.handle = null;
        }
        if (self.root) |root| {
            if (builtin.target.os.tag == .windows)
                fs.deleteOpenDirectoryWindows(root) catch {};
            root.close(self.io);
            self.root = null;
        }
    }

    pub fn deinit(self: *Workspace) void {
        self.cleanup();
        self.directory_index.deinit(self.allocator);
        self.directory_index = .{};
        for (self.directories.items) |owned| self.allocator.free(owned.path);
        self.directories.deinit(self.allocator);
        self.directories = .empty;
        if (self.name.len != 0) self.allocator.free(self.name);
        self.name = &.{};
        self.backups_index = null;
    }
};

fn workRootConflicts(candidate: []const u8, paths: []const []const u8) bool {
    for (paths) |path| {
        if (pathHasRoot(path, candidate, builtin.target.os.tag == .windows)) return true;
    }
    return false;
}

pub fn pathHasRoot(path: []const u8, root: []const u8, windows_semantics: bool) bool {
    const end = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    const component = path[0..end];
    return if (windows_semantics)
        path_util.WindowsCaseContext.eql(.{}, root, component)
    else
        std.mem.eql(u8, root, component);
}

pub fn pathIsAncestor(ancestor: []const u8, descendant: []const u8, windows_semantics: bool) bool {
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, descendant, start, '/')) |slash| {
        const prefix = descendant[0..slash];
        if (if (windows_semantics)
            path_util.WindowsCaseContext.eql(.{}, ancestor, prefix)
        else
            std.mem.eql(u8, ancestor, prefix)) return true;
        start = slash + 1;
    }
    return false;
}

pub const Backup = struct {
    original: []u8,
    path: []u8,
    guard: ?std.Io.File = null,
};

const MutationIndex = std.HashMapUnmanaged(
    []const u8,
    usize,
    path_util.WindowsCaseContext,
    std.hash_map.default_max_load_percentage,
);

const MutationCandidate = struct {
    logical_path: []u8,
    restore_path: ?[]u8 = null,
    guard: ?std.Io.File = null,
    kind: ?std.Io.File.Kind = null,
    size: u64 = 0,
    present: bool = false,
    backed: bool = false,
    strict_backup_authority: bool = false,
    backup_descendant_of: ?usize = null,
    captures_descendants: bool = false,
};

const MutationCaptureRole = enum { prefix, backup, removal, backup_descendant };

pub const MutationSet = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    items: std.ArrayList(MutationCandidate) = .empty,
    index: MutationIndex = .empty,
    targets: [][]u8 = &.{},
    removals: [][]u8 = &.{},

    pub fn capture(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        targets: []const []const u8,
        removals: []const []const u8,
    ) !MutationSet {
        var self: MutationSet = .{ .allocator = allocator, .io = io };
        errdefer self.deinit();
        self.targets = try dupeOwnedPaths(allocator, targets);
        self.removals = try dupeOwnedPaths(allocator, removals);
        if (builtin.target.os.tag != .windows) return self;

        for (targets) |target| {
            const target_index = try self.captureRoute(dir, target, .backup);
            const target_item = self.items.items[target_index];
            if (target_item.present and target_item.kind == .directory) {
                self.items.items[target_index].captures_descendants = true;
                try self.captureDirectoryDescendants(dir, target_index);
            }
        }
        for (removals) |removal| {
            if (self.coveredByCapturedTargetDirectory(removal)) continue;
            _ = try self.captureRoute(dir, removal, .removal);
        }
        try self.validateBindings(dir);
        return self;
    }

    pub fn deinit(self: *MutationSet) void {
        for (self.items.items) |*item| {
            if (item.guard) |guard| guard.close(self.io);
            self.allocator.free(item.logical_path);
            if (item.restore_path) |path| self.allocator.free(path);
        }
        self.items.deinit(self.allocator);
        self.index.deinit(self.allocator);
        freeOwnedPaths(self.allocator, self.targets);
        freeOwnedPaths(self.allocator, self.removals);
        self.targets = &.{};
        self.removals = &.{};
    }

    pub fn validateBindings(self: *const MutationSet, dir: std.Io.Dir) !void {
        if (builtin.target.os.tag != .windows) return;
        for (self.items.items) |item| {
            if (item.present) {
                const guard = item.guard orelse return error.MutationBindingChanged;
                if (!guardedObjectPathIdentityMatches(self.io, dir, item.logical_path, guard))
                    return error.MutationBindingChanged;
                continue;
            }
            var raced = fs.openMetadataBeneathWindows(self.io, dir, item.logical_path) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => |other| return other,
            };
            raced.close(self.io);
            return error.MutationBindingChanged;
        }
        for (self.items.items, 0..) |item, index| {
            if (item.captures_descendants)
                try self.validateCapturedDirectoryTree(dir, index);
        }
    }

    pub fn listedRemovalEntries(
        self: *const MutationSet,
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
    ) ![]clean.Extra {
        if (builtin.target.os.tag != .windows)
            return listedRemovals(allocator, io, dir, self.removalSlices());
        var extras: std.ArrayList(clean.Extra) = .empty;
        for (self.removals) |removal| {
            var size: u64 = 0;
            if (self.index.get(removal)) |index| {
                const item = self.items.items[index];
                if (item.present and (item.kind == .file or item.kind == .sym_link))
                    size = item.size;
            }
            // absent removal still enforced against later arrivals
            try extras.append(allocator, .{ .path = removal, .size = size });
        }
        return extras.toOwnedSlice(allocator);
    }

    fn removalSlices(self: *const MutationSet) []const []const u8 {
        return @ptrCast(self.removals);
    }

    fn take(self: *MutationSet) MutationSet {
        const owned = self.*;
        self.* = .{ .allocator = owned.allocator, .io = owned.io };
        return owned;
    }

    fn matchesPlan(
        self: *const MutationSet,
        outputs: []const Output,
        removals: []const []const u8,
    ) bool {
        if (outputs.len != self.targets.len or removals.len != self.removals.len) return false;
        for (outputs, self.targets) |actual, captured|
            if (!std.mem.eql(u8, actual.path, captured)) return false;
        for (removals, self.removals) |actual, captured|
            if (!std.mem.eql(u8, actual, captured)) return false;
        return true;
    }

    fn captureRoute(
        self: *MutationSet,
        dir: std.Io.Dir,
        path: []const u8,
        final_role: MutationCaptureRole,
    ) !usize {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            const index = try self.captureCandidate(dir, path[0..slash], .prefix, null);
            const item = self.items.items[index];
            if (!item.present or item.kind != .directory) return index;
            start = slash + 1;
        }
        return self.captureCandidate(dir, path, final_role, null);
    }

    fn captureCandidate(
        self: *MutationSet,
        dir: std.Io.Dir,
        path: []const u8,
        role: MutationCaptureRole,
        backup_descendant_of: ?usize,
    ) !usize {
        if (self.index.get(path)) |existing| {
            if (role == .backup_descendant) {
                if (self.items.items[existing].backup_descendant_of == backup_descendant_of)
                    return existing;
                return error.MutationPlanMismatch;
            }
            const item = self.items.items[existing];
            if (role == .backup and item.present and !item.strict_backup_authority)
                return error.MutationPlanMismatch;
            return existing;
        }
        try self.index.ensureUnusedCapacity(self.allocator, 1);
        const logical = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(logical);

        var candidate: MutationCandidate = .{
            .logical_path = logical,
            .backup_descendant_of = backup_descendant_of,
        };
        var strict = role == .backup;
        var guard = self.openCandidateAuthority(dir, path, role, &strict) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                try self.items.append(self.allocator, candidate);
                const index = self.items.items.len - 1;
                self.index.putAssumeCapacity(self.items.items[index].logical_path, index);
                return index;
            },
            else => |other| return other,
        };
        errdefer guard.close(self.io);
        const stat = try guard.stat(self.io);
        if (role != .backup and role != .backup_descendant and !strict and stat.kind != .directory)
            return error.UnsafePathAncestor;
        candidate.restore_path = try openedRestorePathAlloc(self.allocator, path, guard);
        errdefer self.allocator.free(candidate.restore_path.?);
        candidate.guard = guard;
        candidate.kind = stat.kind;
        candidate.size = stat.size;
        candidate.present = true;
        candidate.strict_backup_authority = strict;
        try self.items.append(self.allocator, candidate);
        const index = self.items.items.len - 1;
        self.index.putAssumeCapacity(self.items.items[index].logical_path, index);
        return index;
    }

    fn captureDirectoryDescendants(
        self: *MutationSet,
        dir: std.Io.Dir,
        root_index: usize,
    ) !void {
        if (root_index >= self.items.items.len) return error.MutationPlanMismatch;
        const root_path = self.items.items[root_index].logical_path;
        var sub = try dir.openDir(self.io, root_path, .{
            .iterate = true,
            .access_sub_paths = true,
            .follow_symlinks = false,
        });
        defer sub.close(self.io);
        const root_guard = self.items.items[root_index].guard orelse
            return error.MutationBindingChanged;
        if (!(try fs.openDirIdentity(sub)).eql(try fs.openFileIdentity(root_guard)))
            return error.MutationBindingChanged;

        var walker = try sub.walk(self.allocator);
        defer walker.deinit();
        while (try walker.next(self.io)) |entry| {
            const full = try self.allocator.print(
                "{s}/{s}",
                .{ root_path, entry.path },
            );
            defer self.allocator.free(full);
            normalizeWalkedLogicalPath(full);
            const index = try self.captureCandidate(
                dir,
                full,
                .backup_descendant,
                root_index,
            );
            if (self.items.items[index].kind != entry.kind)
                return error.MutationBindingChanged;
        }
    }

    // re-enumeration for arrivals outside the captured set
    fn validateCapturedDirectoryTree(
        self: *const MutationSet,
        dir: std.Io.Dir,
        root_index: usize,
    ) !void {
        if (root_index >= self.items.items.len) return error.MutationPlanMismatch;
        const root = self.items.items[root_index];
        const root_guard = root.guard orelse return error.MutationBindingChanged;
        var sub = dir.openDir(self.io, root.logical_path, .{
            .iterate = true,
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch return error.MutationBindingChanged;
        defer sub.close(self.io);
        if (!(try fs.openDirIdentity(sub)).eql(try fs.openFileIdentity(root_guard)))
            return error.MutationBindingChanged;

        var seen: usize = 0;
        var walker = try sub.walk(self.allocator);
        defer walker.deinit();
        while (try walker.next(self.io)) |entry| {
            const full = try self.allocator.print(
                "{s}/{s}",
                .{ root.logical_path, entry.path },
            );
            defer self.allocator.free(full);
            normalizeWalkedLogicalPath(full);
            const index = self.index.get(full) orelse return error.MutationBindingChanged;
            const candidate = self.items.items[index];
            if (candidate.backup_descendant_of != root_index or
                candidate.kind != entry.kind)
                return error.MutationBindingChanged;
            const guard = candidate.guard orelse return error.MutationBindingChanged;
            if (!guardedObjectPathIdentityMatches(self.io, dir, full, guard))
                return error.MutationBindingChanged;
            seen += 1;
        }
        var expected: usize = 0;
        for (self.items.items) |candidate| {
            if (candidate.backup_descendant_of == root_index) expected += 1;
        }
        if (seen != expected) return error.MutationBindingChanged;
    }

    fn openCandidateAuthority(
        self: *MutationSet,
        dir: std.Io.Dir,
        path: []const u8,
        role: MutationCaptureRole,
        strict: *bool,
    ) !std.Io.File {
        if (role == .backup_descendant)
            return fs.openMetadataBeneathWindows(self.io, dir, path);
        if (role == .backup)
            return fs.openBackupAuthorityBeneathWindows(self.io, dir, path);
        return fs.openMutationDirectoryAuthorityBeneathWindows(self.io, dir, path) catch |err| switch (err) {
            error.NotDir => {
                strict.* = true;
                return fs.openBackupAuthorityBeneathWindows(self.io, dir, path);
            },
            else => |other| return other,
        };
    }

    fn coveredByCapturedTargetDirectory(self: *const MutationSet, path: []const u8) bool {
        for (self.targets) |target| {
            if (!pathIsAncestor(target, path, true)) continue;
            const index = self.index.get(target) orelse continue;
            const item = self.items.items[index];
            if (item.present and item.kind == .directory) return true;
        }
        return false;
    }
};

fn dupeOwnedPaths(allocator: std.mem.Allocator, paths: []const []const u8) ![][]u8 {
    if (paths.len == 0) return &.{};
    const owned = try allocator.alloc([]u8, paths.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |path| allocator.free(path);
        allocator.free(owned);
    }
    for (paths, owned) |path, *slot| {
        slot.* = try allocator.dupe(u8, path);
        initialized += 1;
    }
    return owned;
}

fn freeOwnedPaths(allocator: std.mem.Allocator, paths: [][]u8) void {
    for (paths) |path| allocator.free(path);
    if (paths.len != 0) allocator.free(paths);
}

fn openedRestorePathAlloc(
    allocator: std.mem.Allocator,
    logical_path: []const u8,
    guard: std.Io.File,
) ![]u8 {
    const actual_basename = try fs.windowsOpenedBasenameAlloc(allocator, guard);
    defer allocator.free(actual_basename);
    return if (std.mem.lastIndexOfScalar(u8, logical_path, '/')) |slash|
        allocator.print("{s}/{s}", .{ logical_path[0..slash], actual_basename })
    else
        allocator.dupe(u8, actual_basename);
}

const PublishedState = enum {
    active,
    quarantined,
};

const PublishedGuard = struct {
    file: std.Io.File,
    state: PublishedState,
};

pub const Output = struct {
    path: []const u8,
    work_rel: []const u8,
    size: u64,
    md5: [16]u8 = @splat(0),
    state: union(enum) {
        staged: std.Io.File,
        published: PublishedGuard,
        consumed,
    },

    pub fn stagedFile(self: Output) !std.Io.File {
        return switch (self.state) {
            .staged => |file| file,
            else => error.GuardAlreadyConsumed,
        };
    }

    pub fn discard(self: *Output, io: std.Io) !void {
        const state = self.state;
        self.state = .consumed;
        switch (state) {
            .staged => |file| {
                if (builtin.target.os.tag == .windows) return fs.discardOpenObjectWindows(io, file);
                file.close(io);
            },
            .published => |publication| publication.file.close(io),
            .consumed => {},
        }
    }
};

const CreatedDirectory = struct {
    path: []const u8,
    identity: fs.ObjectIdentity,
    handle: ?std.Io.Dir,
};

const RetainedDirectory = struct {
    path: []const u8,
    identity: fs.ObjectIdentity,
    // namespace pin, not transaction ownership
    handle: ?std.Io.File,
};

pub const Commit = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    outputs: []Output,
    created_directories: std.ArrayList(CreatedDirectory) = .empty,
    retained_directories: std.ArrayList(RetainedDirectory) = .empty,
    backups: std.ArrayList(Backup) = .empty,
    mutations: MutationSet,
    // caller-owned
    workspace: *Workspace,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        workspace: *Workspace,
        outputs: []Output,
        removals: []const []const u8,
        mutations: *MutationSet,
    ) !Commit {
        var owned_mutations = mutations.take();
        errdefer owned_mutations.deinit();
        errdefer discardOutputs(io, outputs) catch {};
        if (outputs.len != owned_mutations.targets.len) return error.GuardCountMismatch;
        for (outputs) |output| if (output.state != .staged) return error.GuardSlotMissing;
        if (!owned_mutations.matchesPlan(outputs, removals)) return error.MutationPlanMismatch;
        var self: Commit = .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .outputs = outputs,
            .mutations = owned_mutations,
            .workspace = workspace,
        };
        owned_mutations = .{ .allocator = allocator, .io = io };
        errdefer self.deinit();
        try workspace.validateAt(dir);
        const prepare_result = if (builtin.target.os.tag == .windows)
            self.prepareCaptured(removals)
        else
            self.prepare(removals);
        prepare_result catch |err| {
            self.closeStagedGuards();
            self.restoreBackups() catch {
                self.preserveRecovery() catch {};
                return error.RollbackConflict;
            };
            return err;
        };
        return self;
    }

    pub fn deinit(self: *Commit) void {
        self.closeStagedGuards();
        self.closePublishedGuards();
        self.closeCreatedDirectories();
        self.created_directories.deinit(self.allocator);
        self.closeRetainedDirectories();
        self.retained_directories.deinit(self.allocator);
        self.closeBackupGuards();
        for (self.backups.items) |item| {
            self.allocator.free(item.original);
            self.allocator.free(item.path);
        }
        self.backups.deinit(self.allocator);
        self.mutations.deinit();
    }

    // posix: no rename-by-fd; pinned parents and name rebinding
    pub fn publish(self: *Commit, index: usize) !void {
        if (index >= self.outputs.len) return error.InvalidGuardIndex;
        const output = self.outputs[index];
        const guarded = try output.stagedFile();
        if (!std.mem.eql(u8, output.path, self.mutations.targets[index])) return error.GuardedTargetMismatch;
        const source = output.work_rel;
        const target = output.path;
        const expected_size = output.size;

        try fs.validateGuardedOutput(self.io, guarded, expected_size);
        var source_parent = fs.openParentBeneath(self.io, self.dir, source) catch |err| switch (err) {
            error.FileNotFound, error.PathAncestorNotDirectory, error.UnsafePathAncestor => return error.StagingBindingChanged,
            else => |other| return other,
        };
        defer source_parent.close(self.io);
        var rebound_source = fs.openRead(self.io, source_parent.dir, source_parent.basename) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir, error.SymLinkLoop => return error.StagingBindingChanged,
            else => |other| return other,
        };
        defer rebound_source.close(self.io);
        if (!try fs.sameOpenFile(self.io, guarded, rebound_source)) {
            return error.StagingBindingChanged;
        }
        try fs.validateGuardedOutput(self.io, guarded, expected_size);

        try self.ensureParentTracked(target);
        if (builtin.target.os.tag == .windows) {
            fs.renameGuardedOutputBeneath(
                self.io,
                self.dir,
                target,
                guarded,
                expected_size,
            ) catch |rename_err| {
                if (rename_err == error.PublishedBindingChanged) {
                    self.transferPublished(index);
                    return rename_err;
                }
                if (guardedPathMatches(self.io, self.dir, target, guarded, expected_size)) {
                    self.transferPublished(index);
                    return;
                }
                if (guardedPathIdentityMatches(self.io, self.dir, source, guarded)) {
                    return rename_err;
                }
                if (guardedPathIdentityMatches(self.io, self.dir, target, guarded)) {
                    self.transferPublished(index);
                    return rename_err;
                }
                // redirector failure after rename: exact handle retained for rollback
                self.transferPublished(index);
                return error.PublicationOutcomeUnknown;
            };
            self.transferPublished(index);
            return;
        }

        var target_parent = try fs.openParentBeneath(self.io, self.dir, target);
        defer target_parent.close(self.io);
        try fs.validateGuardedOutput(self.io, guarded, expected_size);

        source_parent.dir.renamePreserve(
            source_parent.basename,
            target_parent.dir,
            target_parent.basename,
            self.io,
        ) catch |rename_err| {
            // NFS: possible post-rename failure; full-root identity rebind for success
            if (guardedTargetMatches(
                self.io,
                self.dir,
                target_parent.dir,
                target_parent.basename,
                target,
                guarded,
                expected_size,
            )) {
                self.transferPublished(index);
                return;
            }
            if (guardedPathIdentityMatches(self.io, self.dir, source, guarded)) {
                return rename_err;
            }
            if (guardedPathIdentityMatches(self.io, self.dir, target, guarded)) {
                self.transferPublished(index);
                return rename_err;
            }
            self.transferPublished(index);
            return error.PublicationOutcomeUnknown;
        };

        self.transferPublished(index);
        if (!guardedTargetMatches(
            self.io,
            self.dir,
            target_parent.dir,
            target_parent.basename,
            target,
            guarded,
            expected_size,
        )) return error.PublishedBindingChanged;
    }

    pub fn remove(self: *Commit, path: []const u8) !void {
        if (builtin.target.os.tag == .windows) {
            for (self.mutations.removals) |removal| {
                if (!path_util.WindowsCaseContext.eql(.{}, removal, path)) continue;
                if (try self.removalCoveredByPublishedTargets(path)) return;
                var raced = fs.openMetadataBeneathWindows(self.io, self.dir, path) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => return,
                    else => |other| return other,
                };
                raced.close(self.io);
                return error.MutationBindingChanged;
            }
            return error.MutationPlanMismatch;
        }
        const stat = self.dir.statFile(self.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => |e| return e,
        };
        switch (stat.kind) {
            .file, .sym_link => try self.backup(path),
            .directory => {},
            else => return error.SourcePathConflict,
        }
    }

    fn removalCoveredByPublishedTargets(self: *Commit, removal: []const u8) !bool {
        var covered = false;
        for (self.outputs) |output| {
            if (!pathIsAncestor(removal, output.path, true) and
                !pathIsAncestor(output.path, removal, true)) continue;
            covered = true;
            const publication = switch (output.state) {
                .published => |value| value,
                else => return error.MutationBindingChanged,
            };
            if (!guardedPathMatches(self.io, self.dir, output.path, publication.file, output.size))
                return error.MutationBindingChanged;
        }
        return covered;
    }

    pub fn rollback(self: *Commit) !void {
        if (builtin.target.os.tag == .windows) return self.rollbackGuardedInWorkspace();
        self.closeStagedGuards();
        self.quarantineGuardedPublications() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.removeCreatedDirectories() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.closePublishedGuards();
        self.restoreBackups() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
    }

    fn rollbackGuardedInWorkspace(self: *Commit) !void {
        self.discardStagedGuards() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.quarantineGuardedPublications() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.removeCreatedDirectories() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        // quarantined outputs retained until all originals restored
        self.restoreBackups() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.discardQuarantinedPublicationsWindows() catch {
            self.preserveRecovery() catch {};
            return error.RollbackConflict;
        };
        self.closePublishedGuards();
    }

    pub fn rollbackOr(self: *Commit, original_error: anyerror) anyerror {
        self.rollback() catch |err| return err;
        return original_error;
    }

    pub fn finish(self: *Commit) !void {
        for (self.outputs) |output| {
            const publication = switch (output.state) {
                .published => |value| value,
                else => return error.MutationBindingChanged,
            };
            if (!guardedPathMatches(
                self.io,
                self.dir,
                output.path,
                publication.file,
                output.size,
            )) return error.MutationBindingChanged;
        }
        if (builtin.target.os.tag == .windows) {
            for (self.mutations.removals) |removal| {
                if (try self.removalCoveredByPublishedTargets(removal)) continue;
                var raced = fs.openMetadataBeneathWindows(self.io, self.dir, removal) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => continue,
                    else => |other| return other,
                };
                raced.close(self.io);
                return error.MutationBindingChanged;
            }
        }
        self.releaseBackups();
    }

    fn releaseBackups(self: *Commit) void {
        self.closeStagedGuards();
        // final names pinned through backup disposal
        defer self.closePublishedGuards();
        defer self.closeCreatedDirectories();
        defer self.closeRetainedDirectories();
        if (builtin.target.os.tag == .windows) {
            // workspace-owned backups directory; Commit owns contents only
            self.discardExactBackupObjectsWindows();
            self.closeBackupGuards();
            return;
        }

        self.closeBackupGuards();
        const backups_root = self.allocator.print("{s}/backups", .{self.workspace.name}) catch return;
        defer self.allocator.free(backups_root);
        self.dir.deleteTree(self.io, backups_root) catch return;
        fs.createDirPathBeneath(self.io, self.dir, backups_root) catch return;
    }

    fn discardExactBackupObjectsWindows(self: *Commit) void {
        for (self.backups.items) |*item| {
            const guard = item.guard orelse continue;
            fs.deleteOpenObjectWindows(guard) catch continue;
            guard.close(self.io);
            item.guard = null;
        }
    }

    fn restoreBackups(self: *Commit) !void {
        var first_error: ?anyerror = null;
        // failed ancestor restore blocks descendant restoration
        var blocked_ancestors: std.ArrayList([]const u8) = .empty;
        defer blocked_ancestors.deinit(self.allocator);
        var i = self.backups.items.len;
        while (i != 0) {
            i -= 1;
            const item = self.backups.items[i];
            if (builtin.target.os.tag == .windows) {
                if (item.guard) |guard| {
                    var blocked = false;
                    for (blocked_ancestors.items) |ancestor| {
                        if (path_util.WindowsCaseContext.eql(.{}, ancestor, item.original) or
                            pathIsAncestor(ancestor, item.original, true))
                        {
                            blocked = true;
                            break;
                        }
                    }
                    if (blocked) continue;
                    ensureParent(self.io, self.dir, item.original) catch
                        return error.RollbackConflict;
                    fs.renameOpenObjectBeneathWindows(
                        self.io,
                        self.dir,
                        item.original,
                        guard,
                    ) catch {
                        // possibly detached parent: full-root rebind before restoration
                        if (guardedObjectPathIdentityAndBasenameMatches(
                            self.allocator,
                            self.io,
                            self.dir,
                            item.original,
                            guard,
                        )) continue;
                        try blocked_ancestors.append(self.allocator, item.original);
                        if (first_error == null) first_error = error.RollbackConflict;
                    };
                    continue;
                }
            }

            ensureParent(self.io, self.dir, item.original) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            const result = self.dir.renamePreserve(item.path, self.dir, item.original, self.io);
            result catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        if (first_error) |err| return err;
    }

    fn quarantineGuardedPublications(self: *Commit) !void {
        var first_error: ?anyerror = null;
        var index = self.outputs.len;
        while (index != 0) {
            index -= 1;
            const publication = switch (self.outputs[index].state) {
                .published => |value| value,
                else => continue,
            };
            self.quarantineGuardedPublication(index, publication) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            self.outputs[index].state.published.state = .quarantined;
        }
        if (first_error) |err| return err;
    }

    fn quarantineGuardedPublication(
        self: *Commit,
        index: usize,
        publication: PublishedGuard,
    ) !void {
        const quarantine_path = try self.allocator.print(
            "{s}/rollback-{d}",
            .{ self.workspace.name, index },
        );
        defer self.allocator.free(quarantine_path);

        if (builtin.target.os.tag == .windows) {
            const target = self.outputs[index].path;
            var quarantine_name_buf: [64]u8 = undefined;
            const quarantine_root = try self.workspace.rootDir();
            const quarantine_relative = try std.fmt.bufPrint(&quarantine_name_buf, "rollback-{d}", .{index});
            fs.renameOpenFileBeneathWindows(
                self.io,
                quarantine_root,
                quarantine_relative,
                publication.file,
            ) catch |err| {
                // PublishedBindingChanged: completed rename, old target name check required
                const target_matches = guardedPathIdentityMatches(
                    self.io,
                    self.dir,
                    target,
                    publication.file,
                );
                const quarantine_matches = guardedPathIdentityMatches(
                    self.io,
                    quarantine_root,
                    quarantine_relative,
                    publication.file,
                );
                if (!target_matches and
                    (quarantine_matches or err == error.PublishedBindingChanged)) return;
                return error.RollbackConflict;
            };
            if (guardedPathIdentityMatches(self.io, self.dir, target, publication.file))
                return error.RollbackConflict;
            return;
        }

        const target = self.outputs[index].path;
        if (!guardedPathMatches(
            self.io,
            self.dir,
            target,
            publication.file,
            self.outputs[index].size,
        )) return error.RollbackConflict;

        var target_parent = fs.openParentBeneath(self.io, self.dir, target) catch
            return error.RollbackConflict;
        defer target_parent.close(self.io);
        var quarantine_parent = fs.openParentBeneath(self.io, self.dir, quarantine_path) catch
            return error.RollbackConflict;
        defer quarantine_parent.close(self.io);
        target_parent.dir.renamePreserve(
            target_parent.basename,
            quarantine_parent.dir,
            quarantine_parent.basename,
            self.io,
        ) catch {
            if (guardedPathMatches(
                self.io,
                self.dir,
                quarantine_path,
                publication.file,
                self.outputs[index].size,
            )) return;
            return error.RollbackConflict;
        };
        if (!guardedPathMatches(
            self.io,
            self.dir,
            quarantine_path,
            publication.file,
            self.outputs[index].size,
        )) return error.RollbackConflict;
    }

    fn discardQuarantinedPublicationsWindows(self: *Commit) !void {
        var first_error: ?anyerror = null;
        for (self.outputs) |*output| {
            const publication = switch (output.state) {
                .published => |value| value,
                else => continue,
            };
            if (publication.state != .quarantined) {
                if (first_error == null) first_error = error.RollbackConflict;
                continue;
            }
            output.state = .consumed;
            fs.discardOpenObjectWindows(self.io, publication.file) catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        if (first_error) |err| return err;
    }

    fn preserveRecovery(self: *Commit) !void {
        const backups_root = try self.workspace.backupsDir();
        const marker = "RECOVERY_REQUIRED";
        var file = fs.createFileBeneath(self.io, backups_root, marker, .{
            .exclusive = true,
            .truncate = false,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => return,
            else => |other| return other,
        };
        defer file.close(self.io);
        try file.writePositionalAll(
            self.io,
            "Zift preserved this transaction after a rollback conflict.\n",
            0,
        );
        try file.sync(self.io);
    }

    fn ensureParentTracked(self: *Commit, path: []const u8) !void {
        try path_util.validate(path);
        const parent_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return;
        if (parent_end == 0) return;
        const parent_path = path[0..parent_end];

        var current = self.dir;
        var current_owned = false;
        defer if (current_owned) current.close(self.io);

        var start: usize = 0;
        while (start < parent_path.len) {
            const end = std.mem.indexOfScalarPos(u8, parent_path, start, '/') orelse parent_path.len;
            const component = parent_path[start..end];
            const prefix = parent_path[0..end];
            try self.created_directories.ensureUnusedCapacity(self.allocator, 1);

            var created = true;
            const next = fs.createGuardedDirectory(self.io, current, component) catch |err| switch (err) {
                error.PathAlreadyExists => existing: {
                    created = false;
                    var new_authority: ?std.Io.File = null;
                    errdefer if (new_authority) |authority| authority.close(self.io);
                    var expected_identity: ?fs.ObjectIdentity = null;
                    if (builtin.target.os.tag == .windows) {
                        expected_identity = self.retainedDirectoryIdentity(prefix) orelse
                            try self.capturedDirectoryIdentity(prefix);
                        if (expected_identity == null) {
                            try self.retained_directories.ensureUnusedCapacity(self.allocator, 1);
                            const authority = fs.openMutationDirectoryAuthorityBeneathWindows(
                                self.io,
                                self.dir,
                                prefix,
                            ) catch |open_err| switch (open_err) {
                                error.NotDir => return error.PathAncestorNotDirectory,
                                else => |other| return other,
                            };
                            new_authority = authority;
                            const authority_stat = try authority.stat(self.io);
                            if (authority_stat.kind != .directory) return error.UnsafePathAncestor;
                            expected_identity = try fs.openFileIdentity(authority);
                        }
                    }

                    var opened = current.openDir(self.io, component, .{
                        .access_sub_paths = true,
                        .follow_symlinks = false,
                    }) catch |open_err| switch (open_err) {
                        error.NotDir => return error.PathAncestorNotDirectory,
                        error.SymLinkLoop => return error.UnsafePathAncestor,
                        else => |other| return other,
                    };
                    errdefer opened.close(self.io);
                    const component_stat = try opened.stat(self.io);
                    if (component_stat.kind != .directory) return error.UnsafePathAncestor;
                    const opened_identity = try fs.openDirIdentity(opened);
                    if (expected_identity) |expected| {
                        if (!expected.eql(opened_identity)) return error.MutationBindingChanged;
                    }
                    if (new_authority) |authority| {
                        self.retained_directories.appendAssumeCapacity(.{
                            .path = prefix,
                            .identity = opened_identity,
                            .handle = authority,
                        });
                        new_authority = null;
                    }
                    break :existing opened;
                },
                else => |other| return other,
            };
            errdefer next.close(self.io);
            const stat = try next.stat(self.io);
            if (stat.kind != .directory) return error.UnsafePathAncestor;

            if (created) {
                self.created_directories.appendAssumeCapacity(.{
                    .path = prefix,
                    .identity = try fs.openDirIdentity(next),
                    .handle = if (builtin.target.os.tag == .windows) next else null,
                });
            }
            if (current_owned) current.close(self.io);
            current = next;
            current_owned = !created or builtin.target.os.tag != .windows;
            start = end + 1;
        }
    }

    fn retainedDirectoryIdentity(self: *const Commit, path: []const u8) ?fs.ObjectIdentity {
        for (self.retained_directories.items) |retained| {
            if (!path_util.WindowsCaseContext.eql(.{}, retained.path, path)) continue;
            if (retained.handle == null) return null;
            return retained.identity;
        }
        return null;
    }

    fn capturedDirectoryIdentity(self: *const Commit, path: []const u8) !?fs.ObjectIdentity {
        const mutations = &self.mutations;
        const candidate_index = mutations.index.get(path) orelse return null;
        const candidate = mutations.items.items[candidate_index];
        if (!candidate.present or candidate.backed or candidate.kind != .directory) return null;
        const guard = candidate.guard orelse return error.MutationBindingChanged;
        return try fs.openFileIdentity(guard);
    }

    fn removeCreatedDirectories(self: *Commit) !void {
        var first_error: ?anyerror = null;
        var index = self.created_directories.items.len;
        while (index != 0) {
            index -= 1;
            self.removeCreatedDirectory(&self.created_directories.items[index]) catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        if (first_error) |err| return err;
    }

    fn removeCreatedDirectory(self: *Commit, created: *CreatedDirectory) !void {
        if (created.handle) |directory| {
            fs.deleteOpenDirectoryWindows(directory) catch return error.RollbackConflict;
            directory.close(self.io);
            created.handle = null;
            return;
        }

        var parent = fs.openParentBeneath(self.io, self.dir, created.path) catch |err| switch (err) {
            error.FileNotFound, error.PathAncestorNotDirectory => return,
            else => return error.RollbackConflict,
        };
        defer parent.close(self.io);
        var current = parent.dir.openDir(self.io, parent.basename, .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return error.RollbackConflict,
        };
        const actual_identity = fs.openDirIdentity(current) catch {
            current.close(self.io);
            return error.RollbackConflict;
        };
        if (!created.identity.eql(actual_identity)) {
            current.close(self.io);
            return error.RollbackConflict;
        }
        current.close(self.io);
        parent.dir.deleteDir(self.io, parent.basename) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return error.RollbackConflict,
        };
    }

    fn prepareCaptured(self: *Commit, removals: []const []const u8) !void {
        const mutations = &self.mutations;
        try mutations.validateBindings(self.dir);

        const scratch = std.heap.smp_allocator;
        var removal_set: std.StringHashMapUnmanaged(void) = .empty;
        defer removal_set.deinit(scratch);
        try removal_set.ensureTotalCapacity(scratch, @intCast(removals.len));
        for (removals) |removal| removal_set.putAssumeCapacity(removal, {});

        for (self.outputs) |output| {
            const target = output.path;
            var route_blocked = false;
            var start: usize = 0;
            while (std.mem.indexOfScalarPos(u8, target, start, '/')) |slash| {
                const ancestor = target[0..slash];
                const candidate_index = mutations.index.get(ancestor) orelse
                    return error.MutationPlanMismatch;
                const candidate = mutations.items.items[candidate_index];
                if (candidate.backed or !candidate.present) {
                    route_blocked = true;
                    break;
                }
                if (candidate.kind == .directory) {
                    start = slash + 1;
                    continue;
                }
                if (!removal_set.contains(ancestor)) return error.SourcePathConflict;
                try self.backupCaptured(candidate_index);
                route_blocked = true;
                break;
            }
            if (route_blocked) continue;

            const candidate_index = mutations.index.get(target) orelse
                return error.MutationPlanMismatch;
            const candidate = mutations.items.items[candidate_index];
            if (candidate.backed or !candidate.present) continue;
            switch (candidate.kind.?) {
                .directory => {
                    try requireRemovedDirectory(
                        self.allocator,
                        self.io,
                        self.dir,
                        target,
                        removal_set,
                    );
                    try self.backupCapturedDirectoryTree(candidate_index);
                },
                .file, .sym_link => try self.backupCaptured(candidate_index),
                else => return error.SourcePathConflict,
            }
        }

        for (removals) |removal| {
            const candidate_index = mutations.index.get(removal) orelse {
                if (mutationRouteWasClosed(mutations, removal)) continue;
                return error.MutationPlanMismatch;
            };
            const candidate = mutations.items.items[candidate_index];
            if (candidate.backed or !candidate.present or
                mutationCoveredByBackedAncestor(mutations, removal)) continue;
            switch (candidate.kind.?) {
                .file, .sym_link => try self.backupCaptured(candidate_index),
                .directory => {},
                else => return error.SourcePathConflict,
            }
        }
    }

    // windows: open child handles block directory rename, even with DELETE sharing
    fn backupCapturedDirectoryTree(self: *Commit, root_index: usize) !void {
        const mutations = &self.mutations;
        if (root_index >= mutations.items.items.len) return error.MutationPlanMismatch;

        var index: usize = 0;
        while (index < mutations.items.items.len) : (index += 1) {
            const candidate = mutations.items.items[index];
            if (candidate.backup_descendant_of != root_index) continue;
            switch (candidate.kind orelse return error.MutationBindingChanged) {
                .file, .sym_link => try self.backupCaptured(index),
                .directory => {},
                else => return error.SourcePathConflict,
            }
        }

        var maximum_depth: usize = 0;
        for (mutations.items.items) |candidate| {
            if (candidate.backup_descendant_of != root_index or
                candidate.kind != .directory) continue;
            maximum_depth = @max(
                maximum_depth,
                std.mem.count(u8, candidate.logical_path, "/"),
            );
        }
        var depth = maximum_depth + 1;
        while (depth != 0) {
            depth -= 1;
            index = 0;
            while (index < mutations.items.items.len) : (index += 1) {
                const candidate = mutations.items.items[index];
                if (candidate.backup_descendant_of != root_index or
                    candidate.kind != .directory) continue;
                if (std.mem.count(u8, candidate.logical_path, "/") != depth) continue;
                try self.backupCaptured(index);
            }
        }
        try self.backupCaptured(root_index);
    }

    fn backupCaptured(self: *Commit, candidate_index: usize) !void {
        const mutations = &self.mutations;
        if (candidate_index >= mutations.items.items.len) return error.MutationPlanMismatch;
        if (mutations.items.items[candidate_index].backup_descendant_of != null and
            !mutations.items.items[candidate_index].strict_backup_authority)
            try self.upgradeCapturedBackupAuthority(candidate_index);
        const candidate = &mutations.items.items[candidate_index];
        if (!candidate.present or candidate.backed) return error.MutationPlanMismatch;
        if (!candidate.strict_backup_authority) return error.MutationPlanMismatch;
        const guard = candidate.guard orelse return error.MutationBindingChanged;
        const restore_path = candidate.restore_path orelse return error.MutationBindingChanged;

        const backups_root = try self.allocator.print("{s}/backups", .{self.workspace.name});
        defer self.allocator.free(backups_root);

        var path: ?[]u8 = try self.allocator.print(
            "{s}/{d}",
            .{ backups_root, self.backups.items.len },
        );
        errdefer if (path) |owned| self.allocator.free(owned);
        try self.backups.ensureUnusedCapacity(self.allocator, 1);

        var outcome_error: ?anyerror = null;
        const backup_root = try self.workspace.backupsDir();
        var backup_name_buf: [32]u8 = undefined;
        const backup_relative = try std.fmt.bufPrint(&backup_name_buf, "{d}", .{self.backups.items.len});
        fs.renameOpenObjectBeneathWindows(self.io, backup_root, backup_relative, guard) catch |err| {
            const backup_matches = guardedObjectPathIdentityMatches(self.io, backup_root, backup_relative, guard);
            const original_matches = guardedObjectPathIdentityMatches(
                self.io,
                self.dir,
                candidate.logical_path,
                guard,
            );
            if (backup_matches and !original_matches) {
                // remote filesystem: possible failure after completed move
            } else if (original_matches) {
                return err;
            } else {
                outcome_error = error.PublicationOutcomeUnknown;
            }
        };
        self.backups.appendAssumeCapacity(.{
            .original = restore_path,
            .path = path.?,
            .guard = guard,
        });
        candidate.restore_path = null;
        candidate.guard = null;
        candidate.backed = true;
        path = null;
        if (outcome_error) |err| return err;
    }

    // full-root rebind before upgrading permissive capture shares
    fn upgradeCapturedBackupAuthority(self: *Commit, candidate_index: usize) !void {
        const mutations = &self.mutations;
        if (candidate_index >= mutations.items.items.len) return error.MutationPlanMismatch;
        const candidate = &mutations.items.items[candidate_index];
        if (candidate.strict_backup_authority) return;
        const pin = candidate.guard orelse return error.MutationBindingChanged;

        var strict = fs.openBackupAuthorityBeneathWindows(
            self.io,
            self.dir,
            candidate.logical_path,
        ) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.PathAncestorNotDirectory,
            error.UnsafePathAncestor,
            => return error.MutationBindingChanged,
            else => |other| return other,
        };
        errdefer strict.close(self.io);
        if (!try fs.sameOpenFile(self.io, pin, strict))
            return error.MutationBindingChanged;
        candidate.guard = strict;
        candidate.strict_backup_authority = true;
        pin.close(self.io);
    }

    fn prepare(self: *Commit, removals: []const []const u8) !void {
        const scratch = std.heap.smp_allocator;
        var removal_set: std.StringHashMapUnmanaged(void) = .empty;
        defer removal_set.deinit(scratch);
        try removal_set.ensureTotalCapacity(scratch, @intCast(removals.len));
        for (removals) |removal| removal_set.putAssumeCapacity(removal, {});

        for (self.outputs) |output| {
            const target = output.path;
            var start: usize = 0;
            while (std.mem.indexOfScalarPos(u8, target, start, '/')) |slash| {
                const ancestor = target[0..slash];
                start = slash + 1;
                const stat = self.dir.statFile(self.io, ancestor, .{ .follow_symlinks = false }) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => |e| return e,
                };
                switch (stat.kind) {
                    .directory => {},
                    .file, .sym_link => {
                        if (!removal_set.contains(ancestor)) return error.SourcePathConflict;
                        try self.backup(ancestor);
                    },
                    else => return error.SourcePathConflict,
                }
            }

            const stat = self.dir.statFile(self.io, target, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            switch (stat.kind) {
                .directory => {
                    try requireRemovedDirectory(self.allocator, self.io, self.dir, target, removal_set);
                    try self.backup(target);
                },
                .file, .sym_link => try self.backup(target),
                else => return error.SourcePathConflict,
            }
        }
    }

    fn backup(self: *Commit, original: []const u8) !void {
        const backups_root = try self.allocator.print("{s}/backups", .{self.workspace.name});
        defer self.allocator.free(backups_root);

        var path: ?[]u8 = try self.allocator.print("{s}/{d}", .{ backups_root, self.backups.items.len });
        errdefer if (path) |owned| self.allocator.free(owned);
        try self.backups.ensureUnusedCapacity(self.allocator, 1);

        const restore_path = try self.allocator.dupe(u8, original);
        errdefer self.allocator.free(restore_path);
        try self.dir.renamePreserve(original, self.dir, path.?, self.io);
        self.backups.appendAssumeCapacity(.{ .original = restore_path, .path = path.? });
        path = null;
    }

    fn transferPublished(self: *Commit, index: usize) void {
        const output = &self.outputs[index];
        const guarded = output.state.staged;
        output.state = .{ .published = .{ .file = guarded, .state = .active } };
    }

    fn closeStagedGuards(self: *Commit) void {
        self.discardStagedGuards() catch {};
    }

    fn discardStagedGuards(self: *Commit) !void {
        var first_error: ?anyerror = null;
        for (self.outputs) |*output| {
            if (output.state != .staged) continue;
            output.discard(self.io) catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        if (first_error) |err| return err;
    }

    fn closePublishedGuards(self: *Commit) void {
        for (self.outputs) |*output| {
            if (output.state != .published) continue;
            output.state.published.file.close(self.io);
            output.state = .consumed;
        }
    }

    fn closeCreatedDirectories(self: *Commit) void {
        for (self.created_directories.items) |*created| {
            if (created.handle) |directory| directory.close(self.io);
            created.handle = null;
        }
    }

    fn closeRetainedDirectories(self: *Commit) void {
        for (self.retained_directories.items) |*retained| {
            if (retained.handle) |directory| directory.close(self.io);
            retained.handle = null;
        }
    }

    fn closeBackupGuards(self: *Commit) void {
        for (self.backups.items) |*item| {
            if (item.guard) |guard| guard.close(self.io);
            item.guard = null;
        }
    }
};

fn discardOutputs(io: std.Io, outputs: []Output) !void {
    var first_error: ?anyerror = null;
    for (outputs) |*output| {
        output.discard(io) catch |err| {
            if (first_error == null) first_error = err;
        };
    }
    if (first_error) |err| return err;
}

fn mutationRouteWasClosed(mutations: *const MutationSet, path: []const u8) bool {
    for (mutations.items.items) |candidate| {
        if (!pathIsAncestor(candidate.logical_path, path, true)) continue;
        if (candidate.backed or !candidate.present or candidate.kind != .directory) return true;
    }
    return false;
}

fn mutationCoveredByBackedAncestor(mutations: *const MutationSet, path: []const u8) bool {
    for (mutations.items.items) |candidate| {
        if (candidate.backed and pathIsAncestor(candidate.logical_path, path, true)) return true;
    }
    return false;
}

fn guardedPathMatches(
    io: std.Io,
    root: std.Io.Dir,
    path: []const u8,
    guarded: std.Io.File,
    expected_size: u64,
) bool {
    fs.validateGuardedOutput(io, guarded, expected_size) catch return false;
    var rebound = fs.openReadBeneath(io, root, path) catch return false;
    defer rebound.close(io);
    if (!(fs.sameOpenFile(io, guarded, rebound) catch return false)) return false;
    fs.validateGuardedOutput(io, guarded, expected_size) catch return false;
    return true;
}

fn guardedPathIdentityMatches(
    io: std.Io,
    root: std.Io.Dir,
    path: []const u8,
    guarded: std.Io.File,
) bool {
    var rebound = fs.openReadBeneath(io, root, path) catch return false;
    defer rebound.close(io);
    return fs.sameOpenFile(io, guarded, rebound) catch false;
}

fn guardedObjectPathIdentityMatches(
    io: std.Io,
    root: std.Io.Dir,
    path: []const u8,
    guarded: std.Io.File,
) bool {
    if (builtin.target.os.tag != .windows) return false;
    var rebound = fs.openMetadataBeneathWindows(io, root, path) catch return false;
    defer rebound.close(io);
    return fs.sameOpenFile(io, guarded, rebound) catch false;
}

fn guardedObjectPathIdentityAndBasenameMatches(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    path: []const u8,
    guarded: std.Io.File,
) bool {
    if (builtin.target.os.tag != .windows) return false;
    var rebound = fs.openMetadataBeneathWindows(io, root, path) catch return false;
    defer rebound.close(io);
    if (!(fs.sameOpenFile(io, guarded, rebound) catch return false)) return false;

    const actual_basename = fs.windowsOpenedBasenameAlloc(allocator, rebound) catch return false;
    defer allocator.free(actual_basename);
    const basename_start = if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| slash + 1 else 0;
    return std.mem.eql(u8, path[basename_start..], actual_basename);
}

// unproven publication: original rename error retained
fn guardedTargetMatches(
    io: std.Io,
    root: std.Io.Dir,
    target_parent: std.Io.Dir,
    target_basename: []const u8,
    target_path: []const u8,
    guarded: std.Io.File,
    expected_size: u64,
) bool {
    fs.validateGuardedOutput(io, guarded, expected_size) catch return false;

    var bound = fs.openRead(io, target_parent, target_basename) catch return false;
    defer bound.close(io);
    if (!(fs.sameOpenFile(io, guarded, bound) catch return false)) return false;

    // possibly detached parent: re-walk from install root
    var logical = fs.openReadBeneath(io, root, target_path) catch return false;
    defer logical.close(io);
    if (!(fs.sameOpenFile(io, guarded, logical) catch return false)) return false;

    fs.validateGuardedOutput(io, guarded, expected_size) catch return false;
    return true;
}

fn requireRemovedDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    removals: std.StringHashMapUnmanaged(void),
) !void {
    var sub = try dir.openDir(io, path, .{ .iterate = true, .access_sub_paths = true });
    defer sub.close(io);
    var walker = try sub.walk(allocator);
    defer walker.deinit();
    var full_buf: [std.fs.max_path_bytes]u8 = undefined;
    while (try walker.next(io)) |entry| switch (entry.kind) {
        .directory => {},
        .file, .sym_link => {
            const full = std.fmt.bufPrint(&full_buf, "{s}/{s}", .{ path, entry.path }) catch return error.PathTooLongForZip;
            normalizeWalkedLogicalPath(full);
            if (!removals.contains(full)) return error.SourcePathConflict;
        },
        else => return error.SourcePathConflict,
    };
}

fn normalizeWalkedLogicalPath(path: []u8) void {
    if (std.fs.path.sep == '/') return;
    for (path) |*byte| if (byte.* == std.fs.path.sep) {
        byte.* = '/';
    };
}

// nonempty cleanup token: preserved backups and raced private entries
pub fn cleanupWorkAt(io: std.Io, dir: std.Io.Dir, work_root: []const u8) void {
    var backups_buf: [std.fs.max_path_bytes]u8 = undefined;
    const backups_path = std.fmt.bufPrint(&backups_buf, "{s}/backups", .{work_root}) catch return;
    var backups = dir.openDir(io, backups_path, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return,
    };
    const token_stat = backups.stat(io) catch {
        backups.close(io);
        return;
    };
    if (token_stat.kind != .directory) {
        backups.close(io);
        return;
    }
    var iterator = backups.iterate();
    const first = iterator.next(io) catch {
        backups.close(io);
        return;
    };
    backups.close(io);
    if (first != null) return;
    dir.deleteTree(io, work_root) catch {};
}

test "cleanup requires a positively established empty backup token" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "work/staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "work/staged/owned.bin", .data = "keep" });
    cleanupWorkAt(io, tmp.dir, "work");
    _ = try tmp.dir.statFile(io, "work/staged/owned.bin", .{});

    try fs.createDirPathBeneath(io, tmp.dir, "work/backups");
    try tmp.dir.writeFile(io, .{ .sub_path = "work/backups/sentinel", .data = "keep" });
    cleanupWorkAt(io, tmp.dir, "work");
    const bytes = try tmp.dir.readFileAlloc(io, "work/backups/sentinel", std.testing.allocator, .limited(5));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("keep", bytes);
    try tmp.dir.deleteFile(io, "work/backups/sentinel");
    cleanupWorkAt(io, tmp.dir, "work");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "work", .{}));
}

test "Windows workspace root remains pinned until exact cleanup" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(std.testing.allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    _ = try workspace.rootDir();
    _ = try workspace.backupsDir();
    try workspace.ensureDirectory("staged");

    if (tmp.dir.rename(workspace.name, tmp.dir, "detached-work", io)) |_| {
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expect(err == error.FileBusy or err == error.AccessDenied);
    }
    _ = try tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false });

    var source_buf: [std.fs.max_path_bytes]u8 = undefined;
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pinned_children = [_][]const u8{ "backups", "staged" };
    for (pinned_children) |child| {
        const source = try std.fmt.bufPrint(&source_buf, "{s}/{s}", .{ workspace.name, child });
        const target = try std.fmt.bufPrint(&target_buf, "{s}/{s}-detached", .{ workspace.name, child });
        if (tmp.dir.rename(source, tmp.dir, target, io)) |_| {
            return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expect(err == error.FileBusy or err == error.AccessDenied);
        }
        _ = try tmp.dir.statFile(io, source, .{ .follow_symlinks = false });
    }
}

test "Windows workspace exact cleanup removes only its owned empty tree" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged/deep");
    const staged_path = try allocator.print(
        "{s}/staged/deep/owned.bin",
        .{workspace.name},
    );
    defer allocator.free(staged_path);
    const staged = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    try staged.writePositionalAll(io, "owned", 0);
    try fs.discardOpenObjectWindows(io, staged);

    workspace.cleanup();
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false }),
    );
}

test "Windows workspace cleanup preserves unknown entries everywhere" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const root_sentinel = try allocator.print("{s}/root.bin", .{workspace.name});
    defer allocator.free(root_sentinel);
    const staged_sentinel = try allocator.print("{s}/staged/staged.bin", .{workspace.name});
    defer allocator.free(staged_sentinel);
    const backup_sentinel = try allocator.print("{s}/backups/backup.bin", .{workspace.name});
    defer allocator.free(backup_sentinel);
    const unknown_directory = try allocator.print("{s}/unknown-empty", .{workspace.name});
    defer allocator.free(unknown_directory);
    try tmp.dir.writeFile(io, .{ .sub_path = root_sentinel, .data = "root" });
    try tmp.dir.writeFile(io, .{ .sub_path = staged_sentinel, .data = "stage" });
    try tmp.dir.writeFile(io, .{ .sub_path = backup_sentinel, .data = "backup" });
    try tmp.dir.createDir(io, unknown_directory, .default_dir);

    workspace.cleanup();
    const root = try tmp.dir.readFileAlloc(io, root_sentinel, allocator, .limited(5));
    defer allocator.free(root);
    const staged = try tmp.dir.readFileAlloc(io, staged_sentinel, allocator, .limited(6));
    defer allocator.free(staged);
    const backup = try tmp.dir.readFileAlloc(io, backup_sentinel, allocator, .limited(7));
    defer allocator.free(backup);
    try std.testing.expectEqualStrings("root", root);
    try std.testing.expectEqualStrings("stage", staged);
    try std.testing.expectEqualStrings("backup", backup);
    const unknown = try tmp.dir.statFile(io, unknown_directory, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.directory, unknown.kind);
}

test "Windows workspace never adopts an untracked raced directory" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    const raced = try allocator.print("{s}/staged", .{workspace.name});
    defer allocator.free(raced);
    try tmp.dir.createDir(io, raced, .default_dir);
    try std.testing.expectError(error.WorkspaceContaminated, workspace.ensureDirectory("staged"));

    workspace.cleanup();
    const stat = try tmp.dir.statFile(io, raced, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.directory, stat.kind);
}

test "Windows workspace successful directory replacement exact-cleans the backup tree" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    try tmp.dir.createDirPath(io, "old/deep/empty");
    try tmp.dir.writeFile(io, .{ .sub_path = "old/root.bin", .data = "old root" });
    try tmp.dir.writeFile(io, .{ .sub_path = "old/deep/leaf.bin", .data = "old leaf" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "old", .work_rel = staged_path, .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    const targets = [_][]const u8{"old"};
    const removals = [_][]const u8{ "old/root.bin", "old/deep/leaf.bin" };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &removals);
    defer mutations.deinit();
    {
        var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &removals, &mutations);
        defer commit.deinit();
        try commit.publish(0);
        try commit.finish();
    }

    const replacement = try tmp.dir.readFileAlloc(io, "old", allocator, .limited(4));
    defer allocator.free(replacement);
    try std.testing.expectEqualStrings("new", replacement);
    workspace.cleanup();
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false }),
    );
}

test "Windows workspace successful finish preserves late unowned backup residue" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    var raced_path: ?[]u8 = null;
    defer if (raced_path) |path| allocator.free(path);
    try tmp.dir.createDirPath(io, "old/empty");
    try tmp.dir.writeFile(io, .{ .sub_path = "old/removed.bin", .data = "old" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "old", .work_rel = staged_path, .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    const targets = [_][]const u8{"old"};
    const removals = [_][]const u8{"old/removed.bin"};
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &removals);
    defer mutations.deinit();

    // stale handle for residue injection after backup rename
    var stale = try tmp.dir.openDir(io, "old", .{
        .access_sub_paths = true,
        .follow_symlinks = false,
    });
    defer stale.close(io);
    {
        var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &removals, &mutations);
        defer commit.deinit();
        const root_backup = commit.backups.items[commit.backups.items.len - 1].path;
        raced_path = try allocator.print("{s}/raced", .{root_backup});
        try stale.createDir(io, "raced", .default_dir);
        try commit.publish(0);
        try commit.finish();
    }

    workspace.cleanup();
    const residue = try tmp.dir.statFile(io, raced_path.?, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.directory, residue.kind);
    _ = try tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false });
}

test "Windows captured descendant departure is never pulled into backup or disposed" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    var outputs = [_]Output{.{ .path = "old", .work_rel = staged_path, .size = 0, .state = .{ .staged = guarded } }};
    try tmp.dir.createDirPath(io, "old/deep");
    try tmp.dir.writeFile(io, .{ .sub_path = "old/deep/leaf.bin", .data = "escape" });
    const targets = [_][]const u8{"old"};
    const removals = [_][]const u8{"old/deep/leaf.bin"};
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &removals);
    defer mutations.deinit();
    var commit: Commit = .{
        .allocator = allocator,
        .io = io,
        .dir = tmp.dir,
        .outputs = &outputs,
        .mutations = mutations.take(),
        .workspace = &workspace,
    };
    defer commit.deinit();
    const leaf_index = commit.mutations.index.get("old/deep/leaf.bin") orelse
        return error.TestUnexpectedResult;

    try tmp.dir.rename("old/deep/leaf.bin", tmp.dir, "escaped.bin", io);
    try std.testing.expectError(
        error.MutationBindingChanged,
        commit.backupCaptured(leaf_index),
    );
    const escaped = try tmp.dir.readFileAlloc(io, "escaped.bin", allocator, .limited(7));
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("escape", escaped);
    try std.testing.expectEqual(@as(usize, 0), commit.backups.items.len);
}

test "Windows rollback after a partial directory flatten restores the exact tree" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    var outputs = [_]Output{.{ .path = "old", .work_rel = staged_path, .size = 0, .state = .{ .staged = guarded } }};
    try tmp.dir.createDirPath(io, "old/deep/empty");
    try tmp.dir.writeFile(io, .{ .sub_path = "old/deep/leaf.bin", .data = "restore" });
    try tmp.dir.writeFile(io, .{ .sub_path = "old/root.bin", .data = "root" });
    const targets = [_][]const u8{"old"};
    const removals = [_][]const u8{ "old/deep/leaf.bin", "old/root.bin" };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &removals);
    defer mutations.deinit();
    {
        var commit: Commit = .{
            .allocator = allocator,
            .io = io,
            .dir = tmp.dir,
            .outputs = &outputs,
            .mutations = mutations.take(),
            .workspace = &workspace,
        };
        defer commit.deinit();
        const leaf_index = commit.mutations.index.get("old/deep/leaf.bin") orelse
            return error.TestUnexpectedResult;
        try commit.backupCaptured(leaf_index);
        try std.testing.expectError(
            error.FileNotFound,
            tmp.dir.statFile(io, "old/deep/leaf.bin", .{ .follow_symlinks = false }),
        );
        try commit.restoreBackups();
    }

    const leaf = try tmp.dir.readFileAlloc(io, "old/deep/leaf.bin", allocator, .limited(8));
    defer allocator.free(leaf);
    const root = try tmp.dir.readFileAlloc(io, "old/root.bin", allocator, .limited(5));
    defer allocator.free(root);
    try std.testing.expectEqualStrings("restore", leaf);
    try std.testing.expectEqualStrings("root", root);
    _ = try tmp.dir.statFile(io, "old/deep/empty", .{ .follow_symlinks = false });

    workspace.cleanup();
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false }),
    );
}

test "Windows flattened rollback root conflict preserves every descendant backup" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    const quarantine_path = try allocator.print("{s}/rollback-0", .{workspace.name});
    defer allocator.free(quarantine_path);
    const marker_path = try allocator.print(
        "{s}/backups/RECOVERY_REQUIRED",
        .{workspace.name},
    );
    defer allocator.free(marker_path);

    try tmp.dir.createDirPath(io, "old/deep");
    try tmp.dir.writeFile(io, .{ .sub_path = "old/deep/leaf.bin", .data = "original" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "old", .work_rel = staged_path, .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    const targets = [_][]const u8{"old"};
    const removals = [_][]const u8{"old/deep/leaf.bin"};
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &removals);
    defer mutations.deinit();
    {
        var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &removals, &mutations);
        defer commit.deinit();
        try std.testing.expectEqual(@as(usize, 3), commit.backups.items.len);
        try commit.publish(0);
        try commit.quarantineGuardedPublications();

        try tmp.dir.createDir(io, "old", .default_dir);
        try tmp.dir.writeFile(io, .{ .sub_path = "old/raced.bin", .data = "unknown" });
        try std.testing.expectError(error.RollbackConflict, commit.restoreBackups());
        try commit.preserveRecovery();

        const unknown = try tmp.dir.readFileAlloc(io, "old/raced.bin", allocator, .limited(8));
        defer allocator.free(unknown);
        try std.testing.expectEqualStrings("unknown", unknown);
        try std.testing.expectError(
            error.FileNotFound,
            tmp.dir.statFile(io, "old/deep", .{ .follow_symlinks = false }),
        );
        for (commit.backups.items) |backup| {
            try std.testing.expect(backup.guard != null);
            _ = try tmp.dir.statFile(io, backup.path, .{ .follow_symlinks = false });
        }
        _ = try tmp.dir.statFile(io, quarantine_path, .{ .follow_symlinks = false });
        _ = try tmp.dir.statFile(io, marker_path, .{ .follow_symlinks = false });
    }

    workspace.cleanup();
    const unknown = try tmp.dir.readFileAlloc(io, "old/raced.bin", allocator, .limited(8));
    defer allocator.free(unknown);
    try std.testing.expectEqualStrings("unknown", unknown);
    var backup_buf: [std.fs.max_path_bytes]u8 = undefined;
    for (0..3) |index| {
        const backup_path = try std.fmt.bufPrint(
            &backup_buf,
            "{s}/backups/{d}",
            .{ workspace.name, index },
        );
        _ = try tmp.dir.statFile(io, backup_path, .{ .follow_symlinks = false });
    }
    _ = try tmp.dir.statFile(io, marker_path, .{ .follow_symlinks = false });
    _ = try tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false });
}

test "workspace successful finish leaves a removable cleanup token on every platform" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    const work_name = try allocator.dupe(u8, workspace.name);
    defer allocator.free(work_name);
    try workspace.ensureDirectory("staged");
    const staged_path = try allocator.print("{s}/staged/new.bin", .{workspace.name});
    defer allocator.free(staged_path);
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_path);
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = staged_path, .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &.{"final.bin"}, &.{});
    defer mutations.deinit();
    {
        var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{}, &mutations);
        defer commit.deinit();
        try commit.publish(0);
        try commit.finish();
    }

    // double deinit intentional: idempotence test
    workspace.deinit();
    cleanupWorkAt(io, tmp.dir, work_name);
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, work_name, .{ .follow_symlinks = false }),
    );
}

test "Windows workspace rollback conflict preserves backups quarantine and marker" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const staged_one = try allocator.print("{s}/staged/one.bin", .{workspace.name});
    defer allocator.free(staged_one);
    const staged_two = try allocator.print("{s}/staged/two.bin", .{workspace.name});
    defer allocator.free(staged_two);
    const backup_two = try allocator.print("{s}/backups/1", .{workspace.name});
    defer allocator.free(backup_two);
    const quarantine_one = try allocator.print("{s}/rollback-0", .{workspace.name});
    defer allocator.free(quarantine_one);
    const marker = try allocator.print("{s}/backups/RECOVERY_REQUIRED", .{workspace.name});
    defer allocator.free(marker);
    try tmp.dir.writeFile(io, .{ .sub_path = "one.bin", .data = "old one" });
    try tmp.dir.writeFile(io, .{ .sub_path = "two.bin", .data = "old two" });
    const first = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_one);
    try first.writePositionalAll(io, "new one", 0);
    try first.sync(io);
    const second = try fs.createGuardedOutputBeneath(io, tmp.dir, staged_two);
    try second.writePositionalAll(io, "new two", 0);
    try second.sync(io);
    var outputs = [_]Output{
        .{ .path = "one.bin", .work_rel = staged_one, .size = try first.length(io), .state = .{ .staged = first } },
        .{ .path = "two.bin", .work_rel = staged_two, .size = try second.length(io), .state = .{ .staged = second } },
    };
    const targets = [_][]const u8{ "one.bin", "two.bin" };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &targets, &.{});
    defer mutations.deinit();
    {
        var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{}, &mutations);
        defer commit.deinit();
        try commit.publish(0);
        try tmp.dir.writeFile(io, .{ .sub_path = "two.bin", .data = "sentinel" });
        try std.testing.expectError(
            error.PathAlreadyExists,
            commit.publish(1),
        );
        try std.testing.expectError(error.RollbackConflict, commit.rollback());
    }

    workspace.cleanup();
    const restored_one = try tmp.dir.readFileAlloc(io, "one.bin", allocator, .limited(8));
    defer allocator.free(restored_one);
    const sentinel = try tmp.dir.readFileAlloc(io, "two.bin", allocator, .limited(9));
    defer allocator.free(sentinel);
    const preserved_backup = try tmp.dir.readFileAlloc(io, backup_two, allocator, .limited(8));
    defer allocator.free(preserved_backup);
    const preserved_publication = try tmp.dir.readFileAlloc(io, quarantine_one, allocator, .limited(8));
    defer allocator.free(preserved_publication);
    try std.testing.expectEqualStrings("old one", restored_one);
    try std.testing.expectEqualStrings("sentinel", sentinel);
    try std.testing.expectEqualStrings("old two", preserved_backup);
    try std.testing.expectEqualStrings("new one", preserved_publication);
    _ = try tmp.dir.statFile(io, marker, .{});
}

test "prepared guarded commit refuses objects raced into captured absences" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(
        allocator,
        io,
        tmp.dir,
        &.{"final.bin"},
        &.{"late.bin"},
    );
    defer mutations.deinit();

    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "target sentinel" });
    try tmp.dir.writeFile(io, .{ .sub_path = "late.bin", .data = "removal sentinel" });
    try std.testing.expectError(
        error.MutationBindingChanged,
        Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{"late.bin"}, &mutations),
    );
    try std.testing.expect(outputs[0].state == .consumed);

    const target = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(16));
    defer allocator.free(target);
    const removal = try tmp.dir.readFileAlloc(io, "late.bin", allocator, .limited(17));
    defer allocator.free(removal);
    try std.testing.expectEqualStrings("target sentinel", target);
    try std.testing.expectEqualStrings("removal sentinel", removal);
}

test "prepared guarded commit pins captured object identity and casing" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "Foo.bin", .data = "original" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "foo.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &.{"foo.bin"}, &.{});
    defer mutations.deinit();

    try std.testing.expectError(error.FileBusy, tmp.dir.deleteFile(io, "Foo.bin"));
    try std.testing.expectError(
        error.FileBusy,
        tmp.dir.rename("Foo.bin", tmp.dir, "raced.bin", io),
    );
    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{}, &mutations);
    defer commit.deinit();
    try commit.rollback();

    var root = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer root.close(io);
    var iterator = root.iterate();
    var exact_case = false;
    while (try iterator.next(io)) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, "foo.bin")) {
            exact_case = std.mem.eql(u8, entry.name, "Foo.bin");
            break;
        }
    }
    try std.testing.expect(exact_case);
}

test "raced existing target ancestor retains namespace authority" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "raced/sub.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &.{"raced/sub.bin"}, &.{});
    defer mutations.deinit();
    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{}, &mutations);
    defer commit.deinit();

    try tmp.dir.createDir(io, "raced", .default_dir);
    try commit.publish(0);
    try std.testing.expectError(
        error.FileBusy,
        tmp.dir.rename("raced", tmp.dir, "detached", io),
    );
    try commit.finish();
}

test "prepared removal refuses a raced replacement and preserves recovery" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "obsolete.bin", .data = "original" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "new.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(
        allocator,
        io,
        tmp.dir,
        &.{"new.bin"},
        &.{"obsolete.bin"},
    );
    defer mutations.deinit();
    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{"obsolete.bin"}, &mutations);
    defer commit.deinit();

    try tmp.dir.writeFile(io, .{ .sub_path = "obsolete.bin", .data = "sentinel" });
    try std.testing.expectError(error.MutationBindingChanged, commit.remove("obsolete.bin"));
    try std.testing.expectError(error.RollbackConflict, commit.rollback());

    const sentinel = try tmp.dir.readFileAlloc(io, "obsolete.bin", allocator, .limited(9));
    defer allocator.free(sentinel);
    const backup = try tmp.dir.readFileAlloc(io, ".zift-work/backups/0", allocator, .limited(9));
    defer allocator.free(backup);
    try std.testing.expectEqualStrings("sentinel", sentinel);
    try std.testing.expectEqualStrings("original", backup);
    _ = try tmp.dir.statFile(io, ".zift-work/backups/RECOVERY_REQUIRED", .{});
}

test "prepared absent removal remains an enforced absence" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "new.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(
        allocator,
        io,
        tmp.dir,
        &.{"new.bin"},
        &.{"late.bin"},
    );
    defer mutations.deinit();
    const removals = try mutations.listedRemovalEntries(allocator, io, tmp.dir);
    defer allocator.free(removals);
    try std.testing.expectEqual(@as(usize, 1), removals.len);
    try std.testing.expectEqual(@as(u64, 0), removals[0].size);

    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{"late.bin"}, &mutations);
    defer commit.deinit();
    try tmp.dir.writeFile(io, .{ .sub_path = "late.bin", .data = "sentinel" });
    try std.testing.expectError(error.MutationBindingChanged, commit.remove("late.bin"));
    try commit.rollback();

    const sentinel = try tmp.dir.readFileAlloc(io, "late.bin", allocator, .limited(9));
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings("sentinel", sentinel);
}

test "prepared blocking-ancestor removal is covered by its bound publication" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "old" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "a/b", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &.{"a/b"}, &.{"a"});
    defer mutations.deinit();
    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{"a"}, &mutations);
    defer commit.deinit();

    try commit.publish(0);
    try commit.remove("a");
    try commit.finish();
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const bytes = try tmp.dir.readFileAlloc(io, "a/b", allocator, .limited(4));
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("new", bytes);
}

pub fn listedRemovals(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, paths: []const []const u8) ![]clean.Extra {
    var extras: std.ArrayList(clean.Extra) = .empty;
    for (paths) |path| {
        const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => continue,
            else => |e| return e,
        };
        if (stat.kind == .file or stat.kind == .sym_link) try extras.append(allocator, .{ .path = path, .size = stat.size });
    }
    return extras.toOwnedSlice(allocator);
}

pub fn extrasSize(extras: []const clean.Extra) u64 {
    var total: u64 = 0;
    for (extras) |extra| total +|= extra.size;
    return total;
}

fn ensureParent(io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
    try fs.createParentPathBeneath(io, dir, path);
}

fn testingWorkspace(io: std.Io, dir: std.Io.Dir) !Workspace {
    var workspace = try Workspace.create(std.testing.allocator, io, dir, &.{});
    errdefer workspace.deinit();
    try workspace.ensureDirectory("staged");
    return workspace;
}

fn testingCleanupWorkspace(io: std.Io, dir: std.Io.Dir, workspace: *Workspace) void {
    workspace.cleanup();
    if (builtin.target.os.tag != .windows) cleanupWorkAt(io, dir, workspace.name);
}

fn testingCommit(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    workspace: *Workspace,
    targets: []const []const u8,
    removals: []const []const u8,
    outputs: []Output,
) !Commit {
    var mutations = MutationSet.capture(allocator, io, dir, targets, removals) catch |err| {
        discardOutputs(io, outputs) catch {};
        return err;
    };
    defer mutations.deinit();
    return Commit.init(allocator, io, dir, workspace, outputs, removals, &mutations);
}

test "commit parent tracking reuses target paths through finish and rollback" {
    const io = std.testing.io;
    for ([_]bool{ false, true }) |rollback| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var workspace = try testingWorkspace(io, tmp.dir);
        defer workspace.deinit();
        try tmp.dir.createDir(io, "existing", .default_dir);
        try tmp.dir.writeFile(io, .{ .sub_path = "existing/sentinel", .data = "preserved" });

        const target_path = try std.testing.allocator.dupe(u8, "existing/new/deep/payload.bin");
        defer std.testing.allocator.free(target_path);
        const staged = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/payload.bin");
        try staged.writePositionalAll(io, "payload", 0);
        var outputs = [_]Output{.{
            .path = target_path,
            .work_rel = ".zift-work/staged/payload.bin",
            .size = 7,
            .state = .{ .staged = staged },
        }};

        var allocator_state = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const allocator = allocator_state.allocator();
        var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{target_path}, &.{}, &outputs);
        defer commit.deinit();
        try commit.created_directories.ensureUnusedCapacity(allocator, 3);
        allocator_state.fail_index = allocator_state.alloc_index;
        try commit.publish(0);
        try std.testing.expect(!allocator_state.has_induced_failure);
        allocator_state.fail_index = std.math.maxInt(usize);

        const published = try tmp.dir.readFileAlloc(io, target_path, std.testing.allocator, .limited(8));
        defer std.testing.allocator.free(published);
        try std.testing.expectEqualStrings("payload", published);
        if (builtin.target.os.tag == .windows) {
            if (tmp.dir.rename("existing/new", tmp.dir, "existing/moved", io)) |_| {
                return error.TestUnexpectedResult;
            } else |err| {
                try std.testing.expect(err == error.FileBusy or err == error.AccessDenied);
            }
        }
        if (rollback) {
            try commit.rollback();
            try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "existing/new", .{}));
        } else {
            try commit.finish();
            try std.testing.expectEqual(@as(u64, 7), (try tmp.dir.statFile(io, target_path, .{})).size);
        }
        const sentinel = try tmp.dir.readFileAlloc(io, "existing/sentinel", std.testing.allocator, .limited(10));
        defer std.testing.allocator.free(sentinel);
        try std.testing.expectEqualStrings("preserved", sentinel);
    }
}

test "work root selection avoids live and semantic first components" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, default_work_root, .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = default_work_root ++ "/sentinel", .data = "keep" });
    var workspace = try Workspace.create(allocator, io, tmp.dir, &.{ ".zift-work-1/user.bin", "ordinary.bin" });
    defer workspace.deinit();
    try std.testing.expectEqualStrings(".zift-work-2", workspace.name);
    try std.testing.expect(pathHasRoot(".ZIFT-WORK-2/child", workspace.name, true));
    try std.testing.expect(!pathHasRoot(".ZIFT-WORK-2/child", workspace.name, false));
    const sentinel = try tmp.dir.readFileAlloc(io, default_work_root ++ "/sentinel", allocator, .limited(5));
    try std.testing.expectEqualStrings("keep", sentinel);
}

test "commit refuses blocking directory with unlisted files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try tmp.dir.createDir(io, "a", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "a/removed", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "a/extra", .data = "extra" });

    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new");
    var outputs = [_]Output{
        .{ .path = "a", .work_rel = ".zift-work/staged/new", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    try std.testing.expectError(error.SourcePathConflict, testingCommit(allocator, io, tmp.dir, &workspace, &.{"a"}, &.{"a/removed"}, &outputs));
    _ = try tmp.dir.statFile(io, "a/removed", .{});
    _ = try tmp.dir.statFile(io, "a/extra", .{});
}

test "commit accepts listed symlink blocking target ancestor" {
    if (@import("builtin").target.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged/a");
    try tmp.dir.writeFile(io, .{ .sub_path = "real", .data = "keep" });
    try tmp.dir.symLink(io, "real", "a", .{});
    var staged = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/a/b");
    try staged.writePositionalAll(io, "new", 0);
    var outputs = [_]Output{
        .{ .path = "a/b", .work_rel = ".zift-work/staged/a/b", .size = try staged.length(io), .state = .{ .staged = staged } },
    };

    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{"a/b"}, &.{"a"}, &outputs);
    defer commit.deinit();
    try commit.publish(0);
    try commit.finish();

    const replacement = try tmp.dir.readFileAlloc(io, "a/b", allocator, .limited(4));
    const real = try tmp.dir.readFileAlloc(io, "real", allocator, .limited(5));
    try std.testing.expectEqualStrings("new", replacement);
    try std.testing.expectEqualStrings("keep", real);
}

test "commit accepts listed symlink inside blocking directory" {
    if (@import("builtin").target.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.createDir(io, "a", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "real", .data = "keep" });
    try tmp.dir.symLink(io, "../real", "a/link", .{});
    var staged = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new");
    try staged.writePositionalAll(io, "new", 0);
    var outputs = [_]Output{
        .{ .path = "a", .work_rel = ".zift-work/staged/new", .size = try staged.length(io), .state = .{ .staged = staged } },
    };

    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{"a"}, &.{"a/link"}, &outputs);
    defer commit.deinit();
    try commit.publish(0);
    try commit.finish();

    const replacement = try tmp.dir.readFileAlloc(io, "a", allocator, .limited(4));
    const real = try tmp.dir.readFileAlloc(io, "real", allocator, .limited(5));
    try std.testing.expectEqualStrings("new", replacement);
    try std.testing.expectEqualStrings("keep", real);
}

test "commit rollback restores blocking directory" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.createDir(io, "a", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "a/removed", .data = "old" });
    var staged = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new");
    try staged.writePositionalAll(io, "new", 0);
    var outputs = [_]Output{
        .{ .path = "a", .work_rel = ".zift-work/staged/new", .size = try staged.length(io), .state = .{ .staged = staged } },
    };

    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{"a"}, &.{"a/removed"}, &outputs);
    defer commit.deinit();
    try commit.publish(0);
    try commit.rollback();

    const bytes = try tmp.dir.readFileAlloc(io, "a/removed", allocator, .limited(4));
    try std.testing.expectEqualStrings("old", bytes);
}

test "commit rollback restores earlier replacements after later failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "one", .data = "old one" });
    try tmp.dir.writeFile(io, .{ .sub_path = "two", .data = "old two" });
    var first = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/one");
    try first.writePositionalAll(io, "new one", 0);
    var second = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/two");
    try second.writePositionalAll(io, "new two", 0);
    var outputs = [_]Output{
        .{ .path = "one", .work_rel = ".zift-work/staged/one", .size = try first.length(io), .state = .{ .staged = first } },
        .{ .path = "two", .work_rel = ".zift-work/staged/two", .size = try second.length(io), .state = .{ .staged = second } },
    };

    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{ "one", "two" }, &.{}, &outputs);
    defer commit.deinit();
    try commit.publish(0);
    outputs[1].work_rel = ".zift-work/staged/missing";
    try std.testing.expectError(error.StagingBindingChanged, commit.publish(1));
    try commit.rollback();

    const one = try tmp.dir.readFileAlloc(io, "one", allocator, .limited(8));
    const two = try tmp.dir.readFileAlloc(io, "two", allocator, .limited(8));
    try std.testing.expectEqualStrings("old one", one);
    try std.testing.expectEqualStrings("old two", two);
}

test "guarded commit publishes the indexed object and consumes its handle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    const payload = "guarded replacement";
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, payload, 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };

    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();
    try commit.publish(0);
    try std.testing.expect(outputs[0].state == .published);
    try commit.finish();
    try std.testing.expect(outputs[0].state == .consumed);

    const actual = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(payload.len + 1));
    try std.testing.expectEqualStrings(payload, actual);
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, ".zift-work/staged/new.bin", .{}),
    );
}

test "guarded commit owns outputs on initialization errors" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");

    const count_guard = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/count.bin");
    var count_outputs = [_]Output{
        .{ .path = "unused.bin", .work_rel = ".zift-work/staged/count.bin", .size = try count_guard.length(io), .state = .{ .staged = count_guard } },
    };
    try std.testing.expectError(
        error.GuardCountMismatch,
        testingCommit(
            std.testing.allocator,
            io,
            tmp.dir,
            &workspace,
            &.{},
            &.{},
            &count_outputs,
        ),
    );
    try std.testing.expect(count_outputs[0].state == .consumed);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/staged/count.bin", .{}));
    } else {
        try tmp.dir.deleteFile(io, ".zift-work/staged/count.bin");
    }

    const missing_guard = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/missing.bin");
    var missing_outputs = [_]Output{
        .{ .path = "first.bin", .work_rel = ".zift-work/staged/missing.bin", .size = try missing_guard.length(io), .state = .{ .staged = missing_guard } },
        .{ .path = "second.bin", .work_rel = "", .size = 0, .state = .consumed },
    };
    try std.testing.expectError(
        error.GuardSlotMissing,
        testingCommit(
            std.testing.allocator,
            io,
            tmp.dir,
            &workspace,
            &.{ "first.bin", "second.bin" },
            &.{},
            &missing_outputs,
        ),
    );
    try std.testing.expect(missing_outputs[0].state == .consumed);
    try std.testing.expect(missing_outputs[1].state == .consumed);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/staged/missing.bin", .{}));
    } else {
        try tmp.dir.deleteFile(io, ".zift-work/staged/missing.bin");
    }

    try tmp.dir.createDir(io, "blocked", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "blocked/foreign.bin", .data = "foreign" });
    const prepare_guard = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/prepare.bin");
    var prepare_outputs = [_]Output{
        .{ .path = "blocked", .work_rel = ".zift-work/staged/prepare.bin", .size = try prepare_guard.length(io), .state = .{ .staged = prepare_guard } },
    };
    try std.testing.expectError(
        error.SourcePathConflict,
        testingCommit(
            std.testing.allocator,
            io,
            tmp.dir,
            &workspace,
            &.{"blocked"},
            &.{},
            &prepare_outputs,
        ),
    );
    try std.testing.expect(prepare_outputs[0].state == .consumed);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/staged/prepare.bin", .{}));
    } else {
        try tmp.dir.deleteFile(io, ".zift-work/staged/prepare.bin");
    }
    testingCleanupWorkspace(io, tmp.dir, &workspace);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, workspace.name, .{}));
}

test "guarded backup collision preserves both original and private sentinel" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try workspace.ensureDirectory("backups");
    try tmp.dir.writeFile(io, .{ .sub_path = ".zift-work/backups/0", .data = "sentinel" });
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "original" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };

    try std.testing.expectError(
        error.PathAlreadyExists,
        testingCommit(
            std.testing.allocator,
            io,
            tmp.dir,
            &workspace,
            &.{"final.bin"},
            &.{},
            &outputs,
        ),
    );
    try std.testing.expect(outputs[0].state == .consumed);
    const original = try tmp.dir.readFileAlloc(io, "final.bin", std.testing.allocator, .limited(9));
    defer std.testing.allocator.free(original);
    const sentinel = try tmp.dir.readFileAlloc(io, ".zift-work/backups/0", std.testing.allocator, .limited(9));
    defer std.testing.allocator.free(sentinel);
    try std.testing.expectEqualStrings("original", original);
    try std.testing.expectEqualStrings("sentinel", sentinel);
}

test "guarded backup hard-link collision does not masquerade as a completed move" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try workspace.ensureDirectory("backups");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "original" });
    try fs.hardLinkInTmp(allocator, &tmp, "final.bin", ".zift-work/backups/0");
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };

    var commit = testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    ) catch |err| {
        try std.testing.expectEqual(error.PathAlreadyExists, err);
        try std.testing.expect(outputs[0].state == .consumed);
        const original = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(9));
        defer allocator.free(original);
        try std.testing.expectEqualStrings("original", original);
        _ = try tmp.dir.statFile(io, ".zift-work/backups/0", .{});
        return;
    };
    defer commit.deinit();

    // NTFS hard-link coalescing: backup complete only with original name gone
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "final.bin", .{}));
    _ = try tmp.dir.statFile(io, ".zift-work/backups/0", .{});
    try commit.rollback();
    const restored = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(9));
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("original", restored);
}

test "guarded backup remains pinned and restores original Windows casing" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "Foo.bin", .data = "original" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    var outputs = [_]Output{
        .{ .path = "foo.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"foo.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();

    try std.testing.expectError(error.FileBusy, fs.openWrite(io, tmp.dir, ".zift-work/backups/0"));
    try std.testing.expectError(error.FileBusy, tmp.dir.deleteFile(io, ".zift-work/backups/0"));
    try commit.rollback();
    try std.testing.expectEqualStrings("original", try tmp.dir.readFileAlloc(io, "Foo.bin", allocator, .limited(9)));
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    var root = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer root.close(io);
    var iterator = root.iterate();
    var restored_name: ?[]const u8 = null;
    while (try iterator.next(io)) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, "foo.bin")) {
            restored_name = entry.name;
            break;
        }
    }
    try std.testing.expect(restored_name != null);
    try std.testing.expectEqualStrings("Foo.bin", restored_name.?);
}

test "guarded rollback distinguishes same-object casing before NTFS coalescing" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "Foo.bin", .data = "original" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    var outputs = [_]Output{
        .{ .path = "foo.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var mutations = try MutationSet.capture(allocator, io, tmp.dir, &.{"foo.bin"}, &.{});
    defer mutations.deinit();
    var commit = try Commit.init(allocator, io, tmp.dir, &workspace, &outputs, &.{}, &mutations);
    defer commit.deinit();

    // matching hard link != restored captured basename
    try fs.hardLinkInTmp(allocator, &tmp, ".zift-work/backups/0", "foo.bin");
    const backup_guard = commit.backups.items[0].guard.?;
    try std.testing.expect(!guardedObjectPathIdentityAndBasenameMatches(
        allocator,
        io,
        tmp.dir,
        "Foo.bin",
        backup_guard,
    ));
    try std.testing.expect(guardedObjectPathIdentityAndBasenameMatches(
        allocator,
        io,
        tmp.dir,
        "foo.bin",
        backup_guard,
    ));

    try commit.rollback();
    const restored = try tmp.dir.readFileAlloc(io, "Foo.bin", allocator, .limited(9));
    try std.testing.expectEqualStrings("original", restored);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/backups/0", .{}));
    try std.testing.expectEqual(@as(u64, 1), (try backup_guard.stat(io)).nlink);

    var root = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer root.close(io);
    var iterator = root.iterate();
    var restored_name: ?[]const u8 = null;
    while (try iterator.next(io)) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, "foo.bin")) {
            restored_name = entry.name;
            break;
        }
    }
    try std.testing.expect(restored_name != null);
    try std.testing.expectEqualStrings("Foo.bin", restored_name.?);
}

test "guarded replacement mismatch retains its staged object until rollback" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };

    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();
    outputs[0].path = "other.bin";
    try std.testing.expectError(
        error.GuardedTargetMismatch,
        commit.publish(0),
    );
    try std.testing.expect(outputs[0].state == .staged);
    try commit.rollback();
    try std.testing.expect(outputs[0].state == .consumed);

    const restored = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(4));
    try std.testing.expectEqualStrings("old", restored);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "other.bin", .{}));
}

test "guarded replacement refuses a changed POSIX staging binding" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "expected", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };

    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();
    try tmp.dir.rename(
        ".zift-work/staged/new.bin",
        tmp.dir,
        ".zift-work/staged/moved.bin",
        io,
    );
    try tmp.dir.writeFile(io, .{ .sub_path = ".zift-work/staged/new.bin", .data = "sentinel" });

    try std.testing.expectError(
        error.StagingBindingChanged,
        commit.publish(0),
    );
    try std.testing.expect(outputs[0].state == .staged);
    try commit.rollback();
    try std.testing.expect(outputs[0].state == .consumed);

    const restored = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(4));
    // readFileAlloc rejects a reached limit; 8-byte sentinel needs limit 9
    const sentinel = try tmp.dir.readFileAlloc(io, ".zift-work/staged/new.bin", allocator, .limited(9));
    try std.testing.expectEqualStrings("old", restored);
    try std.testing.expectEqualStrings("sentinel", sentinel);
}

test "guarded rollback closes every staged object before restoration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();

    try commit.rollback();
    try std.testing.expect(outputs[0].state == .consumed);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/staged/new.bin", .{}));
    } else {
        try tmp.dir.deleteFile(io, ".zift-work/staged/new.bin");
    }
    const restored = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(4));
    try std.testing.expectEqualStrings("old", restored);
}

test "guarded rollback preserves a destination raced in before publication" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();

    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "sentinel" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        commit.publish(0),
    );
    try std.testing.expect(outputs[0].state == .staged);
    try commit.rollback();
    try std.testing.expect(outputs[0].state == .consumed);

    const sentinel = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(9));
    try std.testing.expectEqualStrings("sentinel", sentinel);
}

test "guarded rollback preserves both raced sentinel and unrestored backup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "original" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();

    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "sentinel" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        commit.publish(0),
    );
    try std.testing.expectError(error.RollbackConflict, commit.rollback());
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const sentinel = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(9));
    const backup = try tmp.dir.readFileAlloc(io, ".zift-work/backups/0", allocator, .limited(9));
    try std.testing.expectEqualStrings("sentinel", sentinel);
    try std.testing.expectEqualStrings("original", backup);
    _ = try tmp.dir.statFile(io, ".zift-work/backups/RECOVERY_REQUIRED", .{});
}

test "guarded rollback quarantines an earlier publication before restoring backups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "one.bin", .data = "old one" });
    var first = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/one.bin");
    try first.writePositionalAll(io, "new one", 0);
    try first.sync(io);
    var second = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/two.bin");
    try second.writePositionalAll(io, "new two", 0);
    try second.sync(io);
    var outputs = [_]Output{
        .{ .path = "one.bin", .work_rel = ".zift-work/staged/one.bin", .size = try first.length(io), .state = .{ .staged = first } },
        .{ .path = "two.bin", .work_rel = ".zift-work/staged/two.bin", .size = try second.length(io), .state = .{ .staged = second } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{ "one.bin", "two.bin" },
        &.{},
        &outputs,
    );
    defer commit.deinit();

    try commit.publish(0);
    try std.testing.expect(outputs[0].state == .published);
    try tmp.dir.writeFile(io, .{ .sub_path = "two.bin", .data = "sentinel" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        commit.publish(1),
    );
    try commit.rollback();
    try std.testing.expect(outputs[0].state == .consumed);
    try std.testing.expect(outputs[1].state == .consumed);
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const one = try tmp.dir.readFileAlloc(io, "one.bin", allocator, .limited(8));
    const two = try tmp.dir.readFileAlloc(io, "two.bin", allocator, .limited(9));
    try std.testing.expectEqualStrings("old one", one);
    try std.testing.expectEqualStrings("sentinel", two);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, default_work_root, .{}));
}

test "guarded rollback removes its created parents before restoring a blocking file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "original" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "a/b", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"a/b"},
        &.{"a"},
        &outputs,
    );
    defer commit.deinit();

    try commit.publish(0);
    try commit.rollback();
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const restored = try tmp.dir.readFileAlloc(io, "a", allocator, .limited(9));
    try std.testing.expectEqualStrings("original", restored);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, default_work_root, .{}));
}

test "guarded directory rollback preserves a raced child and original backup" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "original" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "a/b", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"a/b"},
        &.{"a"},
        &outputs,
    );
    defer commit.deinit();
    try commit.publish(0);
    try tmp.dir.writeFile(io, .{ .sub_path = "a/sentinel", .data = "keep" });

    try std.testing.expectError(error.RollbackConflict, commit.rollback());
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const sentinel = try tmp.dir.readFileAlloc(io, "a/sentinel", allocator, .limited(5));
    const backup = try tmp.dir.readFileAlloc(io, ".zift-work/backups/0", allocator, .limited(9));
    try std.testing.expectEqualStrings("keep", sentinel);
    try std.testing.expectEqualStrings("original", backup);
    _ = try tmp.dir.statFile(io, ".zift-work/backups/RECOVERY_REQUIRED", .{});
}

test "guarded publication stays pinned until finish on Windows" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        std.testing.allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();
    try commit.publish(0);

    try std.testing.expectError(error.FileBusy, fs.openWrite(io, tmp.dir, "final.bin"));
    try std.testing.expectError(error.FileBusy, tmp.dir.deleteFile(io, "final.bin"));
    try std.testing.expectError(
        error.FileBusy,
        tmp.dir.rename("final.bin", tmp.dir, "moved.bin", io),
    );
    try commit.finish();
    try tmp.dir.deleteFile(io, "final.bin");
}

test "guarded finish disposes only exact backups and preserves a raced private sentinel" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "final.bin", .data = "old" });
    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/new.bin");
    try guarded.writePositionalAll(io, "new", 0);
    try guarded.sync(io);
    var outputs = [_]Output{
        .{ .path = "final.bin", .work_rel = ".zift-work/staged/new.bin", .size = try guarded.length(io), .state = .{ .staged = guarded } },
    };
    var commit = try testingCommit(
        allocator,
        io,
        tmp.dir,
        &workspace,
        &.{"final.bin"},
        &.{},
        &outputs,
    );
    defer commit.deinit();
    try commit.publish(0);
    try tmp.dir.writeFile(io, .{ .sub_path = ".zift-work/backups/sentinel", .data = "keep" });

    try commit.finish();
    testingCleanupWorkspace(io, tmp.dir, &workspace);

    const final = try tmp.dir.readFileAlloc(io, "final.bin", allocator, .limited(4));
    defer allocator.free(final);
    const sentinel = try tmp.dir.readFileAlloc(io, ".zift-work/backups/sentinel", allocator, .limited(5));
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings("new", final);
    try std.testing.expectEqualStrings("keep", sentinel);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work/backups/0", .{}));
}

test "commit rollback restores removals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try workspace.ensureDirectory("staged");
    try tmp.dir.writeFile(io, .{ .sub_path = "change", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "remove", .data = "gone" });
    var staged = try fs.createGuardedOutputBeneath(io, tmp.dir, ".zift-work/staged/change");
    try staged.writePositionalAll(io, "new", 0);
    var outputs = [_]Output{
        .{ .path = "change", .work_rel = ".zift-work/staged/change", .size = try staged.length(io), .state = .{ .staged = staged } },
    };

    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{"change"}, &.{"remove"}, &outputs);
    defer commit.deinit();
    try commit.publish(0);
    try commit.remove("remove");
    try commit.rollback();

    const change = try tmp.dir.readFileAlloc(io, "change", allocator, .limited(4));
    const remove = try tmp.dir.readFileAlloc(io, "remove", allocator, .limited(5));
    try std.testing.expectEqualStrings("old", change);
    try std.testing.expectEqualStrings("gone", remove);
}

test "listed removal treats final symlink as the path itself" {
    if (@import("builtin").target.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var workspace = try testingWorkspace(io, tmp.dir);
    defer workspace.deinit();

    try tmp.dir.writeFile(io, .{ .sub_path = "real", .data = "keep" });
    try tmp.dir.symLink(io, "real", "link", .{});

    const removals = try listedRemovals(allocator, io, tmp.dir, &.{"link"});
    try std.testing.expectEqual(@as(usize, 1), removals.len);
    var outputs: [0]Output = .{};
    var commit = try testingCommit(allocator, io, tmp.dir, &workspace, &.{}, &.{"link"}, &outputs);
    defer commit.deinit();
    try commit.remove("link");
    try commit.finish();

    try std.testing.expect(try @import("../verify.zig").pathAbsent(io, tmp.dir, "link"));
    const real = try tmp.dir.readFileAlloc(io, "real", allocator, .limited(5));
    try std.testing.expectEqualStrings("keep", real);
}

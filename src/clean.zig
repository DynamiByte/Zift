const manifest_mod = @import("core/manifest.zig");
const std = @import("std");
const fs = @import("core/fs.zig");
const builtin = @import("builtin");

const cli = @import("cli.zig");
const clean_policy = @import("clean_policy.zig");
const ui = @import("ui.zig");
const integrations = @import("integrations.zig");
const verify = @import("verify.zig");

pub const Extra = struct {
    path: []const u8,
    size: u64,
    snapshot: ?Snapshot = null,
};

pub const Snapshot = struct {
    kind: std.Io.File.Kind,
    size: u64,
    inode: std.Io.File.INode,
    mtime: std.Io.Timestamp,
    ctime: std.Io.Timestamp,

    fn fromStat(stat: std.Io.File.Stat) Snapshot {
        return .{
            .kind = stat.kind,
            .size = stat.size,
            .inode = stat.inode,
            .mtime = stat.mtime,
            .ctime = stat.ctime,
        };
    }

    fn matches(self: Snapshot, stat: std.Io.File.Stat) bool {
        return stat.kind == self.kind and
            stat.size == self.size and
            stat.inode == self.inode and
            stat.mtime.nanoseconds == self.mtime.nanoseconds and
            stat.ctime.nanoseconds == self.ctime.nanoseconds;
    }
};

pub const TemporaryDirectory = struct {
    path: []const u8,
    snapshot: Snapshot,
};

pub const Plan = struct {
    extras: []Extra,
    total_size: u64,
};

const Scope = enum { normal, complete };

const PolicyContext = struct {
    // null = generic mode, no deletion authority
    view: ?integrations.InstallView,
    scope: Scope,
    user_authority: bool = false,
    overlays: []const []const u8 = &.{},
};

const PolicyPlan = struct {
    removals: []Extra,
    removal_size: u64,
    candidate_count: usize,
    candidate_size: u64,
};

const CachePolicyPlan = struct {
    removals: []TemporaryDirectory,
    candidate_count: usize,
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    complete: bool,
    assume_yes: bool,
    verify_md5: bool,
    out: *std.Io.Writer,
) !void {
    const detected = (integrations.detect(io, directory) catch |err| return reportCleanAccessError(out, directory, err)) orelse {
        try ui.warning(out);
        try out.writeAll("Software not supported.");
        try ui.reset(out);
        try out.writeByte('\n');
        return error.Reported;
    };
    const view = integrations.inspectInstall(allocator, io, detected.software, directory) catch |err|
        return integrations.reportExpectedError(out, detected.software, directory, err);
    const complete_active = hasCompleteActiveView(view);
    const authoritative_expected = hasAuthoritativeExpected(view);
    if (!authoritative_expected and verify_md5) {
        try ui.writeErrorPrefix(out);
        try out.writeAll(" hash verification is unavailable for this installation\n");
        return error.Reported;
    }
    if (!complete_active) {
        try ui.writeWarningLine(out, "No complete manifest found; report only.");
        try out.writeByte('\n');
    }

    const expected: manifest_mod.Set = if (view.state) |state| state.expected else emptyExpected();
    const context = authorizedContext(view, if (complete) .complete else .normal);
    var scanning: ui.Progress = .{ .io = io, .writer = out, .label = "Scanning", .indeterminate = true };
    try scanning.start();
    errdefer scanning.abort();
    const p = planWithPolicy(allocator, io, directory, context, &scanning) catch |err| {
        scanning.abort();
        return reportCleanAccessError(out, directory, err);
    };
    try scanning.finish();
    const temp_paths = if (complete and context.view != null) integrations.cleanTemporaryDirectories(allocator, io, detected.software, directory) catch |err| return reportCleanAccessError(out, directory, err) else &.{};
    const cache_plan = planCachesWithPolicy(allocator, io, directory, context, temp_paths) catch |err| return reportCleanAccessError(out, directory, err);
    const report_only = !complete_active;

    try ui.writeHeading(out, "Clean:");
    try out.writeByte('\n');
    try ui.writeField(out, "    Software:", detected.name());
    if (trustedIdentity(view)) |version| try ui.writeField(out, "    Version:", version.full);
    try ui.writeField(out, "    Directory:", directory);
    try ui.writeField(out, "    Scope:", if (complete) "Complete" else "StreamingAssets");
    try out.writeByte('\n');
    try ui.writeCountSize(
        out,
        if (report_only) "Candidate files found:" else "Files to remove:",
        if (report_only) p.candidate_count else p.removals.len,
        if (report_only) p.candidate_size else p.removal_size,
    );
    if (complete) try ui.writeCount(
        out,
        if (report_only) "Cache directories found:" else "Directories to remove:",
        if (report_only) cache_plan.candidate_count else cache_plan.removals.len,
    );

    if (report_only) {
        try out.writeByte('\n');
        try ui.writeSuccessLine(out, "Complete!");
        return;
    }

    if (p.removals.len == 0 and cache_plan.removals.len == 0) {
        var had_errors = false;
        try out.writeByte('\n');
        try ui.writeSuccessLine(out, "Nothing to clean.");
        if (authoritative_expected) {
            try out.writeByte('\n');
            had_errors = checkOrVerify(allocator, io, directory, expected, verify_md5, out) catch |err| return reportCleanAccessError(out, directory, err);
        }
        try out.writeByte('\n');
        try ui.complete(out, had_errors);
        return;
    }

    if (!try cli.confirm(allocator, io, out, assume_yes)) return error.Aborted;
    try out.flush();

    var had_errors = false;
    var root = try std.Io.Dir.cwd().openDir(io, directory, .{ .access_sub_paths = true });
    var operation: ui.Operation = .{ .io = io, .writer = out };
    defer operation.stop();
    defer root.close(io);

    if (p.removals.len != 0) {
        var progress: ui.Progress = .{
            .io = io,
            .writer = out,
            .label = "Cleaning",
            .total_bytes = p.removal_size,
            .total_files = p.removals.len,
            .operation = &operation,
        };
        try progress.start();
        errdefer progress.abort();
        had_errors = try deletePlanned(io, root, p.removals, &progress) or had_errors;
        try progress.finish();
    }
    if (cache_plan.removals.len != 0) {
        var progress: ui.Progress = .{
            .io = io,
            .writer = out,
            .label = "Cleaning",
            .total_files = cache_plan.removals.len,
            .item_label = "directories",
            .operation = &operation,
        };
        try progress.start();
        errdefer progress.abort();
        for (cache_plan.removals) |path| {
            deleteTreeNoSymlinkAncestors(io, root, path) catch |err| {
                if (err == error.Canceled) return err;
                had_errors = true;
                try progress.fileError("Cleaning", path.path, err);
            };
            try progress.finishFile();
        }
        try progress.finish();
    }

    if (authoritative_expected) had_errors = (checkOrVerify(allocator, io, directory, expected, verify_md5, out) catch |err| return reportCleanAccessError(out, directory, err)) or had_errors;
    try out.writeByte('\n');
    try ui.complete(out, had_errors);
}

fn deletePlanned(io: std.Io, root: std.Io.Dir, extras: []const Extra, progress: *ui.Progress) !bool {
    var had_errors = false;
    for (extras) |extra| {
        deleteOneExtra(io, root, extra) catch |err| {
            if (err == error.Canceled) return err;
            had_errors = true;
            try progress.fileError("Cleaning", extra.path, err);
            try progress.finishFile();
            continue;
        };
        try progress.addBytes(extra.size);
        try progress.finishFile();
    }
    return had_errors;
}

fn reportCleanAccessError(out: *std.Io.Writer, directory: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.AccessDenied, error.ReadOnlyFileSystem, error.FileNotFound, error.NotDir, error.IsDir => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" cannot access directory for cleaning\n") catch return err;
            ui.writeField(out, "Directory:", directory) catch return err;
            return error.Reported;
        },
        error.FileChangedDuringClean => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" file changed during cleaning; skipped\n") catch return err;
            return error.Reported;
        },
        else => return err,
    }
}

fn emptyExpected() manifest_mod.Set {
    return .{ .entries = &.{}, .map = .empty };
}

fn hasCompleteActiveView(view: integrations.InstallView) bool {
    return if (view.state) |state| state.managed_set_complete else false;
}

fn hasAuthoritativeExpected(view: integrations.InstallView) bool {
    const state = view.state orelse return false;
    return state.managed_set_complete and state.digest_authority == .authoritative;
}

fn trustedIdentity(view: integrations.InstallView) ?integrations.Version {
    if (!view.integration.identity_trustworthy) return null;
    return view.identity;
}

fn expectedFor(context: PolicyContext) ?manifest_mod.Set {
    const view = context.view orelse return null;
    const state = view.state orelse return null;
    return state.expected;
}

fn authorizedContext(view: integrations.InstallView, scope: Scope) PolicyContext {
    return .{
        .view = if (view.state != null) view else null,
        .scope = scope,
        .user_authority = true,
    };
}

fn inSelectedFileScope(context: PolicyContext, path: []const u8) bool {
    if (context.scope == .complete) return true;
    const view = context.view orelse return false;
    return integrations.normalCleanFilter(view.integration.software)(path);
}

fn pathFacts(context: PolicyContext, path: []const u8) clean_policy.PathFacts {
    const view = context.view orelse return .{
        .managed = false,
        .runtime_state = false,
        .overlay = false,
    };
    const software = view.integration.software;
    const expected = expectedFor(context);
    return .{
        // metadata preservation even when omitted from vendor file lists
        .managed = (if (expected) |set| set.contains(path) else false) or integrations.isMetadataPath(software, path),
        .runtime_state = integrations.ignoreFilter(software)(path),
        .overlay = isActiveOverlay(context, path),
    };
}

fn isActiveOverlay(context: PolicyContext, path: []const u8) bool {
    for (context.overlays) |raw_prefix| {
        const prefix = std.mem.trimEnd(u8, raw_prefix, "/");
        if (prefix.len != 0 and isAtOrBelow(path, prefix)) return true;
    }
    return false;
}

fn ordinaryVerdict(context: PolicyContext, path: []const u8) clean_policy.Verdict {
    const in_scope = inSelectedFileScope(context, path);
    const capabilities: clean_policy.Capabilities = if (context.view) |view| blk: {
        const managed_state_available = view.state != null;
        break :blk .{
            .integration_basis = managed_state_available,
            .managed_set_complete = hasCompleteActiveView(view),
            .software_permits_removals = view.integration.deletion_ever_allowed,
            .user_authority = context.user_authority and in_scope,
        };
    } else .{
        .integration_basis = false,
        .managed_set_complete = false,
        .software_permits_removals = false,
        .user_authority = false,
    };
    return clean_policy.evaluate(.{ .capabilities = capabilities, .path = pathFacts(context, path) });
}

fn planWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    context: PolicyContext,
    progress: ?*ui.Progress,
) !PolicyPlan {
    var dir = try std.Io.Dir.cwd().openDir(io, directory, .{ .iterate = true, .access_sub_paths = true });
    defer dir.close(io);

    var removals: std.ArrayList(Extra) = .empty;
    var removal_size: u64 = 0;
    var candidate_count: usize = 0;
    var candidate_size: u64 = 0;
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var logical_buf: [std.fs.max_path_bytes]u8 = undefined;

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const rel = try logicalPathFromWalkPath(entry.path, &logical_buf);
        const stat = try entry.dir.statFile(io, entry.basename, .{ .follow_symlinks = false });
        if (stat.kind != .file) continue;
        if (progress) |p| {
            try p.finishFile();
        }

        const facts = pathFacts(context, rel);
        const in_scope = inSelectedFileScope(context, rel);
        if (in_scope and !facts.managed and !facts.runtime_state and !facts.overlay) {
            candidate_count += 1;
            candidate_size +|= stat.size;
        }

        const verdict = ordinaryVerdict(context, rel);
        if (!verdict.authorizesDeletion()) continue;
        const extra: Extra = .{
            .path = try allocator.dupe(u8, rel),
            .size = stat.size,
            .snapshot = .fromStat(stat),
        };
        try removals.append(allocator, extra);
        removal_size +|= stat.size;
    }

    return .{
        .removals = try removals.toOwnedSlice(allocator),
        .removal_size = removal_size,
        .candidate_count = candidate_count,
        .candidate_size = candidate_size,
    };
}

pub fn plan(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    expected: manifest_mod.Set,
    candidate: *const fn ([]const u8) bool,
    progress: ?*ui.Progress,
) !Plan {
    var dir = try std.Io.Dir.cwd().openDir(io, directory, .{ .iterate = true, .access_sub_paths = true });
    defer dir.close(io);

    var extras: std.ArrayList(Extra) = .empty;
    var total_size: u64 = 0;

    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var logical_buf: [std.fs.max_path_bytes]u8 = undefined;

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;

        const rel = try logicalPathFromWalkPath(entry.path, &logical_buf);
        const stat = try entry.dir.statFile(io, entry.basename, .{ .follow_symlinks = false });
        if (stat.kind != .file) continue;
        if (progress) |p| {
            try p.addBytes(stat.size);
            try p.finishFile();
        }

        if (expected.contains(rel)) continue;
        if (!candidate(rel)) continue;

        try extras.append(allocator, .{ .path = try allocator.dupe(u8, rel), .size = stat.size, .snapshot = .fromStat(stat) });
        total_size +|= stat.size;
    }

    return .{
        .extras = try extras.toOwnedSlice(allocator),
        .total_size = total_size,
    };
}

fn logicalPathFromWalkPath(path: []const u8, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
    if (builtin.target.os.tag != .windows or std.mem.indexOfScalar(u8, path, '\\') == null) return path;
    if (path.len > buffer.len) return error.PathTooLongForZip;
    @memcpy(buffer[0..path.len], path);
    const logical = buffer[0..path.len];
    std.mem.replaceScalar(u8, logical, '\\', '/');
    return logical;
}

pub fn deleteExtrasProgress(
    io: std.Io,
    directory: []const u8,
    extras: []const Extra,
    progress: ?*ui.Progress,
) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, directory, .{ .access_sub_paths = true });
    defer dir.close(io);

    for (extras) |extra| {
        try deleteOneExtra(io, dir, extra);
        if (progress) |p| {
            try p.addBytes(extra.size);
            try p.finishFile();
        }
    }
}

fn deleteOneExtra(io: std.Io, root: std.Io.Dir, extra: Extra) !void {
    const snapshot = extra.snapshot orelse return error.InvalidCleanPlan;
    var parent = fs.openParentBeneath(io, root, extra.path) catch |err| switch (err) {
        error.FileNotFound => null,
        error.PathAncestorNotDirectory, error.UnsafePathAncestor => return error.FileChangedDuringClean,
        else => |e| return e,
    };
    if (parent) |*bound| {
        defer bound.close(io);
        const current = bound.dir.statFile(io, bound.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => null,
            else => |e| return e,
        };
        if (current) |revalidated| {
            if (!snapshot.matches(revalidated)) return error.FileChangedDuringClean;
            if (revalidated.kind != .file) return error.FileChangedDuringClean;
            try bound.dir.deleteFile(io, bound.basename);
        }
    }
}

pub fn planTemporaryDirectories(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    paths: []const []const u8,
) ![]TemporaryDirectory {
    var dir = try std.Io.Dir.cwd().openDir(io, directory, .{ .access_sub_paths = true });
    defer dir.close(io);

    var planned: std.ArrayList(TemporaryDirectory) = .empty;
    for (paths) |path| {
        var parent = try fs.openParentBeneath(io, dir, path);
        defer parent.close(io);
        const stat = parent.dir.statFile(io, parent.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => continue,
            else => |e| return e,
        };
        if (stat.kind != .directory) return error.FileChangedDuringClean;
        try planned.append(allocator, .{ .path = path, .snapshot = .fromStat(stat) });
    }
    return planned.toOwnedSlice(allocator);
}

fn isAtOrBelow(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len > root.len and path[root.len] == '/' and std.mem.startsWith(u8, path, root));
}

fn cacheContainsManagedState(view: integrations.InstallView, path: []const u8) bool {
    const state = view.state orelse return false;
    for (state.expected.entries) |entry| {
        if (isAtOrBelow(entry.path, path)) return true;
    }
    for (state.metadata) |metadata| {
        if (isAtOrBelow(metadata.path, path)) return true;
    }
    return false;
}

fn cacheOverlapsOverlay(context: PolicyContext, path: []const u8) bool {
    if (isActiveOverlay(context, path)) return true;
    for (context.overlays) |overlay| {
        if (overlay.len != 0 and isAtOrBelow(overlay, path)) return true;
    }
    return false;
}

fn cacheVerdict(context: PolicyContext, path: []const u8) clean_policy.Verdict {
    const capabilities: clean_policy.Capabilities = if (context.view) |view| blk: {
        const managed_state_available = view.state != null;
        break :blk .{
            .integration_basis = managed_state_available,
            .managed_set_complete = hasCompleteActiveView(view),
            // safe-cache removal authority != unmanaged-file removal authority
            .software_permits_removals = true,
            .user_authority = context.user_authority and context.scope == .complete,
        };
    } else .{
        .integration_basis = false,
        .managed_set_complete = false,
        .software_permits_removals = false,
        .user_authority = false,
    };
    const facts: clean_policy.PathFacts = if (context.view) |view| .{
        .managed = cacheContainsManagedState(view, path),
        // safe-cache classification over runtime preservation
        .runtime_state = false,
        .overlay = cacheOverlapsOverlay(context, path),
    } else .{ .managed = false, .runtime_state = false, .overlay = false };
    return clean_policy.evaluate(.{ .capabilities = capabilities, .path = facts });
}

fn planCachesWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    context: PolicyContext,
    paths: []const []const u8,
) !CachePolicyPlan {
    const candidates = try planTemporaryDirectories(allocator, io, directory, paths);
    defer allocator.free(candidates);
    var removals: std.ArrayList(TemporaryDirectory) = .empty;
    for (candidates) |candidate| {
        const verdict = cacheVerdict(context, candidate.path);
        if (!verdict.authorizesDeletion()) continue;
        try removals.append(allocator, candidate);
    }
    return .{
        .removals = try removals.toOwnedSlice(allocator),
        .candidate_count = candidates.len,
    };
}

pub fn deleteTemporaryDirectories(io: std.Io, directory: []const u8, paths: []const TemporaryDirectory, progress: ?*ui.Progress) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, directory, .{ .access_sub_paths = true });
    defer dir.close(io);
    for (paths) |path| {
        try deleteTreeNoSymlinkAncestors(io, dir, path);
        if (progress) |p| try p.finishFile();
    }
}

fn deleteTreeNoSymlinkAncestors(io: std.Io, root: std.Io.Dir, planned: TemporaryDirectory) !void {
    var parent = fs.openParentBeneath(io, root, planned.path) catch |err| switch (err) {
        error.FileNotFound => return,
        error.PathAncestorNotDirectory, error.UnsafePathAncestor => return error.FileChangedDuringClean,
        else => |e| return e,
    };
    defer parent.close(io);

    const stat = parent.dir.statFile(io, parent.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        error.NotDir => return error.FileChangedDuringClean,
        else => |e| return e,
    };
    if (!planned.snapshot.matches(stat)) return error.FileChangedDuringClean;

    try parent.dir.deleteTree(io, parent.basename);
}

fn checkOrVerify(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    expected: manifest_mod.Set,
    verify_md5: bool,
    out: *std.Io.Writer,
) !bool {
    var check_progress: ui.Progress = .{
        .io = io,
        .writer = out,
        .label = "Checking",
        .total_bytes = 0,
        .total_files = expected.entries.len,
    };
    try check_progress.start();
    errdefer check_progress.abort();
    const check_failures = try verify.sizeProblems(allocator, io, directory, expected.entries, &check_progress);
    defer allocator.free(check_failures);
    try check_progress.finish();
    for (check_failures) |failure| try verify.printFailure(out, failure);
    if (check_failures.len != 0) {
        try ui.warning(out);
        try out.print("Check found {d} problem", .{check_failures.len});
        if (check_failures.len != 1) try out.writeByte('s');
        try out.writeAll(".");
        try ui.reset(out);
        try out.writeByte('\n');
    }

    if (!verify_md5) return check_failures.len != 0;

    var verify_progress: ui.Progress = .{
        .io = io,
        .writer = out,
        .label = "Verifying",
        .total_bytes = verify.totalSize(expected),
        .total_files = expected.entries.len,
        .show_speed = true,
    };
    try verify_progress.start();
    errdefer verify_progress.abort();
    const verify_failures = try verify.hashProblems(allocator, io, directory, expected.entries, &verify_progress);
    defer allocator.free(verify_failures);
    try verify_progress.finish();
    for (verify_failures) |failure| try verify.printFailure(out, failure);
    if (verify_failures.len != 0) {
        try ui.warning(out);
        try out.print("Verify found {d} problem", .{verify_failures.len});
        if (verify_failures.len != 1) try out.writeByte('s');
        try out.writeAll(".");
        try ui.reset(out);
        try out.writeByte('\n');
    }
    return check_failures.len != 0 or verify_failures.len != 0;
}

test "clean continues past a replaced file and reports verification errors" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "changed", .data = "before" });
    try tmp.dir.writeFile(io, .{ .sub_path = "junk", .data = "junk" });
    const extras = [_]Extra{
        .{ .path = "changed", .size = 6, .snapshot = .fromStat(try tmp.dir.statFile(io, "changed", .{})) },
        .{ .path = "junk", .size = 4, .snapshot = .fromStat(try tmp.dir.statFile(io, "junk", .{})) },
    };
    try tmp.dir.writeFile(io, .{ .sub_path = "changed", .data = "replaced" });
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    var progress: ui.Progress = .{ .io = io, .writer = &output.writer, .label = "Cleaning" };
    try std.testing.expect(try deletePlanned(io, tmp.dir, &extras, &progress));
    const kept = try tmp.dir.readFileAlloc(io, "changed", a, .limited(16));
    defer a.free(kept);
    try std.testing.expectEqualStrings("replaced", kept);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "junk", .{}));
    var expected = [_]manifest_mod.File{.{ .path = "missing", .size = 1, .md5 = @splat(0) }};
    const path = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer a.free(path);
    try std.testing.expect(try checkOrVerify(a, io, path, .{ .entries = &expected, .map = .empty }, true, &output.writer));
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "missing is missing") != null);
}

test "clean does not delete a file replaced after planning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "stale", .data = "old" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const p = try plan(allocator, io, root, .{ .entries = &.{}, .map = .empty }, struct {
        fn candidate(_: []const u8) bool {
            return true;
        }
    }.candidate, null);
    try std.testing.expectEqual(@as(usize, 1), p.extras.len);

    try tmp.dir.deleteFile(io, "stale");
    try tmp.dir.writeFile(io, .{ .sub_path = "stale", .data = "new" });
    try std.testing.expectError(error.FileChangedDuringClean, deleteExtrasProgress(io, root, p.extras, null));

    const bytes = try tmp.dir.readFileAlloc(io, "stale", allocator, .limited(4));
    try std.testing.expectEqualStrings("new", bytes);
}

test "clean does not delete a file modified after planning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "stale", .data = "old" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const p = try plan(allocator, io, root, .{ .entries = &.{}, .map = .empty }, struct {
        fn candidate(_: []const u8) bool {
            return true;
        }
    }.candidate, null);
    try std.testing.expectEqual(@as(usize, 1), p.extras.len);

    {
        var file = try fs.openWrite(io, tmp.dir, "stale");
        defer file.close(io);
        try file.writePositionalAll(io, "new", 0);
        // coarse timestamps: +2s for deterministic snapshot mismatch
        const planned = p.extras[0].snapshot.?;
        try file.setTimestamps(io, .{
            .modify_timestamp = .{ .new = .fromNanoseconds(planned.mtime.nanoseconds + 2 * std.time.ns_per_s) },
        });
    }
    try std.testing.expectError(error.FileChangedDuringClean, deleteExtrasProgress(io, root, p.extras, null));

    const bytes = try tmp.dir.readFileAlloc(io, "stale", allocator, .limited(4));
    try std.testing.expectEqualStrings("new", bytes);
}

test "clean refuses a replacement reached through a changed ancestor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "tree");
    try tmp.dir.writeFile(io, .{ .sub_path = "tree/stale", .data = "old" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const p = try plan(allocator, io, root, .{ .entries = &.{}, .map = .empty }, struct {
        fn candidate(path: []const u8) bool {
            return std.mem.eql(u8, path, "tree/stale");
        }
    }.candidate, null);
    try std.testing.expectEqual(@as(usize, 1), p.extras.len);

    try tmp.dir.rename("tree", tmp.dir, "original_tree", io);
    try tmp.dir.createDirPath(io, "tree");
    try tmp.dir.writeFile(io, .{ .sub_path = "tree/stale", .data = "new" });

    try std.testing.expectError(error.FileChangedDuringClean, deleteExtrasProgress(io, root, p.extras, null));
    try std.testing.expectEqualStrings("new", try tmp.dir.readFileAlloc(io, "tree/stale", allocator, .limited(4)));
    try std.testing.expectEqualStrings("old", try tmp.dir.readFileAlloc(io, "original_tree/stale", allocator, .limited(4)));
}

test "temporary clean refuses a directory under a replaced ancestor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "Game_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "Game_Data/SDKCaches/original", .data = "old" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const planned = try planTemporaryDirectories(allocator, io, root, &.{"Game_Data/SDKCaches"});

    try tmp.dir.rename("Game_Data", tmp.dir, "original_Game_Data", io);
    try tmp.dir.createDirPath(io, "Game_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "Game_Data/SDKCaches/replacement", .data = "new" });

    try std.testing.expectError(error.FileChangedDuringClean, deleteTemporaryDirectories(io, root, planned, null));
    try std.testing.expectEqualStrings("new", try tmp.dir.readFileAlloc(io, "Game_Data/SDKCaches/replacement", allocator, .limited(4)));
    try std.testing.expectEqualStrings("old", try tmp.dir.readFileAlloc(io, "original_Game_Data/SDKCaches/original", allocator, .limited(4)));
}

test "temporary directory deletion does not traverse symlink ancestors" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "Game_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "Game_Data/SDKCaches/planned", .data = "planned" });
    try tmp.dir.createDirPath(io, "outside/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/SDKCaches/keep", .data = "keep" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const planned = try planTemporaryDirectories(allocator, io, root, &.{"Game_Data/SDKCaches"});
    try std.testing.expectEqual(@as(usize, 1), planned.len);

    try tmp.dir.rename("Game_Data", tmp.dir, "original_Game_Data", io);
    try tmp.dir.symLink(io, "outside", "Game_Data", .{ .is_directory = true });

    try std.testing.expectError(error.FileChangedDuringClean, deleteTemporaryDirectories(io, root, planned, null));
    const bytes = try tmp.dir.readFileAlloc(io, "outside/SDKCaches/keep", allocator, .limited(5));
    try std.testing.expectEqualStrings("keep", bytes);
    const original = try tmp.dir.readFileAlloc(io, "original_Game_Data/SDKCaches/planned", allocator, .limited(8));
    try std.testing.expectEqualStrings("planned", original);
}

test "complete clean without an authoritative manifest is report only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero.exe", .data = "" });
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/Persistent");
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/Persistent/save.bin", .data = "save" });
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/SDKCaches/cache.bin", .data = "cache" });
    try tmp.dir.writeFile(io, .{ .sub_path = "unmanaged.bin", .data = "unmanaged" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try run(allocator, io, root, true, true, false, &output.writer);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output.written(), "report only"));
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "No complete manifest found; report only.") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "no changes were made") == null);
    try std.testing.expectEqualStrings("save", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/Persistent/save.bin", allocator, .limited(5)));
    try std.testing.expectEqualStrings("cache", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/SDKCaches/cache.bin", allocator, .limited(6)));
    try std.testing.expectEqualStrings("unmanaged", try tmp.dir.readFileAlloc(io, "unmanaged.bin", allocator, .limited(10)));
}

test "cache directory deletion preserves Endfield VFS and WuWa resources" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "Endfield_Data/Persistent/VFS");
        try tmp.dir.writeFile(io, .{ .sub_path = "Endfield_Data/Persistent/VFS/resource.pak", .data = "resource" });
        try tmp.dir.createDirPath(io, "Endfield_Data/SDKCaches");
        try tmp.dir.writeFile(io, .{ .sub_path = "Endfield_Data/SDKCaches/cache.bin", .data = "cache" });
        const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        const candidates = try integrations.cleanTemporaryDirectories(allocator, io, .endfield, root);
        const planned = try planTemporaryDirectories(allocator, io, root, candidates);
        try std.testing.expectEqual(@as(usize, 1), planned.len);
        try deleteTemporaryDirectories(io, root, planned, null);
        try std.testing.expectEqualStrings("resource", try tmp.dir.readFileAlloc(io, "Endfield_Data/Persistent/VFS/resource.pak", allocator, .limited(9)));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Endfield_Data/SDKCaches/cache.bin", .{}));
    }

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "Client/Saved/Resources");
        try tmp.dir.writeFile(io, .{ .sub_path = "Client/Saved/Resources/resource.pak", .data = "resource" });
        try tmp.dir.createDirPath(io, "Client/Saved/PSO");
        try tmp.dir.writeFile(io, .{ .sub_path = "Client/Saved/PSO/cache.bin", .data = "cache" });
        try tmp.dir.createDirPath(io, "launcherDownload");
        try tmp.dir.writeFile(io, .{ .sub_path = "launcherDownload/download.pak", .data = "download" });
        const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        const candidates = try integrations.cleanTemporaryDirectories(allocator, io, .wuwa, root);
        const planned = try planTemporaryDirectories(allocator, io, root, candidates);
        try std.testing.expectEqual(@as(usize, 1), planned.len);
        try deleteTemporaryDirectories(io, root, planned, null);
        try std.testing.expectEqualStrings("resource", try tmp.dir.readFileAlloc(io, "Client/Saved/Resources/resource.pak", allocator, .limited(9)));
        try std.testing.expectEqualStrings("download", try tmp.dir.readFileAlloc(io, "launcherDownload/download.pak", allocator, .limited(9)));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Client/Saved/PSO/cache.bin", .{}));
    }
}

fn testingExpected(allocator: std.mem.Allocator, paths: []const []const u8) !manifest_mod.Set {
    const entries = try allocator.alloc(manifest_mod.File, paths.len);
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    try map.ensureTotalCapacity(allocator, @intCast(paths.len));
    for (paths, 0..) |path, index| {
        entries[index] = .{ .path = path, .size = 0, .md5 = @splat(0) };
        map.putAssumeCapacity(path, @intCast(index));
    }
    return .{ .entries = entries, .map = map };
}

fn syntheticView(
    software: integrations.Software,
    managed_set: integrations.ManagedSet,
    expected: manifest_mod.Set,
) integrations.InstallView {
    const definition = integrations.integration(software);
    const available = managed_set != .unavailable;
    const state: ?integrations.State = if (available) .{
        .expected = expected,
        .metadata = &.{},
        .manifest_format = definition.manifest_format,
        .manifest_schema = definition.manifest_schema,
        .digest_authority = definition.digest_authority,
        .managed_set_complete = managed_set == .complete,
    } else null;
    return .{
        .integration = definition,
        .state = state,
    };
}

fn testingRoot(allocator: std.mem.Allocator, tmp: *const std.testing.TmpDir) ![]const u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
}

fn executePolicyPlan(
    io: std.Io,
    root: []const u8,
    files: PolicyPlan,
    caches: CachePolicyPlan,
) !void {
    try deleteExtrasProgress(io, root, files.removals, null);
    try deleteTemporaryDirectories(io, root, caches.removals, null);
}

test "normal and Complete Clean enforce scope and preserve managed runtime overlays and manifests" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/StreamingAssets/Mods");
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/StreamingAssets/managed.bin", .data = "managed" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/StreamingAssets/stale.bin", .data = "stale" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/StreamingAssets/Mods/overlay.bin", .data = "overlay" });
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/Persistent");
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/Persistent/save.bin", .data = "save" });
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero_Data/SDKCaches/cache.bin", .data = "cache" });
    try tmp.dir.writeFile(io, .{ .sub_path = "pkg_version", .data = "manifest" });
    try tmp.dir.writeFile(io, .{ .sub_path = "root-stale.bin", .data = "root" });

    const root = try testingRoot(allocator, &tmp);
    const expected = try testingExpected(allocator, &.{"ZenlessZoneZero_Data/StreamingAssets/managed.bin"});
    const overlays = [_][]const u8{"ZenlessZoneZero_Data/StreamingAssets/Mods"};
    const view = syntheticView(.zzz, .complete, expected);

    const normal_context: PolicyContext = .{ .view = view, .scope = .normal, .user_authority = true, .overlays = &overlays };
    const normal_files = try planWithPolicy(allocator, io, root, normal_context, null);
    const normal_caches = try planCachesWithPolicy(allocator, io, root, normal_context, &.{"ZenlessZoneZero_Data/SDKCaches"});
    try std.testing.expectEqual(@as(usize, 1), normal_files.removals.len);
    try std.testing.expectEqual(@as(usize, 0), normal_caches.removals.len);
    try executePolicyPlan(io, root, normal_files, normal_caches);

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "ZenlessZoneZero_Data/StreamingAssets/stale.bin", .{}));
    try std.testing.expectEqualStrings("root", try tmp.dir.readFileAlloc(io, "root-stale.bin", allocator, .limited(5)));
    try std.testing.expectEqualStrings("managed", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/StreamingAssets/managed.bin", allocator, .limited(8)));
    try std.testing.expectEqualStrings("overlay", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/StreamingAssets/Mods/overlay.bin", allocator, .limited(8)));
    try std.testing.expectEqualStrings("save", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/Persistent/save.bin", allocator, .limited(5)));
    try std.testing.expectEqualStrings("manifest", try tmp.dir.readFileAlloc(io, "pkg_version", allocator, .limited(9)));
    try std.testing.expectEqualStrings("cache", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/SDKCaches/cache.bin", allocator, .limited(6)));

    const complete_context: PolicyContext = .{ .view = view, .scope = .complete, .user_authority = true, .overlays = &overlays };
    const complete_files = try planWithPolicy(allocator, io, root, complete_context, null);
    const complete_caches = try planCachesWithPolicy(allocator, io, root, complete_context, &.{"ZenlessZoneZero_Data/SDKCaches"});
    try std.testing.expectEqual(@as(usize, 1), complete_files.removals.len);
    try std.testing.expectEqual(@as(usize, 1), complete_caches.removals.len);
    try executePolicyPlan(io, root, complete_files, complete_caches);

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "root-stale.bin", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "ZenlessZoneZero_Data/SDKCaches", .{}));
    try std.testing.expectEqualStrings("managed", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/StreamingAssets/managed.bin", allocator, .limited(8)));
    try std.testing.expectEqualStrings("overlay", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/StreamingAssets/Mods/overlay.bin", allocator, .limited(8)));
    try std.testing.expectEqualStrings("save", try tmp.dir.readFileAlloc(io, "ZenlessZoneZero_Data/Persistent/save.bin", allocator, .limited(5)));
    try std.testing.expectEqualStrings("manifest", try tmp.dir.readFileAlloc(io, "pkg_version", allocator, .limited(9)));
}

test "missing advisory partial and generic Clean plans are destructive no-ops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const expected = try testingExpected(allocator, &.{});
    const contexts = [_]struct { name: []const u8, context: PolicyContext, verdict: clean_policy.Verdict, candidates: usize }{
        .{ .name = "manifest missing", .context = authorizedContext(syntheticView(.zzz, .unavailable, expected), .complete), .verdict = .generic_no_basis, .candidates = 2 },
        .{ .name = "without operation authority", .context = .{ .view = syntheticView(.zzz, .complete, expected), .scope = .complete }, .verdict = .no_authority, .candidates = 1 },
        .{ .name = "partial managed set", .context = .{ .view = syntheticView(.zzz, .partial, expected), .scope = .complete, .user_authority = true }, .verdict = .set_incomplete, .candidates = 1 },
        .{ .name = "generic no basis", .context = .{ .view = null, .scope = .complete }, .verdict = .generic_no_basis, .candidates = 2 },
    };
    try std.testing.expect(contexts[0].context.view == null);
    try std.testing.expectEqual(clean_policy.Verdict.generic_no_basis, ordinaryVerdict(contexts[0].context, "pkg_version"));
    try std.testing.expectEqual(clean_policy.PathFacts{
        .managed = false,
        .runtime_state = false,
        .overlay = false,
    }, pathFacts(contexts[0].context, "Game_Data/SDKCaches/cache.bin"));

    for (contexts) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "stale.bin", .data = "keep" });
        try tmp.dir.createDirPath(io, "Game_Data/SDKCaches");
        try tmp.dir.writeFile(io, .{ .sub_path = "Game_Data/SDKCaches/cache.bin", .data = "cache" });
        const root = try testingRoot(allocator, &tmp);
        const files = try planWithPolicy(allocator, io, root, case.context, null);
        const cache_paths: []const []const u8 = if (case.context.view == null) &.{} else &.{"Game_Data/SDKCaches"};
        const caches = try planCachesWithPolicy(allocator, io, root, case.context, cache_paths);
        errdefer std.debug.print("failed non-destructive Clean profile: {s}\n", .{case.name});
        try std.testing.expectEqual(case.verdict, ordinaryVerdict(case.context, "stale.bin"));
        try std.testing.expectEqual(case.candidates, files.candidate_count);
        if (case.context.view == null) try std.testing.expectEqual(@as(usize, 0), caches.candidate_count);
        try std.testing.expectEqual(@as(usize, 0), files.removals.len);
        try std.testing.expectEqual(@as(usize, 0), caches.removals.len);
        try executePolicyPlan(io, root, files, caches);
        try std.testing.expectEqualStrings("keep", try tmp.dir.readFileAlloc(io, "stale.bin", allocator, .limited(5)));
        try std.testing.expectEqualStrings("cache", try tmp.dir.readFileAlloc(io, "Game_Data/SDKCaches/cache.bin", allocator, .limited(6)));
    }
}

test "advisory digest view can authorize membership removal but never content verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "stale.bin", .data = "stale" });
    const root = try testingRoot(allocator, &tmp);
    const expected = try testingExpected(allocator, &.{});

    var view = syntheticView(.zzz, .complete, expected);
    var state = view.state.?;
    state.digest_authority = .advisory;
    view.state = state;
    try std.testing.expect(hasCompleteActiveView(view));
    try std.testing.expect(!hasAuthoritativeExpected(view));

    const context: PolicyContext = .{ .view = view, .scope = .complete, .user_authority = true };
    try std.testing.expectEqual(clean_policy.Verdict.removable, ordinaryVerdict(context, "stale.bin"));
    const files = try planWithPolicy(allocator, io, root, context, null);
    try std.testing.expectEqual(@as(usize, 1), files.removals.len);
    try deleteExtrasProgress(io, root, files.removals, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "stale.bin", .{}));
}

test "version display accepts only trustworthy available identity" {
    const expected = emptyExpected();
    var untrusted = syntheticView(.wuwa, .complete, expected);
    untrusted.identity = .{ .full = "post-launch", .parts = null };
    try std.testing.expectEqual(@as(?integrations.Version, null), trustedIdentity(untrusted));

    const unavailable = syntheticView(.zzz, .complete, expected);
    try std.testing.expectEqual(@as(?integrations.Version, null), trustedIdentity(unavailable));

    var trusted = unavailable;
    trusted.identity = .{ .full = "pristine", .parts = null };
    try std.testing.expectEqualStrings("pristine", trustedIdentity(trusted).?.full);
}

test "Endfield Complete Clean removes only explicit cache while WuWa permits ordinary removal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const expected = try testingExpected(allocator, &.{});

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "unknown.bin", .data = "unknown" });
        try tmp.dir.createDirPath(io, "Endfield_Data/Persistent/VFS");
        try tmp.dir.writeFile(io, .{ .sub_path = "Endfield_Data/Persistent/VFS/resource.pak", .data = "resource" });
        try tmp.dir.createDirPath(io, "Endfield_Data/SDKCaches");
        try tmp.dir.writeFile(io, .{ .sub_path = "Endfield_Data/SDKCaches/cache.bin", .data = "cache" });
        const root = try testingRoot(allocator, &tmp);
        const context: PolicyContext = .{ .view = syntheticView(.endfield, .complete, expected), .scope = .complete, .user_authority = true };
        const files = try planWithPolicy(allocator, io, root, context, null);
        const caches = try planCachesWithPolicy(allocator, io, root, context, &.{"Endfield_Data/SDKCaches"});
        try std.testing.expectEqual(@as(usize, 0), files.removals.len);
        try std.testing.expectEqual(@as(usize, 1), caches.removals.len);
        try executePolicyPlan(io, root, files, caches);
        try std.testing.expectEqualStrings("unknown", try tmp.dir.readFileAlloc(io, "unknown.bin", allocator, .limited(8)));
        try std.testing.expectEqualStrings("resource", try tmp.dir.readFileAlloc(io, "Endfield_Data/Persistent/VFS/resource.pak", allocator, .limited(9)));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Endfield_Data/SDKCaches", .{}));
    }

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "unknown.bin", .data = "unknown" });
        try tmp.dir.createDirPath(io, "Client/Saved/Resources");
        try tmp.dir.writeFile(io, .{ .sub_path = "Client/Saved/Resources/resource.pak", .data = "resource" });
        try tmp.dir.createDirPath(io, "launcherDownload");
        try tmp.dir.writeFile(io, .{ .sub_path = "launcherDownload/download.pak", .data = "download" });
        try tmp.dir.createDirPath(io, "Client/Saved/PSO");
        try tmp.dir.writeFile(io, .{ .sub_path = "Client/Saved/PSO/cache.bin", .data = "cache" });
        const root = try testingRoot(allocator, &tmp);
        const context: PolicyContext = .{ .view = syntheticView(.wuwa, .complete, expected), .scope = .complete, .user_authority = true };
        const files = try planWithPolicy(allocator, io, root, context, null);
        const caches = try planCachesWithPolicy(allocator, io, root, context, &.{"Client/Saved/PSO"});
        try std.testing.expectEqual(@as(usize, 1), files.removals.len);
        try std.testing.expectEqual(@as(usize, 1), caches.removals.len);
        try executePolicyPlan(io, root, files, caches);
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "unknown.bin", .{}));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Client/Saved/PSO", .{}));
        try std.testing.expectEqualStrings("resource", try tmp.dir.readFileAlloc(io, "Client/Saved/Resources/resource.pak", allocator, .limited(9)));
        try std.testing.expectEqualStrings("download", try tmp.dir.readFileAlloc(io, "launcherDownload/download.pak", allocator, .limited(9)));
    }
}

test "managed and overlay descendants block recursive cache deletion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "Managed_Data/SDKCaches");
    try tmp.dir.writeFile(io, .{ .sub_path = "Managed_Data/SDKCaches/managed.bin", .data = "managed" });
    try tmp.dir.createDirPath(io, "Overlay_Data/SDKCaches/user-overlay");
    try tmp.dir.writeFile(io, .{ .sub_path = "Overlay_Data/SDKCaches/user-overlay/keep.bin", .data = "overlay" });
    const root = try testingRoot(allocator, &tmp);
    const expected = try testingExpected(allocator, &.{"Managed_Data/SDKCaches/managed.bin"});
    const overlays = [_][]const u8{"Overlay_Data/SDKCaches/user-overlay"};
    const context: PolicyContext = .{
        .view = syntheticView(.endfield, .complete, expected),
        .scope = .complete,
        .user_authority = true,
        .overlays = &overlays,
    };
    const caches = try planCachesWithPolicy(
        allocator,
        io,
        root,
        context,
        &.{ "Managed_Data/SDKCaches", "Overlay_Data/SDKCaches" },
    );
    try std.testing.expectEqual(@as(usize, 2), caches.candidate_count);
    try std.testing.expectEqual(@as(usize, 0), caches.removals.len);
    try deleteTemporaryDirectories(io, root, caches.removals, null);
    try std.testing.expectEqualStrings("managed", try tmp.dir.readFileAlloc(io, "Managed_Data/SDKCaches/managed.bin", allocator, .limited(8)));
    try std.testing.expectEqualStrings("overlay", try tmp.dir.readFileAlloc(io, "Overlay_Data/SDKCaches/user-overlay/keep.bin", allocator, .limited(8)));
}

test "active overlays use exact component boundaries only" {
    const context: PolicyContext = .{ .view = null, .scope = .complete, .overlays = &.{ "mods/live", "hotfix", "Mods/" } };
    try std.testing.expect(isActiveOverlay(context, "mods/live"));
    try std.testing.expect(isActiveOverlay(context, "mods/live/data.bin"));
    try std.testing.expect(isActiveOverlay(context, "hotfix/a"));
    try std.testing.expect(!isActiveOverlay(context, "mods/lively/data.bin"));
    try std.testing.expect(!isActiveOverlay(context, "hotfix-old/a"));
    try std.testing.expect(isActiveOverlay(context, "Mods/overlay.pak"));
    try std.testing.expect(!isActiveOverlay(context, "Modship/overlay.pak"));
}

const transaction = @import("transaction.zig");
const manifest_mod = @import("../core/manifest.zig");
const std = @import("std");
const builtin = @import("builtin");

const activity = @import("../activity.zig");
const integrity_run = @import("integrity_run.zig");
const clean = @import("../clean.zig");
const delta = @import("../delta.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const integrations = @import("../integrations.zig");
const interrupt = @import("../interrupt.zig");
const hdiff = @import("../hdiff.zig");
const fs = @import("../core/fs.zig");
const ids = @import("../core/ids.zig");
const path_util = @import("../path.zig");
const storage = @import("../storage.zig");
const verify = @import("../verify.zig");
const tar_zstd = @import("../archive/tar.zig");
const zip = @import("../archive/zip.zig");

pub fn apply(
    allocator: std.mem.Allocator,
    io: std.Io,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
) !void {
    var counters: integrity_run.Counters = .{};
    return applyTracked(
        allocator,
        io,
        delta_path,
        directory_path,
        assume_yes,
        verify_md5,
        force,
        out,
        &counters,
    );
}

pub fn applyTracked(
    allocator: std.mem.Allocator,
    io: std.Io,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
    counters: *integrity_run.Counters,
) !void {
    const parent_path = std.fs.path.dirname(delta_path) orelse ".";
    const container_path = std.fs.path.basename(delta_path);
    var container_dir = std.Io.Dir.cwd().openDir(io, parent_path, .{}) catch |err| return reportInspectionError(out, delta_path, err);
    defer container_dir.close(io);
    return applyTrackedFromDir(
        allocator,
        io,
        container_dir,
        container_path,
        delta_path,
        directory_path,
        assume_yes,
        verify_md5,
        force,
        out,
        counters,
    );
}

// retained archive handle for reads; pathname diagnostic only
pub fn applyTrackedFromDir(
    allocator: std.mem.Allocator,
    io: std.Io,
    container_dir: std.Io.Dir,
    container_path: []const u8,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
    counters: *integrity_run.Counters,
) !void {
    var file = fs.openReadContentAuthority(io, container_dir, container_path) catch |err| return reportInspectionError(out, delta_path, err);
    defer file.close(io);
    const archive_size = (file.stat(io) catch |err| return reportInspectionError(out, delta_path, err)).size;
    var magic: [4]u8 = undefined;
    const got = file.readPositionalAll(io, &magic, 0) catch |err| return reportInspectionError(out, delta_path, err);
    if (got != magic.len) return reportInspectionError(out, delta_path, error.UnexpectedEof);
    if (isZstdFrameStart(std.mem.readInt(u32, &magic, .little))) {
        return applyStandardTar(allocator, io, file, archive_size, delta_path, directory_path, assume_yes, verify_md5, force, out, counters);
    }

    var buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const archive = zip.readCentral(allocator, &reader) catch |err| return reportInspectionError(out, delta_path, err);
    return applyStandardZip(allocator, io, archive_size, delta_path, directory_path, assume_yes, verify_md5, force, out, archive, &reader, counters);
}

fn isZstdFrameStart(magic: u32) bool {
    return magic == 0xfd2fb528 or magic & 0xfffffff0 == 0x184d2a50;
}

const StandardMethod = enum { file_delta, hdiff };
const StandardControls = struct {
    method: StandardMethod,
    hdiff_paths: []const []const u8,
    removals: []const []const u8,
};

const Target = transaction.Output;

const StagedGuard = struct {
    file: std.Io.File,
    md5: [16]u8,
    path: []const u8,
};

const Stage = struct {
    errors: u64 = 0,
    targets: []Target,
    removals: []const []const u8,

    fn paths(self: Stage, allocator: std.mem.Allocator) ![]const []const u8 {
        const result = try allocator.alloc([]const u8, self.targets.len);
        for (self.targets, result) |target, *path| path.* = target.path;
        return result;
    }

    fn discardGuards(self: *Stage, io: std.Io) void {
        for (self.targets) |*target| target.discard(io) catch {};
    }
};

fn discardWorkspaceGuard(io: std.Io, guard: std.Io.File) void {
    discardWorkspaceGuardRequired(io, guard) catch {};
}

fn discardWorkspaceGuardRequired(io: std.Io, guard: std.Io.File) !void {
    if (builtin.target.os.tag == .windows) {
        try fs.discardOpenObjectWindows(io, guard);
    } else {
        // posix: no exact unlink-by-handle; private-path cleanup after close
        guard.close(io);
    }
}
const PackageState = struct { software: integrations.Software, state: integrations.State };
const StandardIdentity = struct { detected: integrations.Detected, source_version: ?integrations.Version, target_version: ?integrations.Version };
const HdiffSourceBinding = struct {
    identity: fs.ObjectIdentity,
    size: u64,
    digest: ids.Digest,
};
const HdiffSourcePlan = struct {
    path: []const u8,
    binding: union(enum) { ready: HdiffSourceBinding, failed: anyerror },
    target_size: u64,

    fn source(self: HdiffSourcePlan) !HdiffSourceBinding {
        return switch (self.binding) {
            .ready => |binding| binding,
            .failed => |err| err,
        };
    }
};
const StandardSpacePlan = struct {
    required: u64,
    sources: []const HdiffSourcePlan,
};

fn reportSourceProblems(out: *std.Io.Writer, sources: []const HdiffSourcePlan) !void {
    for (sources) |source| switch (source.binding) {
        .ready => {},
        .failed => |err| try ui.fileError(out, "Skipping unusable HDiff source", source.path, err),
    };
}

fn authoritativeTargetMd5(package: ?PackageState, path: []const u8) ?[16]u8 {
    const state = if (package) |value| value.state else return null;
    if (state.digest_authority != .authoritative) return null;
    const expected = state.expected.find(path) orelse return null;
    return expected.md5;
}

fn rejectPrimaryManifestDirectory(software: integrations.Software, path: []const u8) !void {
    if (integrations.isPrimaryManifestPath(software, path)) return error.InvalidExpectedState;
}

fn readStandardZipControls(allocator: std.mem.Allocator, reader: *std.Io.File.Reader, archive: zip.Archive) !StandardControls {
    const hdiff_entry = archive.find("hdifffiles.txt") orelse {
        const deletion_entry = archive.find(delta.file_delta_deletion_path) orelse
            return .{ .method = .file_delta, .hdiff_paths = &.{}, .removals = &.{} };
        const removals = try parseDeletionList(allocator, try zip.extractEntryAlloc(allocator, reader, deletion_entry, 64 * 1024 * 1024));
        return .{ .method = .file_delta, .hdiff_paths = &.{}, .removals = removals };
    };
    if (archive.find(delta.file_delta_deletion_path) != null) return error.InvalidDeltaLayout;
    const deletion_entry = archive.find("deletefiles.txt") orelse return error.MissingDeletionList;
    const paths = try parseHdiffList(allocator, try zip.extractEntryAlloc(allocator, reader, hdiff_entry, 64 * 1024 * 1024));
    const removals = try parseDeletionList(allocator, try zip.extractEntryAlloc(allocator, reader, deletion_entry, 64 * 1024 * 1024));
    return .{ .method = .hdiff, .hdiff_paths = paths, .removals = removals };
}

fn packageStateZip(allocator: std.mem.Allocator, reader: *std.Io.File.Reader, archive: zip.Archive, detected: ?integrations.Detected) !?PackageState {
    const value = detected orelse return null;
    for (archive.directories) |path| try rejectPrimaryManifestDirectory(value.software, path);
    for (archive.entries) |entry| {
        if (integrations.isPrimaryManifestPath(value.software, entry.path)) break;
    } else return null;

    var files: std.ArrayList(manifest_mod.MetadataFile) = .empty;
    for (archive.entries) |entry| {
        if (!integrations.isMetadataPath(value.software, entry.path)) continue;
        try files.append(allocator, .{
            .path = entry.path,
            .bytes = try zip.extractEntryAlloc(allocator, reader, entry, 128 * 1024 * 1024),
        });
    }
    return .{ .software = value.software, .state = try integrations.loadExpectedMetadata(allocator, value.software, try files.toOwnedSlice(allocator)) };
}

fn standardIdentityZip(allocator: std.mem.Allocator, io: std.Io, directory_path: []const u8, reader: *std.Io.File.Reader, archive: zip.Archive, detected_value: ?integrations.Detected) !?StandardIdentity {
    const detected = detected_value orelse return null;
    if (!integrations.integration(detected.software).identity_trustworthy) {
        return .{ .detected = detected, .source_version = null, .target_version = null };
    }
    const source_version = try integrations.detectVersionBestEffort(allocator, io, detected.software, directory_path);
    var target_version: ?integrations.Version = null;
    for (archive.entries) |entry| {
        if (!integrations.isPackagedVersionPath(detected.software, entry.path) or entry.zip_entry.uncompressed_size > 1024 * 1024) continue;
        const bytes = try zip.extractEntryAlloc(allocator, reader, entry, 1024 * 1024);
        target_version = try integrations.detectPackagedVersion(allocator, detected.software, entry.path, bytes);
        if (target_version != null) break;
    }
    return .{ .detected = detected, .source_version = source_version, .target_version = target_version };
}

fn isStandardControl(method: StandardMethod, path: []const u8) bool {
    return switch (method) {
        .file_delta => std.mem.eql(u8, path, delta.file_delta_deletion_path),
        .hdiff => std.mem.eql(u8, path, "hdifffiles.txt") or std.mem.eql(u8, path, "deletefiles.txt"),
    };
}

fn standardTargetPath(method: StandardMethod, hdiff_set: std.StringHashMapUnmanaged(void), archive_path: []const u8) ?[]const u8 {
    if (method != .hdiff or !std.mem.endsWith(u8, archive_path, ".hdiff")) return null;
    const target = archive_path[0 .. archive_path.len - ".hdiff".len];
    return if (hdiff_set.contains(target)) target else null;
}

const StandardPathLayout = struct {
    representability_paths: [][]const u8,
    effective_removals: [][]const u8,
};

const StandardPathEntry = struct {
    target: ?[]const u8 = null,
    removal: ?[]const u8 = null,
    expected: ?[]const u8 = null,
};

const StandardWindowsPathMap = std.HashMapUnmanaged(
    []const u8,
    StandardPathEntry,
    path_util.WindowsCaseContext,
    std.hash_map.default_max_load_percentage,
);

fn standardDestinationLayout(
    allocator: std.mem.Allocator,
    targets: []const []const u8,
    removals: []const []const u8,
    expected: []const manifest_mod.File,
    windows_semantics: bool,
) !StandardPathLayout {
    if (windows_semantics) for (targets) |target| for (removals) |removal| {
        if ((transaction.pathIsAncestor(target, removal, true) and !transaction.pathIsAncestor(target, removal, false)) or
            (transaction.pathIsAncestor(removal, target, true) and !transaction.pathIsAncestor(removal, target, false))) return error.InvalidDeltaLayout;
    };

    var representability: std.ArrayList([]const u8) = .empty;
    errdefer representability.deinit(allocator);
    var effective_removals: std.ArrayList([]const u8) = .empty;
    errdefer effective_removals.deinit(allocator);

    if (windows_semantics) {
        var paths: StandardWindowsPathMap = .empty;
        defer paths.deinit(allocator);
        for (targets) |path| {
            if (!path_util.windowsPathCompatible(path)) return error.InvalidDeltaLayout;
            const got = try paths.getOrPut(allocator, path);
            if (got.found_existing and got.value_ptr.target != null) return error.InvalidDeltaLayout;
            if (!got.found_existing) got.value_ptr.* = .{};
            got.value_ptr.target = path;
            try representability.append(allocator, path);
        }
        for (removals) |path| {
            if (!path_util.windowsPathCompatible(path)) return error.InvalidDeltaLayout;
            const got = try paths.getOrPut(allocator, path);
            if (!got.found_existing) got.value_ptr.* = .{};
            if (got.value_ptr.removal != null or got.value_ptr.expected != null) return error.InvalidDeltaLayout;
            if (got.value_ptr.target) |target| {
                if (std.mem.eql(u8, target, path)) return error.InvalidDeltaLayout;
                // case-only rename: deleting the old alias would delete the output
            } else {
                try effective_removals.append(allocator, path);
                try representability.append(allocator, path);
            }
            got.value_ptr.removal = path;
        }
        for (expected) |file| {
            const path = file.path;
            if (!path_util.windowsPathCompatible(path)) return error.InvalidDeltaLayout;
            const got = try paths.getOrPut(allocator, path);
            if (!got.found_existing) got.value_ptr.* = .{};
            if (got.value_ptr.expected != null) return error.InvalidDeltaLayout;
            if (got.value_ptr.target) |target| {
                if (!std.mem.eql(u8, target, path)) return error.InvalidDeltaLayout;
            } else {
                if (got.value_ptr.removal) |removal| {
                    if (!std.mem.eql(u8, removal, path)) return error.InvalidDeltaLayout;
                } else try representability.append(allocator, path);
            }
            if (got.value_ptr.removal != null and
                got.value_ptr.target != null and !std.mem.eql(u8, got.value_ptr.target.?, path))
                return error.InvalidDeltaLayout;
            got.value_ptr.expected = path;
        }
    } else {
        var paths: std.StringHashMapUnmanaged(StandardPathEntry) = .empty;
        defer paths.deinit(allocator);
        for (targets) |path| {
            try path_util.validate(path);
            const got = try paths.getOrPut(allocator, path);
            if (got.found_existing) return error.InvalidDeltaLayout;
            got.value_ptr.* = .{ .target = path };
            try representability.append(allocator, path);
        }
        for (removals) |path| {
            try path_util.validate(path);
            const got = try paths.getOrPut(allocator, path);
            if (got.found_existing) return error.InvalidDeltaLayout;
            got.value_ptr.* = .{ .removal = path };
            try effective_removals.append(allocator, path);
            try representability.append(allocator, path);
        }
        for (expected) |file| {
            const path = file.path;
            try path_util.validate(path);
            const got = try paths.getOrPut(allocator, path);
            if (got.found_existing) {
                if (got.value_ptr.expected != null)
                    return error.InvalidDeltaLayout;
                got.value_ptr.expected = path;
            } else {
                got.value_ptr.* = .{ .expected = path };
                try representability.append(allocator, path);
            }
        }
    }

    return .{
        .representability_paths = try representability.toOwnedSlice(allocator),
        .effective_removals = try effective_removals.toOwnedSlice(allocator),
    };
}

fn standardTargetPaths(allocator: std.mem.Allocator, entries: anytype, controls: StandardControls) ![]const []const u8 {
    const scratch = std.heap.smp_allocator;
    var hdiff_set = try pathSet(scratch, controls.hdiff_paths);
    defer hdiff_set.deinit(scratch);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    var paths: std.ArrayList([]const u8) = .empty;
    for (entries) |entry| {
        if (isStandardControl(controls.method, entry.path)) continue;
        const target = standardTargetPath(controls.method, hdiff_set, entry.path) orelse entry.path;
        const got = try seen.getOrPut(scratch, target);
        if (got.found_existing) return error.InvalidDeltaLayout;
        got.value_ptr.* = {};
        try paths.append(allocator, target);
    }
    for (controls.hdiff_paths) |path| if (!seen.contains(path)) return error.MissingHDiffEntry;
    return paths.toOwnedSlice(allocator);
}

const RepeatedObservation = enum { first, second };

fn repeatedObservationMajority(
    first: []const u8,
    second: []const u8,
    third: ?[]const u8,
) !RepeatedObservation {
    if (std.mem.eql(u8, first, second)) return .first;
    const deciding = third orelse return error.Md5Mismatch;
    if (std.mem.eql(u8, first, deciding)) return .first;
    if (std.mem.eql(u8, second, deciding)) return .second;
    return error.Md5Mismatch;
}

fn adjudicatedRepeatedObservationMajority(
    first: []const u8,
    second: []const u8,
    third: []const u8,
    counters: *integrity_run.Counters,
) !RepeatedObservation {
    if (std.mem.eql(u8, first, second)) return .first;
    const selected = repeatedObservationMajority(first, second, third) catch |err| {
        counters.consistencyReread(.unresolved);
        return err;
    };
    counters.consistencyReread(.resolved);
    return selected;
}

fn confirmedZipHdiffPrefix(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    entry: zip.Entry,
    counters: *integrity_run.Counters,
) ![]u8 {
    const first = try zip.extractEntryPrefixAlloc(allocator, reader, entry, hdiff.info_prefix_size);
    errdefer allocator.free(first);
    const second = try zip.extractEntryPrefixAlloc(allocator, reader, entry, hdiff.info_prefix_size);
    errdefer allocator.free(second);
    if (std.mem.eql(u8, first, second)) {
        allocator.free(second);
        return first;
    }
    const third = zip.extractEntryPrefixAlloc(allocator, reader, entry, hdiff.info_prefix_size) catch |err| {
        counters.consistencyReread(.failed);
        return err;
    };
    defer allocator.free(third);
    return switch (try adjudicatedRepeatedObservationMajority(first, second, third, counters)) {
        .first => blk: {
            allocator.free(second);
            break :blk first;
        },
        .second => blk: {
            allocator.free(first);
            break :blk second;
        },
    };
}

fn zipSpaceRequired(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    reader: *std.Io.File.Reader,
    archive: zip.Archive,
    controls: StandardControls,
    package: ?PackageState,
    counters: *integrity_run.Counters,
    progress: ?*ui.Progress,
) !StandardSpacePlan {
    const scratch = std.heap.smp_allocator;
    var hdiff_set = try pathSet(scratch, controls.hdiff_paths);
    defer hdiff_set.deinit(scratch);
    var sources: std.ArrayList(HdiffSourcePlan) = .empty;
    errdefer sources.deinit(allocator);

    var staged: u64 = 0;
    var peak: u64 = 0;
    for (archive.entries) |entry| {
        if (isStandardControl(controls.method, entry.path)) {
            if (progress) |value| try value.finishFile();
            continue;
        }
        if (standardTargetPath(controls.method, hdiff_set, entry.path)) |target| {
            const prefix = try confirmedZipHdiffPrefix(scratch, reader, entry, counters);
            const info = hdiff.infoPrefix(prefix) catch |err| {
                scratch.free(prefix);
                return err;
            };
            scratch.free(prefix);
            const source_binding: @FieldType(HdiffSourcePlan, "binding") = binding: {
                const value = captureHdiffSourceBinding(io, directory, target, info.source_size, counters) catch |err| {
                    if (err == error.Canceled or err == error.OutOfMemory or err == error.Interrupted) return err;
                    break :binding .{ .failed = err };
                };
                break :binding .{ .ready = value };
            };
            try sources.append(allocator, .{
                .path = target,
                .binding = source_binding,
                .target_size = info.target_size,
            });
            const target_copies: u64 = if (authoritativeTargetMd5(package, target) != null) 2 else 4;
            staged +|= entry.zip_entry.uncompressed_size *| 2;
            staged +|= info.target_size *| target_copies;
            peak = @max(peak, staged);
        } else {
            staged +|= entry.zip_entry.uncompressed_size *| 2;
            peak = @max(peak, staged);
        }
        if (progress) |value| try value.finishFile();
    }
    return .{ .required = peak, .sources = try sources.toOwnedSlice(allocator) };
}

fn captureHdiffSourceBinding(
    io: std.Io,
    directory: std.Io.Dir,
    source_rel: []const u8,
    expected_size: u64,
    counters: *integrity_run.Counters,
) !HdiffSourceBinding {
    const first = try observeHdiffSourceBinding(io, directory, source_rel, expected_size);
    const second = try observeHdiffSourceBinding(io, directory, source_rel, expected_size);
    if (hdiffSourceBindingsEqual(first, second)) return first;
    const third = observeHdiffSourceBinding(io, directory, source_rel, expected_size) catch |err| {
        counters.consistencyReread(.failed);
        return err;
    };
    if (hdiffSourceBindingsEqual(first, third)) {
        counters.consistencyReread(.resolved);
        return first;
    }
    if (hdiffSourceBindingsEqual(second, third)) {
        counters.consistencyReread(.resolved);
        return second;
    }
    counters.consistencyReread(.unresolved);
    return error.SourcePathConflict;
}

fn observeHdiffSourceBinding(
    io: std.Io,
    directory: std.Io.Dir,
    source_rel: []const u8,
    expected_size: u64,
) !HdiffSourceBinding {
    var source = fs.openReadBeneath(io, directory, source_rel) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.SourcePathConflict,
        else => |e| return e,
    };
    defer source.close(io);
    return observeOpenHdiffSourceBinding(io, source, expected_size);
}

fn observeOpenHdiffSourceBinding(
    io: std.Io,
    source: std.Io.File,
    expected_size: u64,
) !HdiffSourceBinding {
    const before_stat = try source.stat(io);
    if (before_stat.kind != .file or before_stat.size != expected_size) return error.SourcePathConflict;
    const before_identity = try fs.openFileIdentity(source);

    var hasher = std.crypto.hash.Blake3.init(.{});
    var offset: u64 = 0;
    var buffer: [1024 * 1024]u8 = undefined;
    while (true) {
        try interrupt.check();
        const count = try fs.readAllAt(io, source, &buffer, offset);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    const after_stat = try source.stat(io);
    const after_identity = try fs.openFileIdentity(source);
    if (after_stat.kind != .file or
        before_stat.size != offset or
        after_stat.size != offset or
        !before_identity.eql(after_identity))
        return error.SourcePathConflict;

    var digest: ids.Digest = undefined;
    hasher.final(&digest.bytes);
    return .{ .identity = before_identity, .size = offset, .digest = digest };
}

fn openHdiffSourceAuthority(
    io: std.Io,
    directory: std.Io.Dir,
    source_rel: []const u8,
    expected: HdiffSourceBinding,
    counters: *integrity_run.Counters,
) !std.Io.File {
    var source = fs.openReadAuthorityBeneath(io, directory, source_rel) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.ExpectedFile => return error.SourcePathConflict,
        else => |other| return other,
    };
    errdefer source.close(io);

    const first = try observeOpenHdiffSourceBinding(io, source, expected.size);
    const second = try observeOpenHdiffSourceBinding(io, source, expected.size);
    const actual = if (hdiffSourceBindingsEqual(first, second)) first else blk: {
        const third = observeOpenHdiffSourceBinding(io, source, expected.size) catch |err| {
            counters.consistencyReread(.failed);
            return err;
        };
        if (hdiffSourceBindingsEqual(first, third)) {
            counters.consistencyReread(.resolved);
            break :blk first;
        }
        if (hdiffSourceBindingsEqual(second, third)) {
            counters.consistencyReread(.resolved);
            break :blk second;
        }
        counters.consistencyReread(.unresolved);
        return error.SourcePathConflict;
    };
    if (!hdiffSourceBindingsEqual(actual, expected)) return error.SourcePathConflict;
    return source;
}

fn hdiffSourceBindingsEqual(left: HdiffSourceBinding, right: HdiffSourceBinding) bool {
    return left.size == right.size and
        left.identity.eql(right.identity) and
        left.digest.eql(right.digest);
}

// pathname rebind outside retained-handle interval
fn requireHdiffSourceBinding(
    io: std.Io,
    directory: std.Io.Dir,
    source_rel: []const u8,
    expected: HdiffSourceBinding,
    counters: *integrity_run.Counters,
) !void {
    const actual = try captureHdiffSourceBinding(io, directory, source_rel, expected.size, counters);
    if (!hdiffSourceBindingsEqual(actual, expected))
        return error.SourcePathConflict;
}

fn hdiffSourcePlanFor(
    sources: []const HdiffSourcePlan,
    path: []const u8,
) !HdiffSourcePlan {
    for (sources) |source| {
        if (std.mem.eql(u8, source.path, path)) return source;
    }
    return error.InvalidDeltaLayout;
}

fn validateGuardedHdiffPlan(plan: HdiffSourcePlan, info: hdiff.Info) !void {
    if (info.source_size != (try plan.source()).size) return error.SourcePathConflict;
    if (info.target_size != plan.target_size) return error.Md5Mismatch;
}

const TarEntry = struct {
    path: []const u8,
    size: u64,
    hdiff_prefix: ?[]const u8,
    scan_md5: ?[16]u8,
};

const TarScan = struct {
    entries: []TarEntry,
    controls: StandardControls,
    package: ?PackageState,
    identity: ?StandardIdentity,
};

fn scanStandardTar(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    directory_path: []const u8,
    counters: *integrity_run.Counters,
    progress: ?*ui.Progress,
) !TarScan {
    var stream = try tar_zstd.Stream.initBorrowed(allocator, io, archive_file, 0, archive_size);
    defer stream.deinit();
    var prefix_stream = try tar_zstd.Stream.initBorrowed(allocator, io, archive_file, 0, archive_size);
    defer prefix_stream.deinit();

    const detected = try integrations.detect(io, directory_path);
    const source_version = if (detected) |value|
        if (integrations.integration(value.software).identity_trustworthy)
            try integrations.detectVersionBestEffort(allocator, io, value.software, directory_path)
        else
            null
    else
        null;
    var target_version: ?integrations.Version = null;
    var entries: std.ArrayList(TarEntry) = .empty;
    var metadata: std.ArrayList(manifest_mod.MetadataFile) = .empty;
    var hdiff_bytes: ?[]const u8 = null;
    var hdiff_deletion_bytes: ?[]const u8 = null;
    var file_delta_deletion_bytes: ?[]const u8 = null;

    while (try stream.next()) |file| {
        const prefix_file = (try prefix_stream.next()) orelse return error.InvalidDeltaLayout;
        if (file.kind != prefix_file.kind or
            file.size != prefix_file.size or
            !std.mem.eql(u8, file.name, prefix_file.name))
            return error.InvalidDeltaLayout;
        if (file.kind == .directory) {
            if (file.size != 0) return error.UnsupportedTarEntry;
            if (detected) |value| try rejectPrimaryManifestDirectory(value.software, file.name);
            if (progress) |value| try value.finishFile();
            continue;
        }
        if (file.kind != .file) return error.UnsupportedTarEntry;

        const path = try allocator.dupe(u8, file.name);
        var prefix: ?[]const u8 = null;
        var scan_md5: ?[16]u8 = null;
        if (std.mem.eql(u8, file.name, "hdifffiles.txt")) {
            hdiff_bytes = try stream.readCurrentAlloc(allocator, file, 64 * 1024 * 1024);
            scan_md5 = md5Bytes(hdiff_bytes.?);
        } else if (std.mem.eql(u8, file.name, "deletefiles.txt")) {
            hdiff_deletion_bytes = try stream.readCurrentAlloc(allocator, file, 64 * 1024 * 1024);
            scan_md5 = md5Bytes(hdiff_deletion_bytes.?);
        } else if (std.mem.eql(u8, file.name, delta.file_delta_deletion_path)) {
            file_delta_deletion_bytes = try stream.readCurrentAlloc(allocator, file, 64 * 1024 * 1024);
            scan_md5 = md5Bytes(file_delta_deletion_bytes.?);
        } else if (detected) |value| {
            if (integrations.integration(value.software).identity_trustworthy and
                integrations.isPackagedVersionPath(value.software, file.name) and file.size <= 1024 * 1024)
            {
                const bytes = try stream.readCurrentAlloc(allocator, file, 1024 * 1024);
                scan_md5 = md5Bytes(bytes);
                target_version = try integrations.detectPackagedVersion(allocator, value.software, file.name, bytes);
            } else if (integrations.isMetadataPath(value.software, file.name)) {
                const bytes = try stream.readCurrentAlloc(allocator, file, 128 * 1024 * 1024);
                scan_md5 = md5Bytes(bytes);
                try metadata.append(allocator, .{
                    .path = path,
                    .bytes = bytes,
                });
            } else if (std.mem.endsWith(u8, file.name, ".hdiff")) {
                const observed = try stream.readCurrentPrefixAllocMd5(allocator, file, hdiff.info_prefix_size);
                prefix = observed.bytes;
                scan_md5 = observed.md5;
            }
        } else if (std.mem.endsWith(u8, file.name, ".hdiff")) {
            const observed = try stream.readCurrentPrefixAllocMd5(allocator, file, hdiff.info_prefix_size);
            prefix = observed.bytes;
            scan_md5 = observed.md5;
        }
        if (scan_md5 == null) {
            scan_md5 = try stream.hashCurrentMd5(file, null);
        }
        if (prefix) |first| {
            prefix = try confirmTarHdiffPrefix(
                allocator,
                io,
                archive_file,
                archive_size,
                file,
                prefix_stream,
                prefix_file,
                first,
                counters,
            );
        } else {
            try prefix_stream.discardCurrent(prefix_file);
        }
        try entries.append(allocator, .{
            .path = path,
            .size = file.size,
            .hdiff_prefix = prefix,
            .scan_md5 = scan_md5,
        });
        if (progress) |value| try value.finishFile();
    }
    if (try prefix_stream.next() != null) return error.InvalidDeltaLayout;

    const controls: StandardControls = if (hdiff_bytes) |bytes| blk: {
        if (file_delta_deletion_bytes != null) return error.InvalidDeltaLayout;
        const deletion = hdiff_deletion_bytes orelse return error.MissingDeletionList;
        break :blk .{
            .method = .hdiff,
            .hdiff_paths = try parseHdiffList(allocator, bytes),
            .removals = try parseDeletionList(allocator, deletion),
        };
    } else .{
        .method = .file_delta,
        .hdiff_paths = &.{},
        .removals = if (file_delta_deletion_bytes) |bytes| try parseDeletionList(allocator, bytes) else &.{},
    };

    var package: ?PackageState = null;
    if (detected) |value| {
        for (metadata.items) |file| {
            if (integrations.isPrimaryManifestPath(value.software, file.path)) {
                package = .{
                    .software = value.software,
                    .state = try integrations.loadExpectedMetadata(allocator, value.software, try metadata.toOwnedSlice(allocator)),
                };
                break;
            }
        }
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .controls = controls,
        .package = package,
        .identity = if (detected) |value| .{ .detected = value, .source_version = source_version, .target_version = target_version } else null,
    };
}

fn confirmTarHdiffPrefix(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    wanted: std.tar.Iterator.File,
    prefix_stream: *tar_zstd.Stream,
    prefix_file: std.tar.Iterator.File,
    first: []const u8,
    counters: *integrity_run.Counters,
) ![]const u8 {
    errdefer allocator.free(first);
    const second = try prefix_stream.readCurrentPrefixAlloc(allocator, prefix_file, hdiff.info_prefix_size);
    errdefer allocator.free(second);
    if (std.mem.eql(u8, first, second)) {
        allocator.free(second);
        return first;
    }

    const third = readTarEntryFreshPrefixAlloc(
        allocator,
        io,
        archive_file,
        archive_size,
        wanted,
    ) catch |err| {
        counters.consistencyReread(.failed);
        return err;
    };
    defer allocator.free(third);
    return switch (try adjudicatedRepeatedObservationMajority(first, second, third, counters)) {
        .first => blk: {
            allocator.free(second);
            break :blk first;
        },
        .second => blk: {
            allocator.free(first);
            break :blk second;
        },
    };
}

fn readTarEntryFreshPrefixAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    wanted: std.tar.Iterator.File,
) ![]u8 {
    var stream = try tar_zstd.Stream.initBorrowed(std.heap.smp_allocator, io, archive_file, 0, archive_size);
    defer stream.deinit();
    while (try stream.next()) |file| {
        if (file.kind == .directory) {
            if (file.size != 0) return error.InvalidDeltaLayout;
            continue;
        }
        if (file.kind != .file) return error.InvalidDeltaLayout;
        if (std.mem.eql(u8, file.name, wanted.name)) {
            if (file.size != wanted.size) return error.InvalidDeltaLayout;
            return stream.readCurrentPrefixAlloc(allocator, file, hdiff.info_prefix_size);
        }
        try stream.discardCurrent(file);
    }
    return error.InvalidDeltaLayout;
}

fn md5Bytes(bytes: []const u8) [16]u8 {
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &md5, .{});
    return md5;
}

fn tarSpaceRequired(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    scan: TarScan,
    counters: *integrity_run.Counters,
    progress: ?*ui.Progress,
) !StandardSpacePlan {
    const scratch = std.heap.smp_allocator;
    var hdiff_set = try pathSet(scratch, scan.controls.hdiff_paths);
    defer hdiff_set.deinit(scratch);
    var sources: std.ArrayList(HdiffSourcePlan) = .empty;
    errdefer sources.deinit(allocator);

    var staged: u64 = 0;
    var peak: u64 = 0;
    for (scan.entries) |entry| {
        if (isStandardControl(scan.controls.method, entry.path)) {
            if (progress) |value| try value.finishFile();
            continue;
        }
        if (standardTargetPath(scan.controls.method, hdiff_set, entry.path)) |target| {
            const prefix = entry.hdiff_prefix orelse return error.InvalidHDiff;
            const info = try hdiff.infoPrefix(prefix);
            const source_binding: @FieldType(HdiffSourcePlan, "binding") = binding: {
                const value = captureHdiffSourceBinding(io, directory, target, info.source_size, counters) catch |err| {
                    if (err == error.Canceled or err == error.OutOfMemory or err == error.Interrupted) return err;
                    break :binding .{ .failed = err };
                };
                break :binding .{ .ready = value };
            };
            try sources.append(allocator, .{
                .path = target,
                .binding = source_binding,
                .target_size = info.target_size,
            });
            const target_copies: u64 = if (authoritativeTargetMd5(scan.package, target) != null) 2 else 4;
            staged +|= entry.size *| 2;
            staged +|= info.target_size *| target_copies;
            peak = @max(peak, staged);
        } else {
            staged +|= entry.size *| 2;
            peak = @max(peak, staged);
        }
        if (progress) |value| try value.finishFile();
    }
    return .{ .required = peak, .sources = try sources.toOwnedSlice(allocator) };
}

fn standardPreflight(
    allocator: std.mem.Allocator,
    io: std.Io,
    delta_size: u64,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    method: StandardMethod,
    target_count: usize,
    removal_count: usize,
    identity: ?StandardIdentity,
    space_required: u64,
    force: bool,
    out: *std.Io.Writer,
) !void {
    try ui.writeHeading(out, "Apply delta:");
    try out.writeByte('\n');
    if (identity) |value| {
        try ui.writeField(out, "    Software:", value.detected.name());
        if (value.source_version) |source_version| {
            if (value.target_version) |target_version| try ui.writeDeltaField(out, source_version.full, target_version.full);
        }
    }
    try ui.writeField(out, "    Method:", if (method == .hdiff) "HDiff" else "File Delta");
    try ui.writeField(out, "    File:", delta_path);
    try ui.writeField(out, "    Directory:", directory_path);
    var size_buf: [64]u8 = undefined;
    try out.writeByte('\n');
    try ui.writeField(out, "Size:", try ui.bytes(&size_buf, delta_size));
    try ui.writeCount(out, "Files to write:", target_count);
    try ui.writeCount(out, "Files to remove:", removal_count);
    if (try storage.available(io, directory_path)) |available| {
        var required_buf: [64]u8 = undefined;
        var available_buf: [64]u8 = undefined;
        try ui.writeField(out, "Space required:", try ui.bytes(&required_buf, space_required));
        try ui.writeField(out, "Space available:", try ui.bytes(&available_buf, available));
        if (space_required > available) {
            try out.writeByte('\n');
            if (force) {
                try ui.writeWarningLine(out, "Low disk space; continuing with -f.");
            } else {
                try ui.writeErrorPrefix(out);
                try out.writeAll(" not enough disk space to apply delta\nUse -f to apply anyway.\n");
                return error.Reported;
            }
        }
    }
    if (!try cli.confirm(allocator, io, out, assume_yes)) return error.Aborted;
}

fn applyStandardZip(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_size: u64,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
    archive: zip.Archive,
    reader: *std.Io.File.Reader,
    counters: *integrity_run.Counters,
) !void {
    var controls = readStandardZipControls(allocator, reader, archive) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const detected = integrations.detect(io, directory_path) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const identity = standardIdentityZip(allocator, io, directory_path, reader, archive, detected) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const package = packageStateZip(allocator, reader, archive, detected) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const target_paths = standardTargetPaths(allocator, archive.entries, controls) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const expected_entries: []const manifest_mod.File = if (package) |value| value.state.expected.entries else &.{};
    const path_layout = standardDestinationLayout(allocator, target_paths, controls.removals, expected_entries, builtin.target.os.tag == .windows) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    controls.removals = path_layout.effective_removals;
    validateDestinationPaths(io, directory_path, path_layout.representability_paths, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    validateRemovalPaths(io, directory_path, controls.removals, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    var preflight_directory = std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true }) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer preflight_directory.close(io);
    var checking_operation: ui.Operation = .{ .io = io, .writer = out };
    defer checking_operation.stop();
    var checking: ui.Progress = .{ .io = io, .writer = out, .label = "Checking sources", .total_files = archive.entries.len, .operation = &checking_operation };
    try checking.start();
    const space = zipSpaceRequired(allocator, io, preflight_directory, reader, archive, controls, package, counters, &checking) catch |err| {
        checking.abort();
        return reportApplyError(out, delta_path, directory_path, err);
    };
    try checking.finish();
    try reportSourceProblems(out, space.sources);
    try standardPreflight(allocator, io, archive_size, delta_path, directory_path, assume_yes, controls.method, target_paths.len, controls.removals.len, identity, space.required, force, out);
    try out.flush();

    var workspace = transaction.Workspace.create(allocator, io, preflight_directory, path_layout.representability_paths) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer cleanupArchiveWorkspace(io, preflight_directory, &workspace);
    workspace.ensureDirectory("staged") catch |err| return reportApplyError(out, delta_path, directory_path, err);
    workspace.ensureDirectory("diffs") catch |err| return reportApplyError(out, delta_path, directory_path, err);
    var stage = stageStandardZip(allocator, io, reader, archive, controls, package, space.sources, target_paths.len, directory_path, &workspace, &preflight_directory, out, counters) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer stage.discardGuards(io);
    var mutations = transaction.MutationSet.capture(allocator, io, preflight_directory, try stage.paths(allocator), stage.removals) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer mutations.deinit();
    const had_errors = validateStandardStage(io, directory_path, &preflight_directory, &stage, package, verify_md5, out, counters) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    mutations.validateBindings(preflight_directory) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    commitStage(allocator, io, &workspace, &preflight_directory, &stage, &mutations, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    try out.writeByte('\n');
    if (had_errors or stage.errors != 0) return error.CompletedWithErrors;
}

fn stageGuardedHdiff(
    allocator: std.mem.Allocator,
    io: std.Io,
    progress: *ui.Progress,
    directory: std.Io.Dir,
    workspace: *transaction.Workspace,
    work_rel: []const u8,
    source_rel: []const u8,
    source_binding: HdiffSourceBinding,
    diff_rel: []const u8,
    diff_guard: std.Io.File,
    diff_size: u64,
    target_size: u64,
    authoritative_md5: ?[16]u8,
    counters: *integrity_run.Counters,
) !StagedGuard {
    if (progress.operation) |operation| operation.phase("Reconstructing", target_size, 0);
    var source_authority = try openHdiffSourceAuthority(
        io,
        directory,
        source_rel,
        source_binding,
        counters,
    );
    defer source_authority.close(io);
    const source_input: hdiff.InputPart = .{
        .file = source_authority,
        .size = source_binding.size,
    };
    const diff_input: hdiff.InputPart = .{ .file = diff_guard, .size = diff_size };
    var attempt: u8 = 0;
    while (true) {
        const attempt_rel = try stageAttemptPath(allocator, work_rel, attempt);
        try ensureWorkspaceParent(workspace, attempt_rel);
        const guarded = try fs.createGuardedOutputBeneath(io, directory, attempt_rel);
        var attempt_error: ?anyerror = null;
        var digest_mismatch = false;
        var construction_md5: [16]u8 = undefined;

        if (reconstructGuardedHdiffOnce(
            io,
            progress,
            directory,
            source_rel,
            source_input,
            source_binding,
            diff_input,
            diff_rel,
            diff_guard,
            diff_size,
            guarded,
            target_size,
            counters,
        )) |md5| {
            construction_md5 = md5;
        } else |err| {
            attempt_error = err;
            digest_mismatch = err == error.HDiffOutputHashFailed;
        }
        const manifest_matches = if (attempt_error == null and authoritative_md5 != null)
            std.mem.eql(u8, &construction_md5, &authoritative_md5.?)
        else
            false;
        if (attempt_error == null) {
            verifyGuardedStagePathTwice(
                io,
                directory,
                attempt_rel,
                guarded,
                target_size,
                construction_md5,
                progress,
                counters,
            ) catch |err| {
                attempt_error = err;
                digest_mismatch = isStageDigestMismatch(err);
            };
        }
        if (attempt_error == null and !manifest_matches) {
            const audit_rel = stageIndependentPath(
                std.heap.smp_allocator,
                work_rel,
                attempt,
            ) catch |err| {
                discardWorkspaceGuard(io, guarded);
                return err;
            };
            defer std.heap.smp_allocator.free(audit_rel);
            ensureWorkspaceParent(workspace, audit_rel) catch |err| {
                discardWorkspaceGuard(io, guarded);
                return err;
            };
            var audit_guard: ?std.Io.File = fs.createGuardedOutputBeneath(io, directory, audit_rel) catch |err| {
                discardWorkspaceGuard(io, guarded);
                return err;
            };
            defer if (audit_guard) |guard| discardWorkspaceGuard(io, guard);
            var audit_md5: [16]u8 = undefined;
            if (reconstructGuardedHdiffOnce(
                io,
                null,
                directory,
                source_rel,
                source_input,
                source_binding,
                diff_input,
                diff_rel,
                diff_guard,
                diff_size,
                audit_guard.?,
                target_size,
                counters,
            )) |md5| {
                audit_md5 = md5;
            } else |err| {
                attempt_error = err;
                digest_mismatch = err == error.HDiffOutputHashFailed;
            }
            if (attempt_error == null) {
                verifyGuardedStagePathTwice(
                    io,
                    directory,
                    audit_rel,
                    audit_guard.?,
                    target_size,
                    audit_md5,
                    null,
                    counters,
                ) catch |err| {
                    attempt_error = err;
                    digest_mismatch = isStageDigestMismatch(err);
                };
            }
            if (attempt_error == null and !std.mem.eql(u8, &construction_md5, &audit_md5)) {
                attempt_error = error.Md5Mismatch;
                digest_mismatch = true;
            }
            const consumed_audit = audit_guard.?;
            audit_guard = null;
            discardWorkspaceGuardRequired(io, consumed_audit) catch |err| {
                discardWorkspaceGuard(io, guarded);
                return err;
            };
        }
        if (attempt_error) |err| {
            if (digest_mismatch and takeStageDigestRetry(&attempt, err)) {
                try discardWorkspaceGuardRequired(io, guarded);
                counters.retryStarted();
                continue;
            }
            discardWorkspaceGuard(io, guarded);
            return err;
        }
        if (attempt != 0) counters.retrySucceeded();
        return .{ .file = guarded, .md5 = construction_md5, .path = attempt_rel };
    }
}

fn reconstructGuardedHdiffOnce(
    io: std.Io,
    progress: ?*ui.Progress,
    directory: std.Io.Dir,
    source_rel: []const u8,
    source: hdiff.InputPart,
    source_binding: HdiffSourceBinding,
    diff: hdiff.InputPart,
    diff_rel: []const u8,
    diff_guard: std.Io.File,
    diff_size: u64,
    target: std.Io.File,
    target_size: u64,
    counters: *integrity_run.Counters,
) ![16]u8 {
    var output_hash = hdiff.OutputHash.init(target_size);
    var tracker: hdiff.Progress = .{ .output_hash = &output_hash };
    try requireHdiffSourceBinding(io, directory, source_rel, source_binding, counters);
    try requireGuardedStageBinding(io, directory, diff_rel, diff_guard, diff_size);
    if (progress) |ui_progress| {
        try activity.runTracked(io, ui_progress, .{ .apply_file_at_guarded = .{
            .source = source,
            .container = diff,
            .offset = 0,
            .size = diff_size,
            .target = target,
            .tracker = &tracker,
        } });
    } else {
        try hdiff.applyAtGuardedFiles(
            std.heap.smp_allocator,
            io,
            source,
            diff,
            0,
            diff_size,
            target,
            &tracker,
        );
    }
    try requireGuardedStageBinding(io, directory, diff_rel, diff_guard, diff_size);
    try requireHdiffSourceBinding(io, directory, source_rel, source_binding, counters);
    return output_hash.finish();
}

fn isStageDigestMismatch(err: anyerror) bool {
    return err == error.SizeMismatch or
        err == error.Md5Mismatch or
        err == error.ZipCrcMismatch or
        err == error.ZstdChecksumMismatch or
        err == error.HDiffOutputHashFailed;
}

fn takeStageDigestRetry(attempt: *u8, err: anyerror) bool {
    if (!isStageDigestMismatch(err) or attempt.* != 0) return false;
    attempt.* = 1;
    return true;
}

fn requireExpectedMd5(actual: [16]u8, expected: [16]u8) !void {
    if (!std.mem.eql(u8, &actual, &expected)) return error.Md5Mismatch;
}

fn stageAttemptPath(
    allocator: std.mem.Allocator,
    base: []const u8,
    attempt: u8,
) ![]const u8 {
    if (attempt == 0) return base;
    return privateStagePath(allocator, base, "retry", attempt);
}

fn stageIndependentPath(
    allocator: std.mem.Allocator,
    base: []const u8,
    attempt: u8,
) ![]const u8 {
    return privateStagePath(allocator, base, "independent", attempt);
}

fn privateStagePath(
    allocator: std.mem.Allocator,
    base: []const u8,
    lane: []const u8,
    attempt: u8,
) ![]const u8 {
    const slash = std.mem.indexOfScalar(u8, base, '/') orelse
        return error.InvalidDeltaLayout;
    if (slash == 0 or slash + 1 == base.len) return error.InvalidDeltaLayout;
    return allocator.print(
        "{s}/attempts/{s}-{d}/{s}",
        .{ base[0..slash], lane, attempt, base[slash + 1 ..] },
    );
}

fn requireGuardedStageBinding(
    io: std.Io,
    directory: std.Io.Dir,
    work_rel: []const u8,
    guarded: std.Io.File,
    target_size: u64,
) !void {
    const stat = try guarded.stat(io);
    if (stat.kind != .file or stat.nlink != 1) return error.UnsafeGuardedOutput;
    if (stat.size != target_size) return error.SizeMismatch;
    try fs.validateGuardedOutput(io, guarded, target_size);
    var rebound = try fs.openReadBeneath(io, directory, work_rel);
    defer rebound.close(io);
    if (!try fs.sameOpenFile(io, guarded, rebound))
        return error.StagingBindingChanged;
    try fs.validateGuardedOutput(io, guarded, target_size);
}

fn guardedHdiffInfo(
    io: std.Io,
    directory: std.Io.Dir,
    diff_rel: []const u8,
    diff_guard: std.Io.File,
    diff_size: u64,
    counters: *integrity_run.Counters,
) !hdiff.Info {
    const wanted: usize = @intCast(@min(diff_size, hdiff.info_prefix_size));
    if (wanted == 0) return error.InvalidHDiff;

    var first: [hdiff.info_prefix_size]u8 = undefined;
    try readGuardedHdiffPrefix(io, directory, diff_rel, diff_guard, diff_size, first[0..wanted]);
    var second: [hdiff.info_prefix_size]u8 = undefined;
    try readGuardedHdiffPrefix(io, directory, diff_rel, diff_guard, diff_size, second[0..wanted]);
    if (std.mem.eql(u8, first[0..wanted], second[0..wanted]))
        return hdiff.infoPrefix(first[0..wanted]);

    var third: [hdiff.info_prefix_size]u8 = undefined;
    readGuardedHdiffPrefix(io, directory, diff_rel, diff_guard, diff_size, third[0..wanted]) catch |err| {
        counters.consistencyReread(.failed);
        return err;
    };
    return switch (try adjudicatedRepeatedObservationMajority(
        first[0..wanted],
        second[0..wanted],
        third[0..wanted],
        counters,
    )) {
        .first => hdiff.infoPrefix(first[0..wanted]),
        .second => hdiff.infoPrefix(second[0..wanted]),
    };
}

fn readGuardedHdiffPrefix(
    io: std.Io,
    directory: std.Io.Dir,
    diff_rel: []const u8,
    diff_guard: std.Io.File,
    diff_size: u64,
    out: []u8,
) !void {
    try requireGuardedStageBinding(io, directory, diff_rel, diff_guard, diff_size);
    if (try fs.readAllAt(io, diff_guard, out, 0) != out.len) return error.UnexpectedEof;
    try requireGuardedStageBinding(io, directory, diff_rel, diff_guard, diff_size);
}

fn stageGuardedZipMember(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.File.Reader,
    entry: zip.Entry,
    directory: std.Io.Dir,
    workspace: *transaction.Workspace,
    work_rel: []const u8,
    progress: ?*ui.Progress,
    authoritative_md5: ?[16]u8,
    counters: *integrity_run.Counters,
) !StagedGuard {
    var attempt: u8 = 0;
    while (true) {
        const attempt_rel = try stageAttemptPath(allocator, work_rel, attempt);
        try ensureWorkspaceParent(workspace, attempt_rel);
        const guarded = try fs.createGuardedOutputBeneath(io, directory, attempt_rel);
        var attempt_error: ?anyerror = null;
        var digest_mismatch = false;
        var construction_md5: [16]u8 = undefined;
        if (zip.extractEntryToGuardedFileProgressMd5(io, reader, entry, guarded, progress)) |md5| {
            construction_md5 = md5;
        } else |err| {
            attempt_error = err;
            digest_mismatch = isStageDigestMismatch(err);
        }
        if (attempt_error == null) {
            if (authoritative_md5) |wanted| if (!std.mem.eql(u8, &construction_md5, &wanted)) {
                attempt_error = error.Md5Mismatch;
                digest_mismatch = true;
            };
        }
        if (attempt_error == null) {
            verifyGuardedStagePathTwice(
                io,
                directory,
                attempt_rel,
                guarded,
                entry.zip_entry.uncompressed_size,
                authoritative_md5 orelse construction_md5,
                progress,
                counters,
            ) catch |err| {
                attempt_error = err;
                digest_mismatch = isStageDigestMismatch(err);
            };
        }
        if (attempt_error) |err| {
            if (digest_mismatch and takeStageDigestRetry(&attempt, err)) {
                try discardWorkspaceGuardRequired(io, guarded);
                counters.retryStarted();
                continue;
            }
            discardWorkspaceGuard(io, guarded);
            return err;
        }
        if (attempt != 0) counters.retrySucceeded();
        return .{ .file = guarded, .md5 = construction_md5, .path = attempt_rel };
    }
}

fn stageGuardedTarMember(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    stream: *tar_zstd.Stream,
    file: std.tar.Iterator.File,
    directory: std.Io.Dir,
    workspace: *transaction.Workspace,
    work_rel: []const u8,
    progress: *ui.Progress,
    archive_md5: [16]u8,
    authoritative_md5: ?[16]u8,
    counters: *integrity_run.Counters,
) !StagedGuard {
    var attempt: u8 = 0;
    const expected_md5 = authoritative_md5 orelse archive_md5;
    while (true) {
        const attempt_rel = try stageAttemptPath(allocator, work_rel, attempt);
        try ensureWorkspaceParent(workspace, attempt_rel);
        const guarded = try fs.createGuardedOutputBeneath(io, directory, attempt_rel);
        var attempt_error: ?anyerror = null;
        var digest_mismatch = false;
        var construction_md5: [16]u8 = undefined;
        const extracted = if (attempt == 0)
            stream.extractCurrentToGuardedFileMd5(io, file, guarded, progress)
        else
            extractTarEntryFreshMd5(io, archive_file, archive_size, file, guarded, progress);
        if (extracted) |md5| {
            construction_md5 = md5;
        } else |err| {
            attempt_error = err;
            digest_mismatch = isStageDigestMismatch(err);
        }
        if (attempt_error == null) {
            requireExpectedMd5(construction_md5, expected_md5) catch |err| {
                attempt_error = err;
                digest_mismatch = true;
            };
        }
        if (attempt_error == null) {
            verifyGuardedStagePathTwice(
                io,
                directory,
                attempt_rel,
                guarded,
                file.size,
                expected_md5,
                progress,
                counters,
            ) catch |err| {
                attempt_error = err;
                digest_mismatch = isStageDigestMismatch(err);
            };
        }
        if (attempt_error) |err| {
            if (digest_mismatch and takeStageDigestRetry(&attempt, err)) {
                try discardWorkspaceGuardRequired(io, guarded);
                counters.retryStarted();
                continue;
            }
            discardWorkspaceGuard(io, guarded);
            return err;
        }
        if (attempt != 0) counters.retrySucceeded();
        return .{ .file = guarded, .md5 = construction_md5, .path = attempt_rel };
    }
}

fn extractTarEntryFreshMd5(
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    wanted: std.tar.Iterator.File,
    guarded: std.Io.File,
    progress: *ui.Progress,
) ![16]u8 {
    var stream = try tar_zstd.Stream.initBorrowed(std.heap.smp_allocator, io, archive_file, 0, archive_size);
    defer stream.deinit();
    while (try stream.next()) |file| {
        if (file.kind == .directory) {
            if (file.size != 0) return error.InvalidDeltaLayout;
            continue;
        }
        if (file.kind != .file) return error.InvalidDeltaLayout;
        if (std.mem.eql(u8, file.name, wanted.name)) {
            if (file.size != wanted.size) return error.InvalidDeltaLayout;
            return stream.extractCurrentToGuardedFileMd5(io, file, guarded, progress);
        }
        try stream.discardCurrent(file);
    }
    return error.InvalidDeltaLayout;
}

fn hashTarEntryFreshMd5(
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    wanted: std.tar.Iterator.File,
    progress: ?*ui.Progress,
) ![16]u8 {
    var stream = try tar_zstd.Stream.initBorrowed(std.heap.smp_allocator, io, archive_file, 0, archive_size);
    defer stream.deinit();
    while (try stream.next()) |file| {
        if (file.kind == .directory) {
            if (file.size != 0) return error.InvalidDeltaLayout;
            continue;
        }
        if (file.kind != .file) return error.InvalidDeltaLayout;
        if (std.mem.eql(u8, file.name, wanted.name)) {
            if (file.size != wanted.size) return error.InvalidDeltaLayout;
            return stream.hashCurrentMd5(file, progress);
        }
        try stream.discardCurrent(file);
    }
    return error.InvalidDeltaLayout;
}

fn appendGuardedTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    targets: *std.ArrayList(Target),
    path: []const u8,
    size: u64,
    staged: StagedGuard,
) !void {
    targets.append(allocator, .{
        .path = path,
        .work_rel = staged.path,
        .size = size,
        .md5 = staged.md5,
        .state = .{ .staged = staged.file },
    }) catch |err| {
        discardWorkspaceGuard(io, staged.file);
        return err;
    };
}

fn stageStandardZip(allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.File.Reader, archive: zip.Archive, controls: StandardControls, package: ?PackageState, source_plans: []const HdiffSourcePlan, target_count: usize, directory_path: []const u8, workspace: *transaction.Workspace, directory: *std.Io.Dir, out: *std.Io.Writer, counters: *integrity_run.Counters) !Stage {
    _ = directory_path;
    const scratch = std.heap.smp_allocator;
    var hdiff_set = try pathSet(scratch, controls.hdiff_paths);
    defer hdiff_set.deinit(scratch);
    var targets: std.ArrayList(Target) = .empty;
    errdefer for (targets.items) |*target| target.discard(io) catch {};
    var operation: ui.Operation = .{ .io = io, .writer = out };
    defer operation.stop();
    var progress: ui.Progress = .{ .io = io, .writer = out, .label = "Staging", .total_files = target_count, .show_speed = true, .operation = &operation };
    try progress.start();
    errdefer progress.abort();
    var errors: u64 = 0;
    for (archive.entries) |entry| {
        if (isStandardControl(controls.method, entry.path)) continue;
        stageZipEntry(allocator, io, reader, entry, standardTargetPath(controls.method, hdiff_set, entry.path), package, source_plans, workspace, directory, &targets, &progress, counters) catch |err| {
            if (err == error.Interrupted or err == error.Canceled or err == error.OutOfMemory) return err;
            errors += 1;
            try progress.fileError("Staging", entry.path, err);
        };
        try progress.finishFile();
    }
    try progress.finish();
    var stage: Stage = .{ .targets = try targets.toOwnedSlice(allocator), .removals = controls.removals, .errors = errors };
    errdefer stage.discardGuards(io);
    try validateStageLayout(stage);
    return stage;
}

fn stageZipEntry(allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.File.Reader, entry: zip.Entry, patch_target: ?[]const u8, package: ?PackageState, source_plans: []const HdiffSourcePlan, workspace: *transaction.Workspace, directory: *std.Io.Dir, targets: *std.ArrayList(Target), progress: *ui.Progress, counters: *integrity_run.Counters) !void {
    if (progress.operation) |operation| operation.phase("Extracting", entry.zip_entry.uncompressed_size, 0);
    const scratch = std.heap.smp_allocator;
    const work_root = workspace.name;
    if (patch_target) |target| {
        const source_plan = try hdiffSourcePlanFor(source_plans, target);
        const source_binding = try source_plan.source();
        const diff_rel = try scratch.print("{s}/diffs/{s}.hdiff", .{ work_root, target });
        defer scratch.free(diff_rel);
        const staged_diff = try stageGuardedZipMember(
            allocator,
            io,
            reader,
            entry,
            directory.*,
            workspace,
            diff_rel,
            progress,
            null,
            counters,
        );
        var diff_guard: ?std.Io.File = staged_diff.file;
        defer if (diff_guard) |guard| discardWorkspaceGuard(io, guard);
        const diff_stage_rel = staged_diff.path;
        try requireHdiffSourceBinding(io, directory.*, target, source_binding, counters);
        try requireGuardedStageBinding(io, directory.*, diff_stage_rel, diff_guard.?, entry.zip_entry.uncompressed_size);
        const info = try guardedHdiffInfo(
            io,
            directory.*,
            diff_stage_rel,
            diff_guard.?,
            entry.zip_entry.uncompressed_size,
            counters,
        );
        try validateGuardedHdiffPlan(source_plan, info);
        const work_rel = try allocator.print("{s}/staged/{s}", .{ work_root, target });
        const staged = try stageGuardedHdiff(
            allocator,
            io,
            progress,
            directory.*,
            workspace,
            work_rel,
            target,
            source_binding,
            diff_stage_rel,
            diff_guard.?,
            entry.zip_entry.uncompressed_size,
            source_plan.target_size,
            authoritativeTargetMd5(package, target),
            counters,
        );
        try appendGuardedTarget(
            allocator,
            io,
            targets,
            target,
            source_plan.target_size,
            staged,
        );
        const consumed_diff = diff_guard.?;
        diff_guard = null;
        try discardWorkspaceGuardRequired(io, consumed_diff);
    } else {
        const work_rel = try allocator.print("{s}/staged/{s}", .{ work_root, entry.path });
        const staged = try stageGuardedZipMember(
            allocator,
            io,
            reader,
            entry,
            directory.*,
            workspace,
            work_rel,
            progress,
            null,
            counters,
        );
        try appendGuardedTarget(
            allocator,
            io,
            targets,
            entry.path,
            entry.zip_entry.uncompressed_size,
            staged,
        );
    }
}

fn applyStandardTar(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
    counters: *integrity_run.Counters,
) !void {
    var checking_operation: ui.Operation = .{ .io = io, .writer = out };
    defer checking_operation.stop();
    var checking: ui.Progress = .{ .io = io, .writer = out, .label = "Reading delta", .indeterminate = true, .operation = &checking_operation };
    try checking.start();
    var scan = scanStandardTar(allocator, io, archive_file, archive_size, directory_path, counters, &checking) catch |err| {
        checking.abort();
        return reportApplyError(out, delta_path, directory_path, err);
    };
    try checking.finish();

    const target_paths = standardTargetPaths(allocator, scan.entries, scan.controls) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    const expected_entries: []const manifest_mod.File = if (scan.package) |value| value.state.expected.entries else &.{};
    const path_layout = standardDestinationLayout(allocator, target_paths, scan.controls.removals, expected_entries, builtin.target.os.tag == .windows) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    scan.controls.removals = path_layout.effective_removals;
    validateDestinationPaths(io, directory_path, path_layout.representability_paths, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    validateRemovalPaths(io, directory_path, scan.controls.removals, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    var preflight_directory = std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true }) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer preflight_directory.close(io);
    checking = .{ .io = io, .writer = out, .label = "Checking sources", .total_files = scan.entries.len, .operation = &checking_operation };
    try checking.start();
    const space = tarSpaceRequired(allocator, io, preflight_directory, scan, counters, &checking) catch |err| {
        checking.abort();
        return reportApplyError(out, delta_path, directory_path, err);
    };
    try checking.finish();
    try reportSourceProblems(out, space.sources);
    try standardPreflight(allocator, io, archive_size, delta_path, directory_path, assume_yes, scan.controls.method, target_paths.len, scan.controls.removals.len, scan.identity, space.required, force, out);
    try out.flush();

    var workspace = transaction.Workspace.create(allocator, io, preflight_directory, path_layout.representability_paths) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer cleanupArchiveWorkspace(io, preflight_directory, &workspace);
    workspace.ensureDirectory("staged") catch |err| return reportApplyError(out, delta_path, directory_path, err);
    workspace.ensureDirectory("diffs") catch |err| return reportApplyError(out, delta_path, directory_path, err);

    var stage = stageStandardTar(allocator, io, archive_file, archive_size, directory_path, &workspace, &preflight_directory, scan, space.sources, target_paths.len, out, counters) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer stage.discardGuards(io);
    var mutations = transaction.MutationSet.capture(allocator, io, preflight_directory, try stage.paths(allocator), stage.removals) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    defer mutations.deinit();
    const had_errors = validateStandardStage(io, directory_path, &preflight_directory, &stage, scan.package, verify_md5, out, counters) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    mutations.validateBindings(preflight_directory) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    commitStage(allocator, io, &workspace, &preflight_directory, &stage, &mutations, out) catch |err| return reportApplyError(out, delta_path, directory_path, err);
    try out.writeByte('\n');
    if (had_errors or stage.errors != 0) return error.CompletedWithErrors;
}

fn stageStandardTar(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_file: std.Io.File,
    archive_size: u64,
    directory_path: []const u8,
    workspace: *transaction.Workspace,
    directory: *std.Io.Dir,
    scan: TarScan,
    source_plans: []const HdiffSourcePlan,
    target_count: usize,
    out: *std.Io.Writer,
    counters: *integrity_run.Counters,
) !Stage {
    _ = directory_path;
    const scratch = std.heap.smp_allocator;
    var hdiff_set = try pathSet(scratch, scan.controls.hdiff_paths);
    defer hdiff_set.deinit(scratch);

    var stream = try tar_zstd.Stream.initBorrowed(allocator, io, archive_file, 0, archive_size);
    defer stream.deinit();
    var audit_stream = try tar_zstd.Stream.initBorrowed(allocator, io, archive_file, 0, archive_size);
    defer audit_stream.deinit();

    var targets: std.ArrayList(Target) = .empty;
    errdefer for (targets.items) |*target| target.discard(io) catch {};
    var operation: ui.Operation = .{ .io = io, .writer = out };
    defer operation.stop();
    var progress: ui.Progress = .{ .io = io, .writer = out, .label = "Staging", .total_files = target_count, .show_speed = true, .operation = &operation };
    try progress.start();
    errdefer progress.abort();

    var entry_index: usize = 0;
    var errors: u64 = 0;
    while (try stream.next()) |file| {
        const audit_file = (try audit_stream.next()) orelse return error.InvalidDeltaLayout;
        if (file.kind != audit_file.kind or
            file.size != audit_file.size or
            !std.mem.eql(u8, file.name, audit_file.name))
            return error.InvalidDeltaLayout;
        if (file.kind == .directory) {
            if (file.size != 0) return error.UnsupportedTarEntry;
            continue;
        }
        if (file.kind != .file) return error.UnsupportedTarEntry;
        if (entry_index >= scan.entries.len) return error.InvalidDeltaLayout;
        const planned = scan.entries[entry_index];
        if (!std.mem.eql(u8, file.name, planned.path) or file.size != planned.size) return error.InvalidDeltaLayout;
        entry_index += 1;
        var archive_md5 = try audit_stream.hashCurrentMd5(audit_file, null);
        const scan_md5 = planned.scan_md5 orelse return error.InvalidDeltaLayout;
        if (!std.mem.eql(u8, &archive_md5, &scan_md5)) {
            const fresh_md5 = hashTarEntryFreshMd5(io, archive_file, archive_size, file, null) catch |err| {
                counters.consistencyReread(.failed);
                return err;
            };
            if (!std.mem.eql(u8, &fresh_md5, &scan_md5)) {
                counters.consistencyReread(.unresolved);
                return error.Md5Mismatch;
            }
            counters.consistencyReread(.resolved);
        }
        archive_md5 = scan_md5;

        if (isStandardControl(scan.controls.method, file.name)) {
            try stream.discardCurrent(file);
            continue;
        }

        stageTarEntry(allocator, io, archive_file, archive_size, stream, file, planned.path, archive_md5, standardTargetPath(scan.controls.method, hdiff_set, planned.path), scan.package, source_plans, workspace, directory, &targets, &progress, counters) catch |err| {
            if (err == error.Interrupted or err == error.Canceled or err == error.OutOfMemory) return err;
            errors += 1;
            try progress.fileError("Staging", planned.path, err);
        };
        try progress.finishFile();
    }
    if (entry_index != scan.entries.len) return error.InvalidDeltaLayout;
    if (try audit_stream.next() != null) return error.InvalidDeltaLayout;
    try progress.finish();

    var stage: Stage = .{ .targets = try targets.toOwnedSlice(allocator), .removals = scan.controls.removals, .errors = errors };
    errdefer stage.discardGuards(io);
    try validateStageLayout(stage);
    return stage;
}

fn stageTarEntry(allocator: std.mem.Allocator, io: std.Io, archive_file: std.Io.File, archive_size: u64, stream: *tar_zstd.Stream, file: std.tar.Iterator.File, path: []const u8, archive_md5: [16]u8, patch_target: ?[]const u8, package: ?PackageState, source_plans: []const HdiffSourcePlan, workspace: *transaction.Workspace, directory: *std.Io.Dir, targets: *std.ArrayList(Target), progress: *ui.Progress, counters: *integrity_run.Counters) !void {
    if (progress.operation) |operation| operation.phase("Extracting", file.size, 0);
    const scratch = std.heap.smp_allocator;
    const work_root = workspace.name;
    if (patch_target) |target| {
        const source_plan = try hdiffSourcePlanFor(source_plans, target);
        const source_binding = try source_plan.source();
        const diff_rel = try scratch.print("{s}/diffs/{s}.hdiff", .{ work_root, target });
        defer scratch.free(diff_rel);
        const staged_diff = try stageGuardedTarMember(
            allocator,
            io,
            archive_file,
            archive_size,
            stream,
            file,
            directory.*,
            workspace,
            diff_rel,
            progress,
            archive_md5,
            null,
            counters,
        );
        var diff_guard: ?std.Io.File = staged_diff.file;
        defer if (diff_guard) |guard| discardWorkspaceGuard(io, guard);
        const diff_stage_rel = staged_diff.path;

        try requireHdiffSourceBinding(io, directory.*, target, source_binding, counters);
        try requireGuardedStageBinding(io, directory.*, diff_stage_rel, diff_guard.?, file.size);
        const info = try guardedHdiffInfo(
            io,
            directory.*,
            diff_stage_rel,
            diff_guard.?,
            file.size,
            counters,
        );
        try validateGuardedHdiffPlan(source_plan, info);

        const work_rel = try allocator.print("{s}/staged/{s}", .{ work_root, target });
        const staged = try stageGuardedHdiff(
            allocator,
            io,
            progress,
            directory.*,
            workspace,
            work_rel,
            target,
            source_binding,
            diff_stage_rel,
            diff_guard.?,
            file.size,
            source_plan.target_size,
            authoritativeTargetMd5(package, target),
            counters,
        );
        try appendGuardedTarget(
            allocator,
            io,
            targets,
            target,
            source_plan.target_size,
            staged,
        );
        const consumed_diff = diff_guard.?;
        diff_guard = null;
        try discardWorkspaceGuardRequired(io, consumed_diff);
    } else {
        const work_rel = try allocator.print("{s}/staged/{s}", .{ work_root, path });
        const staged = try stageGuardedTarMember(
            allocator,
            io,
            archive_file,
            archive_size,
            stream,
            file,
            directory.*,
            workspace,
            work_rel,
            progress,
            archive_md5,
            null,
            counters,
        );
        try appendGuardedTarget(
            allocator,
            io,
            targets,
            path,
            file.size,
            staged,
        );
    }
}

fn hashGuardedStagePath(
    io: std.Io,
    directory: std.Io.Dir,
    work_rel: []const u8,
    guarded: std.Io.File,
    progress: ?*ui.Progress,
) !verify.Hash {
    const before = try fs.validateGuardedOutputAuthority(io, guarded);
    var rebound = try fs.openReadBeneath(io, directory, work_rel);
    defer rebound.close(io);
    if (!try fs.sameOpenFile(io, guarded, rebound))
        return error.StagingBindingChanged;
    const actual = try verify.hashOpenFile(io, rebound, progress);
    const after = try fs.validateGuardedOutputAuthority(io, guarded);
    if (before.size != actual.size or after.size != actual.size)
        return error.FileSizeChanged;
    var confirmed = try fs.openReadBeneath(io, directory, work_rel);
    defer confirmed.close(io);
    if (!try fs.sameOpenFile(io, guarded, confirmed))
        return error.StagingBindingChanged;
    return actual;
}

fn verifyGuardedStagePathTwice(
    io: std.Io,
    directory: std.Io.Dir,
    work_rel: []const u8,
    guarded: std.Io.File,
    expected_size: u64,
    expected_md5: [16]u8,
    progress: ?*ui.Progress,
    counters: *integrity_run.Counters,
) !void {
    const first = hashGuardedStagePath(
        io,
        directory,
        work_rel,
        guarded,
        progress,
    ) catch |err| return err;
    if (first.size == expected_size and std.mem.eql(u8, &first.md5, &expected_md5)) return;
    const second = hashGuardedStagePath(io, directory, work_rel, guarded, progress) catch |err| {
        counters.verificationReread(.failed);
        return err;
    };
    if (second.size != expected_size) {
        counters.verificationReread(if (first.size == second.size)
            .confirmed_mismatch
        else
            .inconsistent_mismatch);
        return error.SizeMismatch;
    }
    if (!std.mem.eql(u8, &second.md5, &expected_md5)) {
        counters.verificationReread(if (first.size == second.size and std.mem.eql(u8, &first.md5, &second.md5))
            .confirmed_mismatch
        else
            .inconsistent_mismatch);
        return error.Md5Mismatch;
    }
    counters.verificationReread(.repaired);
}

fn verifyGuardedStageTargetTwice(
    io: std.Io,
    directory: std.Io.Dir,
    target: Target,
    expected_size: u64,
    expected_md5: [16]u8,
    progress: ?*ui.Progress,
    counters: *integrity_run.Counters,
) !void {
    return verifyGuardedStagePathTwice(
        io,
        directory,
        target.work_rel,
        try target.stagedFile(),
        expected_size,
        expected_md5,
        progress,
        counters,
    );
}

fn validateStandardStage(io: std.Io, directory_path: []const u8, directory: *std.Io.Dir, stage: *const Stage, package: ?PackageState, verify_md5: bool, out: *std.Io.Writer, counters: *integrity_run.Counters) !bool {
    var had_errors = false;
    const expected = if (package) |value| value.state else null;
    if (verify_md5 and (expected == null or expected.?.digest_authority != .authoritative)) {
        try ui.writeErrorPrefix(out);
        try out.writeAll(" hash verification is unavailable for this delta\n");
        return error.Reported;
    }

    const scratch = std.heap.smp_allocator;
    const target_paths = try stage.paths(scratch);
    defer scratch.free(target_paths);
    const expected_entries: []const manifest_mod.File = if (expected) |state| state.expected.entries else &.{};
    const layout = try standardDestinationLayout(scratch, target_paths, stage.removals, expected_entries, builtin.target.os.tag == .windows);
    defer scratch.free(layout.representability_paths);
    defer scratch.free(layout.effective_removals);
    if (layout.effective_removals.len != stage.removals.len) return error.InvalidDeltaLayout;
    if (try path_util.firstSymlinkAncestor(io, directory_path, layout.representability_paths) != null)
        return error.InvalidDeltaLayout;

    for (stage.targets) |target| {
        const guarded = try target.stagedFile();
        try requireGuardedStageBinding(io, directory.*, target.work_rel, guarded, target.size);
    }

    if (expected) |state| {
        for (stage.removals) |path| {
            if (state.expected.contains(path)) {
                had_errors = true;
                try ui.fileError(out, "Manifest still lists removed file", path, error.ManifestMismatch);
            }
        }

        var touched: std.StringHashMapUnmanaged(usize) = .empty;
        defer touched.deinit(scratch);
        try touched.ensureTotalCapacity(scratch, @intCast(stage.targets.len));
        for (stage.targets, 0..) |target, index| touched.putAssumeCapacity(target.path, index);
        var removed = try pathSet(scratch, stage.removals);
        defer removed.deinit(scratch);

        var verification: ui.Operation = .{ .io = io, .writer = out };
        defer verification.stop();
        var verify_progress: ui.Progress = .{ .io = io, .writer = out, .label = "Verifying", .total_files = state.expected.entries.len, .operation = &verification };
        try verify_progress.start();
        errdefer verify_progress.abort();
        var live = try std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true });
        defer live.close(io);
        for (state.expected.entries) |entry| {
            if (removed.contains(entry.path)) {
                try verify_progress.finishFile();
                continue;
            }
            checkStandardEntry(io, live, stage, state, touched.get(entry.path), entry, verify_md5, &verify_progress) catch |err| {
                if (err == error.Interrupted or err == error.Canceled or err == error.OutOfMemory) return err;
                had_errors = true;
                try verify_progress.fileError("Verifying", entry.path, err);
            };
            try verify_progress.finishFile();
        }
        try verify_progress.finish();
    }

    // staged-output reread unconditional; -v adds untouched-file checks
    var verification: ui.Operation = .{ .io = io, .writer = out };
    defer verification.stop();
    var progress: ui.Progress = .{ .io = io, .writer = out, .label = "Verifying outputs", .total_files = stage.targets.len, .operation = &verification };
    try progress.start();
    errdefer progress.abort();
    for (stage.targets) |target| {
        verification.phase("Reading", target.size *| 2, 0);
        try verifyGuardedStageTargetTwice(
            io,
            directory.*,
            target,
            target.size,
            target.md5,
            &progress,
            counters,
        );
        try progress.finishFile();
    }
    try progress.finish();
    return had_errors;
}

fn checkStandardEntry(io: std.Io, live: std.Io.Dir, stage: *const Stage, state: integrations.State, target_index: ?usize, entry: manifest_mod.File, verify_md5: bool, progress: *ui.Progress) !void {
    if (target_index) |index| {
        const target = stage.targets[index];
        if (target.size != entry.size) return error.SizeMismatch;
        if (state.digest_authority == .authoritative and
            !std.mem.eql(u8, &target.md5, &entry.md5))
            return error.Md5Mismatch;
    } else {
        const stat = live.statFile(io, entry.path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return error.SourcePathConflict,
            else => |e| return e,
        };
        if (stat.kind != .file or stat.size != entry.size) return error.SourcePathConflict;
        if (verify_md5) {
            if (progress.operation) |operation| operation.phase("Reading", entry.size, 0);
            const actual = try verify.hashFile(io, live, entry.path, progress);
            if (!std.mem.eql(u8, &actual.md5, &entry.md5)) return error.SourcePathConflict;
        }
    }
}

fn reportApplyError(out: *std.Io.Writer, delta_path: []const u8, directory_path: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.MissingHDiffList,
        error.MissingDeletionList,
        error.InvalidHDiffList,
        error.InvalidDeletionList,
        error.MissingHDiffEntry,
        error.UnsupportedTarEntry,
        error.DuplicateTarPath,
        error.UnsupportedCompressionMethod,
        error.ZipCompressedSizeMismatch,
        error.ZipUncompressedSizeMismatch,
        error.ZipCrcMismatch,
        error.ZipDecompressTruncated,
        error.ZipBadFileOffset,
        error.ZipMismatchVersionNeeded,
        error.ZipMismatchFlags,
        error.ZipMismatchModTime,
        error.ZipMismatchModDate,
        error.ZipMismatchFilenameLen,
        error.ZipMismatchFilename,
        error.ZipMismatchCompressionMethod,
        error.ZipMismatchCrc32,
        error.ZipMismatchCompLen,
        error.ZipMismatchUncompLen,
        error.ZstdDecompressFailed,
        error.InvalidZstdStream,
        error.ZstdChecksumMismatch,
        error.UnexpectedEof,
        error.UnexpectedEndOfStream,
        error.EndOfStream,
        error.ReadFailed,
        error.TarHeader,
        error.TarHeaderChksum,
        error.TarHeadersTooBig,
        error.TarInsufficientBuffer,
        error.FileTooLarge,
        error.UnsafePath,
        error.PathTooLongForZip,
        error.InvalidExpectedState,
        error.InvalidDeltaLayout,
        error.NoAvailableWorkRoot,
        error.InvalidHDiff,
        error.InvalidHDiffMemoryRequirement,
        error.MutationPlanMismatch,
        => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" invalid or unsupported delta file\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            return error.Reported;
        },
        error.HDiffApplyFailed => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" could not reconstruct the target\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        error.SourcePathConflict => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" source does not match this delta\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        error.SizeMismatch,
        error.Md5Mismatch,
        error.HDiffOutputHashFailed,
        error.UnsafeGuardedOutput,
        error.StagingBindingChanged,
        error.PublishedBindingChanged,
        error.MutationBindingChanged,
        error.WorkspaceBindingChanged,
        error.WorkspaceContaminated,
        => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" staged target failed verification\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            return error.Reported;
        },
        error.AccessDenied, error.ReadOnlyFileSystem => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" cannot modify destination directory\n") catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        error.NoSpaceLeft, error.DiskQuota => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" not enough disk space to apply delta\n") catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        error.RollbackConflict => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" rollback failed\nInspect the destination and recovery files before retrying.\n") catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        error.PublicationOutcomeUnknown => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" could not confirm file replacement\nVerify the destination before retrying.\n") catch return err;
            ui.writeField(out, "Directory:", directory_path) catch return err;
            return error.Reported;
        },
        else => return err,
    }
}

fn reportInspectionError(out: *std.Io.Writer, delta_path: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.FileNotFound,
        error.AccessDenied,
        error.NotDir,
        error.IsDir,
        error.ExpectedFile,
        error.FileBusy,
        => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" cannot read delta file\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            return error.Reported;
        },
        error.InvalidDeltaLayout,
        error.UnsupportedCompressionMethod,
        error.UnsupportedTarEntry,
        error.ZstdDecompressFailed,
        error.InvalidZstdStream,
        error.ZstdChecksumMismatch,
        error.ZipNoEndRecord,
        error.ZipBadCentralSig,
        error.ZipDirectoryHasData,
        error.DuplicateZipPath,
        error.DuplicateTarPath,
        error.UnsafePath,
        error.PathTooLongForZip,
        error.UnexpectedEof,
        error.UnexpectedEndOfStream,
        error.EndOfStream,
        error.ReadFailed,
        error.TarHeader,
        error.TarHeaderChksum,
        error.TarHeadersTooBig,
        error.TarInsufficientBuffer,
        => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" invalid or unsupported delta file\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            return error.Reported;
        },
        else => return err,
    }
}

fn validateDestinationPaths(
    io: std.Io,
    directory_path: []const u8,
    paths: []const []const u8,
    out: *std.Io.Writer,
) !void {
    if (try path_util.firstSymlinkAncestor(io, directory_path, paths)) |problem| {
        try ui.writeErrorPrefix(out);
        try out.writeAll(" cannot apply through a symbolic-link directory\n");
        try ui.writeField(out, "Path:", problem);
        return error.Reported;
    }
}

fn validateRemovalPaths(io: std.Io, directory_path: []const u8, paths: []const []const u8, out: *std.Io.Writer) !void {
    if (try path_util.firstSymlinkAncestor(io, directory_path, paths)) |problem| {
        try ui.writeErrorPrefix(out);
        try out.writeAll(" cannot apply through a symbolic-link directory\n");
        try ui.writeField(out, "Path:", problem);
        return error.Reported;
    }
}

fn cleanupArchiveWorkspace(
    io: std.Io,
    directory: std.Io.Dir,
    workspace: *transaction.Workspace,
) void {
    workspace.cleanup();
    if (builtin.target.os.tag != .windows)
        transaction.cleanupWorkAt(io, directory, workspace.name);
    workspace.deinit();
}

fn workspaceRelativePath(workspace: *const transaction.Workspace, path: []const u8) ![]const u8 {
    if (path.len <= workspace.name.len or
        !std.mem.eql(u8, path[0..workspace.name.len], workspace.name) or
        path[workspace.name.len] != '/') return error.InvalidDeltaLayout;
    return path[workspace.name.len + 1 ..];
}

fn ensureWorkspaceParent(workspace: *transaction.Workspace, path: []const u8) !void {
    try workspace.ensureParent(try workspaceRelativePath(workspace, path));
}

fn validateStageLayout(stage: Stage) !void {
    const scratch = std.heap.smp_allocator;
    var targets: std.StringHashMapUnmanaged(void) = .empty;
    defer targets.deinit(scratch);
    var removals: std.StringHashMapUnmanaged(void) = .empty;
    defer removals.deinit(scratch);

    for (stage.removals) |path| {
        const got = try removals.getOrPut(scratch, path);
        if (got.found_existing) return error.InvalidDeltaLayout;
        got.value_ptr.* = {};
    }
    for (stage.targets) |target| {
        if (removals.contains(target.path)) return error.InvalidDeltaLayout;
        const got = try targets.getOrPut(scratch, target.path);
        if (got.found_existing) return error.InvalidDeltaLayout;
        got.value_ptr.* = {};
    }
    for (stage.targets) |target| {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, target.path, start, '/')) |slash| {
            if (targets.contains(target.path[0..slash])) return error.InvalidDeltaLayout;
            start = slash + 1;
        }
    }
}

fn commitStage(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: *transaction.Workspace,
    directory: *std.Io.Dir,
    stage: *Stage,
    mutations: *transaction.MutationSet,
    out: *std.Io.Writer,
) !void {
    const removals = try mutations.listedRemovalEntries(allocator, io, directory.*);
    var commit = try transaction.Commit.init(
        allocator,
        io,
        directory.*,
        workspace,
        stage.targets,
        stage.removals,
        mutations,
    );
    defer commit.deinit();
    commitStageChanges(io, stage, removals, out, &commit) catch |err| return commit.rollbackOr(err);
    commit.finish() catch |err| return commit.rollbackOr(err);
}

fn commitStageChanges(io: std.Io, stage: *Stage, removals: []const clean.Extra, out: *std.Io.Writer, commit: *transaction.Commit) !void {
    var operation: ui.Operation = .{ .io = io, .writer = out };
    defer operation.stop();
    var applying: ui.Progress = .{ .io = io, .writer = out, .label = "Applying", .total_files = stage.targets.len, .operation = &operation };
    try applying.start();
    errdefer applying.abort();
    for (0..stage.targets.len) |guard_index| {
        try commit.publish(guard_index);
        try applying.finishFile();
    }
    try applying.finish();

    if (removals.len != 0) {
        var cleaning: ui.Progress = .{ .io = io, .writer = out, .label = "Cleaning", .total_files = removals.len, .total_bytes = transaction.extrasSize(removals), .operation = &operation };
        try cleaning.start();
        errdefer cleaning.abort();
        for (removals) |extra| {
            try commit.remove(extra.path);
            try cleaning.addBytes(extra.size);
            try cleaning.finishFile();
        }
        try cleaning.finish();
    }
}

fn parseHdiffList(allocator: std.mem.Allocator, bytes: []const u8) ![]const []const u8 {
    const Row = struct { remoteName: []const u8 };
    var paths: std.ArrayList([]const u8) = .empty;
    const scratch = std.heap.smp_allocator;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const row = std.json.parseFromSliceLeaky(Row, allocator, line, .{}) catch return error.InvalidHDiffList;
        try path_util.validate(row.remoteName);
        const got = try seen.getOrPut(scratch, row.remoteName);
        if (got.found_existing) return error.InvalidHDiffList;
        got.value_ptr.* = {};
        try paths.append(allocator, row.remoteName);
    }
    return paths.toOwnedSlice(allocator);
}

fn parseDeletionList(allocator: std.mem.Allocator, bytes: []const u8) ![]const []const u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    const scratch = std.heap.smp_allocator;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        try path_util.validate(line);
        const got = try seen.getOrPut(scratch, line);
        if (got.found_existing) return error.InvalidDeletionList;
        got.value_ptr.* = {};
        try paths.append(allocator, line);
    }
    return paths.toOwnedSlice(allocator);
}

fn pathSet(allocator: std.mem.Allocator, paths: []const []const u8) !std.StringHashMapUnmanaged(void) {
    var set: std.StringHashMapUnmanaged(void) = .empty;
    errdefer set.deinit(allocator);
    try set.ensureTotalCapacity(allocator, @intCast(paths.len));
    for (paths) |path| set.putAssumeCapacity(path, {});
    return set;
}

fn testingPackageState(software: integrations.Software, expected: manifest_mod.Set, managed_set_complete: bool) PackageState {
    const definition = integrations.integration(software);
    return .{
        .software = software,
        .state = .{
            .expected = expected,
            .metadata = &.{},
            .manifest_format = definition.manifest_format,
            .manifest_schema = definition.manifest_schema,
            .digest_authority = definition.digest_authority,
            .managed_set_complete = managed_set_complete,
        },
    };
}

test "standard archive manifest anchors are independent of whole-target authority" {
    try std.testing.expect(integrations.isPrimaryManifestPath(.zzz, "pkg_version"));
    try std.testing.expect(integrations.isPrimaryManifestPath(.endfield, "game_files"));
    try std.testing.expect(integrations.isPrimaryManifestPath(.wuwa, "LocalGameResources.json"));
    try std.testing.expect(!integrations.isPrimaryManifestPath(.endfield, "pkg_version"));
    try std.testing.expect(!integrations.isPrimaryManifestPath(.wuwa, "game_files"));

    inline for (.{ .zzz, .genshin, .endfield, .wuwa }) |software| {
        try std.testing.expectError(
            error.InvalidExpectedState,
            rejectPrimaryManifestDirectory(software, integrations.primaryManifestPath(software)),
        );
    }
    try rejectPrimaryManifestDirectory(.zzz, "Audio_English(US)_pkg_version");
}

test "standard preflight reports retained archive size without reopening its pathname" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const missing_delta_path = try std.fs.path.join(allocator, &.{ root, "already-replaced.zip" });
    const retained_size: u64 = 1_234_567;
    var output: std.Io.Writer.Allocating = .init(allocator);

    try standardPreflight(
        allocator,
        io,
        retained_size,
        missing_delta_path,
        root,
        true,
        .file_delta,
        0,
        0,
        null,
        0,
        false,
        &output.writer,
    );

    var expected_buf: [64]u8 = undefined;
    const expected = try ui.bytes(&expected_buf, retained_size);
    var expected_line_buf: [96]u8 = undefined;
    const expected_line = try std.fmt.bufPrint(
        &expected_line_buf,
        "Size: {s}\n",
        .{expected},
    );
    try std.testing.expect(std.mem.indexOf(u8, output.written(), expected_line) != null);
}

test "standard archive apply retains ZIP and tar content across confirmation pathname replacement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    const SwapOnFlushWriter = struct {
        writer: std.Io.Writer,
        io: std.Io,
        dir: std.Io.Dir,
        active: []const u8,
        held: []const u8,
        replacement: []const u8,
        expected_size_line: []const u8,
        triggered: bool = false,
        saw_expected_size: bool = false,
        failure: ?anyerror = null,

        fn init(
            test_io: std.Io,
            dir: std.Io.Dir,
            active: []const u8,
            held: []const u8,
            replacement: []const u8,
            expected_size_line: []const u8,
            buffer: []u8,
        ) @This() {
            return .{
                .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } },
                .io = test_io,
                .dir = dir,
                .active = active,
                .held = held,
                .replacement = replacement,
                .expected_size_line = expected_size_line,
            };
        }

        fn replacePath(self: *@This()) !void {
            if (builtin.target.os.tag == .windows) {
                var namespace_mover = try fs.openMutationAuthorityBeneathWindows(
                    self.io,
                    self.dir,
                    self.active,
                );
                defer namespace_mover.close(self.io);
                try fs.renameOpenObjectBeneathWindows(
                    self.io,
                    self.dir,
                    self.held,
                    namespace_mover,
                );
            } else {
                try self.dir.rename(self.active, self.dir, self.held, self.io);
            }
            try self.dir.rename(self.replacement, self.dir, self.active, self.io);
        }

        fn drain(
            writer: *std.Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) std.Io.Writer.Error!usize {
            const self: *@This() = @alignCast(@fieldParentPtr("writer", writer));
            if (!self.triggered and std.mem.indexOf(
                u8,
                writer.buffer[0..writer.end],
                self.expected_size_line,
            ) != null) {
                self.triggered = true;
                self.saw_expected_size = true;
                self.replacePath() catch |err| {
                    self.failure = err;
                    return error.WriteFailed;
                };
            }
            writer.end = 0;

            var consumed: usize = 0;
            if (data.len == 0) return consumed;
            for (data[0 .. data.len - 1]) |bytes| consumed += bytes.len;
            const last = data[data.len - 1];
            var i: usize = 0;
            while (i < splat) : (i += 1) consumed += last.len;
            return consumed;
        }
    };

    const Format = enum { zip, tar_zstd };
    var replacement_payload: [4096]u8 = undefined;
    var random_state: u32 = 0x9e3779b9;
    for (&replacement_payload) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 17;
        random_state ^= random_state << 5;
        byte.* = @truncate(random_state);
    }
    for ([_]Format{ .zip, .tar_zstd }, 0..) |format, index| {
        const extension = if (format == .zip) "zip" else "tar.zst";
        const active_name = try allocator.print("active-{d}.{s}", .{ index, extension });
        const held_name = try allocator.print("held-{d}.{s}", .{ index, extension });
        const replacement_name = try allocator.print("replacement-{d}.{s}", .{ index, extension });
        const target_name = try allocator.print("target-{d}.bin", .{index});
        const active_path = try std.fs.path.join(allocator, &.{ root, active_name });
        const replacement_path = try std.fs.path.join(allocator, &.{ root, replacement_name });
        const original_payload = "ORIGINAL";

        switch (format) {
            .zip => {
                var original_builder = try zip.Builder.init(allocator, io, root, active_path, .store);
                defer original_builder.deinit();
                try original_builder.add(.{ .path = target_name, .size = original_payload.len, .data = .{ .bytes = original_payload } }, null);
                try original_builder.finish();
                var replacement_builder = try zip.Builder.init(allocator, io, root, replacement_path, .store);
                defer replacement_builder.deinit();
                try replacement_builder.add(.{ .path = target_name, .size = replacement_payload.len, .data = .{ .bytes = &replacement_payload } }, null);
                try replacement_builder.finish();
            },
            .tar_zstd => {
                var original_builder = try tar_zstd.Builder.init(allocator, io, root, active_path, 3);
                defer original_builder.deinit();
                try original_builder.add(.{ .path = target_name, .size = original_payload.len, .data = .{ .bytes = original_payload } }, null);
                try original_builder.finish();
                var replacement_builder = try tar_zstd.Builder.init(allocator, io, root, replacement_path, 3);
                defer replacement_builder.deinit();
                try replacement_builder.add(.{ .path = target_name, .size = replacement_payload.len, .data = .{ .bytes = &replacement_payload } }, null);
                try replacement_builder.finish();
            },
        }

        const original_archive = try tmp.dir.readFileAlloc(io, active_name, allocator, .limited(1024 * 1024));
        const replacement_archive = try tmp.dir.readFileAlloc(io, replacement_name, allocator, .limited(1024 * 1024));
        try std.testing.expect(!std.mem.eql(u8, original_archive, replacement_archive));
        try std.testing.expect(original_archive.len != replacement_archive.len);
        var size_buf: [64]u8 = undefined;
        const displayed_size = try ui.bytes(&size_buf, original_archive.len);
        var replacement_size_buf: [64]u8 = undefined;
        const displayed_replacement_size = try ui.bytes(
            &replacement_size_buf,
            replacement_archive.len,
        );
        try std.testing.expect(!std.mem.eql(u8, displayed_size, displayed_replacement_size));
        var size_line_buf: [96]u8 = undefined;
        const size_line = try std.fmt.bufPrint(&size_line_buf, "Size: {s}\n", .{displayed_size});
        var output_buffer: [64 * 1024]u8 = undefined;
        var output = SwapOnFlushWriter.init(
            io,
            tmp.dir,
            active_name,
            held_name,
            replacement_name,
            size_line,
            &output_buffer,
        );
        var counters: integrity_run.Counters = .{};
        try applyTrackedFromDir(
            allocator,
            io,
            tmp.dir,
            active_name,
            active_path,
            root,
            true,
            false,
            false,
            &output.writer,
            &counters,
        );
        try std.testing.expect(output.triggered);
        try std.testing.expect(output.saw_expected_size);
        try std.testing.expect(output.failure == null);

        const target = try tmp.dir.readFileAlloc(io, target_name, allocator, .limited(1024));
        try std.testing.expectEqualStrings(original_payload, target);
        const active_archive = try tmp.dir.readFileAlloc(io, active_name, allocator, .limited(1024 * 1024));
        try std.testing.expectEqualSlices(u8, replacement_archive, active_archive);
        const held_archive = try tmp.dir.readFileAlloc(io, held_name, allocator, .limited(1024 * 1024));
        try std.testing.expectEqualSlices(u8, original_archive, held_archive);
    }
}

test "standard archive integrity failures authorize exactly one disposable retry" {
    var attempt: u8 = 0;
    try std.testing.expect(takeStageDigestRetry(&attempt, error.ZipCrcMismatch));
    try std.testing.expectEqual(@as(u8, 1), attempt);
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.ZipCrcMismatch));
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.Md5Mismatch));

    attempt = 0;
    try std.testing.expect(takeStageDigestRetry(&attempt, error.Md5Mismatch));
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.SizeMismatch));

    attempt = 0;
    try std.testing.expect(takeStageDigestRetry(&attempt, error.ZstdChecksumMismatch));
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.ZstdChecksumMismatch));

    attempt = 0;
    try std.testing.expect(takeStageDigestRetry(&attempt, error.HDiffOutputHashFailed));
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.HDiffOutputHashFailed));

    const scan_authority = md5Bytes("scan bytes");
    const changed_archive = md5Bytes("changed!!!");
    attempt = 0;
    try std.testing.expectError(
        error.Md5Mismatch,
        requireExpectedMd5(changed_archive, scan_authority),
    );
    try std.testing.expect(takeStageDigestRetry(&attempt, error.Md5Mismatch));
    try std.testing.expectError(
        error.Md5Mismatch,
        requireExpectedMd5(changed_archive, scan_authority),
    );
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.Md5Mismatch));

    attempt = 0;
    try std.testing.expect(!takeStageDigestRetry(&attempt, error.InvalidDeltaLayout));
    try std.testing.expectEqual(@as(u8, 0), attempt);

    const retry_path = try stageAttemptPath(
        std.testing.allocator,
        ".zift-work/staged/name.retry-1",
        1,
    );
    defer std.testing.allocator.free(retry_path);
    try std.testing.expectEqualStrings(
        ".zift-work/attempts/retry-1/staged/name.retry-1",
        retry_path,
    );
    const independent_path = try stageIndependentPath(
        std.testing.allocator,
        ".zift-work/diffs/name.hdiff",
        0,
    );
    defer std.testing.allocator.free(independent_path);
    try std.testing.expectEqualStrings(
        ".zift-work/attempts/independent-0/diffs/name.hdiff",
        independent_path,
    );
}

test "archive guarded ZIP failure records one hard retry and cleans both attempts" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const archive_path = try std.fs.path.join(allocator, &.{ root, "retry.zip" });
    const payload = "archive payload";
    {
        var builder = try zip.Builder.init(allocator, io, root, archive_path, .store);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = payload.len, .data = .{ .bytes = payload } }, null);
        try builder.finish();
    }
    var archive_file = try fs.openRead(io, std.Io.Dir.cwd(), archive_path);
    defer archive_file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = archive_file.reader(io, &buffer);
    const archive = try zip.readCentral(allocator, &reader);

    var workspace = try transaction.Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const root_name = try allocator.dupe(u8, workspace.name);
    const work_rel = try allocator.print("{s}/staged/payload.bin", .{workspace.name});
    var counters: integrity_run.Counters = .{};
    try std.testing.expectError(
        error.Md5Mismatch,
        stageGuardedZipMember(
            allocator,
            io,
            &reader,
            archive.entries[0],
            tmp.dir,
            &workspace,
            work_rel,
            null,
            md5Bytes("different payload"),
            &counters,
        ),
    );
    const evidence = counters.snapshot();
    try std.testing.expectEqual(@as(usize, 1), evidence.reconstruction.started);
    try std.testing.expectEqual(@as(usize, 0), evidence.reconstruction.succeeded);

    workspace.cleanup();
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, root_name, .{ .follow_symlinks = false }));
}

test "archive physical rereads report confirmed size and hash mismatches" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, "guarded.bin");
    defer discardWorkspaceGuard(io, guarded);
    try guarded.writePositionalAll(io, "actual", 0);
    try guarded.sync(io);
    for ([_]struct { size: u64, bytes: []const u8, err: anyerror }{
        .{ .size = 6, .bytes = "wanted", .err = error.Md5Mismatch },
        .{ .size = 5, .bytes = "actual", .err = error.SizeMismatch },
    }) |expected| {
        var counters: integrity_run.Counters = .{};
        try std.testing.expectError(expected.err, verifyGuardedStagePathTwice(io, tmp.dir, "guarded.bin", guarded, expected.size, md5Bytes(expected.bytes), null, &counters));
        const evidence = counters.snapshot();
        try std.testing.expectEqual(@as(usize, 1), evidence.verification.confirmed_mismatch);
        try std.testing.expectEqual(@as(usize, 1), evidence.verification.total());
    }
}

test "archive Stage cleanup preserves an unknown private sentinel" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var workspace = try transaction.Workspace.create(allocator, io, tmp.dir, &.{});
    defer workspace.deinit();
    try workspace.ensureDirectory("staged");
    const owned_path = try allocator.print("{s}/staged/owned.bin", .{workspace.name});
    defer allocator.free(owned_path);
    const sentinel_path = try allocator.print("{s}/staged/sentinel.bin", .{workspace.name});
    defer allocator.free(sentinel_path);
    const guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, owned_path);
    try guarded.writePositionalAll(io, "owned", 0);
    try guarded.sync(io);
    var targets = [_]Target{.{
        .path = "final.bin",
        .work_rel = owned_path,
        .size = 5,
        .md5 = md5Bytes("owned"),
        .state = .{ .staged = guarded },
    }};
    var stage: Stage = .{ .targets = &targets, .removals = &.{} };
    try tmp.dir.writeFile(io, .{ .sub_path = sentinel_path, .data = "keep" });

    stage.discardGuards(io);
    workspace.cleanup();

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, owned_path, .{ .follow_symlinks = false }));
    const sentinel = try tmp.dir.readFileAlloc(io, sentinel_path, allocator, .limited(5));
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings("keep", sentinel);
    _ = try tmp.dir.statFile(io, workspace.name, .{ .follow_symlinks = false });
}

test "HDiff majority adjudication is distinct from physical Target verification" {
    var counters: integrity_run.Counters = .{};
    try std.testing.expectEqual(
        RepeatedObservation.first,
        try adjudicatedRepeatedObservationMajority("same", "same", "unused", &counters),
    );
    try std.testing.expectEqual(
        RepeatedObservation.first,
        try adjudicatedRepeatedObservationMajority("first", "second", "first", &counters),
    );
    try std.testing.expectEqual(
        RepeatedObservation.second,
        try adjudicatedRepeatedObservationMajority("first", "second", "second", &counters),
    );
    try std.testing.expectError(
        error.Md5Mismatch,
        adjudicatedRepeatedObservationMajority("first", "second", "third", &counters),
    );

    const snapshot = counters.snapshot();
    try std.testing.expect(snapshot.hasEvents());
    try std.testing.expectEqual(@as(usize, 0), snapshot.verification.total());
    try std.testing.expectEqual(@as(usize, 2), snapshot.consistency.resolved);
    try std.testing.expectEqual(@as(usize, 1), snapshot.consistency.unresolved);
    try std.testing.expectEqual(@as(usize, 0), snapshot.consistency.failed);
}

test "HDiff source binding rejects same-size pathname replacement" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var counters: integrity_run.Counters = .{};
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "AAAA" });
    const binding = try captureHdiffSourceBinding(io, tmp.dir, "source.bin", 4, &counters);
    try tmp.dir.rename("source.bin", tmp.dir, "old-source.bin", io);
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "BBBB" });
    try std.testing.expectError(
        error.SourcePathConflict,
        requireHdiffSourceBinding(io, tmp.dir, "source.bin", binding, &counters),
    );

    try tmp.dir.writeFile(io, .{ .sub_path = "in-place.bin", .data = "CCCC" });
    const in_place_binding = try captureHdiffSourceBinding(io, tmp.dir, "in-place.bin", 4, &counters);
    var writable = try tmp.dir.openFile(io, "in-place.bin", .{ .mode = .read_write });
    try writable.writePositionalAll(io, "DDDD", 0);
    try writable.sync(io);
    writable.close(io);
    try std.testing.expectError(
        error.SourcePathConflict,
        requireHdiffSourceBinding(io, tmp.dir, "in-place.bin", in_place_binding, &counters),
    );
    try std.testing.expectEqual(@as(usize, 0), counters.snapshot().consistency.total());
}

test "guarded HDiff info must match the preflight target size" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var counters: integrity_run.Counters = .{};
    try tmp.dir.writeFile(io, .{ .sub_path = "source.bin", .data = "AAAA" });
    const binding = try captureHdiffSourceBinding(io, tmp.dir, "source.bin", 4, &counters);
    const plan: HdiffSourcePlan = .{
        .path = "source.bin",
        .binding = .{ .ready = binding },
        .target_size = 4,
    };
    try validateGuardedHdiffPlan(plan, .{ .source_size = 4, .target_size = 4 });
    try std.testing.expectError(
        error.Md5Mismatch,
        validateGuardedHdiffPlan(plan, .{ .source_size = 4, .target_size = 8 }),
    );
}

test "ZIP primary manifest directory is present-invalid instead of absent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "empty", .data = "" });
    var file = try tmp.dir.openFile(io, "empty", .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const archive: zip.Archive = .{ .entries = &.{}, .directories = &.{"pkg_version"} };
    try std.testing.expectError(
        error.InvalidExpectedState,
        packageStateZip(allocator, &reader, archive, .{ .software = .zzz }),
    );
}

test "oversized packaged identity evidence does not hide a valid manifest state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "identity-oversized.zip" });
    const manifest = "{\"remoteName\":\"core.bin\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n";
    const oversized = try allocator.alloc(u8, 1024 * 1024 + 1);
    @memset(oversized, '9');
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZero.exe", .data = "" });
    {
        var builder = try zip.Builder.init(allocator, io, root, zip_path, .deflate);
        defer builder.deinit();
        try builder.add(.{ .path = "pkg_version", .size = manifest.len, .data = .{ .bytes = manifest } }, null);
        try builder.add(.{ .path = "core.bin", .size = 1, .data = .{ .bytes = "1" } }, null);
        try builder.add(.{ .path = "version_info", .size = oversized.len, .data = .{ .bytes = oversized } }, null);
        try builder.finish();
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const archive = try zip.readCentral(allocator, &reader);
    const detected = try integrations.detect(io, root);
    const identity = (try standardIdentityZip(allocator, io, root, &reader, archive, detected)).?;
    try std.testing.expectEqual(@as(?integrations.Version, null), identity.source_version);
    try std.testing.expectEqual(@as(?integrations.Version, null), identity.target_version);

    const package = (try packageStateZip(allocator, &reader, archive, detected)).?;
    try std.testing.expectEqual(integrations.Software.zzz, package.software);
    try std.testing.expectEqual(@as(usize, 1), package.state.expected.entries.len);
    try std.testing.expectEqualStrings("core.bin", package.state.expected.entries[0].path);
}

test "WuWa standard archive identity keeps software detection but suppresses versions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const version_path = "Client/Binaries/Win64/ThirdParty/KrPcSdk_Global/KRSDKRes/KRSDK.bin";
    try tmp.dir.createDirPath(io, "Client/Binaries/Win64/ThirdParty/KrPcSdk_Global/KRSDKRes");
    try tmp.dir.writeFile(io, .{ .sub_path = "Wuthering Waves.exe", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "Client/Binaries/Win64/Client-Win64-Shipping.exe", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = version_path, .data = "KR_GameVersion=3.6.0\r\n" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "delta.zip" });
    {
        var builder = try zip.Builder.init(allocator, io, root, zip_path, .deflate);
        defer builder.deinit();
        try builder.add(.{ .path = version_path, .size = 22, .data = .{ .bytes = "KR_GameVersion=9.9.9\r\n" } }, null);
        try builder.finish();
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const archive = try zip.readCentral(allocator, &reader);
    const detected = try integrations.detect(io, root);
    const identity = (try standardIdentityZip(allocator, io, root, &reader, archive, detected)).?;
    try std.testing.expectEqual(integrations.Software.wuwa, identity.detected.software);
    try std.testing.expectEqual(@as(?integrations.Version, null), identity.source_version);
    try std.testing.expectEqual(@as(?integrations.Version, null), identity.target_version);
}

test "archive stage verification remains bound to retained target guards" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "work/staged");
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, "work/staged/core.bin");
    try guarded.writePositionalAll(io, "1", 0);
    try guarded.sync(io);
    try fs.validateGuardedOutput(io, guarded, 1);

    var targets = [_]Target{.{
        .path = "core.bin",
        .work_rel = "work/staged/core.bin",
        .size = 1,
        .md5 = try verify.parseMd5("c4ca4238a0b923820dcc509a6f75849b"),
        .state = .{ .staged = guarded },
    }};
    var stage: Stage = .{ .targets = &targets, .removals = &.{} };
    defer stage.discardGuards(io);

    const entries = try allocator.dupe(manifest_mod.File, &.{.{
        .path = "core.bin",
        .size = 1,
        .md5 = try verify.parseMd5("c4ca4238a0b923820dcc509a6f75849b"),
    }});
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    try map.put(allocator, "core.bin", 0);
    const package = testingPackageState(.zzz, .{ .entries = entries, .map = map }, true);
    var output: std.Io.Writer.Allocating = .init(allocator);
    var integrity_counters: integrity_run.Counters = .{};
    try std.testing.expect(!try validateStandardStage(io, root, &tmp.dir, &stage, package, true, &output.writer, &integrity_counters));

    try guarded.writePositionalAll(io, "2", 0);
    try guarded.sync(io);
    try std.testing.expectError(
        error.Md5Mismatch,
        validateStandardStage(io, root, &tmp.dir, &stage, package, false, &output.writer, &integrity_counters),
    );
    try guarded.writePositionalAll(io, "1", 0);
    try guarded.sync(io);
    try std.testing.expect(!try validateStandardStage(io, root, &tmp.dir, &stage, package, false, &output.writer, &integrity_counters));

    var observed: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try guarded.readPositionalAll(io, &observed, 0));
    try std.testing.expectEqualStrings("1", &observed);

    if (builtin.target.os.tag != .windows) {
        try tmp.dir.rename("work/staged/core.bin", tmp.dir, "work/staged/moved.bin", io);
        try tmp.dir.writeFile(io, .{ .sub_path = "work/staged/core.bin", .data = "sentinel" });
        try std.testing.expectError(
            error.StagingBindingChanged,
            validateStandardStage(io, root, &tmp.dir, &stage, package, true, &output.writer, &integrity_counters),
        );
        const sentinel = try tmp.dir.readFileAlloc(io, "work/staged/core.bin", allocator, .limited(16));
        try std.testing.expectEqualStrings("sentinel", sentinel);
    }

    stage.discardGuards(io);
    stage.discardGuards(io);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "work/staged/core.bin", .{ .follow_symlinks = false }));
    } else {
        try tmp.dir.deleteFile(io, "work/staged/moved.bin");
    }
}

test "HDiff reports a stale manifest deletion as an error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "kept.bin", .data = "1" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    const entries = try allocator.dupe(manifest_mod.File, &.{.{
        .path = "kept.bin",
        .size = 1,
        .md5 = try verify.parseMd5("c4ca4238a0b923820dcc509a6f75849b"),
    }});
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    try map.put(allocator, "kept.bin", 0);
    const package = testingPackageState(.zzz, .{ .entries = entries, .map = map }, true);
    const stage: Stage = .{ .targets = &.{}, .removals = &.{"kept.bin"} };

    var directory = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer directory.close(io);
    var output: std.Io.Writer.Allocating = .init(allocator);
    var integrity_counters: integrity_run.Counters = .{};
    try std.testing.expect(try validateStandardStage(io, root, &directory, &stage, package, true, &output.writer, &integrity_counters));
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "Manifest still lists removed file: kept.bin") != null);
}

test "standard archive destination layout handles case-only publication without weakening manifest spelling" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const digest: [16]u8 = @splat(0);
    const expected = [_]manifest_mod.File{.{ .path = "new.bin", .size = 1, .md5 = digest }};

    const layout = try standardDestinationLayout(
        allocator,
        &.{"new.bin"},
        &.{"NEW.bin"},
        &expected,
        true,
    );
    try std.testing.expectEqual(@as(usize, 0), layout.effective_removals.len);

    const aliased_expected = [_]manifest_mod.File{.{ .path = "NEW.bin", .size = 1, .md5 = digest }};
    try std.testing.expectError(error.InvalidDeltaLayout, standardDestinationLayout(
        allocator,
        &.{"new.bin"},
        &.{},
        &aliased_expected,
        true,
    ));
    try std.testing.expectError(error.InvalidDeltaLayout, standardDestinationLayout(
        allocator,
        &.{},
        &.{"new.bin"},
        &aliased_expected,
        true,
    ));
    const unsafe_expected = [_]manifest_mod.File{.{ .path = "bad\\name", .size = 1, .md5 = digest }};
    try std.testing.expectError(error.InvalidDeltaLayout, standardDestinationLayout(
        allocator,
        &.{},
        &.{},
        &unsafe_expected,
        true,
    ));
    try std.testing.expectError(error.InvalidDeltaLayout, standardDestinationLayout(
        allocator,
        &.{},
        &.{"..\\outside"},
        &.{},
        true,
    ));
    try std.testing.expectError(error.InvalidDeltaLayout, standardDestinationLayout(
        allocator,
        &.{"Dir/new"},
        &.{"dir"},
        &.{},
        true,
    ));
    const exact_transition = try standardDestinationLayout(
        allocator,
        &.{"dir/new"},
        &.{"dir"},
        &.{},
        true,
    );
    try std.testing.expectEqual(@as(usize, 1), exact_transition.effective_removals.len);

    const posix = try standardDestinationLayout(
        allocator,
        &.{"new.bin"},
        &.{"NEW.bin"},
        &expected,
        false,
    );
    try std.testing.expectEqual(@as(usize, 1), posix.effective_removals.len);
}

test "standard delta methods recognize only their own controls" {
    try std.testing.expect(isStandardControl(.file_delta, delta.file_delta_deletion_path));
    try std.testing.expect(!isStandardControl(.file_delta, "deletefiles.txt"));
    try std.testing.expect(!isStandardControl(.file_delta, "hdifffiles.txt"));
    try std.testing.expect(isStandardControl(.hdiff, "deletefiles.txt"));
    try std.testing.expect(isStandardControl(.hdiff, "hdifffiles.txt"));
}

test "control lists reject duplicate paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectError(error.InvalidDeletionList, parseDeletionList(allocator, "same.bin\nsame.bin\n"));
    try std.testing.expectError(error.InvalidHDiffList, parseHdiffList(allocator, "{\"remoteName\":\"same.bin\"}\n{\"remoteName\":\"same.bin\"}\n"));
}

test "standard archive detection accepts zstd skippable frame starts" {
    try std.testing.expect(isZstdFrameStart(0xfd2fb528));
    try std.testing.expect(isZstdFrameStart(0x184d2a50));
    try std.testing.expect(isZstdFrameStart(0x184d2a5f));
    try std.testing.expect(!isZstdFrameStart(0x184d2a60));
    try std.testing.expect(!isZstdFrameStart(0x04034b50));
}

test "HDiff ZIP space requirement includes bounded retry and independent reconstruction units" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "delta.zip" });

    const patch = [_]u8{ 72, 68, 73, 70, 70, 49, 51, 38, 0, 4, 4, 0, 0, 0, 1, 0, 0, 0, 4, 0, 3, 97, 98, 88, 100 };
    const hdiff_list = "{\"remoteName\":\"a\"}\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "abcd" });
    {
        var builder = try zip.Builder.init(allocator, io, root, zip_path, .deflate);
        defer builder.deinit();
        try builder.add(.{ .path = "a.hdiff", .size = patch.len, .data = .{ .bytes = &patch } }, null);
        try builder.add(.{ .path = "hdifffiles.txt", .size = hdiff_list.len, .data = .{ .bytes = hdiff_list } }, null);
        try builder.add(.{ .path = "deletefiles.txt", .size = 0, .data = .{ .bytes = "" } }, null);
        try builder.finish();
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const archive = try zip.readCentral(allocator, &reader);
    const controls = try readStandardZipControls(allocator, &reader, archive);
    try std.testing.expectEqual(StandardMethod.hdiff, controls.method);
    var counters: integrity_run.Counters = .{};
    const space = try zipSpaceRequired(allocator, io, tmp.dir, &reader, archive, controls, null, &counters, null);
    try std.testing.expectEqual(@as(u64, patch.len * 2 + 4 * 4), space.required);
}

test "HDiff tar.zst scan includes bounded retry and independent reconstruction space" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const archive_path = try std.fs.path.join(allocator, &.{ root, "delta.tar.zst" });

    const patch = [_]u8{ 72, 68, 73, 70, 70, 49, 51, 38, 0, 4, 4, 0, 0, 0, 1, 0, 0, 0, 4, 0, 3, 97, 98, 88, 100 };
    const hdiff_list = "{\"remoteName\":\"a\"}\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "abcd" });
    {
        var builder = try tar_zstd.Builder.init(allocator, io, root, archive_path, 3);
        defer builder.deinit();
        try builder.add(.{ .path = "a.hdiff", .size = patch.len, .data = .{ .bytes = &patch } }, null);
        try builder.add(.{ .path = "hdifffiles.txt", .size = hdiff_list.len, .data = .{ .bytes = hdiff_list } }, null);
        try builder.add(.{ .path = "deletefiles.txt", .size = 0, .data = .{ .bytes = "" } }, null);
        try builder.finish();
    }

    var archive_file = try fs.openRead(io, std.Io.Dir.cwd(), archive_path);
    defer archive_file.close(io);
    const archive_size = (try archive_file.stat(io)).size;
    var counters: integrity_run.Counters = .{};
    const scan = try scanStandardTar(allocator, io, archive_file, archive_size, root, &counters, null);
    try std.testing.expectEqual(StandardMethod.hdiff, scan.controls.method);
    try std.testing.expectEqual(@as(usize, 1), scan.controls.hdiff_paths.len);
    try std.testing.expectEqualStrings("a", scan.controls.hdiff_paths[0]);
    for (scan.entries) |entry| try std.testing.expect(entry.scan_md5 != null);
    const space = try tarSpaceRequired(allocator, io, tmp.dir, scan, &counters, null);
    try std.testing.expectEqual(@as(u64, patch.len * 2 + 4 * 4), space.required);
}

test "HDiff archives skip a missing source while publishing independent files and removals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const patch = [_]u8{ 72, 68, 73, 70, 70, 49, 51, 38, 0, 4, 4, 0, 0, 0, 1, 0, 0, 0, 4, 0, 3, 97, 98, 88, 100 };
    const hdiff_list = "{\"remoteName\":\"a\"}\n";
    for ([_]@import("../archive.zig").Format{ .zip_deflate, .tar_zstd }) |format| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        const package_path = try a.print("{s}/delta{s}", .{ root, format.extension() });
        try tmp.dir.writeFile(io, .{ .sub_path = "old", .data = "old bytes" });
        {
            var builder = try @import("../archive/writer.zig").Builder.init(a, io, root, package_path, format, .{});
            defer builder.deinit();
            try builder.add(.{ .path = "a.hdiff", .size = patch.len, .data = .{ .bytes = &patch } }, null);
            try builder.add(.{ .path = "hdifffiles.txt", .size = hdiff_list.len, .data = .{ .bytes = hdiff_list } }, null);
            try builder.add(.{ .path = "deletefiles.txt", .size = 4, .data = .{ .bytes = "old\n" } }, null);
            try builder.add(.{ .path = "independent", .size = 8, .data = .{ .bytes = "new data" } }, null);
            try builder.finish();
        }
        var output: std.Io.Writer.Allocating = .init(a);
        try std.testing.expectError(error.CompletedWithErrors, apply(a, io, package_path, root, true, false, false, &output.writer));
        try std.testing.expectEqualStrings("new data", try tmp.dir.readFileAlloc(io, "independent", a, .limited(16)));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "old", .{}));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "a", .{}));
        try std.testing.expect(std.mem.indexOf(u8, output.written(), "Staging: a.hdiff") != null);
        try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "abcd" });
        try apply(a, io, package_path, root, true, false, false, &output.writer);
        try std.testing.expectEqualStrings("abXd", try tmp.dir.readFileAlloc(io, "a", a, .limited(16)));
    }
}

test "HDiff tar.zst apply preserves a literal zift-work target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const archive_path = try std.fs.path.join(allocator, &.{ root, "delta.tar.zst" });

    const patch = [_]u8{ 72, 68, 73, 70, 70, 49, 51, 38, 0, 4, 4, 0, 0, 0, 1, 0, 0, 0, 4, 0, 3, 97, 98, 88, 100 };
    const hdiff_list = "{\"remoteName\":\"a\"}\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "abcd" });
    try tmp.dir.createDir(io, ".zift-work", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".zift-work/user.bin", .data = "old user bytes" });
    {
        var builder = try tar_zstd.Builder.init(allocator, io, root, archive_path, 3);
        defer builder.deinit();
        try builder.add(.{ .path = "a.hdiff", .size = patch.len, .data = .{ .bytes = &patch } }, null);
        try builder.add(.{ .path = "hdifffiles.txt", .size = hdiff_list.len, .data = .{ .bytes = hdiff_list } }, null);
        try builder.add(.{ .path = "deletefiles.txt", .size = 0, .data = .{ .bytes = "" } }, null);
        try builder.add(.{ .path = ".zift-work/user.bin", .size = 14, .data = .{ .bytes = "new user bytes" } }, null);
        try builder.finish();
    }

    var output: std.Io.Writer.Allocating = .init(allocator);
    var archive_file = try fs.openRead(io, std.Io.Dir.cwd(), archive_path);
    defer archive_file.close(io);
    const archive_size = (try archive_file.stat(io)).size;
    var integrity_counters: integrity_run.Counters = .{};
    try applyStandardTar(allocator, io, archive_file, archive_size, archive_path, root, true, false, false, &output.writer, &integrity_counters);

    const got = try tmp.dir.readFileAlloc(io, "a", allocator, .limited(5));
    const user = try tmp.dir.readFileAlloc(io, ".zift-work/user.bin", allocator, .limited(15));
    try std.testing.expectEqualStrings("abXd", got);
    try std.testing.expectEqualStrings("new user bytes", user);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".zift-work-1", .{}));
}

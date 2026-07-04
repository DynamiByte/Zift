// Update package planning and apply flows
const std = @import("std");

const clean = @import("clean.zig");
const cli = @import("cli.zig");
const fmt = @import("fmt.zig");
const manifest_mod = @import("manifest.zig");
const version = @import("version.zig");
const zip = @import("zip.zig");

const Game = struct {
    path: []const u8,
    manifest: manifest_mod.Manifest,
    full_version: []const u8,
    parts: version.Parts,
};

const Change = struct {
    entry: manifest_mod.Entry,
};

const AppliedCheck = struct {
    current_version: ?[]const u8 = null,
    same_game_version: bool = false,
    same_pkg_version: bool = false,
};

// Make flow

pub fn make(
    allocator: std.mem.Allocator,
    io: std.Io,
    left_path: []const u8,
    right_path: []const u8,
    explicit_out: ?[]const u8,
    assume_yes: bool,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !void {
    const left = try loadGame(allocator, io, left_path);
    const right = try loadGame(allocator, io, right_path);
    if (!std.mem.eql(u8, left.parts.prefix, right.parts.prefix)) {
        try err_out.print("version client mismatch: {s} and {s}\n", .{ left.full_version, right.full_version });
        return error.Reported;
    }

    const order = version.compareVersion(left.parts.number, right.parts.number) orelse return error.InvalidVersion;
    const old: Game, const new: Game = switch (order) {
        .lt => .{ left, right },
        .gt => .{ right, left },
        .eq => return error.AmbiguousVersions,
    };

    const changes = try planChanges(allocator, old.manifest, new.manifest, null);
    const out_path = explicit_out orelse try std.fmt.allocPrint(
        allocator,
        "zzz-{s}-{s}.zip",
        .{ old.parts.number, new.parts.number },
    );

    var total_size: u64 = new.manifest.pkg_bytes.len;
    for (changes) |change| total_size += change.entry.size;

    var total_buf: [64]u8 = undefined;
    try out.print("Create update {s} to {s}:\n", .{ old.full_version, new.full_version });
    try out.print("    Old: {s}\n    New: {s}\n    Output: {s}\n\n", .{
        old.path,
        new.path,
        out_path,
    });
    try out.print("Files to package: {d} ({s})\n", .{
        changes.len + 1,
        try fmt.bytes(&total_buf, total_size),
    });

    if (!try cli.confirm(io, out, assume_yes)) return error.Aborted;
    try out.writeByte('\n');
    try out.flush();

    const sources = try makeSources(allocator, changes, new.manifest.pkg_bytes);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{out_path});
    if (std.Io.Dir.cwd().statFile(io, out_path, .{})) |_| {
        return error.PathAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }
    if (std.Io.Dir.cwd().statFile(io, tmp_path, .{})) |_| {
        return error.PathAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    var progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Writing",
        .total_bytes = total_size,
        .total_files = sources.len,
        .show_speed = true,
    };
    try progress.start();
    zip.writeStore(allocator, io, new.path, tmp_path, sources, &progress) catch |err| {
        if (err != error.PathAlreadyExists) std.Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
        try out.writeByte('\n');
        return err;
    };
    std.Io.Dir.cwd().renamePreserve(tmp_path, std.Io.Dir.cwd(), out_path, io) catch |err| {
        std.Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
        try out.writeByte('\n');
        return err;
    };
    try progress.finish();
    try out.writeAll("\nComplete!\n");
}

// Change planning

fn loadGame(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Game {
    const man = try manifest_mod.load(allocator, io, path);
    const full = try version.detect(allocator, io, path);
    const parts = version.splitClientVersion(full) orelse return error.InvalidVersion;
    _ = version.compareVersion(parts.number, parts.number) orelse return error.InvalidVersion;
    return .{
        .path = path,
        .manifest = man,
        .full_version = full,
        .parts = parts,
    };
}

fn planChanges(
    allocator: std.mem.Allocator,
    old: manifest_mod.Manifest,
    new: manifest_mod.Manifest,
    progress: ?*fmt.Progress,
) ![]Change {
    var changes: std.ArrayList(Change) = .empty;

    for (new.entries) |new_entry| {
        const old_entry = old.find(new_entry.path) orelse {
            try changes.append(allocator, .{ .entry = new_entry });
            if (progress) |p| try p.finishFile();
            continue;
        };
        if (old_entry.size != new_entry.size or !std.mem.eql(u8, &old_entry.md5, &new_entry.md5)) {
            try changes.append(allocator, .{ .entry = new_entry });
        }
        if (progress) |p| try p.finishFile();
    }

    return changes.toOwnedSlice(allocator);
}

fn makeSources(
    allocator: std.mem.Allocator,
    changes: []const Change,
    pkg_bytes: []const u8,
) ![]zip.Source {
    var sources: std.ArrayList(zip.Source) = .empty;
    try sources.append(allocator, .{
        .path = "pkg_version",
        .size = pkg_bytes.len,
        .data = .{ .bytes = pkg_bytes },
    });

    for (changes) |change| {
        try sources.append(allocator, .{
            .path = change.entry.path,
            .size = change.entry.size,
            .expected_md5 = change.entry.md5,
            .data = .file,
        });
    }

    return sources.toOwnedSlice(allocator);
}

// Apply flow

pub fn apply(
    allocator: std.mem.Allocator,
    io: std.Io,
    zip_path: []const u8,
    game_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    out: *std.Io.Writer,
) !void {
    var zip_file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer zip_file.close(io);
    var zip_buf: [64 * 1024]u8 = undefined;
    var reader = zip_file.reader(io, &zip_buf);

    const pkg = try zip.readCentral(allocator, &reader, null);

    const pkg_entry = pkg.find("pkg_version") orelse return error.PackageMissingManifest;
    const pkg_bytes = try zip.extractEntryAlloc(allocator, &reader, pkg_entry, 128 * 1024 * 1024);
    const new_manifest = try manifest_mod.parse(allocator, pkg_bytes);

    try validatePackage(pkg, new_manifest, null);

    const new_version = try detectPackageVersion(allocator, &reader, pkg);

    const applied_check = if (new_version) |detected|
        try checkAlreadyApplied(allocator, io, game_path, detected, pkg_bytes)
    else
        AppliedCheck{};

    if (applied_check.same_game_version and applied_check.same_pkg_version) {
        try out.writeAll("Already up to date.\n");
        return;
    }

    const extra_plan = try clean.plan(allocator, io, game_path, new_manifest, null);

    var payload_size: u64 = 0;
    for (pkg.entries) |entry| payload_size += entry.zip_entry.uncompressed_size;

    try printApplyHeader(out, zip_path, game_path, applied_check.current_version, new_version);
    var payload_buf: [64]u8 = undefined;
    var stale_buf: [64]u8 = undefined;
    try out.print("\nNew files to update: {d} ({s})\n", .{
        pkg.entries.len,
        try fmt.bytes(&payload_buf, payload_size),
    });
    try out.print("Stale files to remove: {d} ({s})\n", .{
        extra_plan.extras.len,
        try fmt.bytes(&stale_buf, extra_plan.total_size),
    });

    if (!try cli.confirm(io, out, assume_yes)) return error.Aborted;
    try out.writeByte('\n');
    try out.flush();

    var extract_progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Updating",
        .total_bytes = payload_size,
        .total_files = pkg.entries.len,
        .show_speed = true,
    };
    try extract_progress.start();
    zip.extractAll(io, zip_path, game_path, pkg.entries, &extract_progress) catch |err| {
        try out.writeByte('\n');
        return err;
    };
    try extract_progress.finish();

    var clean_progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Cleaning",
        .total_bytes = extra_plan.total_size,
        .total_files = extra_plan.extras.len,
    };
    try clean_progress.start();
    clean.deleteExtrasProgress(io, game_path, extra_plan.extras, &clean_progress) catch |err| {
        try out.writeByte('\n');
        return err;
    };
    try clean_progress.finish();

    try checkAppliedFiles(io, game_path, new_manifest, out);
    if (verify_md5) {
        try verifyAppliedFiles(io, game_path, new_manifest, out);
    }

    try out.writeAll("\nComplete!\n");
}

// Package validation and version checks

fn checkAppliedFiles(
    io: std.Io,
    game_path: []const u8,
    manifest: manifest_mod.Manifest,
    out: *std.Io.Writer,
) !void {
    var check_progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Checking",
        .total_bytes = 0,
        .total_files = manifest.entries.len,
    };
    try check_progress.start();
    manifest_mod.checkFileSizes(io, game_path, manifest, &check_progress) catch |err| {
        try out.writeByte('\n');
        return err;
    };
    try check_progress.finish();
}

fn verifyAppliedFiles(
    io: std.Io,
    game_path: []const u8,
    manifest: manifest_mod.Manifest,
    out: *std.Io.Writer,
) !void {
    var verify_progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Verifying",
        .total_bytes = manifest_mod.totalSize(manifest),
        .total_files = manifest.entries.len,
        .show_speed = true,
    };
    try verify_progress.start();
    manifest_mod.verifyFileHashes(io, game_path, manifest, &verify_progress) catch |err| {
        try out.writeByte('\n');
        return err;
    };
    try verify_progress.finish();
}

fn printApplyHeader(
    out: *std.Io.Writer,
    zip_path: []const u8,
    game_path: []const u8,
    current_version: ?[]const u8,
    new_version: ?[]const u8,
) !void {
    const current = current_version orelse "unknown";
    const new = new_version orelse "unknown";
    try out.print("Update {s} to {s}:\n", .{ current, new });
    try out.print("    Update: {s}\n    Game: {s}\n", .{ zip_path, game_path });
}

fn validatePackage(pkg: zip.Package, man: manifest_mod.Manifest, progress: ?*fmt.Progress) !void {
    for (pkg.entries) |entry| {
        if (!std.mem.eql(u8, entry.path, "pkg_version")) {
            const expected = man.find(entry.path) orelse return error.ZipEntryNotInManifest;
            if (expected.size != entry.zip_entry.uncompressed_size) return error.ZipEntrySizeMismatch;
        }
        if (progress) |p| try p.finishFile();
    }
}

fn detectPackageVersion(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    pkg: zip.Package,
) !?[]const u8 {
    const paths = [_][]const u8{
        "ZenlessZoneZeroBeta_Data/resources.assets",
        "ZenlessZoneZero_Data/resources.assets",
    };

    for (paths) |path| {
        const entry = pkg.find(path) orelse continue;
        if (entry.zip_entry.uncompressed_size > 256 * 1024 * 1024) continue;
        const bytes = try zip.extractEntryAlloc(allocator, reader, entry, 256 * 1024 * 1024);
        if (version.detectFromBytes(bytes)) |detected| {
            const copy: []const u8 = try allocator.dupe(u8, detected);
            return copy;
        }
    }

    return null;
}

fn checkAlreadyApplied(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
    package_version: []const u8,
    package_pkg_bytes: []const u8,
) !AppliedCheck {
    const current_version = try detectGameVersionOptional(allocator, io, game_path);
    const current_pkg_bytes = try readGamePkgVersionOptional(allocator, io, game_path);

    return .{
        .current_version = current_version,
        .same_game_version = if (current_version) |current|
            std.mem.eql(u8, current, package_version)
        else
            false,
        .same_pkg_version = if (current_pkg_bytes) |bytes|
            std.mem.eql(u8, bytes, package_pkg_bytes)
        else
            false,
    };
}

fn detectGameVersionOptional(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
) !?[]const u8 {
    return version.detect(allocator, io, game_path) catch |err| switch (err) {
        error.VersionNotFound => null,
        else => |e| return e,
    };
}

fn readGamePkgVersionOptional(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
) !?[]const u8 {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{});
    defer game_dir.close(io);

    return manifest_mod.readFileAlloc(allocator, io, game_dir, "pkg_version", 128 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound,
        error.ExpectedFile,
        error.FileTooLarge,
        error.UnexpectedEof,
        => null,
        else => |e| return e,
    };
}

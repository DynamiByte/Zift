// Manifest-based stale file pruning
const std = @import("std");

const cli = @import("cli.zig");
const fmt = @import("fmt.zig");
const manifest_mod = @import("manifest.zig");
const version = @import("version.zig");

pub const Extra = struct {
    path: []const u8,
    size: u64,
};

pub const Plan = struct {
    extras: []Extra,
    total_size: u64,
};

// User-facing clean flow

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    out: *std.Io.Writer,
) !void {
    const manifest = try manifest_mod.loadAll(allocator, io, game_path);
    const detected = version.detect(allocator, io, game_path) catch |err| switch (err) {
        error.VersionNotFound => null,
        else => |e| return e,
    };
    const p = try plan(allocator, io, game_path, manifest, null);

    if (p.extras.len == 0) {
        try out.writeAll("No files to remove.\n");
        try checkOrVerify(io, game_path, manifest, verify_md5, out);
        try out.writeAll("\nComplete!\n");
        return;
    }

    try out.print("Clean {s}:\n", .{detected orelse "game"});
    try out.print("    Game: {s}\n\n", .{game_path});
    var size_buf: [64]u8 = undefined;
    try out.print("Stale files to remove: {d} ({s})\n", .{
        p.extras.len,
        try fmt.bytes(&size_buf, p.total_size),
    });

    if (!try cli.confirm(io, out, assume_yes)) return error.Aborted;
    try out.writeByte('\n');
    try out.flush();

    var progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Cleaning",
        .total_bytes = p.total_size,
        .total_files = p.extras.len,
    };
    try progress.start();
    deleteExtrasProgress(io, game_path, p.extras, &progress) catch |err| {
        try out.writeByte('\n');
        return err;
    };
    try progress.finish();

    try checkOrVerify(io, game_path, manifest, verify_md5, out);
    try out.writeAll("\nComplete!\n");
}

// Stale file planning

pub fn plan(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
    manifest: manifest_mod.Manifest,
    progress: ?*fmt.Progress,
) !Plan {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .iterate = true, .access_sub_paths = true });
    defer game_dir.close(io);

    var extras: std.ArrayList(Extra) = .empty;
    var total_size: u64 = 0;

    var walker = try game_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;

        const rel = try allocator.dupe(u8, entry.path);
        const stat = try entry.dir.statFile(io, entry.basename, .{});
        if (progress) |p| {
            try p.addBytes(stat.size);
            try p.finishFile();
        }

        if (isPkgVersionFile(rel)) continue;
        if (manifest.contains(rel)) continue;
        if (!isStreamingAssetsPath(rel)) continue;

        try extras.append(allocator, .{ .path = rel, .size = stat.size });
        total_size += stat.size;
    }

    return .{
        .extras = try extras.toOwnedSlice(allocator),
        .total_size = total_size,
    };
}

pub fn deleteExtras(io: std.Io, game_path: []const u8, extras: []const Extra) !void {
    try deleteExtrasProgress(io, game_path, extras, null);
}

pub fn deleteExtrasProgress(
    io: std.Io,
    game_path: []const u8,
    extras: []const Extra,
    progress: ?*fmt.Progress,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (extras) |extra| {
        try game_dir.deleteFile(io, extra.path);
        if (progress) |p| {
            try p.addBytes(extra.size);
            try p.finishFile();
        }
    }
}

fn checkOrVerify(
    io: std.Io,
    game_path: []const u8,
    manifest: manifest_mod.Manifest,
    verify_md5: bool,
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
    const check_failures = try manifest_mod.reportFileSizeProblems(io, game_path, manifest, &check_progress, out);
    try check_progress.finish();
    if (check_failures != 0) {
        try out.print("Check found {d} problem", .{check_failures});
        if (check_failures != 1) try out.writeByte('s');
        try out.writeAll(".\n");
    }

    if (!verify_md5) return;

    var verify_progress: fmt.Progress = .{
        .io = io,
        .writer = out,
        .label = "Verifying",
        .total_bytes = manifest_mod.totalSize(manifest),
        .total_files = manifest.entries.len,
        .show_speed = true,
    };
    try verify_progress.start();
    const verify_failures = try manifest_mod.reportFileHashProblems(io, game_path, manifest, &verify_progress, out);
    try verify_progress.finish();
    if (verify_failures != 0) {
        try out.print("Verify found {d} problem", .{verify_failures});
        if (verify_failures != 1) try out.writeByte('s');
        try out.writeAll(".\n");
    }
}

fn isPkgVersionFile(path: []const u8) bool {
    if (std.mem.indexOfScalar(u8, path, '/') != null) return false;
    return std.mem.eql(u8, path, "pkg_version") or std.mem.endsWith(u8, path, "_pkg_version");
}

fn isStreamingAssetsPath(path: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(path, "StreamingAssets") != null;
}

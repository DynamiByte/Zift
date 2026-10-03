const manifest_mod = @import("core/manifest.zig");
const std = @import("std");
const fs = @import("core/fs.zig");

const ui = @import("ui.zig");
const interrupt = @import("interrupt.zig");

pub const Hash = struct {
    size: u64,
    md5: [16]u8,
};

pub fn totalSize(set: manifest_mod.Set) u64 {
    var total: u64 = 0;
    for (set.entries) |entry| total +|= entry.size;
    return total;
}

pub const FailureReason = union(enum) {
    missing,
    not_file,
    size_mismatch,
    hash_mismatch,
    read_failed: anyerror,
};

pub const Failure = struct {
    path: []const u8 = "",
    reason: FailureReason = .missing,
    expected_size: u64 = 0,
    actual_size: ?u64 = null,
};

pub fn printFailure(out: *std.Io.Writer, failure: Failure) !void {
    try ui.warning(out);
    try out.writeAll("Verification:");
    try ui.reset(out);
    try out.writeByte(' ');
    try out.writeAll(failure.path);
    switch (failure.reason) {
        .missing => try out.writeAll(" is missing"),
        .not_file => try out.writeAll(" is not a file"),
        .size_mismatch => if (failure.actual_size) |actual| {
            try out.print(" has size {d}, expected {d}", .{ actual, failure.expected_size });
        } else {
            try out.print(" has the wrong size, expected {d}", .{failure.expected_size});
        },
        .hash_mismatch => try out.writeAll(" has the wrong MD5"),
        .read_failed => |err| try out.print(" cannot be read ({s})", .{@errorName(err)}),
    }
    try out.writeByte('\n');
}

pub fn hashFile(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    progress: ?*ui.Progress,
) !Hash {
    var file = fs.openRead(io, dir, path) catch |err| switch (err) {
        error.SymLinkLoop => return error.ExpectedFile,
        else => |e| return e,
    };
    defer file.close(io);
    return hashOpenFile(io, file, progress);
}

// borrowed reconstruction handle against pathname redirection
pub fn hashOpenFile(
    io: std.Io,
    file: std.Io.File,
    progress: ?*ui.Progress,
) !Hash {
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;

    var hasher = std.crypto.hash.Md5.init(.{});
    var offset: u64 = 0;
    var buf: [1024 * 1024]u8 = undefined;
    while (true) {
        try interrupt.check();
        const n = try fs.readAllAt(io, file, &buf, offset);
        if (n == 0) break;
        hasher.update(buf[0..n]);
        offset += n;
        if (progress) |p| try p.addBytes(n);
    }

    var md5: [16]u8 = undefined;
    hasher.final(&md5);
    return .{ .size = offset, .md5 = md5 };
}

pub fn sizeProblem(io: std.Io, directory: std.Io.Dir, entry: manifest_mod.File) !?Failure {
    const stat = directory.statFile(io, entry.path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .{ .path = entry.path, .reason = .missing, .expected_size = entry.size },
        error.Canceled => return err,
        else => return .{ .path = entry.path, .reason = .{ .read_failed = err }, .expected_size = entry.size },
    };
    if (stat.kind != .file) return .{ .path = entry.path, .reason = .not_file, .expected_size = entry.size };
    if (stat.size != entry.size) return .{ .path = entry.path, .reason = .size_mismatch, .expected_size = entry.size, .actual_size = stat.size };
    return null;
}

pub fn sizeProblems(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    expected: []const manifest_mod.File,
    progress: *ui.Progress,
) ![]Failure {
    var directory = try std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true });
    defer directory.close(io);

    var failures: std.ArrayList(Failure) = .empty;
    errdefer failures.deinit(allocator);
    for (expected) |entry| {
        if (try sizeProblem(io, directory, entry)) |failure| try failures.append(allocator, failure);
        try progress.finishFile();
    }
    return failures.toOwnedSlice(allocator);
}

pub fn hashProblems(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    expected: []const manifest_mod.File,
    progress: *ui.Progress,
) ![]Failure {
    var directory = try std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true });
    defer directory.close(io);

    var failures: std.ArrayList(Failure) = .empty;
    errdefer failures.deinit(allocator);
    for (expected) |entry| {
        const actual = hashFile(io, directory, entry.path, progress) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                try failures.append(allocator, .{ .path = entry.path, .reason = .missing, .expected_size = entry.size });
                try progress.finishFile();
                continue;
            },
            error.ExpectedFile => {
                try failures.append(allocator, .{ .path = entry.path, .reason = .not_file, .expected_size = entry.size });
                try progress.finishFile();
                continue;
            },
            error.Interrupted, error.Canceled => return err,
            else => {
                try failures.append(allocator, .{ .path = entry.path, .reason = .{ .read_failed = err }, .expected_size = entry.size });
                try progress.finishFile();
                continue;
            },
        };
        if (actual.size != entry.size) {
            try failures.append(allocator, .{ .path = entry.path, .reason = .size_mismatch, .expected_size = entry.size, .actual_size = actual.size });
        } else if (!std.mem.eql(u8, &actual.md5, &entry.md5)) {
            try failures.append(allocator, .{ .path = entry.path, .reason = .hash_mismatch, .expected_size = entry.size, .actual_size = actual.size });
        }
        try progress.finishFile();
    }
    return failures.toOwnedSlice(allocator);
}

pub fn matchesFile(io: std.Io, dir: std.Io.Dir, path: []const u8, size: u64, md5: [16]u8) !bool {
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    if (stat.kind != .file or stat.size != size) return false;
    const actual = hashFile(io, dir, path, null) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.ExpectedFile => return false,
        else => |e| return e,
    };
    return actual.size == size and std.mem.eql(u8, &actual.md5, &md5);
}

pub fn pathAbsent(io: std.Io, dir: std.Io.Dir, path: []const u8) !bool {
    _ = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return true,
        else => |e| return e,
    };
    return false;
}

pub fn parseMd5(text: []const u8) ![16]u8 {
    if (text.len != 32) return error.InvalidMd5;
    var md5: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&md5, text) catch return error.InvalidMd5;
    return md5;
}

test "hash does not follow final symlink" {
    if (@import("builtin").target.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = "x" });
    try tmp.dir.symLink(io, "target", "link", .{});
    try std.testing.expectError(error.ExpectedFile, hashFile(io, tmp.dir, "link", null));
}

test "size problems treat a file ancestor as a missing target path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "blocker" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Checking", .total_files = 1 };
    try progress.start();
    const failures = try sizeProblems(allocator, io, root, &.{.{ .path = "a/b", .size = 1, .md5 = @splat(0) }}, &progress);
    try progress.finish();
    try std.testing.expectEqual(@as(usize, 1), failures.len);
    try std.testing.expectEqual(FailureReason.missing, failures[0].reason);
}

test "hash problems treat a file ancestor as a missing target path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "blocker" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Verifying", .total_files = 1 };
    try progress.start();
    const failures = try hashProblems(allocator, io, root, &.{.{ .path = "a/b", .size = 1, .md5 = @splat(0) }}, &progress);
    try progress.finish();
    try std.testing.expectEqual(@as(usize, 1), failures.len);
    try std.testing.expectEqual(FailureReason.missing, failures[0].reason);
}

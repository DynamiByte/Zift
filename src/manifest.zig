// pkg_version parsing, path safety, and file verification
const std = @import("std");

const fmt = @import("fmt.zig");

pub const Manifest = struct {
    version: ?[]const u8 = null,
    entries: []Entry,
    map: std.StringHashMapUnmanaged(u32),
    pkg_bytes: []const u8,

    pub fn find(self: Manifest, path: []const u8) ?Entry {
        const index = self.map.get(path) orelse return null;
        return self.entries[index];
    }

    pub fn contains(self: Manifest, path: []const u8) bool {
        return self.map.contains(path);
    }
};

pub const Entry = struct {
    path: []const u8,
    size: u64,
    md5: [16]u8,
};

pub fn totalSize(man: Manifest) u64 {
    var total: u64 = 0;
    for (man.entries) |entry| total += entry.size;
    return total;
}

const RawEntry = struct {
    remoteName: []const u8,
    md5: []const u8,
    fileSize: u64,
};

// Manifest loading and parsing

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
) !Manifest {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{});
    defer game_dir.close(io);

    const bytes = try readFileAlloc(allocator, io, game_dir, "pkg_version", 128 * 1024 * 1024);
    return parse(allocator, bytes);
}

pub fn loadAll(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
) !Manifest {
    const main = load(allocator, io, game_path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => |e| return e,
    };
    const audio = try loadAudio(allocator, io, game_path);

    if (main == null and audio == null) return error.FileNotFound;
    if (main) |man| {
        if (audio) |aud| return combine(allocator, man, aud);
        return man;
    }
    return audio.?;
}

pub fn loadAudio(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
) !?Manifest {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .iterate = true });
    defer game_dir.close(io);

    var bytes = std.ArrayList(u8).empty;
    var found = false;

    var it = game_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isAudioPkgVersion(entry.name)) continue;

        const data = try readFileAlloc(allocator, io, game_dir, entry.name, 128 * 1024 * 1024);
        try bytes.appendSlice(allocator, data);
        try appendNewline(allocator, &bytes);
        found = true;
    }

    if (!found) return null;
    return try parse(allocator, try bytes.toOwnedSlice(allocator));
}

pub fn combine(
    allocator: std.mem.Allocator,
    first: Manifest,
    second: Manifest,
) !Manifest {
    var entries: std.ArrayList(Entry) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;

    try appendEntries(allocator, &entries, &map, first.entries);
    try appendEntries(allocator, &entries, &map, second.entries);

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .map = map,
        .pkg_bytes = first.pkg_bytes,
    };
}

fn appendEntries(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(Entry),
    map: *std.StringHashMapUnmanaged(u32),
    source: []const Entry,
) !void {
    for (source) |entry| {
        const got = try map.getOrPut(allocator, entry.path);
        if (got.found_existing) continue;
        got.value_ptr.* = @intCast(entries.items.len);
        try entries.append(allocator, entry);
    }
}

fn isAudioPkgVersion(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "Audio_") and std.mem.endsWith(u8, name, "_pkg_version");
}

fn appendNewline(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8)) !void {
    if (bytes.items.len == 0 or bytes.items[bytes.items.len - 1] != '\n') {
        try bytes.append(allocator, '\n');
    }
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Manifest {
    var entries: std.ArrayList(Entry) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;

    var line_it = std.mem.splitScalar(u8, bytes, '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;

        const raw = std.json.parseFromSliceLeaky(RawEntry, allocator, line, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return error.InvalidManifestJson;

        try validatePath(raw.remoteName);
        const path = try allocator.dupe(u8, raw.remoteName);
        const md5 = parseMd5(raw.md5) catch return error.InvalidMd5;

        const got = try map.getOrPut(allocator, path);
        if (got.found_existing) return error.DuplicateManifestPath;
        got.value_ptr.* = @intCast(entries.items.len);

        try entries.append(allocator, .{
            .path = path,
            .size = raw.fileSize,
            .md5 = md5,
        });
    }

    if (entries.items.len == 0) return error.EmptyManifest;

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .map = map,
        .pkg_bytes = bytes,
    };
}

pub fn validatePath(path: []const u8) !void {
    if (path.len == 0) return error.UnsafePath;
    if (path[0] == '/' or path[0] == '\\') return error.UnsafePath;
    if (path.len >= 2 and path[1] == ':') return error.UnsafePath;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.UnsafePath;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.UnsafePath;
    if (path.len > std.math.maxInt(u16)) return error.PathTooLongForZip;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0) return error.UnsafePath;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) {
            return error.UnsafePath;
        }
    }
}

pub fn managedRoots(
    allocator: std.mem.Allocator,
    manifest: Manifest,
) ![]const []const u8 {
    var roots = std.ArrayList([]const u8).empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;

    for (manifest.entries) |entry| {
        const slash = std.mem.indexOfScalar(u8, entry.path, '/') orelse continue;
        if (slash == 0) continue;
        const root = entry.path[0..slash];
        const got = try seen.getOrPut(allocator, root);
        if (!got.found_existing) {
            got.value_ptr.* = {};
            try roots.append(allocator, root);
        }
    }

    return roots.toOwnedSlice(allocator);
}

// File hashing and verification

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    max_size: u64,
) ![]u8 {
    var file = try dir.openFile(io, path, .{ .allow_directory = false });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;
    if (stat.size > max_size) return error.FileTooLarge;
    const len: usize = @intCast(stat.size);
    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);
    const n = try file.readPositionalAll(io, bytes, 0);
    if (n != len) return error.UnexpectedEof;
    return bytes;
}

pub const VerifyFailureReason = enum {
    missing,
    not_file,
    size_mismatch,
    hash_mismatch,
};

pub const VerifyFailure = struct {
    path: []const u8 = "",
    reason: VerifyFailureReason = .missing,
    expected_size: u64 = 0,
    actual_size: ?u64 = null,
};

pub fn printVerifyFailure(out: *std.Io.Writer, failure: VerifyFailure) !void {
    try out.print("verification failed: {s}", .{failure.path});
    switch (failure.reason) {
        .missing => try out.writeAll(" is missing"),
        .not_file => try out.writeAll(" is not a file"),
        .size_mismatch => if (failure.actual_size) |actual| {
            try out.print(" has size {d}, expected {d}", .{ actual, failure.expected_size });
        } else {
            try out.print(" has the wrong size, expected {d}", .{failure.expected_size});
        },
        .hash_mismatch => try out.writeAll(" has the wrong MD5"),
    }
    try out.writeByte('\n');
}

fn setVerifyFailure(
    failure: ?*VerifyFailure,
    path: []const u8,
    reason: VerifyFailureReason,
    expected_size: u64,
    actual_size: ?u64,
) void {
    if (failure) |out| {
        out.* = .{
            .path = path,
            .reason = reason,
            .expected_size = expected_size,
            .actual_size = actual_size,
        };
    }
}

pub fn hashFile(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    progress: ?*fmt.Progress,
) !struct { size: u64, md5: [16]u8 } {
    var file = try dir.openFile(io, path, .{ .allow_directory = false });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;

    var hasher = std.crypto.hash.Md5.init(.{});
    var offset: u64 = 0;
    var buf: [1024 * 1024]u8 = undefined;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, offset);
        if (n == 0) break;
        hasher.update(buf[0..n]);
        offset += n;
        if (progress) |p| try p.addBytes(n);
    }

    var md5: [16]u8 = undefined;
    hasher.final(&md5);
    return .{ .size = stat.size, .md5 = md5 };
}

pub fn reportFileSizeProblems(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
    out: *std.Io.Writer,
) !u64 {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    var failures: u64 = 0;
    for (man.entries) |entry| {
        const stat = game_dir.statFile(io, entry.path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                try progress.finishFile();
                try out.writeByte('\n');
                try printVerifyFailure(out, .{ .path = entry.path, .reason = .missing, .expected_size = entry.size });
                failures += 1;
                continue;
            },
            else => |e| return e,
        };
        if (stat.kind != .file) {
            try out.writeByte('\n');
            try printVerifyFailure(out, .{ .path = entry.path, .reason = .not_file, .expected_size = entry.size });
            failures += 1;
        } else if (stat.size != entry.size) {
            try out.writeByte('\n');
            try printVerifyFailure(out, .{ .path = entry.path, .reason = .size_mismatch, .expected_size = entry.size, .actual_size = stat.size });
            failures += 1;
        }
        try progress.finishFile();
    }
    return failures;
}

pub fn reportFileHashProblems(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
    out: *std.Io.Writer,
) !u64 {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    var failures: u64 = 0;
    for (man.entries) |entry| {
        const actual = hashFile(io, game_dir, entry.path, progress) catch |err| switch (err) {
            error.FileNotFound => {
                try out.writeByte('\n');
                try printVerifyFailure(out, .{ .path = entry.path, .reason = .missing, .expected_size = entry.size });
                failures += 1;
                try progress.finishFile();
                continue;
            },
            error.ExpectedFile => {
                try out.writeByte('\n');
                try printVerifyFailure(out, .{ .path = entry.path, .reason = .not_file, .expected_size = entry.size });
                failures += 1;
                try progress.finishFile();
                continue;
            },
            else => |e| return e,
        };
        if (actual.size != entry.size) {
            try out.writeByte('\n');
            try printVerifyFailure(out, .{ .path = entry.path, .reason = .size_mismatch, .expected_size = entry.size, .actual_size = actual.size });
            failures += 1;
        } else if (!std.mem.eql(u8, &actual.md5, &entry.md5)) {
            try out.writeByte('\n');
            try printVerifyFailure(out, .{ .path = entry.path, .reason = .hash_mismatch, .expected_size = entry.size, .actual_size = actual.size });
            failures += 1;
        }
        try progress.finishFile();
    }
    return failures;
}

pub fn checkFileSizes(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
    failure: ?*VerifyFailure,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (man.entries) |entry| {
        const stat = game_dir.statFile(io, entry.path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                setVerifyFailure(failure, entry.path, .missing, entry.size, null);
                return error.VerificationFailed;
            },
            else => |e| return e,
        };
        if (stat.kind != .file) {
            setVerifyFailure(failure, entry.path, .not_file, entry.size, null);
            return error.VerificationFailed;
        }
        if (stat.size != entry.size) {
            setVerifyFailure(failure, entry.path, .size_mismatch, entry.size, stat.size);
            return error.VerificationFailed;
        }
        try progress.finishFile();
    }
}

pub fn verifyFileHashes(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
    failure: ?*VerifyFailure,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (man.entries) |entry| {
        const actual = hashFile(io, game_dir, entry.path, progress) catch |err| switch (err) {
            error.FileNotFound => {
                setVerifyFailure(failure, entry.path, .missing, entry.size, null);
                return error.VerificationFailed;
            },
            error.ExpectedFile => {
                setVerifyFailure(failure, entry.path, .not_file, entry.size, null);
                return error.VerificationFailed;
            },
            else => |e| return e,
        };
        if (actual.size != entry.size) {
            setVerifyFailure(failure, entry.path, .size_mismatch, entry.size, actual.size);
            return error.VerificationFailed;
        }
        if (!std.mem.eql(u8, &actual.md5, &entry.md5)) {
            setVerifyFailure(failure, entry.path, .hash_mismatch, entry.size, actual.size);
            return error.VerificationFailed;
        }
        try progress.finishFile();
    }
}

fn parseMd5(text: []const u8) ![16]u8 {
    if (text.len != 32) return error.InvalidMd5;

    var out: [16]u8 = undefined;
    for (&out, 0..) |*byte, i| {
        const hi = try hexValue(text[i * 2]);
        const lo = try hexValue(text[i * 2 + 1]);
        byte.* = (hi << 4) | lo;
    }
    return out;
}

fn hexValue(ch: u8) !u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => error.InvalidMd5,
    };
}

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

pub fn checkFileSizes(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (man.entries) |entry| {
        const stat = game_dir.statFile(io, entry.path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.VerificationFailed,
            else => |e| return e,
        };
        if (stat.kind != .file) return error.VerificationFailed;
        if (stat.size != entry.size) return error.VerificationFailed;
        try progress.finishFile();
    }
}

pub fn verifyFileHashes(
    io: std.Io,
    game_path: []const u8,
    man: Manifest,
    progress: *fmt.Progress,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (man.entries) |entry| {
        const actual = try hashFile(io, game_dir, entry.path, progress);
        if (actual.size != entry.size) return error.VerificationFailed;
        if (!std.mem.eql(u8, &actual.md5, &entry.md5)) return error.VerificationFailed;
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

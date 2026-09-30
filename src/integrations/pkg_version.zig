const manifest_mod = @import("../core/manifest.zig");
const std = @import("std");
const fs = @import("../core/fs.zig");

const path_util = @import("../path.zig");
const verify = @import("../verify.zig");

const Manifest = manifest_mod.Set;

const Set = manifest_mod.Snapshot;

const Entry = manifest_mod.File;

const RawEntry = struct {
    remoteName: []const u8,
    md5: []const u8,
    fileSize: u64,
};

pub fn loadFamilyOptional(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    is_member: *const fn ([]const u8) bool,
) !?Set {
    var directory = try std.Io.Dir.cwd().openDir(io, directory_path, .{ .iterate = true });
    defer directory.close(io);

    const anchor = directory.statFile(io, "pkg_version", .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    if (anchor.kind != .file) return error.ExpectedFile;

    var it = directory.iterate();
    var files: std.ArrayList(manifest_mod.MetadataFile) = .empty;
    while (try it.next(io)) |entry| {
        if (!is_member(entry.name)) continue;
        if (entry.kind != .file) return error.ExpectedFile;
        try files.append(allocator, .{
            .path = try allocator.dupe(u8, entry.name),
            .bytes = try fs.readFileAlloc(allocator, io, directory, entry.name, 128 * 1024 * 1024),
        });
    }
    const owned = try files.toOwnedSlice(allocator);
    return try loadManifestFiles(allocator, owned, "pkg_version");
}

pub fn loadSetFiles(allocator: std.mem.Allocator, files: []manifest_mod.MetadataFile) !Set {
    var has_main = false;
    for (files) |file| {
        if (!isMetadataFile(file.path)) return error.InvalidManifestJson;
        if (std.mem.eql(u8, file.path, "pkg_version")) has_main = true;
    }
    if (!has_main) return error.MissingManifest;
    return loadManifestFiles(allocator, files, "pkg_version");
}

pub fn loadManifestFiles(
    allocator: std.mem.Allocator,
    files: []manifest_mod.MetadataFile,
    required_main: ?[]const u8,
) !Set {
    if (required_main) |required| {
        var found = false;
        for (files) |file| if (std.mem.eql(u8, file.path, required)) {
            found = true;
            break;
        };
        if (!found) return error.MissingManifest;
    }

    std.mem.sortUnstable(manifest_mod.MetadataFile, files, {}, struct {
        fn lessThan(_: void, a: manifest_mod.MetadataFile, b: manifest_mod.MetadataFile) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lessThan);
    for (files[1..], files[0 .. files.len - 1]) |file, previous| {
        if (std.mem.eql(u8, file.path, previous.path)) return error.DuplicateManifestPath;
    }

    var entries: std.ArrayList(Entry) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    for (files) |file| {
        if (std.mem.trim(u8, file.bytes, " \t\r\n").len == 0) continue;
        try appendManifest(allocator, &entries, &map, file.bytes);
    }
    if (entries.items.len == 0) return error.EmptyManifest;
    try validateManifestLayout(entries.items, map);
    return .{
        .expected = .{ .entries = try entries.toOwnedSlice(allocator), .map = map },
        .metadata = files,
    };
}

fn appendManifest(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(Entry),
    map: *std.StringHashMapUnmanaged(u32),
    bytes: []const u8,
) !void {
    const scratch = std.heap.smp_allocator;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;
        const raw = std.json.parseFromSliceLeaky(RawEntry, allocator, line, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidManifestJson;
        try path_util.validate(raw.remoteName);
        const md5 = verify.parseMd5(raw.md5) catch return error.InvalidMd5;
        const duplicate = try seen.getOrPut(scratch, raw.remoteName);
        if (duplicate.found_existing) return error.DuplicateManifestPath;
        const entry: Entry = .{ .path = raw.remoteName, .size = raw.fileSize, .md5 = md5 };
        const got = try map.getOrPut(allocator, entry.path);
        if (got.found_existing) {
            const existing = entries.items[got.value_ptr.*];
            if (existing.size != entry.size or !std.mem.eql(u8, &existing.md5, &entry.md5)) return error.ConflictingManifestPath;
            continue;
        }
        got.value_ptr.* = @intCast(entries.items.len);
        try entries.append(allocator, entry);
    }
    if (seen.count() == 0) return error.EmptyManifest;
}

fn validateManifestLayout(entries: []const Entry, map: std.StringHashMapUnmanaged(u32)) !void {
    for (entries) |entry| {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, entry.path, start, '/')) |slash| {
            if (map.contains(entry.path[0..slash])) return error.ConflictingManifestPath;
            start = slash + 1;
        }
    }
}

pub fn isMetadataFile(name: []const u8) bool {
    return std.mem.eql(u8, name, "pkg_version") or isAudioPkgVersion(name);
}

pub fn isPkgVersionFamily(path: []const u8) bool {
    return std.mem.indexOfScalar(u8, path, '/') == null and isMetadataFile(path);
}

pub fn isAudioPkgVersion(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "Audio_") and std.mem.endsWith(u8, name, "_pkg_version");
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Manifest {
    var entries: std.ArrayList(Entry) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    try appendManifest(allocator, &entries, &map, bytes);

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .map = map,
    };
}

pub fn correctedMetadata(allocator: std.mem.Allocator, files: []const manifest_mod.MetadataFile, actual: Manifest) ![]manifest_mod.MetadataFile {
    const result = try allocator.dupe(manifest_mod.MetadataFile, files);
    for (result) |*file| {
        if (!isPkgVersionFamily(file.path)) continue;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        var lines = std.mem.splitScalar(u8, file.bytes, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) {
                if (lines.index != null) try output.writer.writeByte('\n');
                continue;
            }
            const scratch = std.heap.smp_allocator;
            var parsed = try std.json.parseFromSlice(std.json.Value, scratch, trimmed, .{ .parse_numbers = false });
            defer parsed.deinit();
            const path = parsed.value.object.get("remoteName").?.string;
            const entry = actual.find(path) orelse continue;
            const old_md5 = parsed.value.object.get("md5").?.string;
            const old_size: u64 = switch (parsed.value.object.get("fileSize").?) {
                .integer => |value| @intCast(value),
                .number_string => |value| try std.fmt.parseInt(u64, value, 10),
                else => return error.InvalidManifestJson,
            };
            const hash = std.fmt.bytesToHex(entry.md5, .lower);
            if (old_size == entry.size and std.ascii.eqlIgnoreCase(old_md5, &hash)) {
                try output.writer.writeAll(line);
            } else {
                parsed.value.object.getPtr("md5").?.* = .{ .string = &hash };
                var size_buffer: [20]u8 = undefined;
                parsed.value.object.getPtr("fileSize").?.* = .{ .number_string = try std.fmt.bufPrint(&size_buffer, "{d}", .{entry.size}) };
                try std.json.Stringify.value(parsed.value, .{}, &output.writer);
            }
            if (lines.index != null) try output.writer.writeByte('\n');
        }
        if (std.mem.eql(u8, output.written(), file.bytes)) {
            output.deinit();
        } else file.bytes = try output.toOwnedSlice();
    }
    return result;
}

test "pkg_version correction preserves unrelated fields and empty audio membership" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unchanged = "{\"remoteName\":\"keep\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1,\"flag\":true}\r\n";
    const bad = "{\"remoteName\":\"bad\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1,\"extra\":{\"value\":3}}\n";
    const missing = "{\"remoteName\":\"missing\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n";
    const original = [_]manifest_mod.MetadataFile{
        .{ .path = "pkg_version", .bytes = unchanged ++ bad ++ missing },
        .{ .path = "Audio_English_pkg_version", .bytes = missing },
        .{ .path = "Audio_Chinese_pkg_version", .bytes = unchanged },
    };
    var actual: Manifest = .{
        .entries = try a.dupe(Entry, &.{
            .{ .path = "keep", .size = 1, .md5 = try verify.parseMd5("c4ca4238a0b923820dcc509a6f75849b") },
            .{ .path = "bad", .size = std.math.maxInt(u64), .md5 = try verify.parseMd5("c81e728d9d4c2f636f067f89cc14862c") },
        }),
        .map = .empty,
    };
    for (actual.entries, 0..) |entry, index| try actual.map.put(a, entry.path, @intCast(index));
    const corrected = try correctedMetadata(a, &original, actual);
    try std.testing.expect(std.mem.startsWith(u8, corrected[0].bytes, unchanged));
    try std.testing.expectEqualStrings("", corrected[1].bytes);
    try std.testing.expectEqual(original[2].bytes.ptr, corrected[2].bytes.ptr);
    try std.testing.expect(std.mem.indexOf(u8, corrected[0].bytes, "\"extra\":{\"value\":3}") != null);
    const parsed = try loadSetFiles(a, corrected);
    try std.testing.expectEqual(@as(usize, 2), parsed.expected.entries.len);
    try std.testing.expectEqual(std.math.maxInt(u64), parsed.expected.find("bad").?.size);
    try std.testing.expectEqual(actual.find("bad").?.md5, parsed.expected.find("bad").?.md5);
    try std.testing.expectEqualStrings(unchanged ++ bad ++ missing, original[0].bytes);
}

test "loads root and audio metadata files together" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "pkg_version",
        .data = "{\"remoteName\":\"main.bin\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "Audio_English_pkg_version",
        .data = "{\"remoteName\":\"audio.bin\",\"md5\":\"c81e728d9d4c2f636f067f89cc14862c\",\"fileSize\":2}\n",
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const set = (try loadFamilyOptional(allocator, io, root, isMetadataFile)).?;
    try std.testing.expectEqual(@as(usize, 2), set.metadata.len);
    try std.testing.expect(set.expected.contains("main.bin"));
    try std.testing.expect(set.expected.contains("audio.bin"));
}

test "combined manifests reject file ancestor conflicts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const files = try allocator.dupe(manifest_mod.MetadataFile, &.{
        .{
            .path = "pkg_version",
            .bytes = "{\"remoteName\":\"a\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n",
        },
        .{
            .path = "Audio_English_pkg_version",
            .bytes = "{\"remoteName\":\"a/b\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n",
        },
    });
    try std.testing.expectError(error.ConflictingManifestPath, loadSetFiles(allocator, files));
}

test "combined manifests reject duplicate metadata files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const row = "{\"remoteName\":\"a\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n";
    const files = try allocator.dupe(manifest_mod.MetadataFile, &.{
        .{ .path = "pkg_version", .bytes = row },
        .{ .path = "pkg_version", .bytes = row },
    });
    try std.testing.expectError(error.DuplicateManifestPath, loadSetFiles(allocator, files));
}

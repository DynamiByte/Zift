const std = @import("std");
const manifest_mod = @import("../core/manifest.zig");
const pkg = @import("pkg_version.zig");
const fs = @import("../core/fs.zig");
const verify = @import("../verify.zig");
const path_util = @import("../path.zig");

const endfield_key = [_]u8{
    0xc0, 0xf3, 0x0e, 0x1c, 0xe7, 0x63, 0xbb, 0xc2, 0x1c, 0xc3, 0x55, 0xa3, 0x43, 0x03, 0xac, 0x50,
    0x39, 0x94, 0x44, 0xbf, 0xf6, 0x8c, 0x4a, 0x22, 0xaf, 0x39, 0x8c, 0x0a, 0x16, 0x6e, 0xe1, 0x43,
};
const endfield_iv = [_]u8{ 0x33, 0x46, 0x78, 0x61, 0x19, 0x27, 0x50, 0x64, 0x95, 0x01, 0x93, 0x72, 0x64, 0x60, 0x84, 0x00 };

pub fn loadGenshinExpected(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?manifest_mod.Snapshot {
    return pkg.loadFamilyOptional(allocator, io, root, isGenshinManifest);
}

pub fn loadGenshinMetadata(allocator: std.mem.Allocator, files: []manifest_mod.MetadataFile) !manifest_mod.Snapshot {
    for (files) |file| if (!isGenshinManifest(file.path)) return error.InvalidManifestJson;
    return pkg.loadManifestFiles(allocator, files, "pkg_version");
}

const EndfieldEntry = struct {
    path: []const u8,
    md5: []const u8,
    size: u64,
};

pub fn loadEndfieldExpected(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?manifest_mod.Snapshot {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const bytes = try fs.readOptionalFile(allocator, io, dir, endfield_manifest_path, 16 * 1024 * 1024) orelse return null;
    const files = try allocator.dupe(manifest_mod.MetadataFile, &.{.{ .path = endfield_manifest_path, .bytes = bytes }});
    return @as(?manifest_mod.Snapshot, try loadEndfieldMetadata(allocator, files));
}

pub fn loadEndfieldMetadata(allocator: std.mem.Allocator, files: []manifest_mod.MetadataFile) !manifest_mod.Snapshot {
    if (files.len != 1 or !std.mem.eql(u8, files[0].path, endfield_manifest_path)) return error.MissingManifest;
    const plain = try decryptEndfield(allocator, files[0].bytes);
    const expected = try parseEndfieldManifest(allocator, plain);
    return .{ .expected = expected, .metadata = files };
}

fn decryptEndfield(allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return error.InvalidManifestCrypto;
    const out = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(out);
    const aes = std.crypto.core.aes.Aes256.initDec(endfield_key);
    var previous = endfield_iv;
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        aes.decrypt(&block, ciphertext[offset..][0..16]);
        for (&block, previous) |*byte, prev| byte.* ^= prev;
        @memcpy(out[offset..][0..16], &block);
        @memcpy(&previous, ciphertext[offset..][0..16]);
    }
    const padding = out[out.len - 1];
    if (padding == 0 or padding > 16 or padding > out.len) return error.InvalidManifestCrypto;
    for (out[out.len - padding ..]) |byte| if (byte != padding) return error.InvalidManifestCrypto;
    return try allocator.realloc(out, out.len - padding);
}

fn parseEndfieldManifest(allocator: std.mem.Allocator, bytes: []const u8) !manifest_mod.Set {
    var entries: std.ArrayList(manifest_mod.File) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const raw = std.json.parseFromSliceLeaky(EndfieldEntry, allocator, line, .{ .ignore_unknown_fields = true }) catch return error.InvalidManifestJson;
        if (std.mem.eql(u8, raw.path, "config.ini")) continue;
        try appendExpected(allocator, &entries, &map, raw.path, raw.size, raw.md5);
    }
    if (entries.items.len == 0) return error.EmptyManifest;
    try validateExpectedLayout(entries.items, map);
    return .{ .entries = try entries.toOwnedSlice(allocator), .map = map };
}

const WuwaManifest = struct {
    resource: []const WuwaEntry,
};

const WuwaEntry = struct {
    dest: []const u8,
    size: u64,
    md5: []const u8,
};

pub fn loadWuwaExpected(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?manifest_mod.Snapshot {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const bytes = try fs.readOptionalFile(allocator, io, dir, wuwa_manifest_path, 16 * 1024 * 1024) orelse return null;
    const files = try allocator.dupe(manifest_mod.MetadataFile, &.{.{ .path = wuwa_manifest_path, .bytes = bytes }});
    return @as(?manifest_mod.Snapshot, try loadWuwaMetadata(allocator, files));
}

pub fn loadWuwaMetadata(allocator: std.mem.Allocator, files: []manifest_mod.MetadataFile) !manifest_mod.Snapshot {
    if (files.len != 1 or !std.mem.eql(u8, files[0].path, wuwa_manifest_path)) return error.MissingManifest;
    const raw = std.json.parseFromSliceLeaky(WuwaManifest, allocator, files[0].bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidManifestJson;
    var entries: std.ArrayList(manifest_mod.File) = .empty;
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    for (raw.resource) |entry| try appendExpected(allocator, &entries, &map, entry.dest, entry.size, entry.md5);
    if (entries.items.len == 0) return error.EmptyManifest;
    try validateExpectedLayout(entries.items, map);
    return .{ .expected = .{ .entries = try entries.toOwnedSlice(allocator), .map = map }, .metadata = files };
}

fn appendExpected(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(manifest_mod.File),
    map: *std.StringHashMapUnmanaged(u32),
    path: []const u8,
    size: u64,
    md5_text: []const u8,
) !void {
    try path_util.validate(path);
    const md5 = verify.parseMd5(md5_text) catch return error.InvalidMd5;
    const got = try map.getOrPut(allocator, path);
    if (got.found_existing) return error.DuplicateManifestPath;
    got.value_ptr.* = @intCast(entries.items.len);
    try entries.append(allocator, .{ .path = path, .size = size, .md5 = md5 });
}

fn validateExpectedLayout(entries: []const manifest_mod.File, map: std.StringHashMapUnmanaged(u32)) !void {
    for (entries) |entry| {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, entry.path, start, '/')) |slash| {
            if (map.contains(entry.path[0..slash])) return error.ConflictingManifestPath;
            start = slash + 1;
        }
    }
}

pub fn isGenshinManifest(path: []const u8) bool {
    return std.mem.indexOfScalar(u8, path, '/') == null and
        (std.mem.eql(u8, path, "pkg_version") or
            std.mem.eql(u8, path, genshin_beyond_manifest) or
            pkg.isAudioPkgVersion(path));
}

pub const wuwa_manifest_path = "LocalGameResources.json";
pub const endfield_manifest_path = "game_files";
pub const genshin_beyond_manifest = "beyond_pkg_version";
test "genshin manifest family merges root audio and beyond" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var files = [_]manifest_mod.MetadataFile{
        .{ .path = "pkg_version", .bytes = "{\"remoteName\":\"base.bin\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n" },
        .{ .path = "Audio_English(US)_pkg_version", .bytes = "{\"remoteName\":\"audio.pck\",\"md5\":\"c81e728d9d4c2f636f067f89cc14862c\",\"fileSize\":2}\n" },
        .{ .path = "beyond_pkg_version", .bytes = "{\"remoteName\":\"BeyondAssets/data.bin\",\"md5\":\"eccbc87e4b5ce2fe28308fd9f2a7baf3\",\"fileSize\":3}\n" },
    };
    const state = try loadGenshinMetadata(allocator, &files);
    try std.testing.expectEqual(@as(usize, 3), state.expected.entries.len);
    try std.testing.expect(state.expected.contains("base.bin"));
    try std.testing.expect(state.expected.contains("audio.pck"));
    try std.testing.expect(state.expected.contains("BeyondAssets/data.bin"));
}

test "wuwa manifest parses required resource records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"resource":[
        \\  {"dest":"Client/Content/Paks/a.pak","size":4,"md5":"a87ff679a2f3e71d9181a67b7542122c","fromFolder":"","chunkInfos":[]},
        \\  {"dest":"Client/Content/Paks/b.pak","size":5,"md5":"e4da3b7fbbce2345d7772b0674a318d5","fromFolder":"","chunkInfos":[]}
        \\]}
    ;
    var files = [_]manifest_mod.MetadataFile{.{ .path = wuwa_manifest_path, .bytes = json }};
    const state = try loadWuwaMetadata(allocator, &files);
    try std.testing.expectEqual(@as(usize, 2), state.expected.entries.len);
    try std.testing.expect(state.expected.contains("Client/Content/Paks/a.pak"));
}

test "endfield manifest skips launcher config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const plain =
        "{\"path\":\"Endfield.exe\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"size\":1}\n" ++
        "{\"path\":\"config.ini\",\"md5\":\"c81e728d9d4c2f636f067f89cc14862c\",\"size\":2}";
    const set = try parseEndfieldManifest(allocator, plain);
    try std.testing.expectEqual(@as(usize, 1), set.entries.len);
    try std.testing.expect(set.contains("Endfield.exe"));
    try std.testing.expect(!set.contains("config.ini"));
}

test "endfield AES CBC decoder validates PKCS7" {
    const allocator = std.testing.allocator;
    const plain = "endfield manifest";
    const padded_len = ((plain.len / 16) + 1) * 16;
    var padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);
    @memcpy(padded[0..plain.len], plain);
    const pad: u8 = @intCast(padded_len - plain.len);
    @memset(padded[plain.len..], pad);

    var ciphertext = try allocator.alloc(u8, padded_len);
    defer allocator.free(ciphertext);
    const aes = std.crypto.core.aes.Aes256.initEnc(endfield_key);
    var previous = endfield_iv;
    var offset: usize = 0;
    while (offset < padded.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        for (padded[offset..][0..16], previous, &block) |byte, prev, *out| out.* = byte ^ prev;
        aes.encrypt(ciphertext[offset..][0..16], &block);
        @memcpy(&previous, ciphertext[offset..][0..16]);
    }

    const decoded = try decryptEndfield(allocator, ciphertext);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(plain, decoded);
}

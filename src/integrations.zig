const manifests = @import("integrations/manifests.zig");
const versions = @import("integrations/versions.zig");
pub const Version = versions.Version;
pub const VersionParts = versions.VersionParts;
const manifest_mod = @import("core/manifest.zig");
const std = @import("std");
const fs = @import("core/fs.zig");
const builtin = @import("builtin");

const ui = @import("ui.zig");
const pkg = @import("integrations/pkg_version.zig");
const ids = @import("core/ids.zig");

pub const Software = enum(u16) {
    zzz = 0x0001,
    genshin = 0x0002,
    endfield = 0x0005,
    wuwa = 0x0006,
};

pub const ManagedSet = enum {
    unavailable,
    partial,
    complete,
};

pub const ManifestFormat = enum {
    pkg_version_ndjson,
    endfield_encrypted_game_files,
    wuwa_resource_json,
};

// per-game policy; installation state in InstallView
pub const Integration = struct {
    software: Software,
    manifest_format: ManifestFormat,
    manifest_schema: ids.VendorSchema,
    digest_authority: ids.ClaimAuthority,
    manifest_managed_set: ManagedSet,
    // integration support != user deletion permission
    deletion_ever_allowed: bool,
    identity_trustworthy: bool,
};

pub const State = struct {
    expected: manifest_mod.Set,
    metadata: []const manifest_mod.MetadataFile,
    manifest_format: ManifestFormat,
    manifest_schema: ids.VendorSchema,
    digest_authority: ids.ClaimAuthority,
    managed_set_complete: bool,
};

pub const InstallView = struct {
    integration: Integration,
    state: ?State = null,
    identity: ?Version = null,
};

pub fn integration(software: Software) Integration {
    return switch (software) {
        .zzz => .{
            .software = software,
            .manifest_format = .pkg_version_ndjson,
            .manifest_schema = .hoyo_pkg_version_md5,
            .digest_authority = .authoritative,
            .manifest_managed_set = .complete,
            .deletion_ever_allowed = true,
            .identity_trustworthy = true,
        },
        .genshin => .{
            .software = software,
            .manifest_format = .pkg_version_ndjson,
            .manifest_schema = .hoyo_pkg_version_md5,
            .digest_authority = .authoritative,
            .manifest_managed_set = .complete,
            .deletion_ever_allowed = true,
            .identity_trustworthy = true,
        },
        .endfield => .{
            .software = software,
            .manifest_format = .endfield_encrypted_game_files,
            .manifest_schema = .endfield_game_files_md5,
            .digest_authority = .authoritative,
            .manifest_managed_set = .complete,
            .deletion_ever_allowed = false,
            .identity_trustworthy = true,
        },
        .wuwa => .{
            .software = software,
            .manifest_format = .wuwa_resource_json,
            .manifest_schema = .wuwa_local_resources_md5,
            .digest_authority = .authoritative,
            .manifest_managed_set = .complete,
            .deletion_ever_allowed = true,
            .identity_trustworthy = false,
        },
    };
}

fn stateFromManifest(software: Software, manifest: manifest_mod.Snapshot) State {
    const definition = integration(software);
    return .{
        .expected = manifest.expected,
        .metadata = manifest.metadata,
        .manifest_format = definition.manifest_format,
        .manifest_schema = definition.manifest_schema,
        .digest_authority = definition.digest_authority,
        .managed_set_complete = definition.manifest_managed_set == .complete,
    };
}

pub fn inspectInstall(
    allocator: std.mem.Allocator,
    io: std.Io,
    software: Software,
    root: []const u8,
) !InstallView {
    // generic fallback for absent manifests only
    const maybe_state = try loadExpected(allocator, io, software, root);
    const definition = integration(software);
    const state = maybe_state orelse return .{ .integration = definition };
    const identity = if (definition.identity_trustworthy)
        try detectVersionBestEffort(allocator, io, software, root)
    else
        null;
    return .{
        .integration = definition,
        .state = state,
        .identity = identity,
    };
}

pub fn usablePair(source: InstallView, target: InstallView) bool {
    return source.integration.software == target.integration.software and
        source.state != null and target.state != null;
}

pub const Detected = struct {
    software: Software,

    pub fn name(self: Detected) []const u8 {
        return displayName(self.software);
    }
};

const zzz_executables = [_][]const u8{
    "ZenlessZoneZero.exe",
    "ZenlessZoneZeroBeta.exe",
};

const genshin_app_info = "miHoYo\nGenshin Impact";
const endfield_app_info = "Gryphline\nEndfield";

const genshin_data = "GenshinImpact_Data";
const endfield_data = "Endfield_Data";

const wuwa_version_path = versions.wuwa_version_path;
const wuwa_manifest_path = manifests.wuwa_manifest_path;
const endfield_manifest_path = manifests.endfield_manifest_path;
const genshin_beyond_manifest = manifests.genshin_beyond_manifest;

pub fn integrationId(software: Software) u16 {
    return @intFromEnum(software);
}

pub fn fromIntegrationId(id: u16) ?Software {
    return switch (id) {
        @intFromEnum(Software.zzz) => .zzz,
        @intFromEnum(Software.genshin) => .genshin,
        @intFromEnum(Software.endfield) => .endfield,
        @intFromEnum(Software.wuwa) => .wuwa,
        else => null,
    };
}

pub fn detect(io: std.Io, path: []const u8) !?Detected {
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .access_sub_paths = true });
    defer dir.close(io);

    for (zzz_executables) |exe| {
        if (try isFile(io, dir, exe)) return .{ .software = .zzz };
    }
    if (try matchesUnityInstall(io, dir, "GenshinImpact.exe", genshin_data, genshin_app_info)) return .{ .software = .genshin };
    if (try matchesUnityInstall(io, dir, "Endfield.exe", endfield_data, endfield_app_info)) return .{ .software = .endfield };
    if (try isFile(io, dir, "Wuthering Waves.exe") and
        try isFile(io, dir, "Client/Binaries/Win64/Client-Win64-Shipping.exe") and
        try isFile(io, dir, wuwa_version_path)) return .{ .software = .wuwa };
    return null;
}

pub fn displayName(software: Software) []const u8 {
    return switch (software) {
        .zzz => "Zenless Zone Zero",
        .genshin => "Genshin Impact",
        .endfield => "Arknights: Endfield",
        .wuwa => "Wuthering Waves",
    };
}

pub fn defaultPrefix(software: Software) []const u8 {
    return switch (software) {
        .zzz => "zzz",
        .genshin => "gi",
        .endfield => "akef",
        .wuwa => "wuwa",
    };
}

pub fn detectVersion(allocator: std.mem.Allocator, io: std.Io, software: Software, root: []const u8) !?Version {
    return switch (software) {
        .zzz => versions.detectZzzVersion(allocator, io, root),
        .genshin => versions.detectGenshinVersion(allocator, io, root),
        .endfield => versions.detectUnitySemver(allocator, io, root, endfield_data, "Endfield"),
        .wuwa => versions.detectWuwaVersion(allocator, io, root),
    };
}

pub fn detectVersionBestEffort(allocator: std.mem.Allocator, io: std.Io, software: Software, root: []const u8) !?Version {
    return detectVersion(allocator, io, software, root) catch |err| switch (err) {
        error.FileNotFound,
        error.IsDir,
        error.NotDir,
        error.AccessDenied,
        error.PermissionDenied,
        error.SymLinkLoop,
        error.FileTooLarge,
        => null,
        else => |e| return e,
    };
}

fn primaryManifestPresent(io: std.Io, software: Software, root: []const u8) !bool {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const stat = dir.statFile(io, primaryManifestPath(software), .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.SymLinkLoop => return error.InvalidExpectedState,
        else => |e| return e,
    };
    if (stat.kind != .file) return error.InvalidExpectedState;
    return true;
}

pub fn loadExpected(allocator: std.mem.Allocator, io: std.Io, software: Software, root: []const u8) !?State {
    if (!try primaryManifestPresent(io, software, root)) return null;
    const manifest: ?manifest_mod.Snapshot = (switch (software) {
        .zzz => pkg.loadFamilyOptional(allocator, io, root, pkg.isMetadataFile),
        .genshin => manifests.loadGenshinExpected(allocator, io, root),
        .endfield => manifests.loadEndfieldExpected(allocator, io, root),
        .wuwa => manifests.loadWuwaExpected(allocator, io, root),
    }) catch |err| switch (err) {
        error.InvalidManifestJson,
        error.InvalidMd5,
        error.InvalidManifestCrypto,
        error.DuplicateManifestPath,
        error.ConflictingManifestPath,
        error.EmptyManifest,
        error.UnsafePath,
        error.PathTooLongForZip,
        error.ExpectedFile,
        error.FileTooLarge,
        error.UnexpectedEof,
        error.FileChangedDuringRead,
        error.MissingManifest,
        => return error.InvalidExpectedState,
        else => |e| return e,
    };
    return if (manifest) |value| stateFromManifest(software, value) else error.InvalidExpectedState;
}

pub fn loadExpectedMetadata(allocator: std.mem.Allocator, software: Software, files: []manifest_mod.MetadataFile) !State {
    const manifest: manifest_mod.Snapshot = (switch (software) {
        .zzz => pkg.loadSetFiles(allocator, files),
        .genshin => manifests.loadGenshinMetadata(allocator, files),
        .endfield => manifests.loadEndfieldMetadata(allocator, files),
        .wuwa => manifests.loadWuwaMetadata(allocator, files),
    }) catch |err| switch (err) {
        error.InvalidManifestJson,
        error.InvalidMd5,
        error.InvalidManifestCrypto,
        error.DuplicateManifestPath,
        error.ConflictingManifestPath,
        error.EmptyManifest,
        error.UnsafePath,
        error.PathTooLongForZip,
        error.MissingManifest,
        => return error.InvalidExpectedState,
        else => |e| return e,
    };
    return stateFromManifest(software, manifest);
}

pub fn reportExpectedError(out: *std.Io.Writer, software: Software, root: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.InvalidExpectedState => {
            ui.writeErrorPrefix(out) catch return err;
            out.print(" invalid {s} manifest data\n", .{displayName(software)}) catch return err;
            ui.writeField(out, "Directory:", root) catch return err;
            return error.Reported;
        },
        error.AccessDenied, error.FileNotFound, error.NotDir, error.IsDir => {
            ui.writeErrorPrefix(out) catch return err;
            out.print(" cannot read {s} manifest data\n", .{displayName(software)}) catch return err;
            ui.writeField(out, "Directory:", root) catch return err;
            return error.Reported;
        },
        else => return err,
    }
}

pub fn isMetadataPath(software: Software, path: []const u8) bool {
    return switch (software) {
        .zzz => pkg.isPkgVersionFamily(path),
        .genshin => manifests.isGenshinManifest(path),
        .endfield => std.mem.eql(u8, path, endfield_manifest_path),
        .wuwa => std.mem.eql(u8, path, wuwa_manifest_path),
    };
}

pub fn primaryManifestPath(software: Software) []const u8 {
    return switch (software) {
        .zzz, .genshin => "pkg_version",
        .endfield => endfield_manifest_path,
        .wuwa => wuwa_manifest_path,
    };
}

pub fn isPrimaryManifestPath(software: Software, path: []const u8) bool {
    return std.mem.eql(u8, path, primaryManifestPath(software));
}

pub fn isPackagedVersionPath(software: Software, path: []const u8) bool {
    return switch (software) {
        .zzz => std.mem.eql(u8, path, "version_info"),
        .wuwa => std.mem.eql(u8, path, wuwa_version_path),
        .genshin, .endfield => false,
    };
}

pub fn detectPackagedVersion(allocator: std.mem.Allocator, software: Software, path: []const u8, bytes: []const u8) !?Version {
    if (!isPackagedVersionPath(software, path)) return null;
    return switch (software) {
        .zzz => blk: {
            const text = std.mem.trim(u8, bytes, " \t\r\n\x00");
            if (text.len == 0 or text.len > 256 or versions.splitClientVersion(text) == null) break :blk null;
            const full = try allocator.dupe(u8, text);
            break :blk .{ .full = full, .parts = versions.splitClientVersion(full) };
        },
        .wuwa => versions.versionFromKeyValue(allocator, bytes, "KR_GameVersion"),
        .genshin, .endfield => null,
    };
}

pub fn normalCleanFilter(software: Software) *const fn ([]const u8) bool {
    return switch (software) {
        .zzz => zzzCleanPath,
        .genshin => genshinCleanPath,
        .endfield, .wuwa => neverCleanPath,
    };
}

fn zzzCleanPath(path: []const u8) bool {
    if (pkg.isPkgVersionFamily(path) or ignoredZzzPath(path)) return false;
    return unityStreamingPath(path);
}

fn genshinCleanPath(path: []const u8) bool {
    if (manifests.isGenshinManifest(path) or ignoredGenshinPath(path)) return false;
    return unityStreamingPath(path) or std.mem.startsWith(u8, path, "BeyondAssets/");
}

fn unityStreamingPath(path: []const u8) bool {
    const first_slash = std.mem.indexOfScalar(u8, path, '/') orelse return false;
    if (!std.ascii.endsWithIgnoreCase(path[0..first_slash], "_Data")) return false;
    const rest = path[first_slash + 1 ..];
    const second_slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    return std.ascii.eqlIgnoreCase(rest[0..second_slash], "StreamingAssets");
}

fn neverCleanPath(_: []const u8) bool {
    return false;
}

pub fn cleanTemporaryDirectories(allocator: std.mem.Allocator, io: std.Io, software: Software, root: []const u8) ![][]const u8 {
    return switch (software) {
        .zzz, .genshin => unityTemporaryDirectories(allocator, io, root),
        .endfield => endfieldTemporaryDirectories(allocator, io, root),
        .wuwa => wuwaTemporaryDirectories(allocator, io, root),
    };
}

fn unityTemporaryDirectories(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![][]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true, .access_sub_paths = true });
    defer dir.close(io);

    var paths: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory or !std.ascii.endsWithIgnoreCase(entry.name, "_Data")) continue;
        var data_dir = try dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer data_dir.close(io);
        var children = data_dir.iterate();
        while (try children.next(io)) |child| {
            if (child.kind != .directory) continue;
            if (!std.ascii.eqlIgnoreCase(child.name, "SDKCaches") and
                !std.ascii.eqlIgnoreCase(child.name, "webCaches")) continue;
            try paths.append(allocator, try std.fmt.allocPrint(allocator, "{s}/{s}", .{ entry.name, child.name }));
        }
    }
    return paths.toOwnedSlice(allocator);
}

fn endfieldTemporaryDirectories(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![][]const u8 {
    // Endfield Persistent/VFS: game data
    return unityTemporaryDirectories(allocator, io, root);
}

fn wuwaTemporaryDirectories(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![][]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const candidates = [_][]const u8{
        // Saved/Resources: game data; only PSO subtree disposable
        "Client/Saved/PSO",
    };
    var paths: std.ArrayList([]const u8) = .empty;
    for (candidates) |path| if (try isDirectory(io, dir, path))
        try paths.append(allocator, try allocator.dupe(u8, path));
    return paths.toOwnedSlice(allocator);
}

pub fn ignoreFilter(software: Software) *const fn ([]const u8) bool {
    return switch (software) {
        .zzz => ignoredZzzPath,
        .genshin => ignoredGenshinPath,
        .wuwa => ignoredWuwaPath,
        .endfield => ignoredEndfieldPath,
    };
}

fn ignoredZzzPath(path: []const u8) bool {
    return ignoredUnityRuntimePath(path);
}

fn ignoredGenshinPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "config.ini") or ignoredUnityRuntimePath(path);
}

fn ignoredEndfieldPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "config.ini") or ignoredUnityRuntimePath(path);
}

fn ignoredUnityRuntimePath(path: []const u8) bool {
    const first_slash = std.mem.indexOfScalar(u8, path, '/') orelse return false;
    const data_dir = path[0..first_slash];
    if (!std.ascii.endsWithIgnoreCase(data_dir, "_Data")) return false;

    const rest = path[first_slash + 1 ..];
    const second_slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const child = rest[0..second_slash];
    return std.ascii.eqlIgnoreCase(child, "Persistent") or
        std.ascii.eqlIgnoreCase(child, "SDKCaches") or
        std.ascii.eqlIgnoreCase(child, "webCaches");
}

fn ignoredWuwaPath(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "Client/Saved/") or
        std.mem.eql(u8, path, "launcherDownloadConfig.json") or
        std.mem.eql(u8, path, "launcherDownload") or
        std.mem.startsWith(u8, path, "launcherDownload/");
}

fn matchesUnityInstall(io: std.Io, dir: std.Io.Dir, exe: []const u8, data_dir: []const u8, expected_app_info: []const u8) !bool {
    if (!try isFile(io, dir, exe)) return false;
    const app_info_path = try std.fmt.allocPrint(std.heap.smp_allocator, "{s}/app.info", .{data_dir});
    defer std.heap.smp_allocator.free(app_info_path);
    var file = fs.openRead(io, dir, app_info_path) catch |err| switch (err) {
        error.FileNotFound, error.IsDir => return false,
        else => |e| return e,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.size != expected_app_info.len) return false;
    var buf: [64]u8 = undefined;
    if (expected_app_info.len > buf.len) return false;
    const n = try file.readPositionalAll(io, buf[0..expected_app_info.len], 0);
    return n == expected_app_info.len and std.mem.eql(u8, buf[0..n], expected_app_info);
}

fn isDirectory(io: std.Io, dir: std.Io.Dir, path: []const u8) !bool {
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return stat.kind == .directory;
}

fn isFile(io: std.Io, dir: std.Io.Dir, path: []const u8) !bool {
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return stat.kind == .file;
}

test "detect zzz" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "ZenlessZoneZeroBeta.exe", .data = "" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const found = (try detect(io, root)).?;
    try std.testing.expectEqual(Software.zzz, found.software);
    try std.testing.expectEqualStrings("Zenless Zone Zero", found.name());
    try std.testing.expectEqualStrings("zzz", defaultPrefix(found.software));
}

test "zzz detection does not follow executable symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "real.exe", .data = "" });
    try tmp.dir.symLink(io, "real.exe", "ZenlessZoneZero.exe", .{});
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    try std.testing.expectEqual(@as(?Detected, null), try detect(io, root));
}

test "zzz unmanaged data paths" {
    try std.testing.expect(ignoredZzzPath("ZenlessZoneZero_Data/Persistent/foo"));
    try std.testing.expect(ignoredZzzPath("Anything_Data/SDKCaches/a"));
    try std.testing.expect(ignoredZzzPath("Anything_Data/webCaches/a/b"));
    try std.testing.expect(!ignoredZzzPath("Anything_Data/StreamingAssets/a"));
    try std.testing.expect(!ignoredZzzPath("Persistent/a"));
}

test "normal Clean scope contains no complete or authority axis" {
    const normal = normalCleanFilter(.zzz);
    try std.testing.expect(normal("ZenlessZoneZero_Data/StreamingAssets/Blocks/old"));
    try std.testing.expect(!normal("ZenlessZoneZero_Data/Persistent/cache"));
    try std.testing.expect(!normal("random.bin"));
    try std.testing.expect(!normal("ZenlessZoneZero_Data/NotStreamingAssets/old"));
    try std.testing.expect(!normal("Other/StreamingAssets/old"));
    try std.testing.expect(normal("Anything_Data/streamingassets/old"));
    try std.testing.expect(normalCleanFilter(.genshin)("GenshinImpact_Data/StreamingAssets/old"));
    try std.testing.expect(normalCleanFilter(.genshin)("BeyondAssets/old"));
    try std.testing.expect(!normalCleanFilter(.endfield)("random.bin"));
    try std.testing.expect(!normalCleanFilter(.wuwa)("random.bin"));
}

test "zzz metadata paths are only supported root manifests" {
    try std.testing.expect(isMetadataPath(.zzz, "pkg_version"));
    try std.testing.expect(isMetadataPath(.zzz, "Audio_English_pkg_version"));
    try std.testing.expect(!isMetadataPath(.zzz, "Other_pkg_version"));
    try std.testing.expect(!isMetadataPath(.zzz, "Data/pkg_version"));
    try std.testing.expect(!isMetadataPath(.zzz, "Data/Audio_English_pkg_version"));
}

test "zzz packaged version_info exposes dispatch version" {
    try std.testing.expect(isPackagedVersionPath(.zzz, "version_info"));
    try std.testing.expect(!isPackagedVersionPath(.zzz, "Data/version_info"));
    const version = (try detectPackagedVersion(std.testing.allocator, .zzz, "version_info", "OSPRODWin3.1.0\r\n")).?;
    defer std.testing.allocator.free(version.full);
    try std.testing.expectEqualStrings("OSPRODWin3.1.0", version.full);
    try std.testing.expectEqualStrings("OSPRODWin", version.parts.?.prefix);
    try std.testing.expectEqualStrings("3.1.0", version.parts.?.number);
}

test "zzz temporary directories are discovered case insensitively" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/persistent/nested");
    try tmp.dir.createDirPath(io, "ZenlessZoneZero_Data/SDKCaches");
    try tmp.dir.createDirPath(io, "Other_Data/webcaches");
    try tmp.dir.createDirPath(io, "Other_Data/StreamingAssets");
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const paths = try cleanTemporaryDirectories(allocator, io, .zzz, root);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    try std.testing.expectEqual(@as(usize, 2), paths.len);
    for (paths) |path| try std.testing.expect(!std.ascii.endsWithIgnoreCase(path, "/persistent"));
}

fn writeUnityDetectionFixture(io: std.Io, dir: std.Io.Dir, exe: []const u8, data_dir: []const u8, app_info: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = exe, .data = "" });
    try dir.createDirPath(io, data_dir);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/app.info", .{data_dir});
    defer std.testing.allocator.free(path);
    try dir.writeFile(io, .{ .sub_path = path, .data = app_info });
}

fn testingRoot(allocator: std.mem.Allocator, tmp: anytype) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
}

test "integration registry assigns ids and prefixes" {
    const expected = [_]struct { software: Software, id: u16, prefix: []const u8, name: []const u8 }{
        .{ .software = .zzz, .id = 0x0001, .prefix = "zzz", .name = "Zenless Zone Zero" },
        .{ .software = .genshin, .id = 0x0002, .prefix = "gi", .name = "Genshin Impact" },
        .{ .software = .endfield, .id = 0x0005, .prefix = "akef", .name = "Arknights: Endfield" },
        .{ .software = .wuwa, .id = 0x0006, .prefix = "wuwa", .name = "Wuthering Waves" },
    };
    for (expected) |item| {
        try std.testing.expectEqual(item.id, integrationId(item.software));
        try std.testing.expectEqual(item.software, fromIntegrationId(item.id).?);
        try std.testing.expectEqualStrings(item.prefix, defaultPrefix(item.software));
        try std.testing.expectEqualStrings(item.name, displayName(item.software));
    }
    try std.testing.expect(fromIntegrationId(0x0000) == null);
    try std.testing.expect(fromIntegrationId(0xffff) == null);
}

test "integration capability axes match the static evidence matrix" {
    const expected = [_]struct {
        software: Software,
        format: ManifestFormat,
        schema: ids.VendorSchema,
        managed_set: ManagedSet,
        removal_basis: bool,
        identity_trustworthy: bool,
    }{
        .{ .software = .zzz, .format = .pkg_version_ndjson, .schema = .hoyo_pkg_version_md5, .managed_set = .complete, .removal_basis = true, .identity_trustworthy = true },
        .{ .software = .genshin, .format = .pkg_version_ndjson, .schema = .hoyo_pkg_version_md5, .managed_set = .complete, .removal_basis = true, .identity_trustworthy = true },
        .{ .software = .endfield, .format = .endfield_encrypted_game_files, .schema = .endfield_game_files_md5, .managed_set = .complete, .removal_basis = false, .identity_trustworthy = true },
        .{ .software = .wuwa, .format = .wuwa_resource_json, .schema = .wuwa_local_resources_md5, .managed_set = .complete, .removal_basis = true, .identity_trustworthy = false },
    };
    for (expected) |item| {
        const value = integration(item.software);
        try std.testing.expectEqual(item.format, value.manifest_format);
        try std.testing.expectEqual(item.schema, value.manifest_schema);
        try std.testing.expectEqual(ids.ClaimAuthority.authoritative, value.digest_authority);
        try std.testing.expectEqual(item.managed_set, value.manifest_managed_set);
        try std.testing.expectEqual(item.removal_basis, value.deletion_ever_allowed);
        try std.testing.expectEqual(item.identity_trustworthy, value.identity_trustworthy);
    }
}

test "missing managed state remains distinct from readable capabilities" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "Audio_English_pkg_version",
        .data = "{\"remoteName\":\"audio.bin\",\"md5\":\"c81e728d9d4c2f636f067f89cc14862c\",\"fileSize\":2}\n",
    });
    const root = try testingRoot(allocator, tmp);

    const view = try inspectInstall(allocator, io, .zzz, root);
    try std.testing.expect(view.state == null);
    try std.testing.expect(view.identity == null);
    try std.testing.expectEqual(Software.zzz, view.integration.software);
}

test "manifest anchor with the wrong type is invalid rather than absent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "pkg_version", .default_dir);
    try tmp.dir.createDir(io, endfield_manifest_path, .default_dir);
    try tmp.dir.createDir(io, wuwa_manifest_path, .default_dir);
    const root = try testingRoot(allocator, tmp);
    for (std.enums.values(Software)) |software|
        try std.testing.expectError(error.InvalidExpectedState, loadExpected(allocator, io, software, root));
}

test "manifest anchor symlinks are invalid for every integration" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "real-manifest", .data = "not followed" });
    try tmp.dir.symLink(io, "real-manifest", "pkg_version", .{});
    try tmp.dir.symLink(io, "real-manifest", endfield_manifest_path, .{});
    try tmp.dir.symLink(io, "real-manifest", wuwa_manifest_path, .{});
    const root = try testingRoot(allocator, tmp);
    for (std.enums.values(Software)) |software|
        try std.testing.expectError(error.InvalidExpectedState, loadExpected(allocator, io, software, root));
}

test "non-file sibling in an active manifest family is invalid" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const row = "{\"remoteName\":\"a.bin\",\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\",\"fileSize\":1}\n";

    var zzz = std.testing.tmpDir(.{});
    defer zzz.cleanup();
    try zzz.dir.writeFile(io, .{ .sub_path = "pkg_version", .data = row });
    try zzz.dir.createDir(io, "Audio_English_pkg_version", .default_dir);
    const zzz_root = try testingRoot(allocator, zzz);
    try std.testing.expectError(error.InvalidExpectedState, loadExpected(allocator, io, .zzz, zzz_root));

    var genshin = std.testing.tmpDir(.{});
    defer genshin.cleanup();
    try genshin.dir.writeFile(io, .{ .sub_path = "pkg_version", .data = row });
    try genshin.dir.createDir(io, genshin_beyond_manifest, .default_dir);
    const genshin_root = try testingRoot(allocator, genshin);
    try std.testing.expectError(error.InvalidExpectedState, loadExpected(allocator, io, .genshin, genshin_root));
}

test "WuWa identity evidence is never exposed as a create default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = wuwa_manifest_path,
        .data = "{\"resource\":[{\"dest\":\"Client/Content/Paks/a.pak\",\"size\":1,\"md5\":\"c4ca4238a0b923820dcc509a6f75849b\"}]}",
    });
    try tmp.dir.createDirPath(io, std.fs.path.dirname(wuwa_version_path).?);
    try tmp.dir.writeFile(io, .{ .sub_path = wuwa_version_path, .data = "KR_GameVersion=3.6.0\r\n" });
    const root = try testingRoot(allocator, tmp);

    const view = try inspectInstall(allocator, io, .wuwa, root);
    try std.testing.expect(view.state != null);
    try std.testing.expect(!view.integration.identity_trustworthy);
    try std.testing.expect(view.identity == null);
}

test "detect supported pristine install markers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var genshin = std.testing.tmpDir(.{});
    defer genshin.cleanup();
    try writeUnityDetectionFixture(io, genshin.dir, "GenshinImpact.exe", genshin_data, genshin_app_info);
    const genshin_root = try testingRoot(allocator, genshin);
    defer allocator.free(genshin_root);
    try std.testing.expectEqual(Software.genshin, (try detect(io, genshin_root)).?.software);

    var endfield = std.testing.tmpDir(.{});
    defer endfield.cleanup();
    try writeUnityDetectionFixture(io, endfield.dir, "Endfield.exe", endfield_data, endfield_app_info);
    const endfield_root = try testingRoot(allocator, endfield);
    defer allocator.free(endfield_root);
    try std.testing.expectEqual(Software.endfield, (try detect(io, endfield_root)).?.software);

    var wuwa = std.testing.tmpDir(.{});
    defer wuwa.cleanup();
    try wuwa.dir.writeFile(io, .{ .sub_path = "Wuthering Waves.exe", .data = "" });
    try wuwa.dir.createDirPath(io, "Client/Binaries/Win64/ThirdParty/KrPcSdk_Global/KRSDKRes");
    try wuwa.dir.writeFile(io, .{ .sub_path = "Client/Binaries/Win64/Client-Win64-Shipping.exe", .data = "" });
    try wuwa.dir.writeFile(io, .{ .sub_path = wuwa_version_path, .data = "KR_GameVersion=3.6.0\r\n" });
    const wuwa_root = try testingRoot(allocator, wuwa);
    defer allocator.free(wuwa_root);
    try std.testing.expectEqual(Software.wuwa, (try detect(io, wuwa_root)).?.software);
}

test "unity detection rejects wrong app info" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeUnityDetectionFixture(io, tmp.dir, "Endfield.exe", endfield_data, "Gryphline\nSomething Else");
    const root = try testingRoot(allocator, tmp);
    defer allocator.free(root);
    try std.testing.expectEqual(@as(?Detected, null), try detect(io, root));
}

test "packaged WuWa version format handles unrelated keys and CRLF" {
    const allocator = std.testing.allocator;
    const wuwa = (try detectPackagedVersion(allocator, .wuwa, wuwa_version_path, "KR_ChannelId=19\r\nKR_GameVersion=3.6.0\r\n")).?;
    defer allocator.free(wuwa.full);
    try std.testing.expectEqualStrings("3.6.0", wuwa.full);
    try std.testing.expect(!integration(.wuwa).identity_trustworthy);
}

test "integration fallback scans exclude only known non-canonical state" {
    try std.testing.expect(ignoredGenshinPath("config.ini"));
    try std.testing.expect(ignoredGenshinPath("GenshinImpact_Data/Persistent/foo"));
    try std.testing.expect(!ignoredGenshinPath("GenshinImpact_Data/StreamingAssets/foo"));

    try std.testing.expect(ignoredEndfieldPath("config.ini"));
    try std.testing.expect(ignoredEndfieldPath("Endfield_Data/Persistent/VFS/foo"));
    try std.testing.expect(!ignoredEndfieldPath("Endfield_Data/StreamingAssets/VFS/foo"));

    try std.testing.expect(ignoredWuwaPath("Client/Saved/Resources/a.pak"));
    try std.testing.expect(ignoredWuwaPath("launcherDownloadConfig.json"));
    try std.testing.expect(ignoredWuwaPath("launcherDownload/launcherDownloadConfig.json"));
    try std.testing.expect(!ignoredWuwaPath("Client/Content/Paks/pakchunk0-WindowsNoEditor.pak"));
}

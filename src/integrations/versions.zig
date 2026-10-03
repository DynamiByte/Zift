const std = @import("std");
const fs = @import("../core/fs.zig");

pub const Version = struct {
    full: []const u8,
    parts: ?VersionParts,
};

pub const VersionParts = struct {
    prefix: []const u8,
    number: []const u8,
};

const read_buffer_size = 32768;
const scan_tail_size = 8192;
const app_version_name = "app_version";
const dispatch_version_name = "\"DispatchVersion\"";

pub fn detectGenshinVersion(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?Version {
    return detectDispatchVersionFile(allocator, io, root, "GenshinImpact.exe");
}

pub fn detectWuwaVersion(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?Version {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const bytes = try fs.readOptionalFile(allocator, io, dir, wuwa_version_path, 1024 * 1024) orelse return null;
    defer allocator.free(bytes);
    return versionFromKeyValue(allocator, bytes, "KR_GameVersion");
}

pub fn detectUnitySemver(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    data_dir: []const u8,
    product_name: []const u8,
) !?Version {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    const path = try allocator.print("{s}/globalgamemanagers", .{data_dir});
    defer allocator.free(path);
    const bytes = try fs.readOptionalFile(allocator, io, dir, path, 256 * 1024) orelse return null;
    defer allocator.free(bytes);
    const product_at = std.mem.indexOf(u8, bytes, product_name) orelse return null;
    const limit = @min(bytes.len, product_at + product_name.len + 8192);
    var offset = product_at + product_name.len;
    while (offset + 4 <= limit) : (offset += 1) {
        const len = std.mem.readInt(u32, bytes[offset..][0..4], .little);
        if (len == 0 or len > 128 or offset + 4 + len > limit) continue;
        const candidate = bytes[offset + 4 .. offset + 4 + len];
        if (!isUnityVersion(candidate)) continue;
        const full = try allocator.dupe(u8, candidate);
        return .{ .full = full, .parts = null };
    }
    return null;
}

fn isUnityVersion(text: []const u8) bool {
    if (text.len < 5) return false;
    var dots: usize = 0;
    var digit_in_part = false;
    for (text, 0..) |ch, index| switch (ch) {
        '0'...'9' => digit_in_part = true,
        '.' => {
            if (!digit_in_part or dots >= 2) return false;
            dots += 1;
            digit_in_part = false;
        },
        '_', '-', 'A'...'Z', 'a'...'z' => {
            if (dots < 2 or index == 0) return false;
        },
        else => return false,
    };
    return dots == 2 and digit_in_part;
}

fn detectDispatchVersionFile(allocator: std.mem.Allocator, io: std.Io, root: []const u8, path: []const u8) !?Version {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer dir.close(io);
    var file = fs.openRead(io, dir, path) catch |err| switch (err) {
        error.FileNotFound, error.IsDir => return null,
        else => |e| return e,
    };
    defer file.close(io);
    var buf: [read_buffer_size + 128]u8 = undefined;
    var tail_len: usize = 0;
    var offset: u64 = 0;
    while (true) {
        const n = try file.readPositionalAll(io, buf[tail_len .. tail_len + read_buffer_size], offset);
        offset += n;
        const data = buf[0 .. tail_len + n];
        if (extractDispatchToken(data)) |found| {
            const full = try allocator.dupe(u8, found);
            return .{ .full = full, .parts = splitClientVersion(full) };
        }
        if (n == 0) return null;
        tail_len = @min(data.len, 128);
        std.mem.copyForwards(u8, buf[0..tail_len], data[data.len - tail_len ..]);
    }
}

fn extractDispatchToken(data: []const u8) ?[]const u8 {
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, data, search, "Win")) |win| {
        search = win + 3;
        var start = win;
        while (start > 0 and std.ascii.isAlphabetic(data[start - 1]) and win - (start - 1) <= 16) start -= 1;
        const prefix = data[start..win];
        if (!(std.mem.startsWith(u8, prefix, "OS") or std.mem.startsWith(u8, prefix, "CN")) or prefix.len < 4) continue;
        var end = win + 3;
        var dots: usize = 0;
        var digit = false;
        while (end < data.len) : (end += 1) {
            const ch = data[end];
            if (std.ascii.isDigit(ch)) {
                digit = true;
                continue;
            }
            if (ch == '.' and digit and dots < 2) {
                dots += 1;
                digit = false;
                continue;
            }
            break;
        }
        if (dots == 2 and digit) return data[start..end];
    }
    return null;
}

pub fn versionFromKeyValue(allocator: std.mem.Allocator, bytes: []const u8, key: []const u8) !?Version {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, key) or line.len <= key.len or line[key.len] != '=') continue;
        const value = std.mem.trim(u8, line[key.len + 1 ..], " \t\r\n\x00");
        if (value.len == 0 or value.len > 128) return null;
        const full = try allocator.dupe(u8, value);
        return .{ .full = full, .parts = null };
    }
    return null;
}

pub fn detectZzzVersion(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?Version {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true, .access_sub_paths = true });
    defer dir.close(io);

    var scan_buf: [read_buffer_size + scan_tail_size]u8 = undefined;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory or !std.ascii.endsWithIgnoreCase(entry.name, "_Data")) continue;
        const rel = try allocator.print("{s}/resources.assets", .{entry.name});
        defer allocator.free(rel);
        var file = fs.openRead(io, dir, rel) catch |err| switch (err) {
            error.FileNotFound, error.IsDir => continue,
            else => |e| return e,
        };
        defer file.close(io);

        if (try readAppVersion(io, file, &scan_buf)) |found| {
            const full = try allocator.dupe(u8, found);
            return .{ .full = full, .parts = splitClientVersion(full) };
        }
    }
    return null;
}

fn readAppVersion(io: std.Io, file: std.Io.File, buf: []u8) !?[]const u8 {
    var tail_len: usize = 0;
    var offset: u64 = 0;

    while (true) {
        const read_len = @min(read_buffer_size, buf.len - tail_len);
        const read_buf = buf[tail_len .. tail_len + read_len];
        const n = try file.readPositionalAll(io, read_buf, offset);
        offset += n;

        const data = buf[0 .. tail_len + n];
        if (extractDispatchVersion(data)) |version| return version;
        if (n == 0) return null;

        tail_len = @min(data.len, scan_tail_size);
        std.mem.copyForwards(u8, buf[0..tail_len], data[data.len - tail_len ..]);
    }
}

fn extractDispatchVersion(data: []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < data.len) {
        const app_index = std.mem.indexOf(u8, data[index..], app_version_name) orelse return null;
        index += app_index + app_version_name.len;
        const json_start = std.mem.indexOfScalar(u8, data[index..], '{') orelse continue;
        const json = jsonObject(data[index + json_start ..]) orelse continue;
        return jsonStringField(json, dispatch_version_name) orelse continue;
    }
    return null;
}

fn jsonObject(data: []const u8) ?[]const u8 {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (data, 0..) |ch, index| {
        if (in_string) {
            if (escaped) escaped = false else if (ch == '\\') escaped = true else if (ch == '"') in_string = false;
            continue;
        }
        if (ch == '"') in_string = true else if (ch == '{') depth += 1 else if (ch == '}') {
            if (depth == 0) return null;
            depth -= 1;
            if (depth == 0) return data[0 .. index + 1];
        }
    }
    return null;
}

fn jsonStringField(json: []const u8, field: []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < json.len) {
        const found = std.mem.indexOf(u8, json[index..], field) orelse return null;
        index += found + field.len;
        index = skipWhitespace(json, index);
        if (index >= json.len or json[index] != ':') continue;
        index = skipWhitespace(json, index + 1);
        if (index >= json.len or json[index] != '"') continue;
        return jsonString(json, index + 1);
    }
    return null;
}

fn jsonString(json: []const u8, start: usize) ?[]const u8 {
    var index = start;
    while (index < json.len) : (index += 1) {
        if (json[index] == '\\') return null;
        if (json[index] == '"') return json[start..index];
    }
    return null;
}

fn skipWhitespace(text: []const u8, start: usize) usize {
    var index = start;
    while (index < text.len and switch (text[index]) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    }) : (index += 1) {}
    return index;
}

pub fn splitClientVersion(text: []const u8) ?VersionParts {
    var version_start: usize = 0;
    while (version_start < text.len and !std.ascii.isDigit(text[version_start])) version_start += 1;
    if (version_start == 0 or version_start >= text.len) return null;
    return .{ .prefix = text[0..version_start], .number = text[version_start..] };
}

pub const wuwa_version_path = "Client/Binaries/Win64/ThirdParty/KrPcSdk_Global/KRSDKRes/KRSDK.bin";
test "dispatch token extraction keeps distribution identity" {
    try std.testing.expectEqualStrings("OSRELWin7.0.0", extractDispatchToken("xx\x00OSRELWin7.0.0\x00yy").?);
    try std.testing.expectEqualStrings("OSPRODWin4.5.0", extractDispatchToken("20260813-OSPRODWin4.5.0-OSLive").?);
    try std.testing.expectEqualStrings("CNBetaWin3.2.1", extractDispatchToken("foo CNBetaWin3.2.1 bar").?);
    try std.testing.expect(extractDispatchToken("Windows 11") == null);
}

test "unity semver shape accepts build suffix but not loose text" {
    try std.testing.expect(isUnityVersion("1.4.4"));
    try std.testing.expect(isUnityVersion("7.0.0_47144228_47194594"));
    try std.testing.expect(!isUnityVersion("v1.4.4"));
    try std.testing.expect(!isUnityVersion("1.4"));
    try std.testing.expect(!isUnityVersion("1.4.4/evil"));
}

test "Endfield pristine Unity bundle version is detected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "Endfield_Data");

    var bytes: [64]u8 = @splat(0);
    const product = "Endfield";
    @memcpy(bytes[4 .. 4 + product.len], product);
    const offset = 4 + product.len + 3;
    std.mem.writeInt(u32, bytes[offset..][0..4], 5, .little);
    @memcpy(bytes[offset + 4 .. offset + 9], "1.4.4");
    try tmp.dir.writeFile(io, .{ .sub_path = "Endfield_Data/globalgamemanagers", .data = &bytes });

    const root = try testingRoot(allocator, tmp);
    defer allocator.free(root);
    const version = (try detectUnitySemver(allocator, io, root, "Endfield_Data", "Endfield")).?;
    defer allocator.free(version.full);
    try std.testing.expectEqualStrings("1.4.4", version.full);
}

fn testingRoot(allocator: std.mem.Allocator, tmp: anytype) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
}

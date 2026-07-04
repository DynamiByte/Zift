// Version detection from resources.assets
const std = @import("std");

const read_buffer_size = 32768;
const scan_tail_size = 8192;
const app_version_name = "app_version";
const dispatch_version_name = "\"DispatchVersion\"";
const resources_assets_paths = [_][]const u8{
    "ZenlessZoneZeroBeta_Data/resources.assets",
    "ZenlessZoneZero_Data/resources.assets",
};

// Client version model

pub const Parts = struct {
    prefix: []const u8,
    number: []const u8,
};

pub fn detect(allocator: std.mem.Allocator, io: std.Io, game_path: []const u8) ![]const u8 {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{});
    defer game_dir.close(io);

    var scan_buf: [read_buffer_size + scan_tail_size]u8 = undefined;
    for (resources_assets_paths) |rel| {
        var file = game_dir.openFile(io, rel, .{ .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer file.close(io);

        if (try readAppVersion(io, file, &scan_buf)) |found| {
            return allocator.dupe(u8, found);
        }
    }

    return error.VersionNotFound;
}

pub fn detectFromBytes(data: []const u8) ?[]const u8 {
    return extractDispatchVersion(data);
}

// resources.assets scanning

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
        std.mem.copyBackwards(u8, buf[0..tail_len], data[data.len - tail_len ..]);
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
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
        } else if (ch == '{') {
            depth += 1;
        } else if (ch == '}') {
            if (depth == 0) return null;
            depth -= 1;
            if (depth == 0) return data[0 .. index + 1];
        }
    }
    return null;
}

fn jsonStringField(json: []const u8, name: []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < json.len) {
        const found = std.mem.indexOf(u8, json[index..], name) orelse return null;
        index += found + name.len;
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

// Comparable client version parsing

pub fn splitClientVersion(text: []const u8) ?Parts {
    var version_start: usize = 0;
    while (version_start < text.len and !std.ascii.isDigit(text[version_start])) {
        version_start += 1;
    }
    if (version_start == 0 or version_start >= text.len) return null;
    return .{
        .prefix = text[0..version_start],
        .number = text[version_start..],
    };
}

pub fn compareVersion(left: []const u8, right: []const u8) ?std.math.Order {
    var left_index: usize = 0;
    var right_index: usize = 0;

    while (left_index < left.len or right_index < right.len) {
        const left_value = readVersionNumber(left, &left_index) orelse return null;
        const right_value = readVersionNumber(right, &right_index) orelse return null;
        if (left_value < right_value) return .lt;
        if (left_value > right_value) return .gt;
    }
    return .eq;
}

fn readVersionNumber(text: []const u8, index: *usize) ?u64 {
    if (index.* >= text.len) return 0;
    if (text[index.*] == '.') index.* += 1;
    if (index.* >= text.len) return null;

    var value: u64 = 0;
    var saw_digit = false;
    while (index.* < text.len and text[index.*] != '.') {
        const ch = text[index.*];
        if (!std.ascii.isDigit(ch)) return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, ch - '0') catch return null;
        saw_digit = true;
        index.* += 1;
    }

    if (!saw_digit) return null;
    return value;
}

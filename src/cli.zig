// Argument parsing and operation inference
const std = @import("std");

pub const Parsed = struct {
    assume_yes: bool,
    verify_md5: bool,
    operation: Operation,
};

pub const Operation = union(enum) {
    clean: struct { game: []const u8 },
    make: struct { left: []const u8, right: []const u8, out: ?[]const u8 },
    apply: struct { zip: []const u8, game: []const u8 },
};

pub const ParseResult = union(enum) {
    ok: Parsed,
    problem: Problem,
};

pub const Problem = union(enum) {
    empty_arguments,
    empty_argument,
    unknown_option: []const u8,
    home_not_found,
    path_not_found: []const u8,
    invalid_path: []const u8,
    update_zip_not_found: []const u8,
    invalid_combination,
};

const Classified = struct {
    path: []const u8,
    kind: Kind,

    const Kind = enum {
        folder,
        zip_input,
        zip_output,
        missing,
        invalid,
    };
};

pub fn parse(
    allocator: std.mem.Allocator,
    io: std.Io,
    args_src: std.process.Args,
    env: *std.process.Environ.Map,
) !ParseResult {
    var it = try std.process.Args.Iterator.initAllocator(args_src, allocator);
    defer it.deinit();

    _ = it.next();

    var assume_yes = false;
    var verify_md5 = false;
    var classified: std.ArrayList(Classified) = .empty;

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-y")) {
            assume_yes = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-v")) {
            verify_md5 = true;
            continue;
        }
        if (arg.len > 0 and arg[0] == '-') {
            return .{ .problem = .{ .unknown_option = arg } };
        }
        if (arg.len == 0) return .{ .problem = .empty_argument };

        const expanded = expandHome(allocator, env, arg) catch |err| switch (err) {
            error.HomeNotFound => return .{ .problem = .home_not_found },
            else => |e| return e,
        };
        try classified.append(allocator, .{
            .path = expanded,
            .kind = try classifyPath(io, expanded),
        });
    }

    if (classified.items.len == 0) return .{ .problem = .empty_arguments };

    var folders: std.ArrayList([]const u8) = .empty;
    var zip_inputs: std.ArrayList([]const u8) = .empty;
    var zip_outputs: std.ArrayList([]const u8) = .empty;
    var missing: std.ArrayList([]const u8) = .empty;
    var invalid: std.ArrayList([]const u8) = .empty;

    for (classified.items) |item| {
        switch (item.kind) {
            .folder => try folders.append(allocator, item.path),
            .zip_input => try zip_inputs.append(allocator, item.path),
            .zip_output => try zip_outputs.append(allocator, item.path),
            .missing => try missing.append(allocator, item.path),
            .invalid => try invalid.append(allocator, item.path),
        }
    }

    if (folders.items.len == 1 and zip_inputs.items.len == 0 and zip_outputs.items.len == 0 and missing.items.len == 0 and invalid.items.len == 0) {
        return .{ .ok = .{ .assume_yes = assume_yes, .verify_md5 = verify_md5, .operation = .{ .clean = .{ .game = folders.items[0] } } } };
    }
    if (folders.items.len == 2 and zip_inputs.items.len == 0 and zip_outputs.items.len == 0 and missing.items.len == 0 and invalid.items.len == 0) {
        return .{ .ok = .{ .assume_yes = assume_yes, .verify_md5 = verify_md5, .operation = .{ .make = .{
            .left = folders.items[0],
            .right = folders.items[1],
            .out = null,
        } } } };
    }
    if (folders.items.len == 2 and zip_inputs.items.len == 0 and zip_outputs.items.len == 1 and missing.items.len == 0 and invalid.items.len == 0) {
        return .{ .ok = .{ .assume_yes = assume_yes, .verify_md5 = verify_md5, .operation = .{ .make = .{
            .left = folders.items[0],
            .right = folders.items[1],
            .out = zip_outputs.items[0],
        } } } };
    }
    if (folders.items.len == 1 and zip_inputs.items.len == 1 and zip_outputs.items.len == 0 and missing.items.len == 0 and invalid.items.len == 0) {
        return .{ .ok = .{ .assume_yes = assume_yes, .verify_md5 = verify_md5, .operation = .{ .apply = .{
            .zip = zip_inputs.items[0],
            .game = folders.items[0],
        } } } };
    }

    if (folders.items.len == 1 and zip_inputs.items.len == 0 and zip_outputs.items.len == 1 and missing.items.len == 0 and invalid.items.len == 0) {
        return .{ .problem = .{ .update_zip_not_found = zip_outputs.items[0] } };
    }
    if (missing.items.len > 0) return .{ .problem = .{ .path_not_found = missing.items[0] } };
    if (invalid.items.len > 0) return .{ .problem = .{ .invalid_path = invalid.items[0] } };

    return .{ .problem = .invalid_combination };
}

fn expandHome(
    allocator: std.mem.Allocator,
    env: *std.process.Environ.Map,
    arg: []const u8,
) ![]const u8 {
    if (arg.len == 0 or arg[0] != '~') return allocator.dupe(u8, arg);
    if (arg.len > 1 and arg[1] != '/' and arg[1] != '\\') return allocator.dupe(u8, arg);

    const home = env.get("HOME") orelse env.get("USERPROFILE") orelse return error.HomeNotFound;
    if (arg.len == 1) return allocator.dupe(u8, home);

    var out = std.ArrayList(u8).empty;
    try out.appendSlice(allocator, home);
    if (home.len > 0 and home[home.len - 1] != '/' and home[home.len - 1] != '\\') {
        try out.append(allocator, std.Io.Dir.path.sep);
    }
    try out.appendSlice(allocator, arg[2..]);
    return out.toOwnedSlice(allocator);
}

fn classifyPath(io: std.Io, path: []const u8) !Classified.Kind {
    const is_zip = hasZipExtension(path);
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return if (is_zip) .zip_output else .missing,
        else => |e| return e,
    };

    return switch (stat.kind) {
        .directory => .folder,
        .file => if (is_zip) .zip_input else .invalid,
        else => .invalid,
    };
}

fn hasZipExtension(path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.Io.Dir.path.extension(path), ".zip");
}

pub fn confirm(io: std.Io, out: *std.Io.Writer, assume_yes: bool) !bool {
    if (assume_yes) return true;

    try out.writeAll("\ncontinue? [y/N] ");
    try out.flush();

    var input_buf: [1]u8 = undefined;
    var stdin_file = std.Io.File.stdin();
    var reader = stdin_file.readerStreaming(io, &input_buf);

    while (true) {
        const ch = reader.interface.takeByte() catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            error.EndOfStream => return false,
        };
        switch (ch) {
            ' ', '\t', '\r' => continue,
            'y', 'Y' => return true,
            else => return false,
        }
    }
}

pub fn printProblem(w: *std.Io.Writer, problem: Problem) !void {
    switch (problem) {
        .empty_arguments => try w.writeAll("Error: no arguments given\n"),
        .empty_argument => try w.writeAll("Error: empty argument\n"),
        .unknown_option => |option| try w.print("Error: unknown option: {s}\n", .{option}),
        .home_not_found => try w.writeAll("Error: cannot expand ~ because HOME is not set\n"),
        .path_not_found => |path| try w.print("Error: path not found: {s}\n", .{path}),
        .invalid_path => |path| try w.print("Error: path is not a folder or zip: {s}\n", .{path}),
        .update_zip_not_found => |path| try w.print("Error: update zip not found: {s}\n", .{path}),
        .invalid_combination => try w.writeAll("Error: expected one folder, two folders, or a folder and zip\n"),
    }
}

pub fn problemNeedsUsage(problem: Problem) bool {
    return switch (problem) {
        .empty_arguments,
        .empty_argument,
        .unknown_option,
        .invalid_combination,
        => true,
        .home_not_found,
        .path_not_found,
        .invalid_path,
        .update_zip_not_found,
        => false,
    };
}

pub fn printUsage(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\Usage:
        \\  zift <game-folder>
        \\  zift <old-folder> <new-folder> [out.zip]
        \\  zift <update.zip> <game-folder>
        \\
        \\Extra options:
        \\  -y  Skips confirmation prompt
        \\  -v  Additionally verifies MD5 hashes
        \\
    );
}

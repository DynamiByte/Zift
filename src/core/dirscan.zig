// windows Dir.Walker: sizes omitted, extra stat/open per file

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

pub const IgnorePath = *const fn ([]const u8) bool;

pub const Entry = struct {
    // root-relative, '/'-normalized paths
    path: []const u8,
    size: u64,
    is_directory: bool,
    is_reparse: bool,
};

pub const Result = struct {
    entries: []Entry,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(result: *Result) void {
        result.arena.deinit();
        result.* = undefined;
    }
};

const FileDirectoryInformation: u32 = 1;
const file_attribute_directory: u32 = 0x10;
const file_attribute_reparse_point: u32 = 0x400;

const FileDirectoryInfo = extern struct {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32,
    // trailing variable-length UTF-16 name
};

// reparse directories included for rejection
pub fn enumerate(
    gpa: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    ignore_path: ?IgnorePath,
) !Result {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    var entries: std.ArrayList(Entry) = .empty;

    var root_dir = try std.Io.Dir.cwd().openDir(io, root, .{
        .iterate = true,
        .access_sub_paths = true,
    });
    defer root_dir.close(io);

    if (builtin.target.os.tag == .windows) {
        const query_buffer = try gpa.alignedAlloc(u8, .of(FileDirectoryInfo), 64 * 1024);
        defer gpa.free(query_buffer);
        try enumerateWindows(allocator, gpa, io, root_dir, ignore_path, &entries, query_buffer);
    } else {
        try enumeratePortable(allocator, gpa, io, root_dir, ignore_path, &entries);
    }

    const owned = try entries.toOwnedSlice(allocator);
    std.mem.sortUnstable(Entry, owned, {}, struct {
        fn lessThan(_: void, lhs: Entry, rhs: Entry) bool {
            return std.mem.order(u8, lhs.path, rhs.path) == .lt;
        }
    }.lessThan);
    return .{ .entries = owned, .arena = arena };
}

fn enumeratePortable(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    ignore_path: ?IgnorePath,
    entries: *std.ArrayList(Entry),
) !void {
    var walker = try root_dir.walkSelectively(scratch);
    defer {
        // SelectiveWalker.deinit leaves child handles open
        while (walker.stack.items.len > 1) walker.leave(io);
        walker.deinit();
    }

    while (try walker.next(io)) |entry| {
        if (shouldIgnore(ignore_path, entry.path)) continue;
        switch (entry.kind) {
            .directory => try walker.enter(io, entry),
            .file => {
                const stat = try entry.dir.statFile(io, entry.basename, .{ .follow_symlinks = false });
                if (stat.kind != .file) return error.FileChangedDuringEnumeration;
                try entries.append(allocator, .{
                    .path = try allocator.dupe(u8, entry.path),
                    .size = stat.size,
                    .is_directory = false,
                    .is_reparse = false,
                });
            },
            else => try entries.append(allocator, .{
                .path = try allocator.dupe(u8, entry.path),
                .size = 0,
                .is_directory = entry.kind == .directory,
                .is_reparse = true,
            }),
        }
    }
}

fn enumerateWindows(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    ignore_path: ?IgnorePath,
    entries: *std.ArrayList(Entry),
    query_buffer: []align(@alignOf(FileDirectoryInfo)) u8,
) !void {
    const Frame = struct {
        dir: std.Io.Dir,
        children: std.ArrayList([]const u8) = .empty,
        next_child: usize = 0,
    };
    var stack: std.ArrayList(Frame) = .empty;
    defer {
        for (stack.items, 0..) |*frame, index| {
            freeDirectoryPaths(scratch, &frame.children);
            if (index != 0) frame.dir.close(io);
        }
        stack.deinit(scratch);
    }
    try stack.append(scratch, .{ .dir = root });
    stack.items[0].children = try enumerateWindowsDirectory(allocator, scratch, root, "", ignore_path, entries, query_buffer);
    while (stack.items.len != 0) {
        const top = &stack.items[stack.items.len - 1];
        if (top.next_child == top.children.items.len) {
            var frame = stack.pop().?;
            freeDirectoryPaths(scratch, &frame.children);
            if (stack.items.len != 0) frame.dir.close(io);
            continue;
        }
        const prefix = top.children.items[top.next_child];
        top.next_child += 1;
        var child = try top.dir.openDir(io, std.fs.path.basename(prefix), .{
            .iterate = true,
            .access_sub_paths = true,
            .follow_symlinks = false,
        });
        errdefer child.close(io);
        var children = try enumerateWindowsDirectory(allocator, scratch, child, prefix, ignore_path, entries, query_buffer);
        errdefer freeDirectoryPaths(scratch, &children);
        try stack.append(scratch, .{ .dir = child, .children = children });
    }
}

fn enumerateWindowsDirectory(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    dir: std.Io.Dir,
    prefix: []const u8,
    ignore_path: ?IgnorePath,
    entries: *std.ArrayList(Entry),
    query_buffer: []align(@alignOf(FileDirectoryInfo)) u8,
) !std.ArrayList([]const u8) {
    var child_directories: std.ArrayList([]const u8) = .empty;
    errdefer freeDirectoryPaths(scratch, &child_directories);

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var restart_scan = true;
    while (true) {
        const status = windows.ntdll.NtQueryDirectoryFile(
            dir.handle,
            null,
            null,
            null,
            &io_status_block,
            query_buffer.ptr,
            @intCast(query_buffer.len),
            @fromBackingInt(FileDirectoryInformation),
            .FALSE,
            null,
            if (restart_scan) .TRUE else .FALSE,
        );
        restart_scan = false;

        switch (status) {
            .SUCCESS => {},
            .NO_MORE_FILES => break,
            .BUFFER_OVERFLOW, .INFO_LENGTH_MISMATCH => return error.DirectoryBufferTooSmall,
            .ACCESS_DENIED => return error.AccessDenied,
            else => return error.DirectoryEnumerationFailed,
        }

        const returned: usize = @intCast(io_status_block.Information);
        if (returned == 0 or returned > query_buffer.len) return error.InvalidDirectoryBuffer;
        var offset: usize = 0;
        while (true) {
            if (offset > returned or returned - offset < @sizeOf(FileDirectoryInfo)) return error.InvalidDirectoryBuffer;
            const info: *align(1) const FileDirectoryInfo = @ptrCast(query_buffer.ptr + offset);
            if ((info.file_name_length & 1) != 0) return error.InvalidDirectoryBuffer;
            const name_bytes: usize = @intCast(info.file_name_length);
            const name_offset = offset + @sizeOf(FileDirectoryInfo);
            if (name_offset > returned or name_bytes > returned - name_offset) return error.InvalidDirectoryBuffer;

            const wide_ptr: [*]align(1) const u16 = @ptrCast(query_buffer.ptr + name_offset);
            const wide_name = wide_ptr[0 .. name_bytes / 2];
            if (!isDotEntry(wide_name)) {
                var name_buffer: [std.fs.max_name_bytes]u8 = undefined;
                if (wide_name.len > std.fs.max_name_bytes / 2) return error.NameTooLong;
                var aligned_name: [std.fs.max_name_bytes / 2]u16 = undefined;
                @memcpy(aligned_name[0..wide_name.len], wide_name);
                const length = std.unicode.wtf16LeToWtf8(&name_buffer, aligned_name[0..wide_name.len]);
                const name = name_buffer[0..length];
                const is_directory = (info.file_attributes & file_attribute_directory) != 0;
                const is_reparse = (info.file_attributes & file_attribute_reparse_point) != 0;
                const path_allocator = if (is_directory and !is_reparse) scratch else allocator;
                const relative = if (prefix.len == 0)
                    try path_allocator.dupe(u8, name)
                else
                    try path_allocator.print("{s}/{s}", .{ prefix, name });
                errdefer path_allocator.free(relative);

                const ignored = shouldIgnore(ignore_path, relative);
                if (!ignored) {
                    if (is_directory and !is_reparse) {
                        try child_directories.append(scratch, relative);
                    } else {
                        if (info.end_of_file < 0) return error.InvalidDirectoryBuffer;
                        try entries.append(allocator, .{
                            .path = relative,
                            .size = @intCast(info.end_of_file),
                            .is_directory = is_directory,
                            .is_reparse = is_reparse,
                        });
                    }
                } else {
                    path_allocator.free(relative);
                }
            }

            if (info.next_entry_offset == 0) break;
            const next: usize = @intCast(info.next_entry_offset);
            if (next < @sizeOf(FileDirectoryInfo) or next > returned - offset) return error.InvalidDirectoryBuffer;
            offset += next;
        }
    }

    return child_directories;
}

fn freeDirectoryPaths(allocator: std.mem.Allocator, paths: *std.ArrayList([]const u8)) void {
    for (paths.items) |path| allocator.free(path);
    paths.deinit(allocator);
}

fn shouldIgnore(ignore_path: ?IgnorePath, path: []const u8) bool {
    // completed receipt excluded from installation content
    const stop = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    if (std.ascii.eqlIgnoreCase(path[0..stop], ".zift-work")) return true;
    return if (ignore_path) |ignore| ignore(path) else false;
}

fn isDotEntry(name: []align(1) const u16) bool {
    return (name.len == 1 and name[0] == '.') or
        (name.len == 2 and name[0] == '.' and name[1] == '.');
}

test "enumeration returns sorted paths and exact sizes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "sub/deep");
    try tmp.dir.writeFile(io, .{ .sub_path = "z.bin", .data = "12345" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/b.bin", .data = "1234567890" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/deep/a.bin", .data = "" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    var result = try enumerate(allocator, io, root, null);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.entries.len);
    try std.testing.expectEqualStrings("sub/b.bin", result.entries[0].path);
    try std.testing.expectEqual(@as(u64, 10), result.entries[0].size);
    try std.testing.expectEqualStrings("sub/deep/a.bin", result.entries[1].path);
    try std.testing.expectEqual(@as(u64, 0), result.entries[1].size);
    try std.testing.expectEqualStrings("z.bin", result.entries[2].path);
    try std.testing.expectEqual(@as(u64, 5), result.entries[2].size);
}

test "Windows enumeration accepts an unaligned allocator backing buffer" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "payload.bin", .data = "payload" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var storage: [128 * 1024]u8 align(@alignOf(FileDirectoryInfo)) = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(storage[1..]);
    var result = try enumerate(allocator.allocator(), io, root, null);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("payload.bin", result.entries[0].path);
    try std.testing.expectEqual(@as(u64, 7), result.entries[0].size);
}

test "enumeration prunes ignored directories before descent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "skip/nested");
    try tmp.dir.writeFile(io, .{ .sub_path = "skip/nested/ignored.bin", .data = "ignored" });
    try tmp.dir.writeFile(io, .{ .sub_path = "kept.bin", .data = "kept" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const ignore = struct {
        fn path(value: []const u8) bool {
            return std.mem.eql(u8, value, "skip") or std.mem.startsWith(u8, value, "skip/");
        }
    }.path;
    var result = try enumerate(allocator, io, root, ignore);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("kept.bin", result.entries[0].path);
}

test "nested enumeration closes directories through allocation failures" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    const Exercise = struct {
        fn descriptorCount(io: std.Io) !usize {
            var directory = try std.Io.Dir.cwd().openDir(io, "/proc/self/fd", .{ .iterate = true });
            defer directory.close(io);
            var iterator = directory.iterate();
            var count: usize = 0;
            while (try iterator.next(io)) |_| count += 1;
            return count;
        }

        fn run(allocator: std.mem.Allocator, root: []const u8) !void {
            const io = std.testing.io;
            const before = try descriptorCount(io);
            var result = enumerate(allocator, io, root, null) catch |err| {
                try std.testing.expectEqual(before, try descriptorCount(io));
                return err;
            };
            defer result.deinit();
            try std.testing.expectEqual(before, try descriptorCount(io));
            try std.testing.expectEqual(@as(usize, 2), result.entries.len);
            try std.testing.expectEqualStrings("sub/deep/a.bin", result.entries[0].path);
            try std.testing.expectEqualStrings("sub/other/b.bin", result.entries[1].path);
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "sub/deep");
    try tmp.dir.createDirPath(io, "sub/other");
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/deep/a.bin", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/other/b.bin", .data = "bb" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    try std.testing.checkAllAllocationFailures(allocator, Exercise.run, .{root});
}

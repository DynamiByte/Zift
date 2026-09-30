const std = @import("std");
const builtin = @import("builtin");

pub fn available(io: std.Io, directory_path: []const u8) !?u64 {
    var directory = try std.Io.Dir.cwd().openDir(io, directory_path, .{});
    defer directory.close(io);

    return switch (builtin.os.tag) {
        .linux => linuxAvailable(directory.handle),
        .windows => windowsAvailable(io, directory),
        else => null,
    };
}

const LinuxStatVfs = extern struct {
    block_size: c_ulong,
    fragment_size: c_ulong,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    files_available: u64,
    filesystem_id: c_ulong,
    flags: c_ulong,
    name_max: c_ulong,
    filesystem_type: c_uint,
    reserved: [5]c_int,
};

extern fn fstatvfs(fd: c_int, info: *LinuxStatVfs) c_int;

fn linuxAvailable(handle: std.Io.Dir.Handle) ?u64 {
    var info: LinuxStatVfs = undefined;
    if (fstatvfs(handle, &info) != 0) return null;
    return std.math.mul(u64, info.blocks_available, info.fragment_size) catch std.math.maxInt(u64);
}

extern "kernel32" fn GetDiskFreeSpaceExW(
    directory_name: [*:0]const u16,
    free_bytes_available: *u64,
    total_bytes: ?*u64,
    total_free_bytes: ?*u64,
) callconv(.winapi) i32;

fn windowsAvailable(io: std.Io, directory: std.Io.Dir) !?u64 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try directory.realPath(io, &path_buffer);
    var wide_buffer: [std.os.windows.PATH_MAX_WIDE + 1]u16 = undefined;
    const wide_len = std.unicode.wtf8ToWtf16Le(wide_buffer[0 .. wide_buffer.len - 1], path_buffer[0..path_len]) catch return null;
    wide_buffer[wide_len] = 0;

    var free: u64 = 0;
    if (GetDiskFreeSpaceExW(wide_buffer[0..wide_len :0].ptr, &free, null, null) == 0) return null;
    return free;
}

test "reports available space on supported desktop platforms" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    const free = try available(std.testing.io, ".");
    try std.testing.expect(free != null);
    try std.testing.expect(free.? > 0);
}

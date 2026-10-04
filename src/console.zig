const std = @import("std");
const builtin = @import("builtin");
const interrupt = @import("interrupt.zig");
const windows = std.os.windows;

pub const OutputEncoding = struct {
    previous: ?u32 = null,

    pub fn init(stdout: std.Io.File, stderr: std.Io.File) !OutputEncoding {
        if (builtin.os.tag != .windows) return .{};
        if (!isNative(stdout) and !isNative(stderr)) return .{};
        const previous = GetConsoleOutputCP();
        if (previous == 0) return windows.unexpectedError(windows.GetLastError());
        if (previous == 65001) return .{};
        if (SetConsoleOutputCP(65001) == .FALSE) return windows.unexpectedError(windows.GetLastError());
        return .{ .previous = previous };
    }

    pub fn deinit(self: OutputEncoding) void {
        if (builtin.os.tag == .windows) {
            if (self.previous) |previous| _ = SetConsoleOutputCP(previous);
        }
    }
};

pub fn isNative(file: std.Io.File) bool {
    if (builtin.os.tag != .windows) return false;
    var mode: u32 = undefined;
    return GetConsoleMode(file.handle, &mode) != .FALSE;
}

pub fn readChar(file: std.Io.File) !?u21 {
    const first = (try readCodeUnit(file)) orelse return null;
    if (!std.unicode.utf16IsHighSurrogate(first)) return first;
    const second = (try readCodeUnit(file)) orelse return error.InvalidUtf16;
    return try std.unicode.utf16DecodeSurrogatePair(&.{ first, second });
}

fn readCodeUnit(file: std.Io.File) !?u16 {
    try interrupt.check();
    var unit: u16 = undefined;
    var count: u32 = undefined;
    const success = ReadConsoleW(file.handle, &unit, 1, &count, null);
    try interrupt.check();
    if (success == .FALSE) return windows.unexpectedError(windows.GetLastError());
    return if (count == 0) null else unit;
}

extern "kernel32" fn GetConsoleMode(windows.HANDLE, *u32) callconv(.winapi) windows.BOOL;
extern "kernel32" fn GetConsoleOutputCP() callconv(.winapi) u32;
extern "kernel32" fn SetConsoleOutputCP(u32) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ReadConsoleW(windows.HANDLE, *anyopaque, u32, *u32, ?*anyopaque) callconv(.winapi) windows.BOOL;

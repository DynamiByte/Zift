const std = @import("std");
const builtin = @import("builtin");

var requested_flag: std.atomic.Value(bool) = .init(false);

pub fn install() !void {
    reset();
    if (builtin.target.os.tag == .windows) {
        if (SetConsoleCtrlHandler(windowsHandler, .TRUE) == .FALSE) return error.InterruptHandlerInstallFailed;
    } else if (builtin.target.os.tag != .wasi and builtin.target.os.tag != .freestanding) {
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = posixHandler },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &action, null);
        std.posix.sigaction(.TERM, &action, null);
        std.posix.sigaction(.HUP, &action, null);
    }
}

pub fn request() void {
    requested_flag.store(true, .release);
}

pub fn reset() void {
    requested_flag.store(false, .release);
}

pub fn requested() bool {
    return requested_flag.load(.acquire);
}

pub fn check() !void {
    if (requested()) return error.Interrupted;
}

fn posixHandler(_: std.posix.SIG) callconv(.c) void {
    request();
}

const WindowsHandler = *const fn (u32) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?WindowsHandler, add: std.os.windows.BOOL) callconv(.winapi) std.os.windows.BOOL;

fn windowsHandler(kind: u32) callconv(.winapi) std.os.windows.BOOL {
    if (kind != 0 and kind != 1) return .FALSE;
    request();
    return .TRUE;
}

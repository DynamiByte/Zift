const std = @import("std");
const builtin = @import("builtin");

pub const Thread = struct {
    inner: std.Thread,

    pub const getCpuCount = std.Thread.getCpuCount;

    pub fn spawn(config: std.Thread.SpawnConfig, comptime function: anytype, args: anytype) std.Thread.SpawnError!Thread {
        return .{ .inner = try std.Thread.spawn(config, function, args) };
    }

    pub fn join(self: Thread) void {
        if (builtin.os.tag == .windows) {
            // zig 0.16 + wine: infinite-wait timeout overflow can return before worker exit
            const windows = std.os.windows;
            const status = windows.ntdll.NtWaitForSingleObject(self.inner.getHandle(), .FALSE, null);
            if (status != windows.NTSTATUS.WAIT_0) std.debug.panic("thread wait failed: {t}", .{status});
        }
        self.inner.join();
    }
};

test "join retains worker storage until the worker finishes" {
    var finished = std.atomic.Value(bool).init(false);
    const Worker = struct {
        fn run(value: *std.atomic.Value(bool)) void {
            for (0..10000) |_| std.atomic.spinLoopHint();
            value.store(true, .release);
        }
    };
    const worker = try Thread.spawn(.{}, Worker.run, .{&finished});
    worker.join();
    try std.testing.expect(finished.load(.acquire));
}

const std = @import("std");

pub const Tracker = struct {
    bytes: std.atomic.Value(u64) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),

    pub fn done(self: *const Tracker) u64 {
        return self.bytes.load(.acquire);
    }

    pub fn add(self: *Tracker, count: u64) void {
        var old = self.bytes.load(.monotonic);
        while (true) {
            const new = old +| count;
            old = self.bytes.cmpxchgWeak(old, new, .release, .monotonic) orelse return;
        }
    }

    pub fn cancel(self: *Tracker) void {
        self.cancelled.store(true, .release);
    }

    pub fn isCancelled(self: *const Tracker) bool {
        return self.cancelled.load(.acquire);
    }
};

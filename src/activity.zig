const std = @import("std");
const Thread = std.Thread;

const ui = @import("ui.zig");
const interrupt = @import("interrupt.zig");
const hdiff = @import("hdiff.zig");
const tracker = @import("tracker.zig");

pub const Operation = union(enum) {
    create_standard_file_at: struct {
        source: hdiff.FileIdentity,
        target: hdiff.FileIdentity,
        output: []const u8,
        offset: u64,
        options: hdiff.CreateOptions,
        result: *hdiff.CreateResult,
        tracker: *hdiff.Progress,
    },
    apply_file_at_guarded: struct {
        source: hdiff.InputPart,
        container: hdiff.InputPart,
        offset: u64,
        size: u64,
        target: std.Io.File,
        tracker: *hdiff.Progress,
    },
    fn workTracker(self: Operation) *tracker.Tracker {
        return switch (self) {
            .create_standard_file_at => |op| &op.tracker.tracker,
            .apply_file_at_guarded => |op| &op.tracker.tracker,
        };
    }
};

pub fn runTracked(io: std.Io, progress: *ui.Progress, operation: Operation) !void {
    return run(io, progress, operation, .bytes);
}

pub fn runPulsedTracked(io: std.Io, progress: *ui.Progress, operation: Operation) !void {
    return run(io, progress, operation, .activity);
}

const ProgressMode = enum { bytes, activity };

fn run(io: std.Io, progress: *ui.Progress, operation: Operation, mode: ProgressMode) !void {
    const work_tracker = operation.workTracker();
    var task: Task = .{ .io = io, .operation = operation };
    const thread = try Thread.spawn(.{}, Task.execute, .{&task});
    defer thread.join();
    errdefer work_tracker.cancel();
    var reported: u64 = 0;
    var interrupted = false;
    while (!task.done.isSet()) {
        if (interrupt.requested()) {
            interrupted = true;
            work_tracker.cancel();
        }
        if (!interrupted) {
            try reportProgress(progress, mode, work_tracker.done(), &reported);
            try progress.pulse();
        }
        task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } }) catch |err| switch (err) {
            error.Timeout => {},
            error.Canceled => return err,
        };
    }
    if (interrupted or interrupt.requested()) return error.Interrupted;
    if (task.err) |err| return err;
    try reportProgress(progress, mode, work_tracker.done(), &reported);
}

fn reportProgress(progress: *ui.Progress, mode: ProgressMode, current: u64, reported: *u64) !void {
    if (current <= reported.*) return;
    const delta = current - reported.*;
    switch (mode) {
        .bytes => try progress.addBytes(delta),
        .activity => try progress.addActivity(delta),
    }
    reported.* = current;
}

const Task = struct {
    operation: Operation,
    io: std.Io,
    done: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn execute(self: *Task) void {
        self.executeInner() catch |err| {
            self.err = err;
        };
        self.done.set(self.io);
    }

    fn executeInner(self: *Task) !void {
        const allocator = std.heap.smp_allocator;
        switch (self.operation) {
            .create_standard_file_at => |op| op.result.* = try hdiff.createAt(allocator, self.io, op.source, op.target, op.output, op.offset, op.options, op.tracker),
            .apply_file_at_guarded => |op| try hdiff.applyAtGuardedFiles(allocator, self.io, op.source, op.container, op.offset, op.size, op.target, op.tracker),
        }
    }
};

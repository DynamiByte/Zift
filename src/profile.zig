// ZIFT_PROFILE phase accounting

const std = @import("std");
const builtin = @import("builtin");

pub const max_phases = 32;

const Phase = struct {
    name: []const u8 = "",
    nanoseconds: u64 = 0,
    read_bytes: u64 = 0,
    calls: u64 = 0,
};

var phases: [max_phases]Phase = @splat(.{});
var phase_count: usize = 0;
var enabled_cache: ?bool = null;
var phase_mutex: std.Io.Mutex = .init;

const IoCounters = extern struct {
    read_operations: u64,
    write_operations: u64,
    other_operations: u64,
    read_transfer: u64,
    write_transfer: u64,
    other_transfer: u64,
};

extern "kernel32" fn GetProcessIoCounters(
    process: ?*anyopaque,
    counters: *IoCounters,
) callconv(.winapi) i32;

// windows: requested reads, including cache hits; elsewhere: zero
fn requestedReadBytes() u64 {
    if (builtin.os.tag != .windows) return 0;
    var counters: IoCounters = undefined;
    if (GetProcessIoCounters(std.os.windows.GetCurrentProcess(), &counters) == 0) return 0;
    return counters.read_transfer;
}

pub fn configure(environ: *std.process.Environ.Map) void {
    enabled_cache = environ.get("ZIFT_PROFILE") != null;
}

pub fn enabled() bool {
    return enabled_cache orelse false;
}

// overlapping spans; timings not additive
pub const Span = struct {
    name: []const u8,
    start_ns: i128,
    start_reads: u64,
    live: bool,

    pub fn end(span: *Span, io: std.Io) void {
        if (!span.live) return;
        span.live = false;
        const now_ns: i128 = std.Io.Timestamp.now(io, .awake).nanoseconds;
        const now_reads = requestedReadBytes();
        const elapsed = now_ns - span.start_ns;
        record(
            io,
            span.name,
            if (elapsed > 0) @intCast(elapsed) else 0,
            now_reads -| span.start_reads,
        );
    }
};

pub fn begin(io: std.Io, name: []const u8) Span {
    if (!enabled()) return .{ .name = name, .start_ns = 0, .start_reads = 0, .live = false };
    return .{
        .name = name,
        .start_ns = @as(i128, std.Io.Timestamp.now(io, .awake).nanoseconds),
        .start_reads = requestedReadBytes(),
        .live = true,
    };
}

fn record(io: std.Io, name: []const u8, nanoseconds: u64, read_bytes: u64) void {
    phase_mutex.lockUncancelable(io);
    defer phase_mutex.unlock(io);
    var index: usize = 0;
    while (index < phase_count) : (index += 1) {
        if (std.mem.eql(u8, phases[index].name, name)) break;
    }
    if (index == phase_count) {
        if (phase_count == max_phases) return;
        phases[phase_count] = .{ .name = name };
        phase_count += 1;
    }
    phases[index].nanoseconds += nanoseconds;
    phases[index].read_bytes += read_bytes;
    phases[index].calls += 1;
}

pub fn report(writer: *std.Io.Writer) !void {
    if (!enabled() or phase_count == 0) return;
    try writer.writeAll("\nZIFT_PROFILE phases (requested read bytes; Windows OS counters, zero elsewhere)\n");
    try writer.print(
        "{s:<34} {s:>10} {s:>16} {s:>10}\n",
        .{ "phase", "seconds", "read_bytes", "calls" },
    );
    for (phases[0..phase_count]) |phase| {
        try writer.print("{s:<34} {d:>10.2} {d:>16} {d:>10}\n", .{
            phase.name,
            @as(f64, @floatFromInt(phase.nanoseconds)) / 1e9,
            phase.read_bytes,
            phase.calls,
        });
    }
    try writer.flush();
}

test "a disabled profile records nothing and costs no state" {
    const io = std.testing.io;
    enabled_cache = false;
    phase_count = 0;
    var span = begin(io, "unused");
    span.end(io);
    try std.testing.expectEqual(@as(usize, 0), phase_count);
    enabled_cache = null;
}

test "spans accumulate per name and count each span once" {
    enabled_cache = true;
    phase_count = 0;
    defer {
        phase_count = 0;
        enabled_cache = null;
    }
    const io = std.testing.io;
    var first = begin(io, "alpha");
    first.end(io);
    first.end(io);
    var second = begin(io, "alpha");
    second.end(io);
    var other = begin(io, "beta");
    other.end(io);
    try std.testing.expectEqual(@as(usize, 2), phase_count);
    try std.testing.expectEqualStrings("alpha", phases[0].name);
    try std.testing.expectEqual(@as(u64, 2), phases[0].calls);
    try std.testing.expectEqualStrings("beta", phases[1].name);
    try std.testing.expectEqual(@as(u64, 1), phases[1].calls);
}

test "concurrent phase registration keeps one record and all calls" {
    const Thread = @import("core/thread.zig").Thread;
    const Worker = struct {
        fn run(io: std.Io, ready: *std.atomic.Value(usize), start: *std.atomic.Value(bool)) void {
            _ = ready.fetchAdd(1, .release);
            while (!start.load(.acquire)) std.atomic.spinLoopHint();
            for (0..100) |_| record(io, "shared phase", 1, 2);
        }
    };
    enabled_cache = true;
    phase_count = 0;
    defer {
        phase_count = 0;
        enabled_cache = null;
    }
    var ready = std.atomic.Value(usize).init(0);
    var start = std.atomic.Value(bool).init(false);
    var threads: [8]Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        start.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    while (spawned < threads.len) : (spawned += 1)
        threads[spawned] = try Thread.spawn(.{}, Worker.run, .{ std.testing.io, &ready, &start });
    while (ready.load(.acquire) != threads.len) std.atomic.spinLoopHint();
    start.store(true, .release);
    for (threads) |thread| thread.join();
    spawned = 0;
    try std.testing.expectEqual(@as(usize, 1), phase_count);
    try std.testing.expectEqualStrings("shared phase", phases[0].name);
    try std.testing.expectEqual(@as(u64, 800), phases[0].calls);
    try std.testing.expectEqual(@as(u64, 800), phases[0].nanoseconds);
    try std.testing.expectEqual(@as(u64, 1600), phases[0].read_bytes);
}

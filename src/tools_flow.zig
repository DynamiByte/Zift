// opt-in harness, outside production CLI
const std = @import("std");
const tree = @import("tree.zig");
const generic = @import("plan/generic.zig");
const plan_mod = @import("create/ziff_plan.zig");
const create_mod = @import("create/ziff.zig");
const ziff_file = @import("format/ziff_file.zig");
const fs = @import("core/fs.zig");
const inplace = @import("apply/inplace.zig");
const builtin = @import("builtin");
const profile = @import("profile.zig");

pub fn main(init: std.process.Init) !u8 {
    const a = init.arena.allocator();
    profile.configure(init.environ_map);
    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, a);
    defer args_iter.deinit();
    var args: std.ArrayList([]const u8) = .empty;
    while (args_iter.next()) |arg| try args.append(a, arg);
    var stdout_file = std.Io.File.stdout();
    var buf: [4096]u8 = undefined;
    var fw = stdout_file.writer(init.io, &buf);
    const out = &fw.interface;
    run(a, init.io, args.items, out) catch |err| {
        try out.print("ERROR {s}\n", .{@errorName(err)});
        try out.flush();
        return 1;
    };
    try profile.report(out);
    try out.flush();
    return 0;
}
fn run(a: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer) !void {
    if (args.len >= 5 and std.mem.eql(u8, args[1], "create")) {
        const slice: u64 = if (args.len >= 6) try std.fmt.parseInt(u64, args[5], 10) else 0;
        const matcher_threads: usize = if (args.len >= 7) try std.fmt.parseInt(usize, args[6], 10) else 0;
        const matcher_search_workers: usize = if (args.len >= 8) try std.fmt.parseInt(usize, args[7], 10) else 0;
        const serializer_workers: usize = if (args.len >= 9) try std.fmt.parseInt(usize, args[8], 10) else 0;
        var source = try tree.inventory(a, io, args[2], null, null);
        defer tree.deinitOwnedTree(a, source);
        var target = try tree.inventory(a, io, args[3], null, null);
        defer tree.deinitOwnedTree(a, target);
        const plan = try generic.build(a, io, &source, &target, null, .{});
        var prepared = try plan_mod.build(a, io, &source, &target, plan, null, "A", "B");
        defer prepared.deinit();
        const stats = try create_mod.create(a, io, &prepared.header, &prepared.directory, .{ .source_root = args[2], .target_root = args[3], .container_path = args[4], .source_manifest = prepared.source_manifest }, .{ .target_observations = &target, .slice_budget = slice, .matcher_threads = matcher_threads, .matcher_search_workers = matcher_search_workers, .serializer_workers = serializer_workers });
        try std.json.Stringify.value(.{ .stats = stats, .comparison_bytes = plan.comparison_bytes, .units = prepared.directory.units.len, .groups = plan.groups.len }, .{}, out);
        try out.writeByte('\n');
    } else if (args.len >= 4 and std.mem.eql(u8, args[1], "apply")) {
        const verify = if (args.len >= 5) std.mem.eql(u8, args[4], "1") else false;
        const checkpoints: u32 = if (args.len >= 6) try std.fmt.parseInt(u32, args[5], 10) else 32;
        const split = if (args.len >= 7) std.mem.eql(u8, args[6], "1") else false;
        const pause: u64 = if (args.len >= 8 and !std.mem.eql(u8, args[7], "off")) try std.fmt.parseInt(u64, args[7], 10) else 0;
        const trace = args.len >= 8 and !std.mem.eql(u8, args[7], "off");
        const write_buffer = if (args.len >= 9) try std.fmt.parseInt(usize, args[8], 10) else 256 * 1024;
        const patch_buffer = if (args.len >= 10) try std.fmt.parseInt(usize, args[9], 10) else 256 * 1024;
        const batch_directories = if (args.len >= 11) !std.mem.eql(u8, args[10], "0") else true;
        const source_handles = if (args.len >= 12) try std.fmt.parseInt(usize, args[11], 10) else 512;
        const verify_workers = if (args.len >= 13) try std.fmt.parseInt(usize, args[12], 10) else 0;
        var package = try fs.openReadContentAuthority(io, std.Io.Dir.cwd(), args[2]);
        defer package.close(io);
        var opened = try ziff_file.openFile(a, io, package);
        defer opened.deinit();
        var root = try std.Io.Dir.cwd().openDir(io, args[3], .{ .iterate = true, .access_sub_paths = true });
        defer root.close(io);
        var events: Events = .{ .out = out, .pause = pause };
        const stats = try inplace.run(a, io, package, &opened, root, .{ .write_buffer_bytes = write_buffer, .patch_buffer_bytes = patch_buffer, .source_handle_capacity = source_handles, .batch_directory_sync = batch_directories, .verify_finished = verify, .verify_workers = verify_workers, .checkpoint_units = checkpoints, .split_writes = split, .event = if (trace) Events.event else null, .event_context = &events });
        try std.json.Stringify.value(stats, .{}, out);
        try out.writeByte('\n');
        if (stats.errors != 0) return error.CompletedWithErrors;
    } else if (args.len == 3 and std.mem.eql(u8, args[1], "inspect")) {
        var f = try fs.openRead(io, std.Io.Dir.cwd(), args[2]);
        defer f.close(io);
        var opened = try ziff_file.openFile(a, io, f);
        defer opened.deinit();
        try std.json.Stringify.value(.{ .header = opened.header, .files = opened.directory.files, .units = opened.directory.units, .sources = opened.directory.sources, .ops = opened.directory.ops, .removed = opened.directory.removed }, .{}, out);
        try out.writeByte('\n');
    } else if (args.len == 3 and std.mem.eql(u8, args[1], "counts")) {
        var f = try fs.openRead(io, std.Io.Dir.cwd(), args[2]);
        defer f.close(io);
        var opened = try ziff_file.openFile(a, io, f);
        defer opened.deinit();
        try std.json.Stringify.value(.{
            .files = opened.directory.files.len,
            .units = opened.directory.units.len,
            .sources = opened.directory.sources.len,
            .ops = opened.directory.ops.len,
            .removed = opened.directory.removed.len,
        }, .{}, out);
        try out.writeByte('\n');
    } else return error.UsageCreateOrInspect;
}

const Events = struct {
    out: *std.Io.Writer,
    pause: u64,
    fn event(raw: ?*anyopaque, name: []const u8, index: u64) !void {
        const self: *Events = @ptrCast(@alignCast(raw.?));
        try self.out.print("EVENT {d} {s}\n", .{ index, name });
        try self.out.flush();
        if (self.pause == index) {
            if (builtin.target.os.tag == .linux) {
                _ = raise(19);
            } else if (builtin.target.os.tag == .windows) {
                // windows: no SIGSTOP; barrier then TerminateProcess
                // no error unwind/flush for crash-recovery test
                self.out.print("PAUSED {d}\n", .{index}) catch {};
                self.out.flush() catch {};
                while (true) Sleep(60_000);
            } else return error.FaultPauseUnsupported;
        }
    }
};
extern "c" fn raise(signal: c_int) c_int;
extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;

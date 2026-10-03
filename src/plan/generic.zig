// manifest-free comparison; inventory then possible keeps
const std = @import("std");
const tree = @import("../tree.zig");
const planner = @import("../plan.zig");
const fs = @import("../core/fs.zig");
const scan = @import("../core/scan.zig");
const ui = @import("../ui.zig");

pub const Options = struct {
    buffer_bytes: usize = 256 * 1024,
    reader: scan.Reader = .direct,
};

pub fn build(allocator: std.mem.Allocator, io: std.Io, source: *tree.Tree, target: *tree.Tree, progress: ?*ui.Progress, options: Options) !planner.Plan {
    if (options.buffer_bytes == 0 or options.buffer_bytes > scan.max_buffer_bytes) return error.InvalidBufferSize;
    var changed: std.ArrayList(planner.Change) = .empty;
    var added: std.ArrayList(u32) = .empty;
    var removed: std.ArrayList(u32) = .empty;
    errdefer changed.deinit(allocator);
    errdefer added.deinit(allocator);
    errdefer removed.deinit(allocator);
    for (source.files, 0..) |file, i| {
        if (target.findIndex(file.path) == null) try removed.append(allocator, @intCast(i));
    }
    var read_bytes: u64 = 0;
    var pending: std.ArrayList(planner.Change) = .empty;
    defer pending.deinit(std.heap.smp_allocator);
    var pending_bytes: u64 = 0;
    if (progress) |p| {
        p.total_files = target.files.len;
        p.indeterminate = false;
    }
    for (target.files, 0..) |new, i| {
        const target_index: u32 = @intCast(i);
        if (source.findIndex(new.path)) |src| {
            const pair: planner.Change = .{ .source = src, .target = target_index };
            if (source.files[src].size != new.size) {
                try changed.append(allocator, pair);
            } else {
                try pending.append(std.heap.smp_allocator, pair);
                pending_bytes +|= new.size *| 2;
            }
        } else try added.append(allocator, target_index);
        if (progress) |p| try p.finishFile();
    }
    if (progress) |p| try p.startReading(pending.items.len, pending_bytes);
    if (pending.items.len != 0) {
        var src_dir = try std.Io.Dir.cwd().openDir(io, source.root, .{ .access_sub_paths = true });
        defer src_dir.close(io);
        var dst_dir = try std.Io.Dir.cwd().openDir(io, target.root, .{ .access_sub_paths = true });
        defer dst_dir.close(io);
        const scratch = std.heap.smp_allocator;
        const buffer = try scratch.alloc(u8, options.buffer_bytes * 2);
        defer scratch.free(buffer);
        const old_buffer = buffer[0..options.buffer_bytes];
        const new_buffer = buffer[options.buffer_bytes..];
        for (pending.items) |pair| {
            const bytes_before = read_bytes;
            const old = &source.files[pair.source];
            const new = &target.files[pair.target];
            var old_file = try fs.openReadAuthorityBeneath(io, src_dir, old.path);
            defer old_file.close(io);
            var new_file = try fs.openReadAuthorityBeneath(io, dst_dir, new.path);
            defer new_file.close(io);
            if (try old_file.length(io) != old.size or try new_file.length(io) != new.size) return error.FileChangedDuringScan;
            const state = try tree.contentState(allocator, new);
            var offset: u64 = 0;
            var equal = true;
            while (offset < new.size) {
                const want: usize = @intCast(@min(@as(u64, old_buffer.len), new.size - offset));
                const old_count = try options.reader.read(io, old_file, old_buffer[0..want], offset);
                const new_count = try options.reader.read(io, new_file, new_buffer[0..want], offset);
                if (old_count != want or new_count != want) return error.FileChangedDuringScan;
                read_bytes += old_count + new_count;
                if (progress) |p| try p.addBytes(old_count + new_count);
                try state.observe(offset, new_buffer[0..want]);
                if (!std.mem.eql(u8, old_buffer[0..want], new_buffer[0..want])) {
                    equal = false;
                    break;
                }
                offset += want;
            }
            if (try old_file.length(io) != old.size or try new_file.length(io) != new.size) return error.FileChangedDuringScan;
            if (equal) {
                try state.observe(new.size, &.{});
                new.digest = state.digest.?;
                old.digest = new.digest;
            } else {
                new.digest = state.digest;
                try changed.append(allocator, pair);
            }
            if (progress) |p| {
                p.reconcileRead(new.size *| 2, read_bytes - bytes_before);
                try p.finishFile();
            }
        }
    }
    const groups = try planner.findGroups(allocator, source.*, target.*, changed.items, added.items, removed.items);
    errdefer {
        for (groups) |group| {
            allocator.free(group.source);
            allocator.free(group.target);
        }
        allocator.free(groups);
    }
    const changed_items = try changed.toOwnedSlice(allocator);
    errdefer allocator.free(changed_items);
    const added_items = try added.toOwnedSlice(allocator);
    errdefer allocator.free(added_items);
    const removed_items = try removed.toOwnedSlice(allocator);
    return .{
        .changed = changed_items,
        .added = added_items,
        .removed = removed_items,
        .groups = groups,
        .comparison_bytes = read_bytes,
    };
}

test "generic result ownership survives every allocation failure" {
    const Exercise = struct {
        fn run(backing_allocator: std.mem.Allocator, source_root: []const u8, target_root: []const u8) !void {
            var relocating = std.testing.FailingAllocator.init(backing_allocator, .{ .resize_fail_index = 0 });
            const allocator = relocating.allocator();
            var source_files = [_]tree.File{
                .{ .path = "same.bin", .size = 4 },
                .{ .path = "change.bin", .size = 3 },
                .{ .path = "removed.blk", .size = 7 },
            };
            var target_files = [_]tree.File{
                .{ .path = "same.bin", .size = 4 },
                .{ .path = "change.bin", .size = 3 },
                .{ .path = "added.blk", .size = 5 },
            };
            var source: tree.Tree = .{ .root = source_root, .files = &source_files, .map = .empty, .deferred_content = true };
            defer source.map.deinit(allocator);
            var target: tree.Tree = .{ .root = target_root, .files = &target_files, .map = .empty, .deferred_content = true };
            defer target.map.deinit(allocator);
            defer for (target.files) |file| if (file.content_state) |state| allocator.destroy(state);
            for (source.files, 0..) |file, index| try source.map.put(allocator, file.path, @intCast(index));
            for (target.files, 0..) |file, index| try target.map.put(allocator, file.path, @intCast(index));
            const result = try build(allocator, std.testing.io, &source, &target, null, .{ .buffer_bytes = 2 });
            defer {
                for (result.groups) |group| {
                    allocator.free(group.source);
                    allocator.free(group.target);
                }
                allocator.free(result.groups);
                allocator.free(result.changed);
                allocator.free(result.added);
                allocator.free(result.removed);
            }
            try std.testing.expectEqualSlices(planner.Change, &.{.{ .source = 1, .target = 1 }}, result.changed);
            try std.testing.expectEqualSlices(u32, &.{2}, result.added);
            try std.testing.expectEqualSlices(u32, &.{2}, result.removed);
            try std.testing.expectEqual(@as(usize, 1), result.groups.len);
            try std.testing.expectEqualSlices(u32, &.{2}, result.groups[0].source);
            try std.testing.expectEqualSlices(u32, &.{2}, result.groups[0].target);
            try std.testing.expectEqual(@as(u64, 12), result.comparison_bytes);
            try std.testing.expect(target.files[0].digest.?.eql(source.files[0].digest.?));
            try std.testing.expectEqual(@as(u64, 2), target.files[1].content_state.?.seen);
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/same.bin", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/same.bin", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/change.bin", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/change.bin", .data = "new" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/removed.blk", .data = "removed" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/added.blk", .data = "added" });
    const source_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "source" });
    defer allocator.free(source_root);
    const target_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "target" });
    defer allocator.free(target_root);
    try std.testing.checkAllAllocationFailures(allocator, Exercise.run, .{ source_root, target_root });
}

test "generic comparison reads only equal-size same-path candidates and keeps partial Target state" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    const Fixture = struct { name: []const u8, old: ?[]const u8, new: ?[]const u8 };
    const cases = [_]Fixture{
        .{ .name = "same.bin", .old = "abcdefgh", .new = "abcdefgh" },
        .{ .name = "early.bin", .old = "abcdefghijkl", .new = "Xbcdefghijkl" },
        .{ .name = "late.bin", .old = "abcdefghijkl", .new = "abcdefghijkX" },
        .{ .name = "size.bin", .old = "x", .new = "xx" },
        .{ .name = "empty", .old = "", .new = "" },
        .{ .name = "added", .old = null, .new = "added" },
        .{ .name = "removed", .old = "removed", .new = null },
    };
    for (cases) |c| {
        if (c.old) |bytes| try tmp.dir.writeFile(io, .{ .sub_path = try allocator.print("source/{s}", .{c.name}), .data = bytes });
        if (c.new) |bytes| try tmp.dir.writeFile(io, .{ .sub_path = try allocator.print("target/{s}", .{c.name}), .data = bytes });
    }
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var source = try tree.inventory(allocator, io, try std.fs.path.join(allocator, &.{ root, "source" }), null, null);
    var target = try tree.inventory(allocator, io, try std.fs.path.join(allocator, &.{ root, "target" }), null, null);
    for (source.files) |f| try std.testing.expect(f.digest == null and f.md5 == null);
    for (target.files) |f| try std.testing.expect(f.digest == null and f.md5 == null);
    const OrderedReader = struct {
        output: *std.Io.Writer.Allocating,
        bytes: u64 = 0,

        fn read(raw: ?*anyopaque, read_io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const text = self.output.written();
            const metadata_end = std.mem.indexOf(u8, text, "100%  files 6/6") orelse return error.MetadataNotFinished;
            const reading_start = std.mem.indexOf(u8, text, "Reading contents...") orelse return error.ReadingNotStarted;
            if (metadata_end >= reading_start) return error.WrongStageOrder;
            const count = try scan.Reader.direct.read(read_io, file, buffer, offset);
            self.bytes += count;
            return count;
        }
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var reader: OrderedReader = .{ .output = &output };
    var progress: ui.Progress = .{ .io = io, .writer = &output.writer, .label = "Comparing" };
    try progress.start();
    const plan = try build(allocator, io, &source, &target, &progress, .{ .buffer_bytes = 4, .reader = .{ .context = &reader, .read_fn = OrderedReader.read } });
    try progress.finish();
    try std.testing.expectEqual(@as(usize, 3), plan.changed.len);
    try std.testing.expectEqual(@as(usize, 1), plan.added.len);
    try std.testing.expectEqual(@as(usize, 1), plan.removed.len);
    try std.testing.expectEqual(@as(u64, 48), plan.comparison_bytes);
    try std.testing.expectEqual(@as(u64, 48), reader.bytes);
    try std.testing.expectEqual(@as(u64, 48), progress.done_bytes);
    try std.testing.expectEqual(@as(usize, 4), progress.total_files);
    try std.testing.expect(target.find("same.bin").?.digest.?.eql(source.find("same.bin").?.digest.?));
    try std.testing.expect(target.find("empty").?.digest.?.eql(@import("../core/ids.zig").Digest.of("")));
    try std.testing.expectEqual(@as(u64, 4), target.find("early.bin").?.content_state.?.seen);
    try std.testing.expect(target.find("early.bin").?.content_state.?.digest == null);
    try std.testing.expectEqual(@as(u64, 12), target.find("late.bin").?.content_state.?.seen);
    try std.testing.expect(target.find("size.bin").?.content_state == null);
    try std.testing.expect(target.find("added").?.content_state == null);
    try std.testing.expect(source.find("removed").?.digest == null);
}

test "generic skips all content reads when paths or lengths already differ" {
    const Never = struct {
        fn read(_: ?*anyopaque, _: std.Io, _: std.Io.File, _: []u8, _: u64) anyerror!usize {
            return error.UnexpectedContentRead;
        }
    };
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "s", .default_dir);
    try tmp.dir.createDir(io, "t", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "s/old.blk", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/new.blk", .data = "new" });
    try tmp.dir.writeFile(io, .{ .sub_path = "s/size", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/size", .data = "bb" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var source = try tree.inventory(allocator, io, try std.fs.path.join(allocator, &.{ root, "s" }), null, null);
    var target = try tree.inventory(allocator, io, try std.fs.path.join(allocator, &.{ root, "t" }), null, null);
    const plan = try build(allocator, io, &source, &target, null, .{ .reader = .{ .read_fn = Never.read } });
    try std.testing.expectEqual(@as(u64, 0), plan.comparison_bytes);
    try std.testing.expectEqual(@as(usize, 1), plan.groups.len);
    try std.testing.expectEqual(@as(usize, 1), plan.changed.len);
    try std.testing.expectEqual(@as(usize, 1), plan.added.len);
    try std.testing.expectEqual(@as(usize, 1), plan.removed.len);
}

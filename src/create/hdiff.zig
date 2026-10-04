const manifest_mod = @import("../core/manifest.zig");
const std = @import("std");

const activity = @import("../activity.zig");
const archive = @import("../archive.zig");
const writer = @import("../archive/writer.zig");
const zip = @import("../archive/zip.zig");
const delta = @import("../delta.zig");
const engine = @import("../hdiff.zig");
const fs = @import("../core/fs.zig");
const planner = @import("../plan.zig");
const tree = @import("../tree.zig");
const ui = @import("../ui.zig");

pub const CreateOptions = struct {
    source_root: []const u8,
    target_root: []const u8,
    source_metadata: []const manifest_mod.MetadataFile,
    target_metadata: []const manifest_mod.MetadataFile,
    source_tree: tree.Tree,
    target_tree: tree.Tree,
    plan: planner.Plan,
    format: archive.Format,
    compression_levels: archive.CompressionLevels = .{},
    hdiff_format: engine.Format = .w26,
    compression_level: c_int = 5,
    compression: @import("../hdiff/w26/create.zig").Compression = .zstd_if_smaller,
    match_block_size: usize,
    out_path: []const u8,
    tmp_path: []const u8,
};

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: CreateOptions,
    out: *std.Io.Writer,
) !void {
    var creation: ui.Operation = .{ .io = io, .writer = out };
    creation.start("Creating");
    defer creation.stop();
    const spool = try allocator.print("{s}.hdiff-spool", .{options.out_path});
    defer allocator.free(spool);
    try requireMissing(io, spool, options.out_path, out, &creation);

    var bundle = try writer.Builder.init(allocator, io, options.target_root, options.tmp_path, options.format, options.compression_levels);
    errdefer std.Io.Dir.cwd().deleteFile(io, options.tmp_path) catch {};
    defer bundle.deinit();

    var source_tree = options.source_tree;
    var target_tree = options.target_tree;
    var source_dir = try std.Io.Dir.cwd().openDir(io, options.source_root, .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try std.Io.Dir.cwd().openDir(io, options.target_root, .{ .access_sub_paths = true });
    defer target_dir.close(io);

    var hdiff_paths: std.ArrayList([]const u8) = .empty;
    var full_pending: std.ArrayList(u32) = .empty;
    var diff_files: usize = 0;
    var total_bytes: u64 = 0;
    var total_files: usize = 0;
    for (options.target_metadata) |file| {
        total_bytes +|= file.bytes.len;
        total_files += 1;
    }
    for (options.plan.changed) |change| {
        const file = target_tree.files[change.target];
        if (manifest_mod.hasMetadataPath(options.target_metadata, file.path)) continue;
        total_bytes +|= file.size;
        total_files += 1;
        if (pathCollides(target_tree, file.path)) {
            try full_pending.append(allocator, change.target);
        } else {
            diff_files += 1;
        }
    }
    for (options.plan.added) |index| {
        const file = target_tree.files[index];
        if (manifest_mod.hasMetadataPath(options.target_metadata, file.path)) continue;
        total_bytes +|= file.size;
        total_files += 1;
    }
    creation.totals(total_bytes, total_files);

    if (diff_files != 0) {
        {
            var spool_file = try fs.createGuardedOutput(io, .cwd(), spool);
            spool_file.close(io);
        }
        defer std.Io.Dir.cwd().deleteFile(io, spool) catch {};
        var progress: ui.Progress = .{
            .io = io,
            .writer = out,
            .label = "Creating file deltas",
            .operation = &creation,
        };
        for (options.plan.changed) |change| {
            const target_path_file = target_tree.files[change.target];
            if (manifest_mod.hasMetadataPath(options.target_metadata, target_path_file.path)) continue;
            if (pathCollides(target_tree, target_path_file.path)) continue;
            creation.phase("Reading identities", 0, 0);
            // independent second observation during construction/replay
            const source_digest = tree.observeDigest(allocator, io, source_dir, &source_tree, change.source, .{}) catch |err| switch (err) {
                error.Interrupted => return err,
                error.FileChangedDuringConstruction => {
                    try full_pending.append(allocator, change.target);
                    continue;
                },
                else => return err,
            };
            const target_digest = tree.observeDigest(allocator, io, target_dir, &target_tree, change.target, .{}) catch |err| switch (err) {
                error.FileChangedDuringConstruction => return error.TargetChangedDuringCreate,
                else => return err,
            };
            const source_file = source_tree.files[change.source];
            const target_file = target_tree.files[change.target];
            {
                var spool_file = try fs.openReadWrite(io, .cwd(), spool);
                defer spool_file.close(io);
                try spool_file.setLength(io, 0);
            }
            const source_path = try std.fs.path.join(allocator, &.{ options.source_root, source_file.path });
            const target_path = try std.fs.path.join(allocator, &.{ options.target_root, target_file.path });
            var tracker: engine.Progress = .{};
            var result: engine.CreateResult = undefined;
            creation.phase("Creating file delta", 0, 0);
            activity.runPulsedTracked(io, &progress, .{ .create_standard_file_at = .{
                .source = .{ .path = source_path, .size = source_file.size, .digest = source_digest },
                .target = .{ .path = target_path, .size = target_file.size, .digest = target_digest },
                .output = spool,
                .offset = 0,
                .options = .{ .format = options.hdiff_format, .compression_level = options.compression_level, .compression = options.compression, .match_block_size = options.match_block_size },
                .result = &result,
                .tracker = &tracker,
            } }) catch |err| switch (err) {
                error.HDiffCreateFailed, error.SourceChangedDuringCreate => {
                    try full_pending.append(allocator, change.target);
                    continue;
                },
                else => return err,
            };
            if (result.patch_size < target_file.size) {
                const archive_path = try allocator.print("{s}.hdiff", .{target_file.path});
                try bundle.add(.{
                    .path = archive_path,
                    .size = result.patch_size,
                    .expected_digest = result.patch_digest,
                    .data = .{ .external = spool },
                }, null);
                try hdiff_paths.append(allocator, target_file.path);
                creation.complete(target_file.size, 1);
            } else {
                try full_pending.append(allocator, change.target);
            }
        }
    }

    for (options.plan.added) |index| {
        if (!manifest_mod.hasMetadataPath(options.target_metadata, target_tree.files[index].path))
            try full_pending.append(allocator, index);
    }
    var full_bytes: u64 = 0;
    for (full_pending.items) |index| full_bytes +|= target_tree.files[index].size;
    for (options.target_metadata) |file| full_bytes +|= file.bytes.len;
    if (full_pending.items.len + options.target_metadata.len != 0) {
        creation.phase("Archiving", full_bytes, full_pending.items.len + options.target_metadata.len);
        var progress: ui.Progress = .{
            .io = io,
            .writer = out,
            .label = "Full files",
            .operation = &creation,
        };
        for (options.target_metadata) |file| {
            try bundle.add(.{ .path = file.path, .size = file.bytes.len, .data = .{ .bytes = file.bytes } }, &progress);
        }
        for (full_pending.items) |index| {
            const file = target_tree.files[index];
            const expected_digest = if (file.md5 == null)
                tree.observeDigest(allocator, io, target_dir, &target_tree, index, .{}) catch |err| switch (err) {
                    error.FileChangedDuringConstruction => return error.TargetChangedDuringCreate,
                    else => return err,
                }
            else
                null;
            bundle.add(.{
                .path = file.path,
                .size = file.size,
                .expected_digest = expected_digest,
                .expected_md5 = file.md5,
                .data = .file,
            }, &progress) catch |err| switch (err) {
                error.DigestMismatch, error.Md5Mismatch => return error.TargetChangedDuringCreate,
                else => return err,
            };
        }
    }

    const hdiff_list = try listBytes(allocator, hdiff_paths.items);
    const removed = try delta.deletionBytes(
        allocator,
        source_tree,
        options.plan,
        if (options.source_metadata.len != 0) options.source_metadata else null,
        options.target_metadata,
    );
    try bundle.add(.{ .path = "hdifffiles.txt", .size = hdiff_list.len, .data = .{ .bytes = hdiff_list } }, null);
    try bundle.add(.{ .path = "deletefiles.txt", .size = removed.len, .data = .{ .bytes = removed } }, null);
    creation.phase("Finalizing", 0, 0);
    try bundle.finish();
    creation.phase("Publishing", 0, 0);
    try bundle.publish(options.tmp_path, options.out_path);
    creation.finish();
    try ui.printCreated(io, options.out_path, out);
}

fn listBytes(allocator: std.mem.Allocator, paths: []const []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    for (paths) |path| {
        try std.json.Stringify.value(.{ .remoteName = path }, .{}, &out.writer);
        try out.writer.writeByte('\n');
    }
    return out.toOwnedSlice();
}

const HdiffPath = struct { base: []const u8 };

const HdiffPathContext = struct {
    const suffix = ".hdiff";

    pub fn hash(_: @This(), key: HdiffPath) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.base);
        hasher.update(suffix);
        return hasher.final();
    }

    pub fn eql(_: @This(), key: HdiffPath, stored: []const u8) bool {
        return stored.len == key.base.len + suffix.len and
            std.mem.startsWith(u8, stored, key.base) and
            std.mem.eql(u8, stored[key.base.len..], suffix);
    }
};

fn pathCollides(target: tree.Tree, path: []const u8) bool {
    return target.map.getAdapted(HdiffPath{ .base = path }, HdiffPathContext{}) != null;
}

test "all colliding changed files are included as full archive entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/file.bin", .data = "before" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/file.bin", .data = "after!" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/file.bin.hdiff", .data = "unrelated file" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/file.bin.hdiff", .data = "unrelated file" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source_root = try std.fs.path.join(allocator, &.{ root, "source" });
    const target_root = try std.fs.path.join(allocator, &.{ root, "target" });
    var source = try tree.scan(allocator, io, source_root, null, null);
    var target = try tree.scan(allocator, io, target_root, null, null);
    const plan = try planner.build(allocator, io, &source, &target, false, null);
    const out_path = try std.fs.path.join(allocator, &.{ root, "delta.zip" });
    var output: std.Io.Writer.Allocating = .init(allocator);
    try create(allocator, io, .{
        .source_root = source_root,
        .target_root = target_root,
        .source_metadata = &.{},
        .target_metadata = &.{},
        .source_tree = source,
        .target_tree = target,
        .plan = plan,
        .format = .zip_store,
        .match_block_size = engine.standardMatchBlockSize(false),
        .out_path = out_path,
        .tmp_path = try allocator.print("{s}.part", .{out_path}),
    }, &output.writer);
    var file = try std.Io.Dir.cwd().openFile(io, out_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const parsed = try zip.readCentral(allocator, &reader);
    const payload = parsed.find("file.bin") orelse return error.MissingChangedPayload;
    try std.testing.expectEqualStrings("after!", try zip.extractEntryAlloc(allocator, &reader, payload, 1024));
    try std.testing.expect(parsed.find("file.bin.hdiff") == null);
}

test "failed archive creation preserves pre-existing working files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const out_path = try std.fs.path.join(allocator, &.{ root, "delta.zip" });
    const spool = try allocator.print("{s}.hdiff-spool", .{out_path});
    const partial = try allocator.print("{s}.part", .{out_path});
    const empty: tree.Tree = .{ .root = root, .files = &.{}, .map = .empty };
    var output: std.Io.Writer.Allocating = .init(allocator);
    const options: CreateOptions = .{
        .source_root = root,
        .target_root = root,
        .source_metadata = &.{},
        .target_metadata = &.{},
        .source_tree = empty,
        .target_tree = empty,
        .plan = .{ .changed = &.{}, .added = &.{}, .removed = &.{}, .groups = &.{} },
        .format = .zip_store,
        .match_block_size = engine.standardMatchBlockSize(false),
        .out_path = out_path,
        .tmp_path = partial,
    };
    for ([_][]const u8{ spool, partial }) |path| {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "belongs to another operation" });
        if (std.mem.eql(u8, path, spool)) {
            try std.testing.expectError(error.Reported, create(allocator, io, options, &output.writer));
        } else {
            try std.testing.expectError(error.PathAlreadyExists, create(allocator, io, options, &output.writer));
        }
        var existing = try std.Io.Dir.cwd().openFile(io, path, .{ .allow_directory = false });
        defer existing.close(io);
        var bytes: [128]u8 = undefined;
        const read = try fs.readAllAt(io, existing, &bytes, 0);
        try std.testing.expectEqualStrings("belongs to another operation", bytes[0..read]);
        try std.Io.Dir.cwd().deleteFile(io, path);
    }
}

test "both standard compression modes publish an HDIFFW26 entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    var source_bytes: [64 * 1024]u8 = undefined;
    for (&source_bytes, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var target_bytes = source_bytes;
    @memcpy(target_bytes[31 * 1024 .. 31 * 1024 + 32], "standard W26 publication proof!!");
    try tmp.dir.writeFile(io, .{ .sub_path = "source/payload.bin", .data = &source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/payload.bin", .data = &target_bytes });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source_root = try std.fs.path.join(allocator, &.{ root, "source" });
    const target_root = try std.fs.path.join(allocator, &.{ root, "target" });
    var source_tree = try tree.scan(allocator, io, source_root, null, null);
    var target_tree = try tree.scan(allocator, io, target_root, null, null);
    const plan = try planner.build(allocator, io, &source_tree, &target_tree, false, null);
    try std.testing.expectEqual(@as(usize, 1), plan.changed.len);

    const cases = [_]struct { compression: @import("../hdiff/w26/create.zig").Compression, name: []const u8 }{
        .{ .compression = .stored, .name = "stored" },
        .{ .compression = .zstd_if_smaller, .name = "zstd" },
    };
    for (cases) |case| {
        const out_path = try allocator.print("{s}/delta-{s}.zip", .{ root, case.name });
        const tmp_path = try allocator.print("{s}.tmp", .{out_path});
        var output: std.Io.Writer.Allocating = .init(allocator);
        try create(allocator, io, .{
            .source_root = source_root,
            .target_root = target_root,
            .source_metadata = &.{},
            .target_metadata = &.{},
            .source_tree = source_tree,
            .target_tree = target_tree,
            .plan = plan,
            .format = .zip_store,
            .compression = case.compression,
            .match_block_size = engine.standardMatchBlockSize(false),
            .out_path = out_path,
            .tmp_path = tmp_path,
        }, &output.writer);

        const spool_path = try allocator.print("{s}.hdiff-spool", .{out_path});
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, spool_path, .{}));

        var file = try std.Io.Dir.cwd().openFile(io, out_path, .{ .allow_directory = false });
        defer file.close(io);
        var read_buffer: [64 * 1024]u8 = undefined;
        var reader = file.reader(io, &read_buffer);
        const parsed = try zip.readCentral(allocator, &reader);
        const entry = parsed.find("payload.bin.hdiff") orelse return error.MissingExpectedHDiffEntry;
        const patch_bytes = try zip.extractEntryAlloc(allocator, &reader, entry, target_bytes.len);
        try std.testing.expect(patch_bytes.len < target_bytes.len);
        try std.testing.expect(std.mem.startsWith(u8, patch_bytes, "HDIFFW26"));
        try std.testing.expect(!std.mem.startsWith(u8, patch_bytes, "HDIFFSF20&"));
    }
}

fn requireMissing(io: std.Io, path: []const u8, out_path: []const u8, out: *std.Io.Writer, creation: *ui.Operation) !void {
    if (std.Io.Dir.cwd().statFile(io, path, .{})) |_| {
        creation.stop();
        try ui.writeErrorPrefix(out);
        try out.writeAll(" cannot create ");
        try out.writeAll(out_path);
        try out.writeByte('\n');
        try ui.writeField(out, "Path already exists:", path);
        return error.Reported;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }
}

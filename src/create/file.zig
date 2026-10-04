const integrations = @import("../integrations.zig");
const manifest_mod = @import("../core/manifest.zig");
const std = @import("std");
const Thread = std.Thread;

const archive = @import("../archive.zig");
const zip = @import("../archive/zip.zig");
const writer = @import("../archive/writer.zig");
const delta = @import("../delta.zig");
const planner = @import("../plan.zig");
const tree = @import("../tree.zig");
const ui = @import("../ui.zig");

const max_archive_workers: usize = 16;
const archive_batch_bytes: u64 = 256 * 1024 * 1024;

pub const CreateOptions = struct {
    source_identity: ?integrations.Identity = null,
    source_metadata: []const manifest_mod.MetadataFile,
    target_root: []const u8,
    target_metadata: []const manifest_mod.MetadataFile,
    source_tree: tree.Tree,
    target_tree: tree.Tree,
    plan: planner.Plan,
    format: archive.Format,
    compression_levels: archive.CompressionLevels = .{},
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
    var bundle = try writer.Builder.init(allocator, io, options.target_root, options.tmp_path, options.format, options.compression_levels);
    errdefer std.Io.Dir.cwd().deleteFile(io, options.tmp_path) catch {};
    defer bundle.deinit();
    if (options.source_identity) |identity| {
        const bytes = try std.json.Stringify.valueAlloc(allocator, identity, .{});
        defer allocator.free(bytes);
        try bundle.add(.{ .path = delta.source_identity_path, .size = bytes.len, .data = .{ .bytes = bytes } }, null);
    }

    const target_tree = options.target_tree;

    var total_bytes: u64 = 0;
    var total_files: usize = 0;
    for (options.target_metadata) |file| {
        total_bytes +|= file.bytes.len;
        total_files += 1;
    }
    for (options.plan.changed) |change| {
        if (manifest_mod.hasMetadataPath(options.target_metadata, target_tree.files[change.target].path)) continue;
        total_bytes +|= target_tree.files[change.target].size;
        total_files += 1;
    }
    for (options.plan.added) |index| {
        if (manifest_mod.hasMetadataPath(options.target_metadata, target_tree.files[index].path)) continue;
        total_bytes +|= target_tree.files[index].size;
        total_files += 1;
    }

    creation.totals(total_bytes, total_files);
    if (total_files != 0) {
        creation.phase("Archiving", total_bytes, total_files);
        var progress: ui.Progress = .{
            .io = io,
            .writer = out,
            .label = "Full files",
            .operation = &creation,
        };

        var sources: std.ArrayList(archive.Source) = .empty;
        defer sources.deinit(allocator);
        for (options.target_metadata) |file| {
            try sources.append(allocator, .{
                .path = file.path,
                .size = file.bytes.len,
                .data = .{ .bytes = file.bytes },
            });
        }
        for (options.plan.changed) |change| {
            if (manifest_mod.hasMetadataPath(options.target_metadata, target_tree.files[change.target].path)) continue;
            try sources.append(allocator, try physicalTarget(target_tree.files[change.target]));
        }
        for (options.plan.added) |index| {
            if (manifest_mod.hasMetadataPath(options.target_metadata, target_tree.files[index].path)) continue;
            try sources.append(allocator, try physicalTarget(target_tree.files[index]));
        }
        const workers = @max(1, @min(max_archive_workers, Thread.getCpuCount() catch 1));
        bundle.addAll(sources.items, &progress, workers, archive_batch_bytes) catch |err| switch (err) {
            error.Md5Mismatch, error.DigestMismatch => return error.TargetChangedDuringCreate,
            else => return err,
        };
    }
    const removed = try delta.deletionBytes(
        allocator,
        options.source_tree,
        options.plan,
        if (options.source_metadata.len != 0) options.source_metadata else null,
        options.target_metadata,
    );
    try bundle.add(.{
        .path = delta.file_delta_deletion_path,
        .size = removed.len,
        .data = .{ .bytes = removed },
    }, null);
    creation.phase("Finalizing", 0, 0);
    try bundle.finish();
    creation.phase("Publishing", 0, 0);
    try bundle.publish(options.tmp_path, options.out_path);
    creation.finish();
    try ui.printCreated(io, options.out_path, out);
}

fn physicalTarget(file: tree.File) !archive.Source {
    return .{
        .path = file.path,
        .size = file.size,
        .expected_md5 = file.md5 orelse return error.MissingHash,
        .data = .file,
    };
}

test "full-file publication rejects a same-length post-plan byte fault" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const before = "GOOD";
    const after = "EVIL";
    comptime std.debug.assert(before.len == after.len);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "payload.bin", .data = before });

    var expected_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(before, &expected_md5, .{});
    const source = try physicalTarget(.{
        .path = "payload.bin",
        .size = before.len,
        .md5 = expected_md5,
    });

    try tmp.dir.writeFile(io, .{ .sub_path = "payload.bin", .data = after });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const archive_path = try std.fs.path.join(allocator, &.{ root, "fault.zip" });
    defer allocator.free(archive_path);
    var bundle = try writer.Builder.init(allocator, io, root, archive_path, .zip_store, .{});
    defer bundle.deinit();
    try std.testing.expectError(error.Md5Mismatch, bundle.add(source, null));
    try std.testing.expectError(error.DigestMismatch, bundle.finish());
}

test "metadata supplied as bytes is not emitted again from the plan" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "target", .default_dir);

    const metadata_bytes = "authoritative manifest bytes\n";
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const target_root = try std.fs.path.join(allocator, &.{ root, "target" });
    const out_path = try std.fs.path.join(allocator, &.{ root, "delta.zip" });
    const tmp_path = try std.fs.path.join(allocator, &.{ root, "delta.zip.part" });
    var files = [_]tree.File{.{ .path = "pkg_version", .size = metadata_bytes.len }};
    var added = [_]u32{0};
    var source_files = [_]tree.File{.{ .path = "obsolete.bin", .size = 1 }};
    var removed = [_]u32{0};
    const metadata = [_]manifest_mod.MetadataFile{.{ .path = "pkg_version", .bytes = metadata_bytes }};
    var output: std.Io.Writer.Allocating = .init(allocator);

    try create(allocator, io, .{
        .source_metadata = &.{},
        .target_root = target_root,
        .target_metadata = &metadata,
        .source_tree = .{ .root = target_root, .files = &source_files, .map = .empty },
        .target_tree = .{ .root = target_root, .files = &files, .map = .empty },
        .plan = .{ .changed = &.{}, .added = &added, .removed = &removed, .groups = &.{} },
        .format = .zip_store,
        .out_path = out_path,
        .tmp_path = tmp_path,
    }, &output.writer);

    var file = try std.Io.Dir.cwd().openFile(io, out_path, .{ .allow_directory = false });
    defer file.close(io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    const parsed = try zip.readCentral(allocator, &reader);
    try std.testing.expectEqual(@as(usize, 2), parsed.entries.len);
    const metadata_entry = parsed.find("pkg_version") orelse return error.TestUnexpectedResult;
    const deletion_entry = parsed.find(delta.file_delta_deletion_path) orelse return error.TestUnexpectedResult;
    const actual = try zip.extractEntryAlloc(allocator, &reader, metadata_entry, metadata_bytes.len);
    try std.testing.expectEqualStrings(metadata_bytes, actual);
    const deletion_bytes = try zip.extractEntryAlloc(allocator, &reader, deletion_entry, 1024);
    try std.testing.expectEqualStrings("obsolete.bin\n", deletion_bytes);
}

test "full-file creation preserves an existing archive temporary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const existing_path = try std.fs.path.join(allocator, &.{ root, "delta.part" });
    const expected = "already present";
    try tmp.dir.writeFile(io, .{ .sub_path = "delta.part", .data = expected });
    const empty: tree.Tree = .{ .root = root, .files = &.{}, .map = .empty };
    var output: std.Io.Writer.Allocating = .init(allocator);
    for ([_]archive.Format{ .zip_store, .tar_zstd }) |format| {
        try std.testing.expectError(error.PathAlreadyExists, create(allocator, io, .{
            .source_metadata = &.{},
            .target_root = root,
            .target_metadata = &.{},
            .source_tree = empty,
            .target_tree = empty,
            .plan = .{ .changed = &.{}, .added = &.{}, .removed = &.{}, .groups = &.{} },
            .format = format,
            .out_path = try std.fs.path.join(allocator, &.{ root, "delta" }),
            .tmp_path = existing_path,
        }, &output.writer));
        var existing = try tmp.dir.openFile(io, "delta.part", .{ .allow_directory = false });
        defer existing.close(io);
        var bytes: [64]u8 = undefined;
        const count = try @import("../core/fs.zig").readAllAt(io, existing, &bytes, 0);
        try std.testing.expectEqualStrings(expected, bytes[0..count]);
    }
}

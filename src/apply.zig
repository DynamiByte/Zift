const std = @import("std");

const cli = @import("cli.zig");
const classify = @import("format/detect.zig");
const archive_delta = @import("apply/archive.zig");
const inplace = @import("apply/inplace.zig");
const ziff_file = @import("format/ziff_file.zig");
const fs = @import("core/fs.zig");
const profile = @import("profile.zig");
const integrity_run = @import("apply/integrity_run.zig");
const ziff = @import("format/ziff.zig");
const integrations = @import("integrations.zig");
const storage = @import("storage.zig");
const ui = @import("ui.zig");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_md5: bool,
    force: bool,
    out: *std.Io.Writer,
) !void {
    const parent_path = std.fs.path.dirname(delta_path) orelse ".";
    const container_path = std.fs.path.basename(delta_path);
    var container_dir = std.Io.Dir.cwd().openDir(io, parent_path, .{}) catch |err| {
        return reportDeltaReadError(out, delta_path, err);
    };
    defer container_dir.close(io);

    const kind = classify.classify(io, container_dir, container_path) catch |err| {
        return reportDeltaReadError(out, delta_path, err);
    };
    switch (kind) {
        .archive => {
            var integrity: integrity_run.Counters = .{};
            archive_delta.applyTrackedFromDir(
                allocator,
                io,
                container_dir,
                container_path,
                delta_path,
                directory_path,
                assume_yes,
                verify_md5,
                force,
                out,
                &integrity,
            ) catch |err| {
                const snapshot = integrity.snapshot();
                reportIntegrityRun(out, snapshot) catch return err;
                if (err == error.CompletedWithErrors) try ui.complete(out, true);
                return err;
            };
            try reportIntegrityRun(out, integrity.snapshot());
            try out.writeByte('\n');
            return ui.complete(out, false);
        },
        .ziff => return applyZiff(
            allocator,
            io,
            container_dir,
            container_path,
            delta_path,
            directory_path,
            assume_yes,
            verify_md5,
            force,
            out,
        ),
    }
}

const ZiffConfirmation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    delta_path: []const u8,
    directory_path: []const u8,
    header: *const ziff.Header,
    assume_yes: bool,
    verify_finished: bool,
    progress: *ui.Operation,
    delta_bytes: u64,

    fn issue(raw_context: ?*anyopaque, problem: inplace.Issue) void {
        const context: *ZiffConfirmation = @ptrCast(@alignCast(raw_context.?));
        context.progress.fileError(problem.action, problem.path, problem.err) catch {};
    }

    fn callback(raw_context: ?*anyopaque, preview: inplace.Preview) !bool {
        const context: *ZiffConfirmation = @ptrCast(@alignCast(raw_context.?));
        context.progress.finish();
        const header = context.header;
        try ui.writeHeading(context.out, "Apply delta:");
        try context.out.writeByte('\n');
        if (integrations.fromIntegrationId(header.software_id)) |software| {
            try ui.writeField(context.out, "    Software:", integrations.displayName(software));
        }
        try ui.writeDeltaField(context.out, if (header.source_identity.len == 0) "generic Source" else header.source_identity, if (header.target_identity.len == 0) "generic Target" else header.target_identity);
        try ui.writeField(context.out, "    Method:", "Ziff");
        try ui.writeField(context.out, "    File:", context.delta_path);
        try ui.writeField(context.out, "    Directory:", context.directory_path);
        try ui.writeField(context.out, "    Verification:", if (context.verify_finished) "Hashes" else "Sizes");
        var size_buffer: [64]u8 = undefined;
        try context.out.writeByte('\n');
        try ui.writeField(context.out, "Delta size:", try ui.bytes(&size_buffer, context.delta_bytes));
        try ui.writeField(context.out, "Target size:", try ui.bytes(&size_buffer, header.target_bytes));
        try ui.writeField(context.out, "Peak extra space (estimated):", try ui.bytes(&size_buffer, preview.estimated_extra_bytes));
        if (preview.available_bytes) |available| {
            try ui.writeField(context.out, "Space available:", try ui.bytes(&size_buffer, available));
        }
        if (preview.forced) try ui.writeWarningLine(context.out, "Low disk space; continuing with -f.");
        if (preview.already_completed) try context.out.writeAll("Already applied.\n") else if (preview.resuming) try context.out.writeAll("Resuming interrupted apply.\n");
        const confirmed = try cli.confirm(context.allocator, context.io, context.out, context.assume_yes);
        if (confirmed) {
            context.progress.start("Applying");
        }
        return confirmed;
    }
};

fn applyZiff(
    allocator: std.mem.Allocator,
    io: std.Io,
    container_dir: std.Io.Dir,
    container_path: []const u8,
    delta_path: []const u8,
    directory_path: []const u8,
    assume_yes: bool,
    verify_finished: bool,
    force_space: bool,
    out: *std.Io.Writer,
) !void {
    var progress: ui.Operation = .{ .io = io, .writer = out };
    progress.start("Checking");
    defer progress.stop();
    var install_dir = std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true, .iterate = true }) catch |err| {
        progress.stop();
        return reportZiffApplyError(out, delta_path, directory_path, err);
    };
    defer install_dir.close(io);
    var package = fs.openReadContentAuthority(io, container_dir, container_path) catch |err| {
        progress.stop();
        return reportZiffApplyError(out, delta_path, directory_path, err);
    };
    defer package.close(io);
    var opened = ziff_file.openFile(allocator, io, package) catch |err| {
        progress.stop();
        return reportZiffApplyError(out, delta_path, directory_path, err);
    };
    defer opened.deinit();
    var confirmation: ZiffConfirmation = .{
        .allocator = allocator,
        .io = io,
        .out = out,
        .delta_path = delta_path,
        .directory_path = directory_path,
        .header = &opened.header,
        .assume_yes = assume_yes,
        .verify_finished = verify_finished,
        .progress = &progress,
        .delta_bytes = opened.file_size,
    };
    var span = profile.begin(io, "apply: byte-in-place");
    defer span.end(io);
    const stats = inplace.run(allocator, io, package, &opened, install_dir, .{
        .issue = ZiffConfirmation.issue,
        .issue_context = &confirmation,
        .verify_finished = verify_finished,
        .available_space = storage.available(io, directory_path) catch null,
        .force_space = force_space,
        .confirm = ZiffConfirmation.callback,
        .confirm_context = &confirmation,
        .progress = &progress,
    }) catch |err| {
        progress.stop();
        return reportZiffApplyError(out, delta_path, directory_path, err);
    };
    if (stats.errors == 0) progress.finish() else progress.stop();
    try reportZiffSuccess(out, stats);
}

fn reportZiffSuccess(out: *std.Io.Writer, stats: inplace.Stats) !void {
    try out.writeByte('\n');
    try ui.writeCount(out, "Files reconstructed:", stats.units_decoded);
    if (stats.resumed) try ui.writeCount(out, "Finished files recovered:", stats.units_recovered);
    try ui.writeCount(out, "Finished files checked:", stats.size_checks);
    try ui.writeCount(out, "Old files removed:", stats.old_files_removed);
    var buffer: [64]u8 = undefined;
    try ui.writeField(out, "Content written:", try ui.bytes(&buffer, stats.output_bytes));
    try ui.writeField(out, "Old bytes preserved:", try ui.bytes(&buffer, stats.preserved_bytes));
    if (stats.final_hash_bytes != 0) try ui.writeField(out, "Finished content hashed:", try ui.bytes(&buffer, stats.final_hash_bytes));
    try out.writeByte('\n');
    try ui.complete(out, stats.errors != 0);
}

fn reportIntegrityRun(out: *std.Io.Writer, snapshot: integrity_run.Snapshot) !void {
    if (!snapshot.hasEvents()) return;
    const Result = struct { label: []const u8, count: usize };
    const sections = [_]struct { label: []const u8, total: usize, results: []const Result }{
        .{ .label = "Reconstruction retries", .total = snapshot.reconstruction.started, .results = &.{
            .{ .label = "succeeded", .count = snapshot.reconstruction.succeeded },
            .{ .label = "failed", .count = snapshot.reconstruction.hardFailures() },
        } },
        .{ .label = "Verification rereads", .total = snapshot.verification.total(), .results = &.{
            .{ .label = "matched", .count = snapshot.verification.repaired },
            .{ .label = "mismatched", .count = snapshot.verification.confirmed_mismatch },
            .{ .label = "inconsistent", .count = snapshot.verification.inconsistent_mismatch },
            .{ .label = "read failures", .count = snapshot.verification.failed },
        } },
        .{ .label = "Inconsistent read retries", .total = snapshot.consistency.total(), .results = &.{
            .{ .label = "resolved", .count = snapshot.consistency.resolved },
            .{ .label = "unresolved", .count = snapshot.consistency.unresolved },
            .{ .label = "read failures", .count = snapshot.consistency.failed },
        } },
    };
    for (sections) |section| {
        if (section.total == 0) continue;
        try out.print("{s}: {d}", .{ section.label, section.total });
        var first = true;
        for (section.results) |result| {
            if (result.count == 0) continue;
            try out.writeAll(if (first) " (" else ", ");
            try out.print("{d} {s}", .{ result.count, result.label });
            first = false;
        }
        if (!first) try out.writeByte(')');
        try out.writeByte('\n');
    }
}

fn reportZiffApplyError(
    out: *std.Io.Writer,
    delta_path: []const u8,
    directory_path: []const u8,
    err: anyerror,
) anyerror {
    switch (err) {
        error.ApplyNotConfirmed => return error.Aborted,
        error.Aborted, error.Interrupted, error.InputRequired, error.Reported, error.OutOfMemory => return err,
        else => {},
    }

    ui.writeErrorPrefix(out) catch return err;
    switch (err) {
        error.UnsupportedSchema, error.UnsupportedRequiredFeature => out.writeAll(" unsupported Ziff format; try updating Zift\n") catch return err,
        error.InsufficientApplySpace => out.writeAll(" not enough disk space to apply Ziff delta\nUse -f to apply anyway.\n") catch return err,
        error.SourcePreflightFailed => out.writeAll(" source does not match this delta\n") catch return err,
        error.InstallChangedDuringConfirmation => out.writeAll(" source changed during confirmation\n") catch return err,
        else => out.writeAll(" cannot apply Ziff delta\n") catch return err,
    }
    ui.writeField(out, "File:", delta_path) catch return err;
    ui.writeField(out, "Directory:", directory_path) catch return err;
    ui.writeField(out, "Reason:", @errorName(err)) catch return err;
    return error.Reported;
}

fn reportDeltaReadError(out: *std.Io.Writer, delta_path: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.FileNotFound, error.AccessDenied, error.NotDir, error.IsDir, error.ContainerChangedDuringClassification => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" cannot read delta file\n") catch return err;
            ui.writeField(out, "File:", delta_path) catch return err;
            return error.Reported;
        },
        else => return err,
    }
}

test "Ziff dispatch uses byte-in-place and final size checks" {
    const ids = @import("core/ids.zig");
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "install", .default_dir);

    const bytes = "Ziff";
    var files = [_]ziff.FileEntry{.{
        .path = "target.bin",
        .size = bytes.len,
        .digest = ids.Digest.of(bytes),
    }};
    var ops = [_]ziff.Op{.{ .kind = .full, .target = 0, .arg = 0 }};
    var units = [_]ziff.Unit{.{
        .kind = .raw,
        .payload_offset = 0,
        .payload_len = bytes.len,
        .target = 0,
        .source_first = 0,
        .source_count = 0,
    }};
    const header: ziff.Header = .{
        .required_features = 0,
        .source_identity = "source",
        .target_identity = "target",
        .source_fingerprint = ziff.logicalFingerprint(&[_]ziff.FileEntry{}),
        .target_fingerprint = ziff.logicalFingerprint(&files),
        .target_bytes = bytes.len,
        .unit_count = 1,
    };
    const directory: ziff.Directory = .{
        .files = &files,
        .ops = &ops,
        .units = &units,
        .sources = &.{},
        .removed = &.{},
    };
    const payload_start = try ziff_file.begin(allocator, io, tmp.dir, "update.ziff", header);
    units[0].payload_offset = payload_start;
    var delta_file = try tmp.dir.openFile(io, "update.ziff", .{ .mode = .read_write, .allow_directory = false });
    try delta_file.writePositionalAll(io, bytes, payload_start);
    delta_file.close(io);
    try ziff_file.finish(allocator, io, tmp.dir, "update.ziff", directory);

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const delta_path = try std.fs.path.join(allocator, &.{ root, "update.ziff" });
    defer allocator.free(delta_path);
    const install_path = try std.fs.path.join(allocator, &.{ root, "install" });
    defer allocator.free(install_path);
    var output_bytes: [4096]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_bytes);
    try run(allocator, io, delta_path, install_path, true, false, false, &output);

    var install = try tmp.dir.openDir(io, "install", .{});
    defer install.close(io);
    const actual = try install.readFileAlloc(io, "target.bin", allocator, .limited(1024));
    defer allocator.free(actual);
    try std.testing.expectEqualStrings(bytes, actual);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Ziff") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Mode:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Verification: Sizes") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Verification rereads:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Files reconstructed:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Complete!") != null);
}

test "external archive integrity renderer exposes retry gaps and every reread outcome" {
    var output_bytes: [4096]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_bytes);
    const snapshot: integrity_run.Snapshot = .{
        .reconstruction = .{ .started = 101, .succeeded = 100 },
        .verification = .{
            .repaired = 303,
            .confirmed_mismatch = 404,
            .inconsistent_mismatch = 505,
            .failed = 606,
        },
        .consistency = .{
            .resolved = 707,
            .unresolved = 808,
            .failed = 909,
        },
    };
    try reportIntegrityRun(&output, snapshot);
    try std.testing.expectEqualStrings(
        "Reconstruction retries: 101 (100 succeeded, 1 failed)\n" ++
            "Verification rereads: 1818 (303 matched, 404 mismatched, 505 inconsistent, 606 read failures)\n" ++
            "Inconsistent read retries: 2424 (707 resolved, 808 unresolved, 909 read failures)\n",
        output.buffered(),
    );
    output = .fixed(&output_bytes);
    try reportIntegrityRun(&output, .{});
    try std.testing.expectEqualStrings("", output.buffered());
    try reportIntegrityRun(&output, .{ .verification = .{ .repaired = 1 } });
    try std.testing.expectEqualStrings("Verification rereads: 1 (1 matched)\n", output.buffered());
}

test "malformed recognized Ziff is rejected by the Ziff reader" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "install", .default_dir);

    var malformed: [ziff.preamble_size]u8 = @splat(0);
    @memcpy(malformed[0..4], ziff.magic);
    std.mem.writeInt(u16, malformed[4..6], ziff.schema, .little);
    std.mem.writeInt(u16, malformed[6..8], 0x8000, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "malformed.ziff", .data = &malformed });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const delta_path = try std.fs.path.join(allocator, &.{ root, "malformed.ziff" });
    defer allocator.free(delta_path);
    const install_path = try std.fs.path.join(allocator, &.{ root, "install" });
    defer allocator.free(install_path);
    var output_bytes: [2048]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_bytes);
    try std.testing.expectError(
        error.Reported,
        run(allocator, io, delta_path, install_path, true, false, false, &output),
    );
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Ziff") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "UnsupportedContainerFlags") != null);

    std.mem.writeInt(u16, malformed[4..6], ziff.schema + 1, .little);
    std.mem.writeInt(u16, malformed[6..8], 0, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "malformed.ziff", .data = &malformed });
    output = .fixed(&output_bytes);
    try std.testing.expectError(error.Reported, run(allocator, io, delta_path, install_path, true, false, false, &output));
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "try updating Zift") != null);

    var install = try tmp.dir.openDir(io, "install", .{});
    defer install.close(io);
    _ = install.statFile(io, ".zift-work", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |other| return other,
    };
    return error.UnexpectedWorkDirectory;
}

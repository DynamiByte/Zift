const manifest_mod = @import("core/manifest.zig");
const std = @import("std");

const ArchiveFormat = @import("archive.zig").Format;
const cli = @import("cli.zig");
const ui = @import("ui.zig");
const delta = @import("delta.zig");
const integrations = @import("integrations.zig");
const file_delta = @import("create/file.zig");
const hdiff = @import("hdiff.zig");
const hdiff_delta = @import("create/hdiff.zig");
const Method = delta.Method;
const planner = @import("plan.zig");
const generic = @import("plan/generic.zig");
const tree = @import("tree.zig");
const production_options = @import("production_options.zig");
const profile = @import("profile.zig");
const ziff_create = @import("create/ziff.zig");
const ziff_plan = @import("create/ziff_plan.zig");
const verify = @import("verify.zig");

const VersionInfo = integrations.Version;

const Side = struct {
    path: []const u8,
    software: ?integrations.Detected,
    version_info: ?VersionInfo,
    state: ?integrations.State,
    fn metadata(self: Side) []const manifest_mod.MetadataFile {
        return if (self.state) |state| state.metadata else &.{};
    }
};

const Comparison = struct {
    source_tree: tree.Tree,
    target_tree: tree.Tree,
    plan: planner.Plan,
    failures: []verify.Failure = &.{},
    source_failures: []verify.Failure = &.{},
};

const Activation = struct {
    software: ?integrations.Software,
    source: Side,
    target: Side,
};

test "source mismatches adopt actual content without validating untouched hashes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/audio.pck", .data = "old audio" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/keep", .data = "keep" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/audio.pck", .data = "new audio!!!" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/keep", .data = "keep" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/missing.exe", .data = "x" });
    const metadata = "{\"remoteName\":\"audio.pck\",\"fileSize\":12,\"md5\":\"00000000000000000000000000000000\"}\r\n" ++
        "{\"remoteName\":\"keep\",\"fileSize\":4,\"md5\":\"00000000000000000000000000000000\"}\r\n" ++
        "{\"remoteName\":\"missing.exe\",\"fileSize\":1,\"md5\":\"00000000000000000000000000000000\"}\r\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "source/pkg_version", .data = metadata });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/pkg_version", .data = metadata });
    var expected = [_]manifest_mod.File{
        .{ .path = "audio.pck", .size = 12, .md5 = @splat(0) },
        .{ .path = "keep", .size = 4, .md5 = @splat(0) },
        .{ .path = "missing.exe", .size = 1, .md5 = @splat(0) },
    };
    var state: integrations.State = .{
        .expected = .{ .entries = &expected, .map = .empty },
        .metadata = &.{.{ .path = "pkg_version", .bytes = metadata }},
        .manifest_format = .pkg_version_ndjson,
        .manifest_schema = .hoyo_pkg_version_md5,
        .digest_authority = .authoritative,
        .managed_set_complete = true,
    };
    for (expected, 0..) |entry, index| try state.expected.map.put(allocator, entry.path, @intCast(index));
    const source: Side = .{
        .path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "source" }),
        .software = .{ .software = .zzz },
        .version_info = null,
        .state = state,
    };
    var target = source;
    target.path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "target" });
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var comparison = try compareSides(allocator, io, source, &target, .zzz, &output.writer);
    try std.testing.expectEqual(@as(usize, 2), comparison.source_failures.len);
    try std.testing.expectEqual(@as(usize, 0), comparison.failures.len);
    try std.testing.expectEqual(@as(u64, 9), comparison.plan.comparison_bytes);
    try std.testing.expectEqual(@as(usize, 1), comparison.plan.changed.len);
    try std.testing.expectEqual(@as(usize, 1), comparison.plan.added.len);
    try std.testing.expect(comparison.source_tree.find("missing.exe") == null);
    const actual = comparison.source_tree.find("audio.pck").?;
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("old audio", &md5, .{});
    try std.testing.expectEqualSlices(u8, &md5, &actual.md5.?);
    try std.testing.expectEqualSlices(u8, &md5, &actual.claim.?.value.bytes);
    try std.testing.expect(comparison.source_tree.find("keep").?.digest == null);
    try std.testing.expectEqual(@as(u64, 12), source.state.?.expected.find("audio.pck").?.size);
    try std.testing.expect(source.state.?.expected.find("missing.exe") != null);
    var prepared = try ziff_plan.build(allocator, io, &comparison.source_tree, &comparison.target_tree, comparison.plan, .zzz, "source", "target");
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 3), prepared.source_manifest.len);
    try std.testing.expectEqual(@as(u64, 9), prepared.directory.sources[0].length);
    for (prepared.source_manifest) |entry| {
        if (std.mem.eql(u8, entry.path, "audio.pck")) {
            try std.testing.expectEqual(@as(u64, 9), entry.size);
            try std.testing.expect(entry.verification.eql(.md5(md5)));
        } else if (std.mem.eql(u8, entry.path, "pkg_version")) {
            try std.testing.expectEqual(@as(u64, metadata.len), entry.size);
            try std.testing.expect(entry.digest.eql(@import("core/ids.zig").Digest.of(metadata)));
        }
    }
    try std.testing.expectEqualStrings(metadata, comparison.source_tree.find("pkg_version").?.bytes.?);
    const source_metadata = try @import("core/fs.zig").readFileAlloc(allocator, io, tmp.dir, "source/pkg_version", 4096);
    try std.testing.expectEqualStrings(metadata, source_metadata);
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    target_path: []const u8,
    explicit_out: ?[]const u8,
    choices: cli.CreateChoices,
    assume_yes: bool,
    automatic: bool,
    minimum_memory: bool,
    out: *std.Io.Writer,
) !void {
    var source = inspectSide(io, source_path) catch |err| return reportScanError(out, "Source", source_path, err);
    var target = inspectSide(io, target_path) catch |err| return reportScanError(out, "Target", target_path, err);

    const detected = commonSoftware(source.software, target.software);
    const inconsistent_software = (source.software == null) != (target.software == null) or
        (source.software != null and target.software != null and source.software.?.software != target.software.?.software);
    var automatic_enabled = automatic and !inconsistent_software;
    const selected_software = try selectIntegration(allocator, io, out, detected, automatic_enabled, choices.integration);
    var software: ?integrations.Software = null;
    if (selected_software) |value| {
        try out.writeAll("Reading source and target manifests...\n");
        try out.flush();
        const source_view = integrations.inspectInstall(allocator, io, value, source.path) catch |err|
            return integrations.reportExpectedError(out, value, source.path, err);
        const target_view = integrations.inspectInstall(allocator, io, value, target.path) catch |err|
            return integrations.reportExpectedError(out, value, target.path, err);
        const activation = activateOrGeneric(source, target, value, source_view, target_view);
        software = activation.software;
        source = activation.source;
        target = activation.target;
        if (software != null and automatic_enabled and
            ((source.version_info == null and choices.source_version == null) or
                (target.version_info == null and choices.target_version == null)))
            automatic_enabled = false;
    } else {
        source = withoutIntegration(source);
        target = withoutIntegration(target);
    }
    var selected_method = choices.method;
    if (choices.format != null) {
        const method = selected_method orelse cli.MethodChoice.defaults(if (automatic_enabled)
            .ziff
        else
            try cli.promptMethod(allocator, io, out, .ziff));
        if (std.meta.activeTag(method) == .ziff) {
            try cli.printProblem(out, .format_not_applicable);
            return error.Reported;
        }
        selected_method = method;
    }
    var comparison = try compareSides(allocator, io, source, &target, software, out);
    defer allocator.free(comparison.failures);
    defer allocator.free(comparison.source_failures);
    var had_errors = false;
    const source_issues = comparison.source_failures.len != 0;
    const target_issues = comparison.failures.len != 0;
    if (source_issues or target_issues) {
        const problems = [_]struct { heading: []const u8, path: []const u8, failures: []verify.Failure }{
            .{ .heading = "Source issues:", .path = source.path, .failures = comparison.source_failures },
            .{ .heading = "Target issues:", .path = target.path, .failures = comparison.failures },
        };
        try out.writeByte('\n');
        for (problems) |problem| {
            if (problem.failures.len == 0) continue;
            try ui.writeHeading(out, problem.heading);
            try out.writeByte('\n');
            try ui.writeField(out, "Directory:", problem.path);
            for (problem.failures) |failure| try verify.printFailure(out, failure);
            try out.writeByte('\n');
        }
        if (source_issues) try ui.writeWarningLine(out, "Delta may not apply to a clean source installation.");
        if (target_issues) try ui.writeWarningLine(out, "Unavailable target files will be omitted.");
        try out.writeByte('\n');
        const continue_anyway = choices.continue_on_errors orelse
            try cli.promptYesNo(allocator, io, out, "Create delta anyway?", false);
        if (!continue_anyway) return error.Aborted;
        const can_correct_target = target_issues and target.state.?.manifest_format == .pkg_version_ndjson;
        if (target_issues and !can_correct_target and choices.correct_target_manifest == true) {
            try ui.writeErrorPrefix(out);
            try out.writeAll(" target manifest correction is unavailable\n");
            return error.Reported;
        }
        const correct_target = can_correct_target and
            (choices.correct_target_manifest orelse
                try cli.promptYesNo(allocator, io, out, "Correct target pkg_version in the delta? (only reported entries)", false));
        if (correct_target) {
            const pkg_version = @import("integrations/pkg_version.zig");
            target.state.?.metadata = try pkg_version.correctedMetadata(allocator, target.metadata(), target.state.?.expected);
        }
        had_errors = source_issues or (target_issues and !correct_target);
    }
    if (canUseExpectedFastPath(source) and canUseExpectedFastPath(target)) try finishMetadataComparison(allocator, target.metadata(), &comparison);
    try out.writeByte('\n');
    const plan = comparison.plan;
    if (plan.changed.len == 0 and plan.added.len == 0 and plan.removed.len == 0) {
        try ui.writeSuccessLine(out, "No differences found.");
        if (had_errors) try ui.complete(out, true);
        return;
    }

    const prefix_default = if (software) |value| integrations.defaultPrefix(value) else null;
    const prefix: ?[]const u8 = if (choices.prefix) |value|
        if (std.ascii.eqlIgnoreCase(value, "n")) null else value
    else if (automatic_enabled)
        prefix_default
    else
        try cli.promptPrefix(allocator, io, out, prefix_default);
    if (prefix) |value| try requireNamePart(out, "Prefix", value);

    const source_default = nameVersion(source.version_info);
    const target_default = nameVersion(target.version_info);
    const source_name = choices.source_version orelse if (automatic_enabled and source_default != null)
        try allocator.dupe(u8, source_default.?)
    else
        try cli.promptVersion(allocator, io, out, "Source version", source_default);
    const target_name = choices.target_version orelse if (automatic_enabled and target_default != null)
        try allocator.dupe(u8, target_default.?)
    else
        try cli.promptVersion(allocator, io, out, "Target version", target_default);
    try requireNamePart(out, "Source version", source_name);
    try requireNamePart(out, "Target version", target_name);

    const source_index_version = try resolvedVersion(allocator, source.version_info, source_name);
    const target_index_version = try resolvedVersion(allocator, target.version_info, target_name);

    const method_default: Method = .ziff;
    const method_choice = selected_method orelse cli.MethodChoice.defaults(if (automatic_enabled)
        method_default
    else
        try cli.promptMethod(allocator, io, out, method_default));
    const method = std.meta.activeTag(method_choice);
    const format_choice: ?cli.FormatChoice = switch (method) {
        .file_delta => choices.format orelse cli.FormatChoice.defaults(if (automatic_enabled) .zip_deflate else try cli.promptFormat(allocator, io, out, .zip_deflate)),
        .hdiff => choices.format orelse cli.FormatChoice.defaults(if (automatic_enabled) .tar_zstd else try cli.promptFormat(allocator, io, out, .tar_zstd)),
        .ziff => null,
    };
    const format: ?ArchiveFormat = if (format_choice) |value| std.meta.activeTag(value) else null;
    const hdiff_format = switch (method_choice) {
        .hdiff => |value| value,
        else => .w26,
    };
    const compression_levels: @import("archive.zig").CompressionLevels = if (format_choice) |value| value.compressionLevels() else .{};

    var source_tree = comparison.source_tree;
    var target_tree = comparison.target_tree;
    if (method != .ziff) {
        if (method == .file_delta) {
            var target_dir = try std.Io.Dir.cwd().openDir(io, target_tree.root, .{ .access_sub_paths = true });
            defer target_dir.close(io);
            for (plan.changed) |change| {
                if (!manifest_mod.hasMetadataPath(target.metadata(), target_tree.files[change.target].path))
                    _ = try tree.ensureHash(io, target_dir, &target_tree, change.target, null);
            }
            for (plan.added) |index| {
                if (!manifest_mod.hasMetadataPath(target.metadata(), target_tree.files[index].path))
                    _ = try tree.ensureHash(io, target_dir, &target_tree, index, null);
            }
        }
        try validateArchivePaths(method, target_tree, plan, out);
    }

    const suffix = if (format) |f| switch (method) {
        .hdiff => try allocator.print("-hdiff{s}", .{f.extension()}),
        else => f.extension(),
    } else ".ziff";
    const out_path = explicit_out orelse try outputName(allocator, prefix, source_name, target_name, suffix);
    const tmp_path = try allocator.print("{s}.part", .{out_path});

    try printCreateSummary(out, software, source_index_version, target_index_version, method, hdiff_format, source.path, target.path, out_path, plan, source_tree, target_tree);

    try requireMissing(io, out_path, out_path, out);
    if (method != .ziff) try requireMissing(io, tmp_path, out_path, out);
    if (!try cli.confirm(allocator, io, out, assume_yes)) return error.Aborted;
    (switch (method) {
        .file_delta => file_delta.create(allocator, io, .{
            .source_metadata = source.metadata(),
            .target_root = target.path,
            .target_metadata = target.metadata(),
            .source_tree = source_tree,
            .target_tree = target_tree,
            .plan = plan,
            .format = format.?,
            .compression_levels = compression_levels,
            .out_path = out_path,
            .tmp_path = tmp_path,
        }, out),
        .hdiff => hdiff_delta.create(allocator, io, .{
            .source_root = source.path,
            .target_root = target.path,
            .source_metadata = source.metadata(),
            .target_metadata = target.metadata(),
            .source_tree = source_tree,
            .target_tree = target_tree,
            .plan = plan,
            .format = format.?,
            .compression_levels = compression_levels,
            .hdiff_format = hdiff_format,
            .match_block_size = hdiff.standardMatchBlockSize(minimum_memory),
            .out_path = out_path,
            .tmp_path = tmp_path,
        }, out),
        .ziff => ziff: {
            var progress: ui.Operation = .{ .io = io, .writer = out };
            progress.start("Creating");
            defer progress.stop();
            progress.phase(if (source_tree.deferred_content and target_tree.deferred_content) "Preparing" else "Reading identities", 0, 0);
            var plan_span = profile.begin(io, "ziff_plan.build (observation)");
            var prepared = ziff_plan.build(
                allocator,
                io,
                &source_tree,
                &target_tree,
                plan,
                software,
                source_index_version,
                target_index_version,
            ) catch |err| {
                progress.stop();
                return reportCreateError(out, source.path, target.path, out_path, err);
            };
            plan_span.end(io);
            defer prepared.deinit();
            var write_span = profile.begin(io, "ziff_create.create (payload)");
            defer write_span.end(io);
            var target_size_problem: ziff_create.TargetSizeProblem = .{};
            _ = ziff_create.create(
                allocator,
                io,
                &prepared.header,
                &prepared.directory,
                .{
                    .source_root = source.path,
                    .target_root = target.path,
                    .container_path = out_path,
                    .source_ignore = if (software) |value| integrations.ignoreFilter(value) else null,
                    .source_manifest = prepared.source_manifest,
                },
                .{
                    .target_metadata = target.metadata(),
                    .target_size_problem = &target_size_problem,
                    .progress = &progress,
                    .slice_budget = if (minimum_memory) production_options.minimum_memory_slice_budget else 0,
                    .serializer_memory_bytes = if (minimum_memory)
                        ziff_create.minimum_serializer_memory_bytes
                    else
                        ziff_create.default_serializer_memory_bytes,
                    .target_observations = if (target_tree.deferred_content) &target_tree else null,
                },
            ) catch |err| {
                progress.stop();
                if (err == error.TargetSizeChanged) {
                    if (target_size_problem.details) |details| {
                        try ui.writeErrorPrefix(out);
                        try out.writeAll(" Target file size differs from the payload plan\n");
                        try ui.writeField(out, "Directory:", target.path);
                        try ui.writeField(out, "File:", details.path);
                        try ui.writeCount(out, "Expected bytes:", details.expected);
                        try ui.writeCount(out, "Actual bytes:", details.actual);
                        return error.Reported;
                    }
                }
                return reportCreateError(out, source.path, target.path, out_path, err);
            };
            progress.finish();
            try ui.printCreated(io, out_path, out);
            break :ziff;
        },
    }) catch |err| return reportCreateError(out, source.path, target.path, out_path, err);

    try out.writeByte('\n');
    try ui.complete(out, had_errors);
}

fn compareSides(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: Side,
    target: *Side,
    software: ?integrations.Software,
    out: *std.Io.Writer,
) !Comparison {
    var source_tree: tree.Tree = undefined;
    var target_tree: tree.Tree = undefined;
    const ignore = if (software) |value| integrations.ignoreFilter(value) else null;
    const source_fast = canUseExpectedFastPath(source);
    const target_fast = canUseExpectedFastPath(target.*);
    const source_managed_scan = needsManagedMembershipScan(source);
    const target_managed_scan = needsManagedMembershipScan(target.*);
    var comparing: ui.Progress = .{ .io = io, .writer = out, .label = "Comparing", .indeterminate = true };
    try comparing.start();
    errdefer comparing.abort();

    if (software == null) {
        source_tree = tree.inventory(allocator, io, source.path, null, ignore) catch |err| {
            comparing.abort();
            return reportScanError(out, "Source", source.path, err);
        };
        try comparing.pulse();
        target_tree = tree.inventory(allocator, io, target.path, null, ignore) catch |err| {
            comparing.abort();
            return reportScanError(out, "Target", target.path, err);
        };
    } else if (source_fast and target_fast) {
        source_tree = try tree.fromExpectedWithMetadata(
            allocator,
            source.path,
            claimsFor(source).?,
            source.metadata(),
        );
        target_tree = try tree.fromExpectedWithMetadata(
            allocator,
            target.path,
            claimsFor(target.*).?,
            target.metadata(),
        );
        const checked = try compareExpected(allocator, io, &source_tree, &target_tree, target.state.?.expected, &comparing);
        if (checked.failures.len != 0) {
            target.state.?.expected = try observedExpected(allocator, target.state.?.expected, target_tree);
        }
        try comparing.finish();
        return .{ .source_tree = source_tree, .target_tree = target_tree, .plan = checked.plan, .failures = checked.failures, .source_failures = checked.source_failures };
    } else {
        source_tree = if (source_fast)
            try tree.fromExpected(allocator, source.path, claimsFor(source).?)
        else
            tree.inventoryWithClaims(allocator, io, source.path, null, ignore, claimsFor(source), source_managed_scan) catch |err| {
                comparing.abort();
                return reportScanError(out, "Source", source.path, err);
            };
        target_tree = if (target_fast)
            try tree.fromExpected(allocator, target.path, claimsFor(target.*).?)
        else
            tree.inventoryWithClaims(allocator, io, target.path, null, ignore, claimsFor(target.*), target_managed_scan) catch |err| {
                comparing.abort();
                return reportScanError(out, "Target", target.path, err);
            };
        var prepared = try planner.prepare(allocator, &source_tree, &target_tree, &comparing);
        defer prepared.deinit();
        const read_tasks = prepared.work.items.len +
            (if (source_fast) @as(usize, 0) else source_tree.files.len) +
            (if (target_fast) @as(usize, 0) else target_tree.files.len);
        var read_bytes = prepared.readBytes();
        if (!source_fast) for (source_tree.files) |file| {
            read_bytes +|= file.size;
        };
        if (!target_fast) for (target_tree.files) |file| {
            read_bytes +|= file.size;
        };
        try comparing.startReading(read_tasks, read_bytes);
        if (!source_fast) tree.observeInventory(io, &source_tree, claimsFor(source), &comparing) catch |err| {
            comparing.abort();
            return reportScanError(out, "Source", source.path, err);
        };
        if (!target_fast) tree.observeInventory(io, &target_tree, claimsFor(target.*), &comparing) catch |err| {
            comparing.abort();
            return reportScanError(out, "Target", target.path, err);
        };
        const plan = prepared.resolve(io, &source_tree, &target_tree, true, &comparing) catch |err| {
            comparing.abort();
            return reportCompareError(out, source.path, target.path, err);
        };
        try comparing.finish();
        return .{ .source_tree = source_tree, .target_tree = target_tree, .plan = plan };
    }

    const plan = generic.build(allocator, io, &source_tree, &target_tree, &comparing, .{}) catch |err| {
        comparing.abort();
        return reportCompareError(out, source.path, target.path, err);
    };
    try comparing.finish();

    return .{
        .source_tree = source_tree,
        .target_tree = target_tree,
        .plan = plan,
    };
}

fn withoutIntegration(side: Side) Side {
    return .{
        .path = side.path,
        .software = null,
        .version_info = null,
        .state = null,
    };
}

fn selectIntegration(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, detected: ?integrations.Detected, automatic: bool, enabled: ?bool) !?integrations.Software {
    if (enabled) |choice| return integrationChoice(detected, choice);
    const value = detected orelse return null;
    if (automatic) return integrationChoice(detected, true);

    try ui.writeField(out, "Detected software:", value.name());
    const prompt = try allocator.print("Use {s} integration?", .{value.name()});
    return integrationChoice(detected, try cli.promptYesNo(allocator, io, out, prompt, true));
}

fn integrationChoice(detected: ?integrations.Detected, enabled: bool) ?integrations.Software {
    if (!enabled) return null;
    const value = detected orelse return null;
    return value.software;
}

fn outputName(allocator: std.mem.Allocator, prefix: ?[]const u8, source_version: []const u8, target_version: []const u8, extension: []const u8) ![]const u8 {
    if (prefix) |p| return allocator.print("{s}-{s}-{s}{s}", .{ p, source_version, target_version, extension });
    return allocator.print("{s}-{s}{s}", .{ source_version, target_version, extension });
}

fn resolvedVersion(allocator: std.mem.Allocator, info: ?VersionInfo, chosen: []const u8) ![]const u8 {
    const found = info orelse return allocator.dupe(u8, chosen);
    if (found.parts) |parts| {
        if (std.mem.eql(u8, chosen, parts.number)) return allocator.dupe(u8, found.full);
        if (std.ascii.isDigit(chosen[0])) return allocator.print("{s}{s}", .{ parts.prefix, chosen });
    }
    return allocator.dupe(u8, chosen);
}

fn withInstallView(side: Side, view: integrations.InstallView) Side {
    var result = side;
    const state = view.state.?;
    result.version_info = if (view.integration.identity_trustworthy) view.identity else null;
    result.state = state;
    return result;
}

fn activateOrGeneric(
    source: Side,
    target: Side,
    software: integrations.Software,
    source_view: integrations.InstallView,
    target_view: integrations.InstallView,
) Activation {
    if (!integrations.usablePair(source_view, target_view)) return .{
        .software = null,
        .source = withoutIntegration(source),
        .target = withoutIntegration(target),
    };
    return .{
        .software = software,
        .source = withInstallView(source, source_view),
        .target = withInstallView(target, target_view),
    };
}

fn compareExpected(allocator: std.mem.Allocator, io: std.Io, source: *tree.Tree, target: *tree.Tree, expected: manifest_mod.Set, progress: *ui.Progress) !struct { plan: planner.Plan, failures: []verify.Failure, source_failures: []verify.Failure } {
    const Decision = union(enum) { keep, add, change: u32, compare: u32, omit };
    const Entry = struct { target: u32, decision: Decision };
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(std.heap.smp_allocator);
    var changed: std.ArrayList(planner.Change) = .empty;
    var added: std.ArrayList(u32) = .empty;
    var removed: std.ArrayList(u32) = .empty;
    var failures: std.ArrayList(verify.Failure) = .empty;
    var source_failures: std.ArrayList(verify.Failure) = .empty;
    errdefer source_failures.deinit(allocator);
    errdefer changed.deinit(allocator);
    errdefer added.deinit(allocator);
    errdefer removed.deinit(allocator);
    errdefer failures.deinit(allocator);
    var comparator = try planner.Comparator.init(io, source, target);
    defer comparator.deinit();
    progress.total_files = source.files.len + target.files.len;
    progress.indeterminate = false;
    var read_tasks: usize = 0;
    var read_bytes: u64 = 0;
    source.map.clearRetainingCapacity();
    var source_count: usize = 0;
    for (source.files) |original| {
        var file = original;
        if (file.bytes == null) {
            const declaration: manifest_mod.File = .{ .path = file.path, .size = file.size, .md5 = file.md5.? };
            if (try verify.sizeProblem(io, comparator.source_dir, declaration)) |failure| {
                try source_failures.append(allocator, failure);
                if (failure.reason != .size_mismatch) {
                    try progress.finishFile();
                    continue;
                }
                file.size = failure.actual_size.?;
                file.md5 = null;
                file.digest = null;
                file.claim.?.authority = .advisory;
                read_tasks += 1;
                read_bytes +|= file.size;
            }
        }
        source.files[source_count] = file;
        try source.map.put(allocator, file.path, @intCast(source_count));
        source_count += 1;
        try progress.finishFile();
    }
    source.files = try allocator.realloc(source.files, source_count);
    for (target.files, 0..) |*file, index| {
        if (file.bytes == null) {
            if (try verify.sizeProblem(io, comparator.target_dir, expected.find(file.path).?)) |failure| {
                try failures.append(allocator, failure);
                if (failure.reason != .size_mismatch) {
                    try progress.finishFile();
                    continue;
                }
                file.size = failure.actual_size.?;
                file.md5 = null;
            }
        }
        var decision: Decision = .keep;
        if (file.bytes == null) {
            if (source.findIndex(file.path)) |source_index| {
                if (file.md5 == null) {
                    decision = .{ .compare = source_index };
                } else if (try planner.metadataDifference(source.files[source_index], file.*, source.deferred_content and target.deferred_content)) |different| {
                    if (different) decision = .{ .change = source_index };
                } else decision = .{ .compare = source_index };
            } else decision = .add;
        }
        if (file.md5 == null or decision == .compare) {
            read_tasks += 1;
            read_bytes +|= if (file.md5 == null) file.size else file.size +| source.files[decision.compare].size;
        }
        try entries.append(std.heap.smp_allocator, .{ .target = @intCast(index), .decision = decision });
        try progress.finishFile();
    }
    try progress.startReading(read_tasks, read_bytes);
    for (source.files, 0..) |file, index| {
        if (file.md5 != null) continue;
        const before = progress.done_bytes;
        var reading: ui.ReadProgress = .{ .progress = progress };
        _ = try tree.observeDigest(std.heap.smp_allocator, io, comparator.source_dir, source, @intCast(index), .{ .reader = reading.reader() });
        source.files[index].claim.?.value.bytes = source.files[index].md5.?;
        source.files[index].claim.?.authority = .authoritative;
        progress.reconcileRead(file.size, progress.done_bytes - before);
        try progress.finishFile();
    }
    if (read_tasks != 0) {
        for (entries.items) |*entry| {
            const file = &target.files[entry.target];
            if (file.md5 != null and entry.decision != .compare) continue;
            const expected_bytes = if (file.md5 == null) file.size else file.size +| source.files[entry.decision.compare].size;
            const bytes_before = progress.done_bytes;
            if (file.md5 == null) {
                const actual = verify.hashFile(io, comparator.target_dir, file.path, progress) catch |err| {
                    if (err == error.Interrupted or err == error.Canceled) return err;
                    try failures.append(allocator, .{ .path = file.path, .reason = .{ .read_failed = err }, .expected_size = expected.find(file.path).?.size, .actual_size = file.size });
                    entry.decision = .omit;
                    progress.reconcileRead(expected_bytes, progress.done_bytes - bytes_before);
                    try progress.finishFile();
                    continue;
                };
                file.size = actual.size;
                file.md5 = actual.md5;
                file.claim.?.value.bytes = actual.md5;
            }
            if (entry.decision == .compare) {
                const source_index = entry.decision.compare;
                entry.decision = if (try comparator.differs(.{ .source = source_index, .target = entry.target }, progress))
                    .{ .change = source_index }
                else
                    .keep;
            }
            progress.reconcileRead(expected_bytes, progress.done_bytes - bytes_before);
            try progress.finishFile();
        }
    }
    target.map.clearRetainingCapacity();
    var count: usize = 0;
    for (entries.items) |entry| {
        if (entry.decision == .omit) continue;
        const file = target.files[entry.target];
        const index: u32 = @intCast(count);
        target.files[count] = file;
        try target.map.put(allocator, file.path, index);
        count += 1;
        switch (entry.decision) {
            .add => try added.append(allocator, index),
            .change => |source_index| try changed.append(allocator, .{ .source = source_index, .target = index }),
            .keep => {},
            .compare, .omit => unreachable,
        }
    }
    target.files = try allocator.realloc(target.files, count);
    for (source.files, 0..) |file, index| if (target.findIndex(file.path) == null) {
        try removed.append(allocator, @intCast(index));
    };
    const changed_items = try changed.toOwnedSlice(allocator);
    errdefer allocator.free(changed_items);
    const added_items = try added.toOwnedSlice(allocator);
    errdefer allocator.free(added_items);
    const removed_items = try removed.toOwnedSlice(allocator);
    errdefer allocator.free(removed_items);
    return .{ .plan = .{ .changed = changed_items, .added = added_items, .removed = removed_items, .groups = &.{}, .comparison_bytes = progress.done_bytes }, .failures = try failures.toOwnedSlice(allocator), .source_failures = try source_failures.toOwnedSlice(allocator) };
}

fn observedExpected(allocator: std.mem.Allocator, original: manifest_mod.Set, actual: tree.Tree) !manifest_mod.Set {
    var entries: std.ArrayList(manifest_mod.File) = .empty;
    errdefer entries.deinit(allocator);
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    errdefer map.deinit(allocator);
    for (original.entries) |entry| {
        const file = actual.find(entry.path) orelse continue;
        try map.put(allocator, entry.path, @intCast(entries.items.len));
        try entries.append(allocator, .{ .path = entry.path, .size = file.size, .md5 = file.md5.? });
    }
    return .{ .entries = try entries.toOwnedSlice(allocator), .map = map };
}

fn finishMetadataComparison(allocator: std.mem.Allocator, metadata: []const manifest_mod.MetadataFile, comparison: *Comparison) !void {
    var changed = std.ArrayList(planner.Change).fromOwnedSlice(comparison.plan.changed);
    var added = std.ArrayList(u32).fromOwnedSlice(comparison.plan.added);
    comparison.plan.changed = &.{};
    comparison.plan.added = &.{};
    defer changed.deinit(allocator);
    defer added.deinit(allocator);
    updateMetadataTree(&comparison.target_tree, metadata);
    for (metadata) |entry| {
        const index = comparison.target_tree.findIndex(entry.path).?;
        if (comparison.source_tree.findIndex(entry.path)) |source_index| {
            if (!std.mem.eql(u8, comparison.source_tree.files[source_index].bytes.?, entry.bytes))
                try changed.append(allocator, .{ .source = source_index, .target = index });
        } else try added.append(allocator, index);
    }
    comparison.plan.changed = try changed.toOwnedSlice(allocator);
    comparison.plan.added = try added.toOwnedSlice(allocator);
    comparison.plan.groups = try planner.findGroups(allocator, comparison.source_tree, comparison.target_tree, comparison.plan.changed, comparison.plan.added, comparison.plan.removed);
}

fn updateMetadataTree(files: *tree.Tree, metadata: []const manifest_mod.MetadataFile) void {
    for (metadata) |entry| {
        const file = &files.files[files.findIndex(entry.path).?];
        if (std.mem.eql(u8, file.bytes.?, entry.bytes)) continue;
        file.bytes = entry.bytes;
        file.size = entry.bytes.len;
        var md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(entry.bytes, &md5, .{});
        file.md5 = md5;
        file.digest = @import("core/ids.zig").Digest.of(entry.bytes);
    }
}

fn canUseExpectedFastPath(side: Side) bool {
    return if (side.state) |state|
        state.managed_set_complete and state.digest_authority == .authoritative
    else
        false;
}

fn needsManagedMembershipScan(side: Side) bool {
    return if (side.state) |state|
        state.managed_set_complete and state.digest_authority != .authoritative
    else
        false;
}

fn claimsFor(side: Side) ?tree.ExpectedClaims {
    const state = side.state orelse return null;
    return .{
        .expected = state.expected,
        .schema = state.manifest_schema,
        .authority = state.digest_authority,
    };
}

fn validateArchivePaths(method: Method, target_tree: tree.Tree, plan: planner.Plan, out: *std.Io.Writer) !void {
    for (plan.changed) |change| {
        const path = target_tree.files[change.target].path;
        if (isReservedPath(method, path)) {
            try ui.writeErrorPrefix(out);
            try out.writeAll(" cannot create delta\n");
            try ui.writeField(out, "Reserved delta path:", path);
            return error.Reported;
        }
    }
    for (plan.added) |index| {
        const path = target_tree.files[index].path;
        if (isReservedPath(method, path)) {
            try ui.writeErrorPrefix(out);
            try out.writeAll(" cannot create delta\n");
            try ui.writeField(out, "Reserved delta path:", path);
            return error.Reported;
        }
    }
}

fn isReservedPath(method: Method, path: []const u8) bool {
    return switch (method) {
        .file_delta => std.mem.eql(u8, path, delta.file_delta_deletion_path),
        .hdiff => std.mem.eql(u8, path, "hdifffiles.txt") or std.mem.eql(u8, path, "deletefiles.txt"),
        .ziff => false,
    };
}

fn inspectSide(io: std.Io, path: []const u8) !Side {
    return .{ .path = path, .software = try integrations.detect(io, path), .version_info = null, .state = null };
}

fn commonSoftware(source: ?integrations.Detected, target: ?integrations.Detected) ?integrations.Detected {
    if (source == null or target == null) return null;
    return if (source.?.software == target.?.software) source.? else null;
}

fn nameVersion(info: ?VersionInfo) ?[]const u8 {
    const value = info orelse return null;
    if (value.parts) |parts| return parts.number;
    return value.full;
}

fn reportCreateError(out: *std.Io.Writer, source: []const u8, target: []const u8, output: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.Reported, error.Aborted, error.Interrupted => return err,
        error.SizeMismatch, error.Md5Mismatch, error.ExpectedFile, error.TargetChangedDuringCreate => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" Target changed while creating delta\n") catch return err;
            ui.writeField(out, "Target:", target) catch return err;
        },
        error.FileNotFound,
        error.AccessDenied,
        error.PermissionDenied,
        error.FileBusy,
        error.NotDir,
        error.IsDir,
        error.ReadOnlyFileSystem,
        error.NoSpaceLeft,
        error.DiskQuota,
        error.EntropyUnavailable,
        error.PathAlreadyExists,
        error.NoAvailableConstructionWorkspace,
        error.InvalidConstructionOutput,
        error.ConstructionOutputBindingChanged,
        error.ConstructionOutputVerificationFailed,
        error.PublishedBindingChanged,
        error.PublicationOutcomeUnknown,
        error.UnsafeGuardedOutput,
        error.HDiffCreateFailed,
        error.HDiffConstructionVerificationFailed,
        error.HDiffRollbackFailed,
        error.ZstdCompressFailed,
        => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" cannot create delta\n") catch return err;
            ui.writeField(out, "Source:", source) catch return err;
            ui.writeField(out, "Target:", target) catch return err;
            ui.writeField(out, "Output:", output) catch return err;
        },
        else => return err,
    }
    ui.writeField(out, "Reason:", @errorName(err)) catch return err;
    return error.Reported;
}

fn reportScanError(out: *std.Io.Writer, side: []const u8, directory: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.UnsupportedFileType => {
            ui.writeErrorPrefix(out) catch return err;
            out.print(" unsupported file type in {s}\n", .{side}) catch return err;
            ui.writeField(out, "Directory:", directory) catch return err;
        },
        error.UnsafePath, error.PathTooLongForZip, error.DuplicatePath => {
            ui.writeErrorPrefix(out) catch return err;
            out.print(" unsupported path in {s}\n", .{side}) catch return err;
            ui.writeField(out, "Directory:", directory) catch return err;
        },
        error.AccessDenied, error.PermissionDenied, error.FileBusy, error.FileNotFound, error.NotDir => {
            ui.writeErrorPrefix(out) catch return err;
            out.print(" cannot read {s}\n", .{side}) catch return err;
            ui.writeField(out, "Directory:", directory) catch return err;
        },
        error.AuthoritativeClaimMissing,
        error.AuthoritativeClaimUnavailable,
        error.AuthoritativeClaimContradiction,
        error.ManagedMemberMissing,
        => {
            try ui.writeErrorPrefix(out);
            try out.print(" {s} files do not match the manifest\n", .{side});
            try ui.writeField(out, "Directory:", directory);
        },
        else => return err,
    }
    ui.writeField(out, "Reason:", @errorName(err)) catch return err;
    return error.Reported;
}

fn reportCompareError(out: *std.Io.Writer, source: []const u8, target: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.FileChangedDuringScan, error.ExpectedFile => {
            ui.writeErrorPrefix(out) catch return err;
            out.writeAll(" Source or Target changed while comparing\n") catch return err;
            ui.writeField(out, "Source:", source) catch return err;
            ui.writeField(out, "Target:", target) catch return err;
        },
        else => return err,
    }
    ui.writeField(out, "Reason:", @errorName(err)) catch return err;
    return error.Reported;
}

fn requireNamePart(out: *std.Io.Writer, label: []const u8, value: []const u8) !void {
    if (cli.isNamePart(value)) return;
    try ui.writeErrorPrefix(out);
    try out.print(" invalid {s}\n", .{label});
    try ui.writeField(out, "Value:", value);
    return error.Reported;
}

fn printCreateSummary(out: *std.Io.Writer, software: ?integrations.Software, source_version: []const u8, target_version: []const u8, method: Method, hdiff_format: hdiff.Format, source_path: []const u8, target_path: []const u8, out_path: []const u8, plan: planner.Plan, source_tree: tree.Tree, target_tree: tree.Tree) !void {
    try ui.writeHeading(out, "Create delta:");
    try out.writeByte('\n');
    if (software) |value| try ui.writeField(out, "    Software:", integrations.displayName(value));
    try ui.writeDeltaField(out, source_version, target_version);
    try ui.writeField(out, "    Method:", method.label());
    if (method == .hdiff) try ui.writeField(out, "    HDiff format:", hdiff_format.label());
    try ui.writeField(out, "    Source:", source_path);
    try ui.writeField(out, "    Target:", target_path);
    try ui.writeField(out, "    Output:", out_path);
    try out.writeByte('\n');

    var changed: u64 = 0;
    var added: u64 = 0;
    var removed: u64 = 0;
    for (plan.changed) |c| changed +|= target_tree.files[c.target].size;
    for (plan.added) |i| added +|= target_tree.files[i].size;
    for (plan.removed) |i| removed +|= source_tree.files[i].size;
    try ui.writeCountSize(out, "Files to change:", plan.changed.len, changed);
    try ui.writeCountSize(out, "Files to add:", plan.added.len, added);
    try ui.writeCountSize(out, "Files to remove:", plan.removed.len, removed);
    if (method == .ziff) {
        var group_size: u64 = 0;
        for (plan.groups) |group| {
            for (group.target) |index| group_size +|= target_tree.files[index].size;
        }
        try ui.writeCountSize(out, "Groups:", plan.groups.len, group_size);
    }
}

fn requireMissing(io: std.Io, path: []const u8, out_path: []const u8, out: *std.Io.Writer) !void {
    if (std.Io.Dir.cwd().statFile(io, path, .{})) |_| {
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

test "declining a detected integration selects generic behavior" {
    const detected: integrations.Detected = .{ .software = .zzz };
    try std.testing.expectEqual(integrations.Software.zzz, integrationChoice(detected, true).?);
    try std.testing.expect(integrationChoice(detected, false) == null);
    try std.testing.expect(integrationChoice(null, true) == null);
}

test "metadata comparison completes before mismatched target contents are read" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "audio.pck", .data = "old audio" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var expected = [_]manifest_mod.File{
        .{ .path = "audio.pck", .size = 12, .md5 = @splat(0) },
        .{ .path = "missing.exe", .size = 1, .md5 = @splat(0) },
    };
    var target: Side = .{
        .path = root,
        .software = .{ .software = .zzz },
        .version_info = null,
        .state = .{
            .expected = .{ .entries = &expected, .map = .empty },
            .metadata = &.{},
            .manifest_format = .pkg_version_ndjson,
            .manifest_schema = .hoyo_pkg_version_md5,
            .digest_authority = .authoritative,
            .managed_set_complete = true,
        },
    };
    for (expected, 0..) |entry, index| try target.state.?.expected.map.put(allocator, entry.path, @intCast(index));
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/audio.pck", .data = "old audio!!!" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/missing.exe", .data = "x" });
    var source = target;
    source.path = try std.fs.path.join(allocator, &.{ root, "source" });
    var first_target = target;
    var comparison = try compareSides(allocator, io, source, &first_target, .zzz, &output.writer);
    try std.testing.expectEqual(@as(usize, 2), comparison.failures.len);
    try std.testing.expectEqual(verify.FailureReason.size_mismatch, comparison.failures[0].reason);
    try std.testing.expectEqual(@as(u64, 9), comparison.failures[0].actual_size.?);
    try std.testing.expectEqual(verify.FailureReason.missing, comparison.failures[1].reason);
    try std.testing.expectEqual(@as(u64, 9), comparison.plan.comparison_bytes);
    try std.testing.expectEqual(@as(usize, 1), comparison.plan.changed.len);
    try std.testing.expectEqualStrings("audio.pck", comparison.target_tree.files[comparison.plan.changed[0].target].path);
    try std.testing.expectEqual(@as(usize, 1), comparison.plan.removed.len);
    try std.testing.expectEqualStrings("missing.exe", comparison.source_tree.files[comparison.plan.removed[0]].path);
    try finishMetadataComparison(allocator, &.{}, &comparison);
    const metadata_end = std.mem.indexOf(u8, output.written(), "100%  files 4/4").?;
    const reading_start = std.mem.indexOf(u8, output.written(), "Reading contents...\n").?;
    try std.testing.expect(metadata_end < reading_start);
    try std.testing.expect(std.mem.indexOf(u8, output.written()[reading_start..], "100%  9 B/9 B") != null);
    try tmp.dir.writeFile(io, .{ .sub_path = "audio.pck", .data = "new audio!!!" });
    try tmp.dir.writeFile(io, .{ .sub_path = "missing.exe", .data = "x" });
    const valid = try compareSides(allocator, io, source, &target, .zzz, &output.writer);
    try std.testing.expectEqual(@as(usize, 0), valid.failures.len);
    try std.testing.expectEqual(@as(u64, 0), valid.plan.comparison_bytes);
}

test "advisory integration stages retain physical observations and actual comparisons" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "s", .default_dir);
    try tmp.dir.createDir(io, "t", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "s/managed.bin", .data = "old bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/managed.bin", .data = "new bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "s/same.bin", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/same.bin", .data = "same" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var files = [_]manifest_mod.File{
        .{ .path = "managed.bin", .size = 999, .md5 = @splat(0xaa) },
        .{ .path = "same.bin", .size = 999, .md5 = @splat(0xaa) },
    };
    var expected: manifest_mod.Set = .{ .entries = &files, .map = .empty };
    for (files, 0..) |file, index| try expected.map.put(allocator, file.path, @intCast(index));
    const state: integrations.State = .{
        .expected = expected,
        .metadata = &.{},
        .manifest_format = .pkg_version_ndjson,
        .manifest_schema = .hoyo_pkg_version_md5,
        .digest_authority = .advisory,
        .managed_set_complete = true,
    };
    const source: Side = .{ .path = try std.fs.path.join(allocator, &.{ root, "s" }), .software = .{ .software = .zzz }, .version_info = null, .state = state };
    var target: Side = .{ .path = try std.fs.path.join(allocator, &.{ root, "t" }), .software = .{ .software = .zzz }, .version_info = null, .state = state };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const result = try compareSides(allocator, io, source, &target, .zzz, &output.writer);
    try std.testing.expectEqual(@as(usize, 1), result.plan.changed.len);
    try std.testing.expectEqualStrings("managed.bin", result.target_tree.files[result.plan.changed[0].target].path);
    try std.testing.expectEqual(@as(u64, 34), result.plan.comparison_bytes);
    const managed = result.target_tree.find("managed.bin").?;
    try std.testing.expectEqual(@as(u64, 9), managed.size);
    try std.testing.expect(managed.digest.?.eql(@import("core/ids.zig").Digest.of("new bytes")));
    try std.testing.expect(!managed.observed_vendor.?.sameClaim(managed.claim.?.value));
    const metadata_end = std.mem.indexOf(u8, output.written(), "100%  files 2/2").?;
    const reading_start = std.mem.indexOf(u8, output.written(), "Reading contents...").?;
    try std.testing.expect(metadata_end < reading_start);
}

test "target repair reuses compared identities and refreshes only virtual metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "audio.pck", .data = "old audio" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep", .data = "keep" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const metadata = "{\"remoteName\":\"audio.pck\",\"md5\":\"00000000000000000000000000000000\",\"fileSize\":12}\n" ++
        "{\"remoteName\":\"missing.exe\",\"md5\":\"00000000000000000000000000000000\",\"fileSize\":1}\n" ++
        "{\"remoteName\":\"keep\",\"md5\":\"09090909090909090909090909090909\",\"fileSize\":4}\n";
    var metadata_files = [_]manifest_mod.MetadataFile{.{ .path = "pkg_version", .bytes = metadata }};
    const original = try @import("integrations/pkg_version.zig").loadSetFiles(allocator, &metadata_files);
    const original_target: Side = .{
        .path = root,
        .software = .{ .software = .zzz },
        .version_info = null,
        .state = .{
            .expected = original.expected,
            .metadata = original.metadata,
            .manifest_format = .pkg_version_ndjson,
            .manifest_schema = .hoyo_pkg_version_md5,
            .digest_authority = .authoritative,
            .managed_set_complete = true,
        },
    };
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/audio.pck", .data = "old audio!!!" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/keep", .data = "keep" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/missing.exe", .data = "x" });
    var source = original_target;
    source.path = try std.fs.path.join(allocator, &.{ root, "source" });
    for ([_]bool{ false, true }) |repair| {
        var target = original_target;
        var comparison = try compareSides(allocator, io, source, &target, .zzz, &output.writer);
        try std.testing.expectEqual(@as(usize, 2), comparison.failures.len);
        try std.testing.expectEqual(@as(u64, 9), comparison.plan.comparison_bytes);
        const expected = target.state.?.expected;
        try std.testing.expect(expected.find("missing.exe") == null);
        try std.testing.expectEqual(original.expected.find("keep").?.md5, expected.find("keep").?.md5);
        var md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash("old audio", &md5, .{});
        try std.testing.expectEqual(@as(u64, 9), expected.find("audio.pck").?.size);
        try std.testing.expectEqual(md5, expected.find("audio.pck").?.md5);
        if (repair) {
            target.state.?.metadata = try @import("integrations/pkg_version.zig").correctedMetadata(allocator, target.metadata(), expected);
            const corrected = try @import("integrations/pkg_version.zig").loadSetFiles(allocator, try allocator.dupe(manifest_mod.MetadataFile, target.metadata()));
            try std.testing.expectEqual(expected.entries.len, corrected.expected.entries.len);
            for (expected.entries) |entry| {
                const repaired = corrected.expected.find(entry.path).?;
                try std.testing.expectEqual(entry.size, repaired.size);
                try std.testing.expectEqual(entry.md5, repaired.md5);
            }
        } else try std.testing.expectEqualStrings(metadata, target.metadata()[0].bytes);
        try finishMetadataComparison(allocator, target.metadata(), &comparison);
        try std.testing.expectEqual(@as(u64, 9), comparison.plan.comparison_bytes);
        try std.testing.expectEqual(@as(usize, if (repair) 2 else 1), comparison.plan.changed.len);
        for (comparison.plan.changed) |change| try std.testing.expect(!std.mem.eql(u8, comparison.target_tree.files[change.target].path, "keep"));
        try std.testing.expectEqualStrings(target.metadata()[0].bytes, comparison.target_tree.find("pkg_version").?.bytes.?);
        try std.testing.expectEqualStrings(metadata, original_target.metadata()[0].bytes);
    }
}

test "one unavailable managed view downgrades both sides to literal generic" {
    const definition = integrations.integration(.zzz);
    const state: integrations.State = .{
        .expected = .{ .entries = &.{}, .map = .empty },
        .metadata = &.{.{ .path = "pkg_version", .bytes = "vendor metadata" }},
        .manifest_format = .pkg_version_ndjson,
        .manifest_schema = .hoyo_pkg_version_md5,
        .digest_authority = .authoritative,
        .managed_set_complete = true,
    };
    const available: integrations.InstallView = .{
        .integration = definition,
        .state = state,
        .identity = .{ .full = "OSPRODWin1.0.0", .parts = null },
    };
    var unavailable = available;
    unavailable.state = null;

    const contaminated: Side = .{
        .path = "install",
        .software = .{ .software = .zzz },
        .version_info = available.identity,
        .state = state,
    };
    const result = activateOrGeneric(contaminated, contaminated, .zzz, available, unavailable);
    try std.testing.expect(result.software == null);
    try std.testing.expect(result.source.software == null and result.target.software == null);
    try std.testing.expect(result.source.version_info == null and result.target.version_info == null);
    try std.testing.expect(result.source.state == null and result.target.state == null);
    try std.testing.expectEqual(@as(usize, 0), result.source.metadata().len);
    try std.testing.expectEqual(@as(usize, 0), result.target.metadata().len);
    try std.testing.expect((if (result.software) |value| integrations.ignoreFilter(value) else null) == null);
}

test "identical generic directories finish without creation prompts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    for ([_][]const u8{ "source/unchanged", "target/unchanged" }) |path|
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "same contents" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const source = try std.fs.path.join(allocator, &.{ root, "source" });
    const target = try std.fs.path.join(allocator, &.{ root, "target" });
    const output_path = try std.fs.path.join(allocator, &.{ root, "unused.ziff" });
    var output: std.Io.Writer.Allocating = .init(allocator);
    try run(allocator, io, source, target, output_path, .{}, false, false, false, &output.writer);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "No differences found.") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "Prefix") == null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "unused.ziff", .{}));
}

test "resolved version keeps full overrides" {
    const allocator = std.testing.allocator;
    const info = VersionInfo{
        .full = "CNBetaWin3.2.2",
        .parts = .{ .prefix = "CNBetaWin", .number = "3.2.2" },
    };

    const detected = try resolvedVersion(allocator, info, "3.2.2");
    defer allocator.free(detected);
    try std.testing.expectEqualStrings("CNBetaWin3.2.2", detected);

    const shorthand = try resolvedVersion(allocator, info, "3.2.4");
    defer allocator.free(shorthand);
    try std.testing.expectEqualStrings("CNBetaWin3.2.4", shorthand);

    const full = try resolvedVersion(allocator, info, "OSPRODWin3.2.4");
    defer allocator.free(full);
    try std.testing.expectEqualStrings("OSPRODWin3.2.4", full);
}

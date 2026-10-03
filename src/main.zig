const std = @import("std");

const cli = @import("cli.zig");
const clean = @import("clean.zig");
const interrupt = @import("interrupt.zig");
const profile = @import("profile.zig");
const ui = @import("ui.zig");
const create = @import("create.zig");
const apply = @import("apply.zig");

fn unexpectedError(w: *std.Io.Writer, err: anyerror) !void {
    try ui.writeErrorPrefix(w);
    try w.print(" {s}\n", .{@errorName(err)});
}

fn operationError(stdout: *std.Io.Writer, stderr: *std.Io.Writer, err: anyerror) !u8 {
    if (err == error.Reported or err == error.Aborted or err == error.Interrupted or err == error.CompletedWithErrors) {
        try stdout.flush();
        return 1;
    }
    if (err == error.InputRequired) {
        try stdout.flush();
        try ui.writeErrorPrefix(stderr);
        try stderr.writeAll(" input required\n");
        try stderr.flush();
        return 1;
    }
    try unexpectedError(stderr, err);
    try stderr.flush();
    try stdout.flush();
    return 1;
}

test "operation failures do not claim completion" {
    for ([_]anyerror{ error.Reported, error.ProcessFdQuotaExceeded, error.Aborted, error.Interrupted, error.CompletedWithErrors }) |err| {
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        if (err == error.CompletedWithErrors)
            try std.testing.expectError(error.CompletedWithErrors, ui.complete(&stdout.writer, true));
        try std.testing.expectEqual(@as(u8, 1), try operationError(&stdout.writer, &stderr.writer, err));
        try std.testing.expectEqualStrings(if (err == error.CompletedWithErrors)
            "Completed with errors (shown above).\n"
        else
            "", stdout.written());
        try std.testing.expectEqualStrings(if (err == error.ProcessFdQuotaExceeded)
            "Error: ProcessFdQuotaExceeded\n"
        else
            "", stderr.written());
    }
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout();
    var stderr_file = std.Io.File.stderr();
    var stdout_writer = stdout_file.writer(init.io, &stdout_buf);
    var stderr_writer = stderr_file.writer(init.io, &stderr_buf);
    const stdout = &stdout_writer.interface;
    const stderr = &stderr_writer.interface;
    const no_color = if (init.environ_map.get("NO_COLOR")) |value| value.len != 0 else false;
    ui.initStream(init.io, stdout_file, stdout, no_color);
    ui.initStream(init.io, stderr_file, stderr, no_color);

    interrupt.install() catch |err| return operationError(stdout, stderr, err);

    profile.configure(init.environ_map);

    const parsed_result = cli.parse(arena, init.io, init.minimal.args, init.environ_map) catch |err| {
        try unexpectedError(stderr, err);
        try stderr.flush();
        return 1;
    };
    const parsed = switch (parsed_result) {
        .ok => |parsed| parsed,
        .help => {
            try cli.printUsage(stdout);
            try stdout.flush();
            return 0;
        },
        .problem => |problem| {
            try cli.printProblem(stderr, problem);
            if (cli.problemNeedsUsage(problem)) {
                try stderr.writeByte('\n');
                try cli.printUsage(stderr);
            }
            try stderr.flush();
            return 1;
        },
    };

    switch (parsed.operation) {
        .clean => |op| clean.run(arena, init.io, op.directory, op.complete, parsed.assume_yes, parsed.verify_md5, stdout) catch |err|
            return operationError(stdout, stderr, err),
        .make => |op| create.run(arena, init.io, op.source, op.target, op.out, op.choices, parsed.assume_yes, parsed.automatic, parsed.minimum_memory, stdout) catch |err|
            return operationError(stdout, stderr, err),
        .apply => |op| apply.run(arena, init.io, op.delta, op.directory, parsed.assume_yes, parsed.verify_md5, parsed.force, stdout) catch |err|
            return operationError(stdout, stderr, err),
    }

    profile.report(stderr) catch {};
    try stdout.flush();
    try stderr.flush();
    return 0;
}

test {
    _ = @import("core/content.zig");
    _ = @import("plan/generic.zig");
    _ = @import("core/dirscan.zig");
    _ = @import("core/fs.zig");
    _ = @import("core/ids.zig");
    _ = @import("core/scan.zig");
    _ = @import("hdiff/encoding.zig");
    _ = @import("compression/decoder.zig");
    _ = @import("hdiff/sf20.zig");
    _ = @import("hdiff/h13.zig");
    _ = @import("hdiff/h13/apply.zig");
    _ = @import("hdiff/h13/create.zig");
    _ = @import("hdiff/w26.zig");
    _ = @import("hdiff/w26/apply.zig");
    _ = @import("hdiff/w26/create.zig");
    _ = @import("hdiff/w26/match.zig");
    _ = @import("match/equality.zig");
    _ = @import("match/merge.zig");
    _ = @import("hdiff/w26/windows.zig");
    _ = @import("format/zar26.zig");
    _ = @import("format/ziff.zig");
    _ = @import("create/ziff_plan.zig");
    _ = @import("compression/frame.zig");
    _ = @import("format/ziff_file.zig");
    _ = @import("create/ziff.zig");
    _ = @import("activity.zig");
    _ = @import("apply.zig");
    _ = @import("archive.zig");
    _ = @import("archive/tar.zig");
    _ = @import("archive/writer.zig");
    _ = @import("archive/zip.zig");
    _ = @import("match/index.zig");
    _ = @import("clean.zig");
    _ = @import("clean_policy.zig");
    _ = @import("cli.zig");
    _ = @import("create.zig");
    _ = @import("delta.zig");
    _ = @import("apply/archive.zig");
    _ = @import("apply/transaction.zig");
    _ = @import("apply/integrity_run.zig");
    _ = @import("format/detect.zig");
    _ = @import("create/file.zig");
    _ = @import("create/hdiff.zig");
    _ = @import("hdiff.zig");
    _ = @import("integrations.zig");
    _ = @import("interrupt.zig");
    _ = @import("path.zig");
    _ = @import("plan.zig");
    _ = @import("profile.zig");
    _ = @import("integrations/pkg_version.zig");
    _ = @import("tree.zig");
    _ = @import("tracker.zig");
    _ = @import("storage.zig");
    _ = @import("ui.zig");
    _ = @import("verify.zig");
    _ = @import("compression/zstd.zig");
    _ = @import("core/ranges.zig");
    _ = @import("apply/inplace.zig");
    _ = @import("apply/inplace_plan.zig");
}

// Zift command entry point
const std = @import("std");

const cli = @import("cli.zig");
const clean = @import("clean.zig");
const package = @import("package.zig");

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

    const parsed_result = cli.parse(arena, init.io, init.minimal.args, init.environ_map) catch |err| {
        try stderr.print("Error: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };
    const parsed = switch (parsed_result) {
        .ok => |parsed| parsed,
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
        .clean => |op| clean.run(arena, init.io, op.game, parsed.assume_yes, parsed.verify_md5, stdout) catch |err| {
            if (err == error.Aborted) return 1;
            if (err == error.Reported) {
                try stdout.flush();
                return 1;
            }
            try stderr.print("Error: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 1;
        },
        .make => |op| package.make(arena, init.io, op.left, op.right, op.out, parsed.assume_yes, stdout, stderr) catch |err| {
            if (err == error.Aborted) return 1;
            if (err == error.Reported) {
                try stderr.flush();
                return 1;
            }
            try stderr.print("Error: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 1;
        },
        .apply => |op| package.apply(arena, init.io, op.zip, op.game, parsed.assume_yes, parsed.verify_md5, stdout) catch |err| {
            if (err == error.Aborted) return 1;
            if (err == error.Reported) {
                try stdout.flush();
                return 1;
            }
            try stderr.print("Error: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 1;
        },
    }

    try stdout.flush();
    try stderr.flush();
    return 0;
}

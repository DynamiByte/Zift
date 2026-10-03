const std = @import("std");

const Method = @import("delta.zig").Method;
const ArchiveFormat = @import("archive.zig").Format;
const HDiffFormat = @import("hdiff.zig").Format;
const ui = @import("ui.zig");
const zstd_c = @import("compression/zstd_c.zig");

pub const MethodChoice = union(Method) {
    ziff,
    hdiff: HDiffFormat,
    file_delta,

    pub fn defaults(method: Method) MethodChoice {
        return switch (method) {
            .ziff => .ziff,
            .hdiff => .{ .hdiff = .w26 },
            .file_delta => .file_delta,
        };
    }

    fn parse(value: []const u8) ?MethodChoice {
        var parts = std.mem.splitScalar(u8, value, ':');
        const method = Method.parse(parts.first()) orelse return null;
        const variant = parts.next() orelse return defaults(method);
        if (method != .hdiff or parts.next() != null) return null;
        return .{ .hdiff = HDiffFormat.parse(variant) orelse return null };
    }
};

pub const FormatChoice = union(ArchiveFormat) {
    zip_store,
    zip_deflate: u4,
    tar_zstd: c_int,

    pub fn defaults(format: ArchiveFormat) FormatChoice {
        return switch (format) {
            .zip_store => .zip_store,
            .zip_deflate => .{ .zip_deflate = 1 },
            .tar_zstd => .{ .tar_zstd = 3 },
        };
    }

    fn parse(value: []const u8) ?FormatChoice {
        var parts = std.mem.splitScalar(u8, value, ':');
        const format = ArchiveFormat.parse(parts.first()) orelse return null;
        const level_text = parts.next() orelse return defaults(format);
        if (parts.next() != null) return null;
        return switch (format) {
            .zip_store => null,
            .zip_deflate => blk: {
                const level = std.fmt.parseInt(u4, level_text, 10) catch return null;
                if (level < 1 or level > 9) return null;
                break :blk .{ .zip_deflate = level };
            },
            .tar_zstd => blk: {
                const level = std.fmt.parseInt(c_int, level_text, 10) catch return null;
                if (level < 1 or level > zstd_c.ZSTD_maxCLevel()) return null;
                break :blk .{ .tar_zstd = level };
            },
        };
    }

    pub fn compressionLevels(self: FormatChoice) @import("archive.zig").CompressionLevels {
        return switch (self) {
            .zip_store => .{},
            .zip_deflate => |level| .{ .deflate = level },
            .tar_zstd => |level| .{ .zstd = level },
        };
    }
};

pub const Parsed = struct {
    assume_yes: bool = false,
    automatic: bool = false,
    minimum_memory: bool = false,
    verify_md5: bool = false,
    force: bool = false,
    operation: Operation,
};

pub const CreateChoices = struct {
    integration: ?bool = null,
    prefix: ?[]const u8 = null,
    source_version: ?[]const u8 = null,
    target_version: ?[]const u8 = null,
    method: ?MethodChoice = null,
    format: ?FormatChoice = null,
    continue_on_errors: ?bool = null,
    correct_target_manifest: ?bool = null,

    fn specified(self: CreateChoices) bool {
        return self.integration != null or self.prefix != null or
            self.source_version != null or self.target_version != null or
            self.method != null or self.format != null or
            self.continue_on_errors != null or self.correct_target_manifest != null;
    }
};

pub const Operation = union(enum) {
    clean: struct { directory: []const u8, complete: bool },
    make: struct {
        source: []const u8,
        target: []const u8,
        out: ?[]const u8,
        choices: CreateChoices = .{},
    },
    apply: struct { delta: []const u8, directory: []const u8 },
};

pub const ParseResult = union(enum) {
    ok: Parsed,
    problem: Problem,
    help,
};

pub const Problem = union(enum) {
    empty_arguments,
    empty_argument,
    unknown_option: []const u8,
    missing_value: []const u8,
    invalid_value: struct { option: []const u8, value: []const u8 },
    creation_options_not_applicable,
    format_not_applicable,
    home_not_found,
    path_not_found: []const u8,
    invalid_path: []const u8,
    delta_not_found: []const u8,
    invalid_combination,
};

const Classified = struct {
    path: []const u8,
    kind: Kind,

    const Kind = enum { directory, file, missing, invalid };
};

const Flag = enum { assume_yes, automatic, minimum_memory, verify_md5, force, complete_clean };

const ValueOption = enum {
    integration,
    prefix,
    source_version,
    target_version,
    method,
    format,
    continue_on_errors,
    correct_target_manifest,
};

const value_options = std.StaticStringMap(ValueOption).initComptime(.{
    .{ "--integration", .integration },
    .{ "--prefix", .prefix },
    .{ "--source-version", .source_version },
    .{ "--target-version", .target_version },
    .{ "--method", .method },
    .{ "--format", .format },
    .{ "--continue-on-errors", .continue_on_errors },
    .{ "--correct-target-manifest", .correct_target_manifest },
});

fn parseFlag(arg: []const u8) ?Flag {
    if (arg.len != 2 or arg[0] != '-') return null;
    return switch (arg[1]) {
        'y' => .assume_yes,
        'a' => .automatic,
        'm' => .minimum_memory,
        'v' => .verify_md5,
        'f' => .force,
        'c' => .complete_clean,
        else => null,
    };
}

pub fn parse(
    allocator: std.mem.Allocator,
    io: std.Io,
    args_src: std.process.Args,
    env: *std.process.Environ.Map,
) !ParseResult {
    var it = try std.process.Args.Iterator.initAllocator(args_src, allocator);
    defer it.deinit();
    _ = it.next();

    var options: Parsed = .{ .operation = undefined };
    var choices: CreateChoices = .{};
    var complete_clean = false;
    var positional_only = false;
    var classified: std.ArrayList(Classified) = .empty;

    while (it.next()) |arg| {
        if (!positional_only) {
            if (std.mem.eql(u8, arg, "--")) {
                positional_only = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
            if (parseFlag(arg)) |flag| {
                switch (flag) {
                    .assume_yes => options.assume_yes = true,
                    .automatic => options.automatic = true,
                    .minimum_memory => options.minimum_memory = true,
                    .verify_md5 => options.verify_md5 = true,
                    .force => options.force = true,
                    .complete_clean => complete_clean = true,
                }
                continue;
            }
            if (value_options.get(arg)) |option| {
                const value = it.next() orelse
                    return .{ .problem = .{ .missing_value = try allocator.dupe(u8, arg) } };
                if (try setChoice(allocator, &choices, option, arg, value)) |problem| return .{ .problem = problem };
                continue;
            }
            if (arg.len > 0 and arg[0] == '-') return .{ .problem = .{ .unknown_option = try allocator.dupe(u8, arg) } };
        }
        if (arg.len == 0) return .{ .problem = .empty_argument };

        const expanded = expandHome(allocator, env, arg) catch |err| switch (err) {
            error.HomeNotFound => return .{ .problem = .home_not_found },
            else => |e| return e,
        };
        try classified.append(allocator, .{ .path = expanded, .kind = try classifyPath(io, expanded) });
    }

    if (classified.items.len == 0) return .{ .problem = .empty_arguments };

    const items = classified.items;
    if (items.len == 1) {
        return switch (items[0].kind) {
            .directory => resolved(options, choices, .{ .clean = .{ .directory = items[0].path, .complete = complete_clean } }),
            .missing => .{ .problem = .{ .path_not_found = items[0].path } },
            .invalid => .{ .problem = .{ .invalid_path = items[0].path } },
            .file => .{ .problem = .invalid_combination },
        };
    }

    if (complete_clean) return .{ .problem = .invalid_combination };

    if (items.len == 2) {
        if (items[0].kind == .directory and items[1].kind == .directory) {
            return resolved(options, choices, .{ .make = .{
                .source = items[0].path,
                .target = items[1].path,
                .out = null,
            } });
        }
        for (0..2) |index| {
            const other = 1 - index;
            if (items[other].kind != .directory) continue;
            if (items[index].kind == .file) return resolved(options, choices, .{ .apply = .{ .delta = items[index].path, .directory = items[other].path } });
            if (items[index].kind == .missing) return .{ .problem = .{ .delta_not_found = items[index].path } };
        }
        for (items) |item| switch (item.kind) {
            .missing => return .{ .problem = .{ .path_not_found = item.path } },
            .invalid => return .{ .problem = .{ .invalid_path = item.path } },
            else => {},
        };
        return .{ .problem = .invalid_combination };
    }

    if (items.len == 3) {
        for (0..3) |index| {
            const source: usize = if (index == 0) 1 else 0;
            const target: usize = if (index == 2) 1 else 2;
            if (items[index].kind == .directory and index != 2) continue;
            if (items[source].kind != .directory or items[target].kind != .directory or items[index].kind == .invalid) continue;
            return resolved(options, choices, .{ .make = .{
                .source = items[source].path,
                .target = items[target].path,
                .out = items[index].path,
            } });
        }
        for (items[0..2]) |item| switch (item.kind) {
            .missing => return .{ .problem = .{ .path_not_found = item.path } },
            .invalid => return .{ .problem = .{ .invalid_path = item.path } },
            else => {},
        };
        if (items[2].kind == .invalid) return .{ .problem = .{ .invalid_path = items[2].path } };
        return .{ .problem = .invalid_combination };
    }

    for (items) |item| switch (item.kind) {
        .missing => return .{ .problem = .{ .path_not_found = item.path } },
        .invalid => return .{ .problem = .{ .invalid_path = item.path } },
        else => {},
    };
    return .{ .problem = .invalid_combination };
}

fn resolved(options: Parsed, choices: CreateChoices, operation: Operation) ParseResult {
    var result = options;
    result.operation = operation;
    switch (result.operation) {
        .make => |*make| {
            make.choices = choices;
            if (choices.method) |method| {
                if (std.meta.activeTag(method) == .ziff and choices.format != null)
                    return .{ .problem = .format_not_applicable };
            }
        },
        else => if (choices.specified()) return .{ .problem = .creation_options_not_applicable },
    }
    return .{ .ok = result };
}

fn setChoice(allocator: std.mem.Allocator, choices: *CreateChoices, option: ValueOption, name: []const u8, value: []const u8) !?Problem {
    switch (option) {
        .integration, .continue_on_errors, .correct_target_manifest => {
            const enabled = parseYesNo(value) orelse return invalidValue(allocator, name, value);
            switch (option) {
                .integration => choices.integration = enabled,
                .continue_on_errors => choices.continue_on_errors = enabled,
                .correct_target_manifest => choices.correct_target_manifest = enabled,
                else => unreachable,
            }
        },
        .prefix, .source_version, .target_version => {
            if (!isNamePart(value)) return invalidValue(allocator, name, value);
            const owned = try allocator.dupe(u8, value);
            switch (option) {
                .prefix => choices.prefix = owned,
                .source_version => choices.source_version = owned,
                .target_version => choices.target_version = owned,
                else => unreachable,
            }
        },
        .method => choices.method = MethodChoice.parse(value) orelse return invalidValue(allocator, name, value),
        .format => choices.format = FormatChoice.parse(value) orelse return invalidValue(allocator, name, value),
    }
    return null;
}

fn invalidValue(allocator: std.mem.Allocator, option: []const u8, value: []const u8) !?Problem {
    return .{ .invalid_value = .{ .option = try allocator.dupe(u8, option), .value = try allocator.dupe(u8, value) } };
}

fn parseYesNo(value: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(value, "y")) return true;
    if (std.ascii.eqlIgnoreCase(value, "n")) return false;
    return null;
}

fn expandHome(allocator: std.mem.Allocator, env: *std.process.Environ.Map, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or arg[0] != '~') return allocator.dupe(u8, arg);
    if (arg.len > 1 and arg[1] != '/' and arg[1] != '\\') return allocator.dupe(u8, arg);
    const home = env.get("HOME") orelse env.get("USERPROFILE") orelse return error.HomeNotFound;
    if (arg.len == 1) return allocator.dupe(u8, home);

    return std.fs.path.join(allocator, &.{ home, arg[2..] });
}

fn classifyPath(io: std.Io, path: []const u8) !Classified.Kind {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => |e| return e,
    };
    return switch (stat.kind) {
        .directory => .directory,
        .file => .file,
        else => .invalid,
    };
}

pub fn confirm(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, assume_yes: bool) !bool {
    try out.writeByte('\n');
    if (assume_yes) return true;
    return promptYesNo(allocator, io, out, "Continue?", false);
}

pub fn promptYesNo(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, label: []const u8, default: bool) !bool {
    while (true) {
        try ui.writePromptLabel(out, label);
        try out.writeByte(' ');
        try ui.writePromptDefault(out, if (default) "Y/n" else "y/N");
        try writeInlinePromptEnd(io, out);
        const input = (readPromptLine(allocator, io, out) catch |err| switch (err) {
            error.InputTooLong => continue,
            else => |e| return e,
        }) orelse return error.InputRequired;
        if (input.len == 0) return default;
        if (parseYesNo(input)) |enabled| return enabled;
        try ui.writeWarningLine(out, "Enter y or n.");
    }
}

pub fn promptPrefix(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    default: ?[]const u8,
) !?[]const u8 {
    while (true) {
        try ui.writePromptLabel(out, "Prefix");
        try out.writeByte(' ');
        try ui.writeChoice(out, "text/n");
        try out.writeByte(' ');
        try ui.writePromptDefault(out, default orelse "n");
        try writeInlinePromptEnd(io, out);
        const input = (readPromptLine(allocator, io, out) catch |err| switch (err) {
            error.InputTooLong => continue,
            else => |e| return e,
        }) orelse return error.InputRequired;
        if (input.len == 0) return if (default) |value| try allocator.dupe(u8, value) else null;
        if (input.len == 1 and (input[0] == 'n' or input[0] == 'N')) return null;
        if (!isNamePart(input)) {
            try ui.writeWarningLine(out, "Invalid prefix.");
            continue;
        }
        return input;
    }
}

pub fn promptVersion(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    label: []const u8,
    default: ?[]const u8,
) ![]const u8 {
    while (true) {
        try ui.writePromptLabel(out, label);
        try out.writeByte(' ');
        try ui.writeChoice(out, "text");
        if (default) |value| {
            try out.writeByte(' ');
            try ui.writePromptDefault(out, value);
        }
        try writeInlinePromptEnd(io, out);
        const input = (readPromptLine(allocator, io, out) catch |err| switch (err) {
            error.InputTooLong => continue,
            else => |e| return e,
        }) orelse return error.InputRequired;
        if (input.len != 0) {
            if (!isNamePart(input)) {
                try ui.writeWarningLine(out, "Invalid version.");
                continue;
            }
            return input;
        }
        if (default) |value| return allocator.dupe(u8, value);
    }
}

pub fn promptMethod(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, default: ?Method) !Method {
    while (true) {
        try ui.writePromptLabel(out, "Method");
        try out.writeByte(' ');
        try ui.writeChoice(out, "1-3");
        if (default) |value| {
            var buf: [8]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "{d}", .{@backingInt(value) + 1});
            try out.writeByte(' ');
            try ui.writePromptDefault(out, text);
        }
        try out.writeAll(":\n");
        try ui.writeOption(out, "1", "Ziff");
        try ui.writeOption(out, "2", "HDiff");
        try ui.writeOption(out, "3", "File Delta");
        try out.flush();
        const input = (readMenuLine(allocator, io, out) catch |err| switch (err) {
            error.InputTooLong => continue,
            else => |e| return e,
        }) orelse return error.InputRequired;
        if (input.len == 0) {
            if (default) |value| return value;
            continue;
        }
        if (Method.parse(input)) |value| return value;
        try ui.writeWarningLine(out, "Invalid method.");
    }
}

pub fn promptFormat(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    default: ArchiveFormat,
) !ArchiveFormat {
    while (true) {
        var buf: [8]u8 = undefined;
        const number = try std.fmt.bufPrint(&buf, "{d}", .{@backingInt(default) + 1});
        try ui.writePromptLabel(out, "Format");
        try out.writeByte(' ');
        try ui.writeChoice(out, "1-3");
        try out.writeByte(' ');
        try ui.writePromptDefault(out, number);
        try out.writeAll(":\n");
        try ui.writeOption(out, "1", "ZIP using Store");
        try ui.writeOption(out, "2", "ZIP using Deflate");
        try ui.writeOption(out, "3", "Tarball using Zstandard");
        try out.flush();
        const input = (readMenuLine(allocator, io, out) catch |err| switch (err) {
            error.InputTooLong => continue,
            else => |e| return e,
        }) orelse return error.InputRequired;
        if (input.len == 0) return default;
        if (ArchiveFormat.parse(input)) |value| return value;
        try ui.writeWarningLine(out, "Invalid format.");
    }
}

pub fn isNamePart(value: []const u8) bool {
    return value.len != 0 and std.mem.indexOfAny(u8, value, "/\\\x00") == null;
}

fn writeInlinePromptEnd(io: std.Io, out: *std.Io.Writer) !void {
    var stdin_file = std.Io.File.stdin();
    if (stdin_file.isTty(io) catch false) try out.writeAll(": ") else try out.writeByte(':');
    try out.flush();
}

fn finishPromptLine(io: std.Io, out: *std.Io.Writer) !void {
    var stdin_file = std.Io.File.stdin();
    if (!(stdin_file.isTty(io) catch false)) try out.writeByte('\n');
}

fn readMenuLine(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer) !?[]const u8 {
    var stdin_file = std.Io.File.stdin();
    if (stdin_file.isTty(io) catch false) {
        try out.writeAll("    ");
        try out.flush();
    }
    return readLine(allocator, io) catch |err| switch (err) {
        error.InputTooLong => {
            try ui.writeWarningLine(out, "Input is too long.");
            return error.InputTooLong;
        },
        else => |e| return e,
    };
}

fn readPromptLine(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer) !?[]const u8 {
    const input = readLine(allocator, io) catch |err| switch (err) {
        error.InputTooLong => {
            try finishPromptLine(io, out);
            try ui.writeWarningLine(out, "Input is too long.");
            return error.InputTooLong;
        },
        else => |e| return e,
    };
    try finishPromptLine(io, out);
    return input;
}

fn readLine(allocator: std.mem.Allocator, io: std.Io) !?[]const u8 {
    var input: [4096]u8 = undefined;
    var len: usize = 0;
    var too_long = false;
    var stdin_file = std.Io.File.stdin();
    var one: [1]u8 = undefined;
    var reader = stdin_file.readerStreaming(io, &one);
    while (true) {
        const ch = reader.interface.takeByte() catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            error.EndOfStream => if (len == 0 and !too_long) return null else break,
        };
        if (ch == '\n') break;
        if (too_long) continue;
        if (len == input.len) {
            too_long = true;
            continue;
        }
        input[len] = ch;
        len += 1;
    }
    if (too_long) return error.InputTooLong;
    const line = try allocator.dupe(u8, std.mem.trim(u8, input[0..len], " \t\r"));
    return line;
}

pub fn printProblem(w: *std.Io.Writer, problem: Problem) !void {
    try ui.writeErrorPrefix(w);
    switch (problem) {
        .empty_arguments => try w.writeAll(" no arguments given\n"),
        .empty_argument => try w.writeAll(" empty argument\n"),
        .unknown_option => |option| try w.print(" unknown option: {s}\n", .{option}),
        .missing_value => |option| try w.print(" missing value for {s}\n", .{option}),
        .invalid_value => |invalid| try w.print(" invalid value for {s}: {s}\n", .{ invalid.option, invalid.value }),
        .creation_options_not_applicable => try w.writeAll(" creation options require source and target directories\n"),
        .format_not_applicable => try w.writeAll(" --format requires File Delta or HDiff\n"),
        .home_not_found => try w.writeAll(" cannot expand ~ because HOME is not set\n"),
        .path_not_found => |path| try writeProblemPath(w, " path not found: ", path),
        .invalid_path => |path| try writeProblemPath(w, " path is not a directory or file: ", path),
        .delta_not_found => |path| try writeProblemPath(w, " delta not found: ", path),
        .invalid_combination => try w.writeAll(" expected a directory, source and target directories, or a delta and directory\n"),
    }
}

fn writeProblemPath(w: *std.Io.Writer, message: []const u8, path: []const u8) !void {
    try w.writeAll(message);
    try w.writeAll(path);
    try w.writeByte('\n');
}

pub fn problemNeedsUsage(problem: Problem) bool {
    return switch (problem) {
        .empty_arguments, .empty_argument, .unknown_option, .missing_value, .invalid_value, .creation_options_not_applicable, .format_not_applicable, .invalid_combination => true,
        else => false,
    };
}

pub fn printUsage(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\Usage:
        \\  zift <directory>                Clean supported software
        \\  zift <source> <target> [out]    Create delta
        \\  zift <delta> <directory>        Apply delta
        \\
        \\Options:
        \\  -a  Use detected values and defaults
        \\  -c  Complete Clean
        \\  -m  Lower matching memory; slower creation
        \\  -f  Apply despite low disk space
        \\  -y  Skip final confirmation
        \\  -v  Verify available content hashes
        \\  -h, --help  Show usage
        \\
        \\Creation choices:
        \\  --integration y|n
        \\  --prefix text|n
        \\  --source-version text
        \\  --target-version text
        \\  --method ziff|hdiff[:w26|h13|sf20]|file  Or 1|2|3 (default 1)
        \\  --format zip-store|zip-deflate[:N]|tar-zstd[:N]
        \\    Deflate: 1..9 (default 1); Zstd: 1..22 (default 3)
        \\  --continue-on-errors y|n
        \\  --correct-target-manifest y|n  Correct reported entries in the delta
        \\  Unspecified choices prompt without -a.
        \\
    );
}

test "only assigned single-letter options are recognized" {
    try std.testing.expectEqual(Flag.force, parseFlag("-f").?);
    try std.testing.expectEqual(Flag.automatic, parseFlag("-a").?);
    try std.testing.expect(parseFlag("--force") == null);
    try std.testing.expect(parseFlag("--writer=zig") == null);
    try std.testing.expect(parseFlag("-force") == null);
    try std.testing.expect(parseFlag("-x") == null);
}

test "unknown option survives argument iterator teardown" {
    var storage: [1024]u8 = undefined;
    var buffer_allocator = std.heap.FixedBufferAllocator.init(&storage);
    const allocator = buffer_allocator.allocator();
    var environ = std.process.Environ.Map.init(allocator);
    defer environ.deinit();
    const args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
        .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral("zift --unrecognized") }
    else
        .{ .vector = &.{ "zift", "--unrecognized" } };
    const result = try parse(allocator, std.testing.io, args, &environ);
    @memset(try allocator.alloc(u8, 512), 0x7f);
    try std.testing.expectEqualStrings("--unrecognized", result.problem.unknown_option);
}

test "choice options reject invalid values and inapplicable operations" {
    @setEvalBranchQuota(10_000);
    const cases = .{
        .{ "zift --method", &.{ "zift", "--method" }, "Error: missing value for --method\n" },
        .{ "zift --method=hdiff:h13", &.{ "zift", "--method=hdiff:h13" }, "Error: unknown option: --method=hdiff:h13\n" },
        .{ "zift --format=tar-zstd:5", &.{ "zift", "--format=tar-zstd:5" }, "Error: unknown option: --format=tar-zstd:5\n" },
        .{ "zift --method wrong", &.{ "zift", "--method", "wrong" }, "Error: invalid value for --method: wrong\n" },
        .{ "zift --integration maybe", &.{ "zift", "--integration", "maybe" }, "Error: invalid value for --integration: maybe\n" },
        .{ "zift --integration yes", &.{ "zift", "--integration", "yes" }, "Error: invalid value for --integration: yes\n" },
        .{ "zift --continue-on-errors no", &.{ "zift", "--continue-on-errors", "no" }, "Error: invalid value for --continue-on-errors: no\n" },
        .{ "zift --correct-target-manifest true", &.{ "zift", "--correct-target-manifest", "true" }, "Error: invalid value for --correct-target-manifest: true\n" },
        .{ "zift --hdiff-format", &.{ "zift", "--hdiff-format" }, "Error: unknown option: --hdiff-format\n" },
        .{ "zift --zstd-level", &.{ "zift", "--zstd-level" }, "Error: unknown option: --zstd-level\n" },
        .{ "zift --deflate-level", &.{ "zift", "--deflate-level" }, "Error: unknown option: --deflate-level\n" },
        .{ "zift --method ziff:5", &.{ "zift", "--method", "ziff:5" }, "Error: invalid value for --method: ziff:5\n" },
        .{ "zift --method file:5", &.{ "zift", "--method", "file:5" }, "Error: invalid value for --method: file:5\n" },
        .{ "zift --method hdiff:12", &.{ "zift", "--method", "hdiff:12" }, "Error: invalid value for --method: hdiff:12\n" },
        .{ "zift --method hdiff:", &.{ "zift", "--method", "hdiff:" }, "Error: invalid value for --method: hdiff:\n" },
        .{ "zift --method hdiff:wrong", &.{ "zift", "--method", "hdiff:wrong" }, "Error: invalid value for --method: hdiff:wrong\n" },
        .{ "zift --method hdiff:h13:12", &.{ "zift", "--method", "hdiff:h13:12" }, "Error: invalid value for --method: hdiff:h13:12\n" },
        .{ "zift --format zip-store:3", &.{ "zift", "--format", "zip-store:3" }, "Error: invalid value for --format: zip-store:3\n" },
        .{ "zift --format zip-deflate:0", &.{ "zift", "--format", "zip-deflate:0" }, "Error: invalid value for --format: zip-deflate:0\n" },
        .{ "zift --format zip-deflate:10", &.{ "zift", "--format", "zip-deflate:10" }, "Error: invalid value for --format: zip-deflate:10\n" },
        .{ "zift --format tar-zstd:-1", &.{ "zift", "--format", "tar-zstd:-1" }, "Error: invalid value for --format: tar-zstd:-1\n" },
        .{ "zift --format tar-zstd:0", &.{ "zift", "--format", "tar-zstd:0" }, "Error: invalid value for --format: tar-zstd:0\n" },
        .{ "zift --format tar-zstd:23", &.{ "zift", "--format", "tar-zstd:23" }, "Error: invalid value for --format: tar-zstd:23\n" },
        .{ "zift --format tar-zstd:", &.{ "zift", "--format", "tar-zstd:" }, "Error: invalid value for --format: tar-zstd:\n" },
        .{ "zift --format tar-zstd:5:6", &.{ "zift", "--format", "tar-zstd:5:6" }, "Error: invalid value for --format: tar-zstd:5:6\n" },
        .{ "zift --source-version \"\"", &.{ "zift", "--source-version", "" }, "Error: invalid value for --source-version: \n" },
        .{ "zift . --prefix n", &.{ "zift", ".", "--prefix", "n" }, "Error: creation options require source and target directories\n" },
        .{ "zift . . --method ziff --format 1", &.{ "zift", ".", ".", "--method", "ziff", "--format", "1" }, "Error: --format requires File Delta or HDiff\n" },
    };
    inline for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var environ = std.process.Environ.Map.init(allocator);
        defer environ.deinit();
        const args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
            .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral(case[0]) }
        else
            .{ .vector = case[1] };
        const result = try parse(allocator, std.testing.io, args, &environ);
        var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        try printProblem(&output.writer, result.problem);
        try std.testing.expectEqualStrings(case[2], output.written());
    }
}

test "creation choices preserve explicit values and positional ordering" {
    @setEvalBranchQuota(10_000);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var environ = std.process.Environ.Map.init(allocator);
    defer environ.deinit();
    const args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
        .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral("zift --integration Y . --prefix n --source-version version-one --target-version version-two --method hdiff:HDIFF13 --format tar-zstd:22 --continue-on-errors y --correct-target-manifest N -a -y choice.tar.zst ..") }
    else
        .{ .vector = &.{ "zift", "--integration", "Y", ".", "--prefix", "n", "--source-version", "version-one", "--target-version", "version-two", "--method", "hdiff:HDIFF13", "--format", "tar-zstd:22", "--continue-on-errors", "y", "--correct-target-manifest", "N", "-a", "-y", "choice.tar.zst", ".." } };
    const result = try parse(allocator, std.testing.io, args, &environ);
    try std.testing.expect(result.ok.automatic and result.ok.assume_yes);
    const make = result.ok.operation.make;
    try std.testing.expectEqualStrings(".", make.source);
    try std.testing.expectEqualStrings("..", make.target);
    try std.testing.expectEqualStrings("choice.tar.zst", make.out.?);
    try std.testing.expectEqual(true, make.choices.integration.?);
    try std.testing.expectEqualStrings("n", make.choices.prefix.?);
    try std.testing.expectEqualStrings("version-one", make.choices.source_version.?);
    try std.testing.expectEqualStrings("version-two", make.choices.target_version.?);
    try std.testing.expectEqual(Method.hdiff, std.meta.activeTag(make.choices.method.?));
    try std.testing.expectEqual(ArchiveFormat.tar_zstd, std.meta.activeTag(make.choices.format.?));
    try std.testing.expectEqual(HDiffFormat.h13, make.choices.method.?.hdiff);
    try std.testing.expectEqual(@as(c_int, 22), make.choices.format.?.tar_zstd);
    try std.testing.expectEqual(true, make.choices.continue_on_errors.?);
    try std.testing.expectEqual(false, make.choices.correct_target_manifest.?);

    inline for (.{ .{ "1", Method.ziff }, .{ "2", Method.hdiff }, .{ "3", Method.file_delta } }) |case| {
        const numeric_args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
            .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral("zift . . --method " ++ case[0]) }
        else
            .{ .vector = &.{ "zift", ".", ".", "--method", case[0] } };
        const parsed = try parse(allocator, std.testing.io, numeric_args, &environ);
        try std.testing.expectEqual(case[1], std.meta.activeTag(parsed.ok.operation.make.choices.method.?));
    }

    inline for (.{ .{ "hdiff", HDiffFormat.w26 }, .{ "hdiff:w26", HDiffFormat.w26 }, .{ "HDIFF:H13", HDiffFormat.h13 }, .{ "hdiff:sf20", HDiffFormat.sf20 } }) |case| {
        const variant_args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
            .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral("zift . . --method " ++ case[0]) }
        else
            .{ .vector = &.{ "zift", ".", ".", "--method", case[0] } };
        const parsed = try parse(allocator, std.testing.io, variant_args, &environ);
        try std.testing.expectEqual(case[1], parsed.ok.operation.make.choices.method.?.hdiff);
    }

    inline for (.{
        .{ "zip-store", FormatChoice.zip_store },
        .{ "zip-deflate", FormatChoice{ .zip_deflate = 1 } },
        .{ "zip-deflate:9", FormatChoice{ .zip_deflate = 9 } },
        .{ "tar-zstd", FormatChoice{ .tar_zstd = 3 } },
        .{ "tar-zstd:1", FormatChoice{ .tar_zstd = 1 } },
        .{ "TAR-ZSTD:22", FormatChoice{ .tar_zstd = 22 } },
    }) |case| {
        const format_args: std.process.Args = if (@import("builtin").target.os.tag == .windows)
            .{ .vector = std.unicode.utf8ToUtf16LeStringLiteral("zift . . --method file --format " ++ case[0]) }
        else
            .{ .vector = &.{ "zift", ".", ".", "--method", "file", "--format", case[0] } };
        const parsed = try parse(allocator, std.testing.io, format_args, &environ);
        try std.testing.expectEqualDeep(case[1], parsed.ok.operation.make.choices.format.?);
    }
}

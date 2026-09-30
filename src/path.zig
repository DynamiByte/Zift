const std = @import("std");
const builtin = @import("builtin");

pub fn validate(path: []const u8) !void {
    if (path.len == 0) return error.UnsafePath;
    if (path[0] == '/') return error.UnsafePath;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.UnsafePath;
    if (path.len > std.math.maxInt(u16)) return error.PathTooLongForZip;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0) return error.UnsafePath;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.UnsafePath;
    }
}

pub fn firstSymlinkAncestor(
    io: std.Io,
    directory_path: []const u8,
    paths: []const []const u8,
) !?[]const u8 {
    var directory = try std.Io.Dir.cwd().openDir(io, directory_path, .{ .access_sub_paths = true });
    defer directory.close(io);

    const scratch = std.heap.smp_allocator;
    var checked: std.StringHashMapUnmanaged(void) = .empty;
    defer checked.deinit(scratch);

    for (paths) |path| {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, start, '/')) |slash| {
            const ancestor = path[0..slash];
            start = slash + 1;
            const got = try checked.getOrPut(scratch, ancestor);
            if (got.found_existing) continue;
            got.value_ptr.* = {};

            const stat = directory.statFile(io, ancestor, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => continue,
                error.NotDir => break,
                else => |e| return e,
            };
            if (stat.kind == .sym_link) return ancestor;
            if (stat.kind != .directory) break;
        }
    }
    return null;
}

pub const WindowsCaseContext = struct {
    pub fn hash(_: WindowsCaseContext, value: []const u8) u64 {
        var hasher = std.hash.Wyhash.init(0);
        var iterator = std.unicode.Wtf8View.initUnchecked(value).iterator();
        while (iterator.nextCodepoint()) |codepoint| {
            const folded: u32 = if (codepoint <= std.math.maxInt(u16))
                std.os.windows.toUpperWtf16(@intCast(codepoint))
            else
                codepoint;
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, folded, .little);
            hasher.update(&bytes);
        }
        return hasher.final();
    }

    pub fn eql(_: WindowsCaseContext, a: []const u8, b: []const u8) bool {
        return std.os.windows.eqlIgnoreCaseWtf8(a, b);
    }
};

// Win32-reinterpreted destinations excluded
pub fn windowsPathCompatible(path: []const u8) bool {
    validate(path) catch return false;
    if (windowsUnsafeProbePath(path)) return false;
    _ = std.unicode.Wtf8View.init(path) catch return false;
    return true;
}

fn windowsUnsafeProbePath(path: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        for (part) |byte| if (byte < 0x20) return true;
        if (std.mem.indexOfAny(u8, part, "\\:<>\"|?*") != null) return true;
        if (part[part.len - 1] == ' ' or part[part.len - 1] == '.') return true;
        const base = if (std.mem.indexOfScalar(u8, part, '.')) |dot| part[0..dot] else part;
        if (windowsDosDeviceBase(base)) return true;
    }
    return false;
}

fn windowsDosDeviceBase(base: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(base, "CON") or
        std.ascii.eqlIgnoreCase(base, "PRN") or
        std.ascii.eqlIgnoreCase(base, "AUX") or
        std.ascii.eqlIgnoreCase(base, "NUL") or
        std.ascii.eqlIgnoreCase(base, "CONIN$") or
        std.ascii.eqlIgnoreCase(base, "CONOUT$") or
        // historical CLOCK$ device alias
        std.ascii.eqlIgnoreCase(base, "CLOCK$")) return true;

    if (base.len == 4 and
        (std.ascii.eqlIgnoreCase(base[0..3], "COM") or std.ascii.eqlIgnoreCase(base[0..3], "LPT")) and
        base[3] >= '1' and base[3] <= '9') return true;

    // Win32 COM/LPT superscript 1/2/3 aliases
    if (base.len == 5 and
        (std.ascii.eqlIgnoreCase(base[0..3], "COM") or std.ascii.eqlIgnoreCase(base[0..3], "LPT")) and
        (std.mem.eql(u8, base[3..], "¹") or
            std.mem.eql(u8, base[3..], "²") or
            std.mem.eql(u8, base[3..], "³"))) return true;
    return false;
}

test "logical path preserves literal backslash and colon" {
    try validate("a\\b");
    try validate("C:file");
}

test "logical path rejects unsafe components" {
    try std.testing.expectError(error.UnsafePath, validate("/absolute"));
    try std.testing.expectError(error.UnsafePath, validate("a/../b"));
    try std.testing.expectError(error.UnsafePath, validate("a//b"));
}

test "detects symbolic link target ancestor" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "real", .default_dir);
    try tmp.dir.symLink(io, "real", "link", .{});
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const got = try firstSymlinkAncestor(io, root, &.{"link/file.bin"});
    try std.testing.expectEqualStrings("link", got.?);
}

test "Windows compatibility rejects reinterpreted destinations and invalid WTF-8" {
    for ([_][]const u8{ "a\\b", "a:b", "CON", "com1.txt", "CONIN$", "conout$.txt", "CLOCK$", "COM¹.txt", "lpt²", "LPT³.bin", "name.", "control\x1fname" }) |path|
        try std.testing.expect(!windowsPathCompatible(path));
    try std.testing.expect(!windowsPathCompatible("C:/absolute"));
    try std.testing.expect(!windowsPathCompatible("..\\outside"));
    try std.testing.expect(!windowsPathCompatible("\\\\server\\share"));
    try std.testing.expect(!windowsPathCompatible("bad\xffname"));
    try std.testing.expect(windowsPathCompatible("safe/path.bin"));
}

// ziff / standard archive dispatch

const std = @import("std");
const ziff = @import("ziff.zig");

pub const Kind = enum {
    archive,
    ziff,
};

// malformed ziff: no format fallback
pub fn classifyFile(io: std.Io, file: std.Io.File) !Kind {
    const initial_size = try file.length(io);
    if (initial_size < ziff.magic.len) return .archive;

    var prefix: [ziff.magic.len]u8 = undefined;
    if (try file.readPositionalAll(io, &prefix, 0) != prefix.len) {
        return error.ContainerChangedDuringClassification;
    }
    if (try file.length(io) != initial_size) {
        return error.ContainerChangedDuringClassification;
    }
    return if (std.mem.eql(u8, &prefix, ziff.magic)) .ziff else .archive;
}

pub fn classify(io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !Kind {
    var file = try dir.openFile(io, sub_path, .{ .allow_directory = false });
    defer file.close(io);
    return classifyFile(io, file);
}

test "classifier routes Ziff magic exclusively to the current reader" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "archive.bin", .data = "PK\x03\x04" });
    try std.testing.expectEqual(Kind.archive, try classify(io, tmp.dir, "archive.bin"));

    try tmp.dir.writeFile(io, .{ .sub_path = "short.ziff", .data = ziff.magic });
    try std.testing.expectEqual(Kind.ziff, try classify(io, tmp.dir, "short.ziff"));

    var unsupported: [ziff.preamble_size]u8 = @splat(0xff);
    @memcpy(unsupported[0..ziff.magic.len], ziff.magic);
    try tmp.dir.writeFile(io, .{ .sub_path = "unsupported.ziff", .data = &unsupported });
    try std.testing.expectEqual(Kind.ziff, try classify(io, tmp.dir, "unsupported.ziff"));
}

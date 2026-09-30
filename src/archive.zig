const std = @import("std");
const ids = @import("core/ids.zig");

pub const Source = struct {
    path: []const u8,
    size: u64,
    // uncompressed BLAKE3
    expected_digest: ?ids.Digest = null,
    expected_md5: ?[16]u8 = null,
    data: Data,

    pub const Data = union(enum) {
        file,
        external: []const u8,
        bytes: []const u8,
    };
};

pub const CompressionLevels = struct {
    zstd: c_int = 3,
    deflate: u4 = 1,
};

pub const Format = enum(u8) {
    zip_store,
    zip_deflate,
    tar_zstd,

    pub fn extension(self: Format) []const u8 {
        return switch (self) {
            .zip_store, .zip_deflate => ".zip",
            .tar_zstd => ".tar.zst",
        };
    }

    pub fn parse(text: []const u8) ?Format {
        if (std.mem.eql(u8, text, "1") or std.ascii.eqlIgnoreCase(text, "zip-store")) return .zip_store;
        if (std.mem.eql(u8, text, "2") or std.ascii.eqlIgnoreCase(text, "zip-deflate")) return .zip_deflate;
        if (std.mem.eql(u8, text, "3") or std.ascii.eqlIgnoreCase(text, "tar-zstd")) return .tar_zstd;
        return null;
    }
};

const std = @import("std");

pub const File = struct {
    path: []const u8,
    size: u64,
    md5: [16]u8,
};

pub const Set = struct {
    entries: []File,
    map: std.StringHashMapUnmanaged(u32),

    pub fn find(self: Set, path: []const u8) ?File {
        const index = self.map.get(path) orelse return null;
        return self.entries[index];
    }

    pub fn contains(self: Set, path: []const u8) bool {
        return self.map.contains(path);
    }
};

pub const MetadataFile = struct {
    path: []const u8,
    bytes: []const u8,
};

pub fn hasMetadataPath(files: []const MetadataFile, path: []const u8) bool {
    for (files) |file| if (std.mem.eql(u8, file.path, path)) return true;
    return false;
}

pub const Snapshot = struct {
    expected: Set,
    metadata: []const MetadataFile,
};

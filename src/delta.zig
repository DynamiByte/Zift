const manifest_mod = @import("core/manifest.zig");
const std = @import("std");

const planner = @import("plan.zig");
const tree = @import("tree.zig");

pub const Method = enum {
    ziff,
    hdiff,
    file_delta,

    pub fn label(self: Method) []const u8 {
        return switch (self) {
            .file_delta => "File Delta",
            .hdiff => "HDiff",
            .ziff => "Ziff",
        };
    }

    pub fn parse(text: []const u8) ?Method {
        if (std.mem.eql(u8, text, "1") or std.ascii.eqlIgnoreCase(text, "ziff")) return .ziff;
        if (std.mem.eql(u8, text, "2") or std.ascii.eqlIgnoreCase(text, "hdiff")) return .hdiff;
        if (std.mem.eql(u8, text, "3") or std.ascii.eqlIgnoreCase(text, "file")) return .file_delta;
        return null;
    }
};

// separate control name; deletefiles.txt allowed as payload
pub const file_delta_deletion_path = ".zift-file-delta-deletefiles-v1.txt";
pub const source_identity_path = ".zift-source-v1.json";

pub fn deletionBytes(
    allocator: std.mem.Allocator,
    source: tree.Tree,
    plan: planner.Plan,
    source_metadata: ?[]const manifest_mod.MetadataFile,
    target_metadata: []const manifest_mod.MetadataFile,
) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    for (plan.removed) |index| {
        try writer.writer.writeAll(source.files[index].path);
        try writer.writer.writeByte('\n');
    }
    if (source_metadata) |files| {
        const scratch = std.heap.smp_allocator;
        var target_paths: std.StringHashMapUnmanaged(void) = .empty;
        defer target_paths.deinit(scratch);
        try target_paths.ensureTotalCapacity(scratch, @intCast(target_metadata.len));
        for (target_metadata) |target_file| target_paths.putAssumeCapacity(target_file.path, {});
        for (files) |source_file| if (!target_paths.contains(source_file.path)) {
            try writer.writer.writeAll(source_file.path);
            try writer.writer.writeByte('\n');
        };
    }
    return writer.toOwnedSlice();
}

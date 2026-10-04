const std = @import("std");

const archive = @import("../archive.zig");
const tar = @import("tar.zig");
const ui = @import("../ui.zig");
const zip = @import("zip.zig");

pub const Builder = union(enum) {
    zip_builder: zip.Builder,
    tar_builder: *tar.Builder,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        root: []const u8,
        path: []const u8,
        format: archive.Format,
        levels: archive.CompressionLevels,
    ) !Builder {
        return switch (format) {
            .zip_store, .zip_deflate => zip: {
                var builder = try zip.Builder.init(allocator, io, root, path, if (format == .zip_store) .store else .deflate);
                builder.deflate_level = levels.deflate;
                break :zip .{ .zip_builder = builder };
            },
            .tar_zstd => .{ .tar_builder = try tar.Builder.init(allocator, io, root, path, levels.zstd) },
        };
    }

    pub fn add(self: *Builder, source: archive.Source, progress: ?*ui.Progress) !void {
        switch (self.*) {
            .zip_builder => |*builder| try builder.add(source, progress),
            .tar_builder => |builder| try builder.add(source, progress),
        }
    }

    pub fn addAll(
        self: *Builder,
        sources: []const archive.Source,
        progress: ?*ui.Progress,
        workers: usize,
        byte_budget: u64,
    ) !void {
        switch (self.*) {
            .zip_builder => |*builder| try builder.addAll(sources, progress, workers, byte_budget),
            .tar_builder => |builder| for (sources) |source| try builder.add(source, progress),
        }
    }

    pub fn finish(self: *Builder) !void {
        switch (self.*) {
            .zip_builder => |*builder| try builder.finish(),
            .tar_builder => |builder| try builder.finish(),
        }
    }

    pub fn publish(self: *Builder, staging_path: []const u8, final_path: []const u8) !void {
        switch (self.*) {
            .zip_builder => |builder| try std.Io.Dir.cwd().renamePreserve(staging_path, std.Io.Dir.cwd(), final_path, builder.io),
            .tar_builder => |builder| try builder.publish(staging_path, final_path),
        }
    }

    pub fn deinit(self: *Builder) void {
        switch (self.*) {
            .zip_builder => |*builder| builder.deinit(),
            .tar_builder => |builder| builder.deinit(),
        }
    }
};

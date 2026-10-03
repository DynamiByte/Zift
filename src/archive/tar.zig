const std = @import("std");
const Thread = std.Thread;
const builtin = @import("builtin");
const fs = @import("../core/fs.zig");
const ids = @import("../core/ids.zig");
const archive = @import("../archive.zig");

const zstd_c = @import("../compression/zstd_c.zig");
const zstd = @import("../compression/zstd.zig");
const ui = @import("../ui.zig");
const path_util = @import("../path.zig");
const max_zstd_workers: usize = 16;
const ZstdOutput = struct {
    writer: std.Io.Writer,
    encoder: *zstd.Encoder,

    fn init(encoder: *zstd.Encoder, buffer: []u8) ZstdOutput {
        return .{
            .encoder = encoder,
            .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *ZstdOutput = @alignCast(@fieldParentPtr("writer", w));
        if (w.end != 0) {
            self.encoder.write(w.buffer[0..w.end]) catch return error.WriteFailed;
            w.end = 0;
        }
        var consumed: usize = 0;
        if (data.len == 0) return 0;
        for (data[0 .. data.len - 1]) |bytes| {
            if (bytes.len != 0) self.encoder.write(bytes) catch return error.WriteFailed;
            consumed += bytes.len;
        }
        const last = data[data.len - 1];
        var i: usize = 0;
        while (i < splat) : (i += 1) {
            if (last.len != 0) self.encoder.write(last) catch return error.WriteFailed;
            consumed += last.len;
        }
        return consumed;
    }
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    encoder: zstd.Encoder,
    zstd: ZstdOutput,
    zstd_buffer: [64 * 1024]u8 = undefined,
    tar: std.tar.Writer,
    publication_blocked: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        root_path: []const u8,
        out_path: []const u8,
        level: c_int,
    ) !*Builder {
        const self = try allocator.create(Builder);
        errdefer allocator.destroy(self);
        const file = try fs.createGuardedOutput(io, .cwd(), out_path);
        errdefer {
            file.close(io);
            std.Io.Dir.cwd().deleteFile(io, out_path) catch {};
        }
        const workers = @max(1, @min(max_zstd_workers, Thread.getCpuCount() catch 1));
        self.* = undefined;
        self.encoder = try zstd.Encoder.init(io, file, 0, level, @intCast(workers), null);
        errdefer self.encoder.deinit();
        self.allocator = allocator;
        self.io = io;
        self.root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .access_sub_paths = true });
        self.zstd = ZstdOutput.init(&self.encoder, &self.zstd_buffer);
        self.tar = .{ .underlying_writer = &self.zstd.writer };
        self.publication_blocked = false;
        return self;
    }

    pub fn deinit(self: *Builder) void {
        self.encoder.deinit();
        self.encoder.file.close(self.io);
        self.root.close(self.io);
        self.allocator.destroy(self);
    }

    pub fn add(self: *Builder, source: archive.Source, progress: ?*ui.Progress) !void {
        try path_util.validate(source.path);
        switch (source.data) {
            .bytes => |bytes| {
                if (bytes.len != source.size) return error.SizeMismatch;
                try self.tar.writeFileBytes(source.path, bytes, .{});
                if (source.expected_md5 != null) {
                    var actual: [16]u8 = undefined;
                    std.crypto.hash.Md5.hash(bytes, &actual, .{});
                    try self.verifyMd5(source.expected_md5, actual);
                }
                if (source.expected_digest != null)
                    try self.verifyDigest(source.expected_digest, ids.Digest.of(bytes));
            },
            .file => try self.addFile(
                self.root,
                source.path,
                source.path,
                source.size,
                source.expected_md5,
                source.expected_digest,
                true,
            ),
            .external => |path| try self.addFile(
                std.Io.Dir.cwd(),
                path,
                source.path,
                source.size,
                source.expected_md5,
                source.expected_digest,
                false,
            ),
        }
        if (progress) |p| {
            try p.addBytes(source.size);
            try p.finishFile();
        }
    }

    fn addFile(
        self: *Builder,
        dir: std.Io.Dir,
        disk_path: []const u8,
        archive_path: []const u8,
        expected_size: u64,
        expected_md5: ?[16]u8,
        expected_digest: ?ids.Digest,
        comptime beneath_root: bool,
    ) !void {
        var file = if (beneath_root)
            try fs.openReadBeneath(self.io, dir, disk_path)
        else
            try fs.openRead(self.io, dir, disk_path);
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.ExpectedFile;
        if (stat.size != expected_size) return error.SizeMismatch;
        var in_buf: [64 * 1024]u8 = undefined;
        var reader = file.reader(self.io, &in_buf);
        if (expected_md5 != null and expected_digest != null) {
            var digest_buf: [64 * 1024]u8 = undefined;
            var digest_reader = reader.interface.hashed(std.crypto.hash.Blake3.init(.{}), &digest_buf);
            var md5_buf: [64 * 1024]u8 = undefined;
            var md5_reader = digest_reader.reader.hashed(std.crypto.hash.Md5.init(.{}), &md5_buf);
            try self.tar.writeFileStream(archive_path, expected_size, &md5_reader.reader, .{});
            var actual_md5: [16]u8 = undefined;
            md5_reader.hasher.final(&actual_md5);
            try self.verifyMd5(expected_md5, actual_md5);
            var actual_digest: ids.Digest = undefined;
            digest_reader.hasher.final(&actual_digest.bytes);
            try self.verifyDigest(expected_digest, actual_digest);
        } else if (expected_md5 != null) {
            var md5_buf: [64 * 1024]u8 = undefined;
            var md5_reader = reader.interface.hashed(std.crypto.hash.Md5.init(.{}), &md5_buf);
            try self.tar.writeFileStream(archive_path, expected_size, &md5_reader.reader, .{});
            var actual_md5: [16]u8 = undefined;
            md5_reader.hasher.final(&actual_md5);
            try self.verifyMd5(expected_md5, actual_md5);
        } else if (expected_digest != null) {
            var digest_buf: [64 * 1024]u8 = undefined;
            var digest_reader = reader.interface.hashed(std.crypto.hash.Blake3.init(.{}), &digest_buf);
            try self.tar.writeFileStream(archive_path, expected_size, &digest_reader.reader, .{});
            var actual_digest: ids.Digest = undefined;
            digest_reader.hasher.final(&actual_digest.bytes);
            try self.verifyDigest(expected_digest, actual_digest);
        } else {
            try self.tar.writeFileStream(archive_path, expected_size, &reader.interface, .{});
        }
        const final_stat = try file.stat(self.io);
        if (final_stat.kind != .file) return error.ExpectedFile;
        if (final_stat.size != expected_size) return error.SizeMismatch;
    }

    fn verifyMd5(self: *Builder, expected: ?[16]u8, actual: [16]u8) !void {
        if (expected) |value| {
            if (!std.mem.eql(u8, &actual, &value)) {
                self.publication_blocked = true;
                return error.Md5Mismatch;
            }
        }
    }

    fn verifyDigest(
        self: *Builder,
        expected: ?ids.Digest,
        actual: ids.Digest,
    ) !void {
        if (expected) |value| {
            if (!actual.eql(value)) {
                self.publication_blocked = true;
                return error.DigestMismatch;
            }
        }
    }

    pub fn finish(self: *Builder) !void {
        if (self.publication_blocked) return error.DigestMismatch;
        try self.tar.finishPedantically();
        try self.zstd.writer.flush();
        self.encoder.finish() catch return error.ZstdCompressFailed;
    }
};

const ZstdInput = struct {
    io: std.Io,
    file: std.Io.File,
    owns_file: bool,
    stream: *zstd_c.ZstdDStream,
    reader: std.Io.Reader,
    input_buffer: [64 * 1024]u8 = undefined,
    output_buffer: [64 * 1024]u8 = undefined,
    input_pos: usize = 0,
    input_len: usize = 0,
    read_pos: u64,
    data_end: u64,
    frame_complete: bool = false,
    err: ?anyerror = null,

    fn init(self: *ZstdInput, io: std.Io, path: []const u8, data_offset: u64, data_end: u64) !void {
        const file = try fs.openRead(io, std.Io.Dir.cwd(), path);
        errdefer file.close(io);
        try self.initBorrowed(io, file, data_offset, data_end);
        self.owns_file = true;
    }

    fn initBorrowed(self: *ZstdInput, io: std.Io, file: std.Io.File, data_offset: u64, data_end: u64) !void {
        if (data_end <= data_offset) return error.InvalidZstdStream;
        const stream = zstd_c.ZSTD_createDStream() orelse return error.OutOfMemory;
        errdefer _ = zstd_c.ZSTD_freeDStream(stream);
        const init_result = zstd_c.ZSTD_initDStream(stream);
        if (zstd_c.ZSTD_isError(init_result) != 0) return error.ZstdDecompressFailed;
        self.* = .{
            .io = io,
            .file = file,
            .owns_file = false,
            .stream = stream,
            .reader = undefined,
            .read_pos = data_offset,
            .data_end = data_end,
        };
        self.reader = .{ .buffer = &self.output_buffer, .seek = 0, .end = 0, .vtable = &.{ .stream = read } };
    }

    fn deinit(self: *ZstdInput) void {
        _ = zstd_c.ZSTD_freeDStream(self.stream);
        if (self.owns_file) self.file.close(self.io);
    }

    fn read(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ZstdInput = @alignCast(@fieldParentPtr("reader", reader));
        const output_slice = limit.slice(try writer.writableSliceGreedy(1));
        if (output_slice.len == 0) return 0;

        while (true) {
            if (self.input_pos == self.input_len) {
                if (self.read_pos == self.data_end) {
                    if (self.frame_complete) return error.EndOfStream;
                    return self.fail(error.UnexpectedEof);
                }
                const remaining = self.data_end - self.read_pos;
                const count: usize = @intCast(@min(@as(u64, self.input_buffer.len), remaining));
                const got = self.file.readPositionalAll(self.io, self.input_buffer[0..count], self.read_pos) catch |err| return self.fail(err);
                if (got != count) return self.fail(error.UnexpectedEof);
                self.read_pos += got;
                self.input_pos = 0;
                self.input_len = got;
            }

            var input: zstd_c.ZstdInBuffer = .{
                .src = self.input_buffer[self.input_pos..self.input_len].ptr,
                .size = self.input_len - self.input_pos,
                .pos = 0,
            };
            var output: zstd_c.ZstdOutBuffer = .{
                .dst = output_slice.ptr,
                .size = output_slice.len,
                .pos = 0,
            };
            const result = zstd_c.ZSTD_decompressStream(self.stream, &output, &input);
            if (zstd_c.ZSTD_isError(result) != 0) {
                const err = if (zstd_c.ZSTD_getErrorCode(result) == zstd_c.zstd_error_checksum_wrong) error.ZstdChecksumMismatch else error.ZstdDecompressFailed;
                return self.fail(err);
            }
            self.input_pos += input.pos;
            self.frame_complete = result == 0;
            if (output.pos != 0) {
                writer.advance(output.pos);
                return output.pos;
            }
            if (input.pos == 0) return self.fail(error.ZstdDecompressFailed);
        }
    }

    fn fail(self: *ZstdInput, err: anyerror) error{ReadFailed} {
        self.err = err;
        return error.ReadFailed;
    }

    fn actualError(self: *const ZstdInput, err: anyerror) anyerror {
        if (err == error.ReadFailed) return self.err orelse err;
        return err;
    }
};

pub const Stream = struct {
    allocator: std.mem.Allocator,
    decoder: ZstdInput,
    iter: std.tar.Iterator,
    name_buffer: [std.fs.max_path_bytes]u8 = undefined,
    link_buffer: [std.fs.max_path_bytes]u8 = undefined,
    seen: std.StringHashMapUnmanaged(void) = .empty,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, path: []const u8, data_offset: u64, data_end: u64) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);
        self.* = undefined;
        try self.decoder.init(io, path, data_offset, data_end);
        errdefer self.decoder.deinit();
        self.allocator = allocator;
        self.iter = .init(&self.decoder.reader, .{ .file_name_buffer = &self.name_buffer, .link_name_buffer = &self.link_buffer });
        self.seen = .empty;
        return self;
    }

    pub fn initBorrowed(
        allocator: std.mem.Allocator,
        io: std.Io,
        file: std.Io.File,
        data_offset: u64,
        data_end: u64,
    ) !*Stream {
        const self = try allocator.create(Stream);
        errdefer allocator.destroy(self);
        self.* = undefined;
        try self.decoder.initBorrowed(io, file, data_offset, data_end);
        errdefer self.decoder.deinit();
        self.allocator = allocator;
        self.iter = .init(&self.decoder.reader, .{ .file_name_buffer = &self.name_buffer, .link_name_buffer = &self.link_buffer });
        self.seen = .empty;
        return self;
    }

    pub fn deinit(self: *Stream) void {
        self.decoder.deinit();
        var it = self.seen.keyIterator();
        while (it.next()) |name| self.allocator.free(name.*);
        self.seen.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn next(self: *Stream) !?std.tar.Iterator.File {
        const file = self.iter.next() catch |err| return self.decoder.actualError(err);
        if (file == null) {
            _ = self.decoder.reader.discardRemaining() catch |err| return self.decoder.actualError(err);
            return null;
        }
        const path = if (file.?.kind == .directory and std.mem.endsWith(u8, file.?.name, "/"))
            file.?.name[0 .. file.?.name.len - 1]
        else
            file.?.name;
        try path_util.validate(path);
        var result = file.?;
        result.name = path;
        if (result.kind == .directory) return result;

        const name = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(name);
        const got = try self.seen.getOrPut(self.allocator, name);
        if (got.found_existing) return error.DuplicateTarPath;
        got.value_ptr.* = {};
        result.name = name;
        return result;
    }

    pub fn extractCurrentTo(self: *Stream, io: std.Io, file: std.tar.Iterator.File, path: []const u8, progress: ?*ui.Progress) !void {
        var out_file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer out_file.close(io);
        var out_buf: [64 * 1024]u8 = undefined;
        var writer = out_file.writer(io, &out_buf);
        self.iter.streamRemaining(file, &writer.interface) catch |err| return self.decoder.actualError(err);
        try writer.end();
        if (progress) |p| try p.addBytes(file.size);
    }

    pub fn extractCurrentToGuardedFile(
        self: *Stream,
        io: std.Io,
        file: std.tar.Iterator.File,
        out_file: std.Io.File,
        progress: ?*ui.Progress,
    ) !void {
        _ = try self.extractCurrentToGuardedFileMd5(io, file, out_file, progress);
    }

    pub fn extractCurrentToGuardedFileMd5(
        self: *Stream,
        io: std.Io,
        file: std.tar.Iterator.File,
        out_file: std.Io.File,
        progress: ?*ui.Progress,
    ) ![16]u8 {
        try fs.validateGuardedOutput(io, out_file, 0);
        var out_buf: [64 * 1024]u8 = undefined;
        var writer = out_file.writer(io, &out_buf);
        var hash_buf: [64 * 1024]u8 = undefined;
        var hashed = writer.interface.hashed(std.crypto.hash.Md5.init(.{}), &hash_buf);
        self.iter.streamRemaining(file, &hashed.writer) catch |err| return self.decoder.actualError(err);
        try hashed.writer.flush();
        // end() truncates, masking an unexpected size change
        try writer.flush();
        try out_file.sync(io);
        const stat = try out_file.stat(io);
        if (stat.kind != .file or stat.nlink != 1) return error.UnsafeGuardedOutput;
        if (stat.size != file.size) return error.SizeMismatch;
        try fs.validateGuardedOutput(io, out_file, file.size);
        if (progress) |p| try p.addBytes(file.size);
        var md5: [16]u8 = undefined;
        hashed.hasher.final(&md5);
        return md5;
    }

    pub fn hashCurrentMd5(
        self: *Stream,
        file: std.tar.Iterator.File,
        progress: ?*ui.Progress,
    ) ![16]u8 {
        var discard_buffer: [64 * 1024]u8 = undefined;
        var sink: std.Io.Writer.Discarding = .init(&discard_buffer);
        var hash_buf: [64 * 1024]u8 = undefined;
        var hashed = sink.writer.hashed(std.crypto.hash.Md5.init(.{}), &hash_buf);
        self.iter.streamRemaining(file, &hashed.writer) catch |err| return self.decoder.actualError(err);
        try hashed.writer.flush();
        if (sink.fullCount() != file.size) return error.SizeMismatch;
        if (progress) |p| try p.addBytes(file.size);
        var md5: [16]u8 = undefined;
        hashed.hasher.final(&md5);
        return md5;
    }

    pub fn readCurrentPrefixAlloc(self: *Stream, allocator: std.mem.Allocator, file: std.tar.Iterator.File, max_size: u64) ![]u8 {
        const size = @min(file.size, max_size);
        const bytes = try allocator.alloc(u8, @intCast(size));
        errdefer allocator.free(bytes);
        self.decoder.reader.readSliceAll(bytes) catch |err| return self.decoder.actualError(err);
        self.iter.unread_file_bytes -= size;
        return bytes;
    }

    pub const PrefixMd5 = struct {
        bytes: []u8,
        md5: [16]u8,
    };

    pub fn readCurrentPrefixAllocMd5(
        self: *Stream,
        allocator: std.mem.Allocator,
        file: std.tar.Iterator.File,
        max_size: u64,
    ) !PrefixMd5 {
        const prefix_size = @min(file.size, max_size);
        const bytes = try allocator.alloc(u8, @intCast(prefix_size));
        errdefer allocator.free(bytes);

        var hasher = std.crypto.hash.Md5.init(.{});
        self.decoder.reader.readSliceAll(bytes) catch |err| return self.decoder.actualError(err);
        self.iter.unread_file_bytes -= prefix_size;
        hasher.update(bytes);

        var remaining = file.size - prefix_size;
        var buffer: [64 * 1024]u8 = undefined;
        while (remaining != 0) {
            const count_u64 = @min(remaining, @as(u64, buffer.len));
            const count: usize = @intCast(count_u64);
            self.decoder.reader.readSliceAll(buffer[0..count]) catch |err| return self.decoder.actualError(err);
            self.iter.unread_file_bytes -= count_u64;
            hasher.update(buffer[0..count]);
            remaining -= count_u64;
        }

        var md5: [16]u8 = undefined;
        hasher.final(&md5);
        return .{ .bytes = bytes, .md5 = md5 };
    }

    pub fn readCurrentAlloc(self: *Stream, allocator: std.mem.Allocator, file: std.tar.Iterator.File, max_size: u64) ![]u8 {
        if (file.size > max_size) return error.FileTooLarge;
        const bytes = try allocator.alloc(u8, @intCast(file.size));
        errdefer allocator.free(bytes);
        var writer = std.Io.Writer.fixed(bytes);
        self.iter.streamRemaining(file, &writer) catch |err| return self.decoder.actualError(err);
        return bytes;
    }

    pub fn discardCurrent(self: *Stream, file: std.tar.Iterator.File) !void {
        self.decoder.reader.discardAll64(file.size) catch |err| return self.decoder.actualError(err);
        self.iter.unread_file_bytes -= file.size;
    }
};

test "BLAKE3 publication guard preserves tar bytes for every source kind" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "root.bin", .data = "root bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "spool.bin", .data = "spool bytes" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const spool_path = try std.fs.path.join(allocator, &.{ root, "spool.bin" });

    const TestBuilder = struct {
        fn build(
            alloc: std.mem.Allocator,
            test_io: std.Io,
            root_path: []const u8,
            output_path: []const u8,
            external_path: []const u8,
            guarded: bool,
        ) !void {
            const root_bytes = "root bytes";
            const spool_bytes = "spool bytes";
            const memory_bytes = "memory bytes";
            const builder = try Builder.init(alloc, test_io, root_path, output_path, 3);
            defer builder.deinit();
            try builder.add(.{
                .path = "root.bin",
                .size = root_bytes.len,
                .expected_digest = if (guarded) ids.Digest.of(root_bytes) else null,
                .data = .file,
            }, null);
            try builder.add(.{
                .path = "external.bin",
                .size = spool_bytes.len,
                .expected_digest = if (guarded) ids.Digest.of(spool_bytes) else null,
                .data = .{ .external = external_path },
            }, null);
            try builder.add(.{
                .path = "memory.bin",
                .size = memory_bytes.len,
                .expected_digest = if (guarded) ids.Digest.of(memory_bytes) else null,
                .data = .{ .bytes = memory_bytes },
            }, null);
            try builder.finish();
        }
    };

    const plain_path = try std.fs.path.join(allocator, &.{ root, "plain.tar.zst" });
    const guarded_path = try std.fs.path.join(allocator, &.{ root, "guarded.tar.zst" });
    try TestBuilder.build(allocator, io, root, plain_path, spool_path, false);
    try TestBuilder.build(allocator, io, root, guarded_path, spool_path, true);
    const plain = try tmp.dir.readFileAlloc(io, "plain.tar.zst", allocator, .limited(1024 * 1024));
    const guarded = try tmp.dir.readFileAlloc(io, "guarded.tar.zst", allocator, .limited(1024 * 1024));
    try std.testing.expectEqualSlices(u8, plain, guarded);
}

test "tar spool mutation fails the BLAKE3 guard and blocks finalization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "spool.bin", .data = "GOOD" });
    const expected = ids.Digest.of("GOOD");
    try tmp.dir.writeFile(io, .{ .sub_path = "spool.bin", .data = "EVIL" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const spool_path = try std.fs.path.join(allocator, &.{ root, "spool.bin" });
    const tar_path = try std.fs.path.join(allocator, &.{ root, "mutated.tar.zst" });

    const builder = try Builder.init(allocator, io, root, tar_path, 3);
    defer builder.deinit();
    try std.testing.expectError(error.DigestMismatch, builder.add(.{
        .path = "payload.bin",
        .size = 4,
        .expected_digest = expected,
        .data = .{ .external = spool_path },
    }, null));
    try std.testing.expectError(error.DigestMismatch, builder.finish());
}

test "tar MD5 mismatch also blocks finalization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const tar_path = try std.fs.path.join(allocator, &.{ root, "bad-md5.tar.zst" });
    const wrong: [16]u8 = @splat(0xff);

    const builder = try Builder.init(allocator, io, root, tar_path, 3);
    defer builder.deinit();
    try std.testing.expectError(error.Md5Mismatch, builder.add(.{
        .path = "payload.bin",
        .size = 4,
        .expected_md5 = wrong,
        .data = .{ .bytes = "GOOD" },
    }, null));
    try std.testing.expectError(error.DigestMismatch, builder.finish());
}

test "stream reads concatenated zstd frames and verifies each checksum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tar_bytes: std.Io.Writer.Allocating = .init(allocator);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    try tar_writer.writeDir("dir", .{});
    try tar_writer.writeFileBytes("dir/file.txt", "hello", .{});
    try tar_writer.finishPedantically();
    const bytes = tar_bytes.written();
    const split = bytes.len / 2;

    try tmp.dir.writeFile(io, .{ .sub_path = "concat.tar.zst", .data = "" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const path = try std.fs.path.join(allocator, &.{ root, "concat.tar.zst" });
    const output = try fs.openReadWrite(io, tmp.dir, "concat.tar.zst");
    defer output.close(io);
    const first_size = blk: {
        var encoder = try zstd.Encoder.init(io, output, 0, 5, 0, null);
        defer encoder.deinit();
        try encoder.write(bytes[0..split]);
        try encoder.finish();
        break :blk encoder.position;
    };
    {
        var encoder = try zstd.Encoder.init(io, output, first_size, 5, 0, null);
        defer encoder.deinit();
        try encoder.write(bytes[split..]);
        try encoder.finish();
    }
    const total_size = (try tmp.dir.statFile(io, "concat.tar.zst", .{})).size;

    var stream = try Stream.init(allocator, io, path, 0, total_size);
    const directory = (try stream.next()).?;
    try std.testing.expectEqual(std.tar.FileKind.directory, directory.kind);
    try std.testing.expectEqualStrings("dir", directory.name);
    const file = (try stream.next()).?;
    try std.testing.expectEqualStrings("dir/file.txt", file.name);
    const contents = try stream.readCurrentAlloc(allocator, file, 5);
    try std.testing.expectEqualStrings("hello", contents);
    try std.testing.expect((try stream.next()) == null);
    stream.deinit();

    var compressed = try tmp.dir.openFile(io, "concat.tar.zst", .{ .mode = .read_write, .allow_directory = false });
    defer compressed.close(io);
    var last: [1]u8 = undefined;
    _ = try compressed.readPositionalAll(io, &last, total_size - 1);
    last[0] ^= 1;
    try compressed.writePositionalAll(io, &last, total_size - 1);

    var corrupt = try Stream.init(allocator, io, path, 0, total_size);
    defer corrupt.deinit();
    const corrupt_directory = (try corrupt.next()).?;
    try std.testing.expectEqual(std.tar.FileKind.directory, corrupt_directory.kind);
    const corrupt_file = (try corrupt.next()).?;
    _ = try corrupt.readCurrentAlloc(allocator, corrupt_file, 5);
    try std.testing.expectError(error.ZstdChecksumMismatch, corrupt.next());
}

test "borrowed stream stays on the retained archive object and leaves it open" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const first_path = try std.fs.path.join(allocator, &.{ root, "first.tar.zst" });
    const second_path = try std.fs.path.join(allocator, &.{ root, "second.tar.zst" });
    {
        var builder = try Builder.init(allocator, io, root, first_path, 3);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = 4, .data = .{ .bytes = "AAAA" } }, null);
        try builder.finish();
    }
    {
        var builder = try Builder.init(allocator, io, root, second_path, 3);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = 4, .data = .{ .bytes = "BBBB" } }, null);
        try builder.finish();
    }

    var retained = try fs.openReadContentAuthority(io, tmp.dir, "first.tar.zst");
    defer retained.close(io);
    const retained_size = (try retained.stat(io)).size;
    if (builtin.target.os.tag == .windows) {
        var namespace_mover = try fs.openMutationAuthorityBeneathWindows(
            io,
            tmp.dir,
            "first.tar.zst",
        );
        defer namespace_mover.close(io);
        try fs.renameOpenObjectBeneathWindows(
            io,
            tmp.dir,
            "renamed.tar.zst",
            namespace_mover,
        );
    } else {
        try tmp.dir.rename("first.tar.zst", tmp.dir, "renamed.tar.zst", io);
    }
    try tmp.dir.rename("second.tar.zst", tmp.dir, "first.tar.zst", io);

    var stream = try Stream.initBorrowed(allocator, io, retained, 0, retained_size);
    const member = (try stream.next()).?;
    const bytes = try stream.readCurrentAlloc(allocator, member, 4);
    try std.testing.expectEqualStrings("AAAA", bytes);
    try std.testing.expect((try stream.next()) == null);
    stream.deinit();

    var magic: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, magic.len), try retained.readPositionalAll(io, &magic, 0));
    try std.testing.expectEqual(@as(u32, 0xfd2fb528), std.mem.readInt(u32, &magic, .little));
}

test "tar duplicate paths release the rejected identity exactly once" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tar_bytes: std.Io.Writer.Allocating = .init(allocator);
    defer tar_bytes.deinit();
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    try tar_writer.writeFileBytes("same.txt", "one", .{});
    try tar_writer.writeFileBytes("same.txt", "two", .{});
    try tar_writer.finishPedantically();

    const compressed = try @import("../compression/frame.zig").compressAlloc(allocator, tar_bytes.written(), 5);
    defer allocator.free(compressed);
    try tmp.dir.writeFile(io, .{ .sub_path = "duplicates.tar.zst", .data = compressed });
    const retained = try fs.openRead(io, tmp.dir, "duplicates.tar.zst");
    defer retained.close(io);
    var stream = try Stream.initBorrowed(allocator, io, retained, 0, compressed.len);
    defer stream.deinit();

    const first = (try stream.next()).?;
    try std.testing.expectError(error.DuplicateTarPath, stream.next());
    try std.testing.expectEqualStrings("same.txt", first.name);
}

test "stream accepts repeated directory records without allocating target identities" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tar_bytes: std.Io.Writer.Allocating = .init(allocator);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    try tar_writer.writeDir("dir/", .{});
    try tar_writer.writeDir("dir/", .{});
    try tar_writer.writeFileBytes("dir/file.txt", "hello", .{});
    try tar_writer.finishPedantically();

    try tmp.dir.writeFile(io, .{ .sub_path = "dirs.tar.zst", .data = "" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const path = try std.fs.path.join(allocator, &.{ root, "dirs.tar.zst" });
    {
        const output = try fs.openReadWrite(io, tmp.dir, "dirs.tar.zst");
        defer output.close(io);
        var encoder = try zstd.Encoder.init(io, output, 0, 5, 0, null);
        defer encoder.deinit();
        try encoder.write(tar_bytes.written());
        try encoder.finish();
    }
    const size = (try tmp.dir.statFile(io, "dirs.tar.zst", .{})).size;

    var stream = try Stream.init(allocator, io, path, 0, size);
    defer stream.deinit();
    const first_directory = (try stream.next()).?;
    try std.testing.expectEqual(std.tar.FileKind.directory, first_directory.kind);
    try std.testing.expectEqualStrings("dir", first_directory.name);
    const second_directory = (try stream.next()).?;
    try std.testing.expectEqual(std.tar.FileKind.directory, second_directory.kind);
    try std.testing.expectEqualStrings("dir", second_directory.name);
    const file = (try stream.next()).?;
    try std.testing.expectEqualStrings("dir/file.txt", file.name);
    const bytes = try stream.readCurrentAlloc(allocator, file, 16);
    try std.testing.expectEqualStrings("hello", bytes);
    try std.testing.expect((try stream.next()) == null);
}

test "stream prefix read leaves remaining file bytes for iterator skip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var data: [8192]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    var tar_bytes: std.Io.Writer.Allocating = .init(allocator);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    try tar_writer.writeFileBytes("first.bin", &data, .{});
    try tar_writer.writeFileBytes("second.txt", "done", .{});
    try tar_writer.finishPedantically();

    try tmp.dir.writeFile(io, .{ .sub_path = "prefix.tar.zst", .data = "" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const path = try std.fs.path.join(allocator, &.{ root, "prefix.tar.zst" });
    {
        const output = try fs.openReadWrite(io, tmp.dir, "prefix.tar.zst");
        defer output.close(io);
        var encoder = try zstd.Encoder.init(io, output, 0, 5, 0, null);
        defer encoder.deinit();
        try encoder.write(tar_bytes.written());
        try encoder.finish();
    }
    const size = (try tmp.dir.statFile(io, "prefix.tar.zst", .{})).size;

    var stream = try Stream.init(allocator, io, path, 0, size);
    defer stream.deinit();
    const first = (try stream.next()).?;
    try std.testing.expectEqualStrings("first.bin", first.name);
    const prefix = try stream.readCurrentPrefixAlloc(allocator, first, 4096);
    try std.testing.expectEqualSlices(u8, data[0..4096], prefix);

    const second = (try stream.next()).?;
    try std.testing.expectEqualStrings("second.txt", second.name);
    const contents = try stream.readCurrentAlloc(allocator, second, 16);
    try std.testing.expectEqualStrings("done", contents);
    try std.testing.expect((try stream.next()) == null);
}

test "guarded tar extraction preserves caller ownership and rejects unsafe outputs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = "guarded tar bytes";
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const archive_path = try std.fs.path.join(allocator, &.{ root, "guarded.tar.zst" });
    {
        var builder = try Builder.init(allocator, io, root, archive_path, 3);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = payload.len, .data = .{ .bytes = payload } }, null);
        try builder.add(.{ .path = "empty.bin", .size = 0, .data = .{ .bytes = "" } }, null);
        try builder.finish();
    }

    const archive_size = (try tmp.dir.statFile(io, "guarded.tar.zst", .{})).size;
    {
        var audit_stream = try Stream.init(allocator, io, archive_path, 0, archive_size);
        defer audit_stream.deinit();
        const audit_first = (try audit_stream.next()).?;
        const observed_md5 = try audit_stream.hashCurrentMd5(audit_first, null);
        var expected_observed_md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(payload, &expected_observed_md5, .{});
        try std.testing.expectEqualSlices(u8, &expected_observed_md5, &observed_md5);
    }
    var stream = try Stream.init(allocator, io, archive_path, 0, archive_size);
    defer stream.deinit();

    const first = (try stream.next()).?;
    try tmp.dir.writeFile(io, .{ .sub_path = "sentinel", .data = "sentinel" });
    var nonempty = try fs.openReadWrite(io, tmp.dir, "sentinel");
    defer nonempty.close(io);
    try std.testing.expectError(
        error.UnsafeGuardedOutput,
        stream.extractCurrentToGuardedFile(io, first, nonempty, null),
    );
    const sentinel = try tmp.dir.readFileAlloc(io, "sentinel", allocator, .limited(16));
    try std.testing.expectEqualStrings("sentinel", sentinel);

    var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, "payload.out");
    defer guarded.close(io);
    const construction_md5 = try stream.extractCurrentToGuardedFileMd5(io, first, guarded, null);
    var expected_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(payload, &expected_md5, .{});
    try std.testing.expectEqualSlices(u8, &expected_md5, &construction_md5);
    try fs.validateGuardedOutput(io, guarded, payload.len);
    try guarded.writePositionalAll(io, payload[0..1], 0);
    try guarded.sync(io);
    var actual: [payload.len]u8 = undefined;
    try std.testing.expectEqual(actual.len, try guarded.readPositionalAll(io, &actual, 0));
    try std.testing.expectEqualStrings(payload, &actual);

    const second = (try stream.next()).?;
    try tmp.dir.writeFile(io, .{ .sub_path = "read-only", .data = "" });
    var read_only = try fs.openRead(io, tmp.dir, "read-only");
    defer read_only.close(io);
    try std.testing.expectError(
        error.UnsafeGuardedOutput,
        stream.extractCurrentToGuardedFile(io, second, read_only, null),
    );

    var empty = try fs.createGuardedOutputBeneath(io, tmp.dir, "empty.out");
    defer empty.close(io);
    const empty_md5 = try stream.extractCurrentToGuardedFileMd5(io, second, empty, null);
    var expected_empty_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("", &expected_empty_md5, .{});
    try std.testing.expectEqualSlices(u8, &expected_empty_md5, &empty_md5);
    try fs.validateGuardedOutput(io, empty, 0);
    try std.testing.expect((try stream.next()) == null);
}

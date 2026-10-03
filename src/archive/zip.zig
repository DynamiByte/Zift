const std = @import("std");
const Thread = std.Thread;
const fs = @import("../core/fs.zig");
const ids = @import("../core/ids.zig");
const flate = std.compress.flate;

const archive = @import("../archive.zig");
const ui = @import("../ui.zig");
const path_util = @import("../path.zig");

pub const Entry = struct {
    path: []const u8,
    zip_entry: std.zip.Iterator.Entry,
};

pub const Archive = struct {
    entries: []Entry,
    // directory records for conflict detection only
    directories: []const []const u8 = &.{},

    pub fn find(self: Archive, path: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.path, path)) return entry;
        }
        return null;
    }
};

pub const Source = archive.Source;
const WrittenEntry = struct {
    path: []const u8,
    uncompressed_size: u64,
    compressed_size: u64,
    crc32: u32,
    local_offset: u64,
    method: u16,
};

const Extracted = struct {
    size: u64,
    crc32: u32,
};

pub fn readCentral(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
) !Archive {
    var iter = try std.zip.Iterator.init(reader);

    var entries: std.ArrayList(Entry) = .empty;
    var directories: std.ArrayList([]const u8) = .empty;
    const scratch = std.heap.smp_allocator;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    while (try iter.next()) |entry| {
        const central = try centralDataAlloc(allocator, reader, entry);
        const name = central.name;
        if (isDirectoryRecord(name)) {
            try validateDirectoryRecord(name, entry);
            const path = name[0 .. name.len - 1];
            const got = try seen.getOrPut(scratch, path);
            if (got.found_existing) return error.DuplicateZipPath;
            got.value_ptr.* = {};
            try directories.append(allocator, path);
            continue;
        }
        try path_util.validate(name);

        const got = try seen.getOrPut(scratch, name);
        if (got.found_existing) return error.DuplicateZipPath;
        got.value_ptr.* = {};

        try entries.append(allocator, .{
            .path = name,
            .zip_entry = entry,
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .directories = try directories.toOwnedSlice(allocator),
    };
}

const CentralData = struct { name: []const u8 };

fn centralDataAlloc(allocator: std.mem.Allocator, reader: *std.Io.File.Reader, entry: std.zip.Iterator.Entry) !CentralData {
    try reader.seekTo(entry.header_zip_offset);
    const header = reader.interface.takeStruct(std.zip.CentralDirectoryFileHeader, .little) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream => return error.UnexpectedEof,
    };
    if (!std.mem.eql(u8, &header.signature, &std.zip.central_file_header_sig)) return error.ZipBadCentralSig;
    const name = try allocator.alloc(u8, header.filename_len);
    errdefer allocator.free(name);
    try reader.interface.readSliceAll(name);
    try reader.interface.discardAll(header.extra_len);
    return .{ .name = name };
}

fn isDirectoryRecord(path: []const u8) bool {
    return path.len > 0 and path[path.len - 1] == '/';
}

fn validateDirectoryRecord(path: []const u8, entry: std.zip.Iterator.Entry) !void {
    if (entry.uncompressed_size != 0 or entry.crc32 != 0) {
        return error.ZipDirectoryHasData;
    }
    if (path.len > std.math.maxInt(u16)) return error.PathTooLongForZip;
    if (path.len < 2) return error.UnsafePath;
    if (path[path.len - 2] == '/') return error.UnsafePath;
    try path_util.validate(path[0 .. path.len - 1]);
}

pub fn extractEntryAlloc(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    entry: Entry,
    max_size: u64,
) ![]u8 {
    if (entry.zip_entry.uncompressed_size > max_size) return error.FileTooLarge;
    const len: usize = @intCast(entry.zip_entry.uncompressed_size);
    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);

    var writer = std.Io.Writer.fixed(bytes);
    try extractEntryToWriter(reader, entry, &writer);
    if (writer.buffered().len != len) return error.UnexpectedEof;
    return bytes;
}

pub fn extractEntryPrefixAlloc(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    entry: Entry,
    max_size: u64,
) ![]u8 {
    if (entry.zip_entry.uncompressed_size <= max_size) {
        return extractEntryAlloc(allocator, reader, entry, max_size);
    }
    const len: usize = @intCast(max_size);
    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);

    switch (entry.zip_entry.compression_method) {
        .store, .deflate => {},
        else => return error.UnsupportedCompressionMethod,
    }
    const data_offset = try localDataOffset(reader, entry);
    try reader.seekTo(data_offset);
    var limit_buf: [64 * 1024]u8 = undefined;
    var limited = reader.interface.limited(.limited64(entry.zip_entry.compressed_size), &limit_buf);
    switch (entry.zip_entry.compression_method) {
        .store => {
            if (entry.zip_entry.compressed_size != entry.zip_entry.uncompressed_size) return error.ZipCompressedSizeMismatch;
            try limited.interface.readSliceAll(bytes);
        },
        .deflate => {
            var flate_buffer: [flate.max_window_len]u8 = undefined;
            var decompress: flate.Decompress = .init(&limited.interface, .raw, &flate_buffer);
            decompress.reader.readSliceAll(bytes) catch |err| switch (err) {
                error.ReadFailed => return decompressReadError(reader, &decompress),
                error.EndOfStream => return error.ZipDecompressTruncated,
            };
        },
        else => unreachable,
    }
    return bytes;
}

// caller-owned output on success/failure; empty, writable, single-link
pub fn extractEntryToGuardedFileProgress(
    io: std.Io,
    reader: *std.Io.File.Reader,
    entry: Entry,
    out_file: std.Io.File,
    progress: ?*ui.Progress,
) !void {
    _ = try extractEntryToGuardedFileProgressMd5(io, reader, entry, out_file, progress);
}

// hash of writes, not a readback
pub fn extractEntryToGuardedFileProgressMd5(
    io: std.Io,
    reader: *std.Io.File.Reader,
    entry: Entry,
    out_file: std.Io.File,
    progress: ?*ui.Progress,
) ![16]u8 {
    try fs.validateGuardedOutput(io, out_file, 0);
    var out_buf: [64 * 1024]u8 = undefined;
    var writer = out_file.writer(io, &out_buf);
    var hash_buf: [64 * 1024]u8 = undefined;
    var hashed = writer.interface.hashed(std.crypto.hash.Md5.init(.{}), &hash_buf);
    try extractEntryToWriterProgress(reader, entry, &hashed.writer, progress);
    try hashed.writer.flush();
    // end() truncates, masking an unexpected size change
    try writer.flush();
    try out_file.sync(io);
    const stat = try out_file.stat(io);
    if (stat.kind != .file or stat.nlink != 1) return error.UnsafeGuardedOutput;
    if (stat.size != entry.zip_entry.uncompressed_size) return error.SizeMismatch;
    try fs.validateGuardedOutput(io, out_file, entry.zip_entry.uncompressed_size);
    var md5: [16]u8 = undefined;
    hashed.hasher.final(&md5);
    return md5;
}

fn extractEntryToWriter(
    reader: *std.Io.File.Reader,
    entry: Entry,
    out: *std.Io.Writer,
) !void {
    return extractEntryToWriterProgress(reader, entry, out, null);
}

fn extractEntryToWriterProgress(
    reader: *std.Io.File.Reader,
    entry: Entry,
    out: *std.Io.Writer,
    progress: ?*ui.Progress,
) !void {
    switch (entry.zip_entry.compression_method) {
        .store, .deflate => {},
        else => return error.UnsupportedCompressionMethod,
    }

    const data_offset = try localDataOffset(reader, entry);
    try reader.seekTo(data_offset);

    var limit_buf: [64 * 1024]u8 = undefined;
    var limited = reader.interface.limited(.limited64(entry.zip_entry.compressed_size), &limit_buf);
    const extracted: Extracted = blk: {
        switch (entry.zip_entry.compression_method) {
            .store => {
                if (entry.zip_entry.compressed_size != entry.zip_entry.uncompressed_size) {
                    return error.ZipCompressedSizeMismatch;
                }
                break :blk try copyExact(&limited.interface, out, entry.zip_entry.uncompressed_size, progress);
            },
            .deflate => {
                var flate_buffer: [flate.max_window_len]u8 = undefined;
                var decompress: flate.Decompress = .init(&limited.interface, .raw, &flate_buffer);
                const result = try decompressExact(reader, &decompress, out, entry.zip_entry.uncompressed_size, progress);
                try expectDeflateEnd(reader, &decompress);
                break :blk result;
            },
            else => return error.UnsupportedCompressionMethod,
        }
    };
    if (extracted.size != entry.zip_entry.uncompressed_size) return error.ZipUncompressedSizeMismatch;
    if (extracted.crc32 != entry.zip_entry.crc32) return error.ZipCrcMismatch;
    if (limited.remaining != .nothing or limited.interface.bufferedLen() != 0) {
        return error.ZipCompressedSizeMismatch;
    }
}

fn copyExact(
    reader: *std.Io.Reader,
    out: *std.Io.Writer,
    len: u64,
    progress: ?*ui.Progress,
) !Extracted {
    var remaining = len;
    var total: u64 = 0;
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var buf: [1024 * 1024]u8 = undefined;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        reader.readSliceAll(buf[0..want]) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => return error.ZipDecompressTruncated,
        };
        const chunk = buf[0..want];
        crc.update(chunk);
        try out.writeAll(chunk);
        remaining -= want;
        total += want;
        if (progress) |p| try p.addBytes(want);
    }
    return .{ .size = total, .crc32 = crc.final() };
}

fn decompressExact(
    file_reader: *std.Io.File.Reader,
    decompress: *flate.Decompress,
    out: *std.Io.Writer,
    len: u64,
    progress: ?*ui.Progress,
) !Extracted {
    var remaining = len;
    var total: u64 = 0;
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var buf: [1024 * 1024]u8 = undefined;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        decompress.reader.readSliceAll(buf[0..want]) catch |err| switch (err) {
            error.ReadFailed => return decompressReadError(file_reader, decompress),
            error.EndOfStream => return error.ZipDecompressTruncated,
        };
        const chunk = buf[0..want];
        crc.update(chunk);
        try out.writeAll(chunk);
        remaining -= want;
        total += want;
        if (progress) |p| try p.addBytes(want);
    }
    return .{ .size = total, .crc32 = crc.final() };
}

fn expectDeflateEnd(
    file_reader: *std.Io.File.Reader,
    decompress: *flate.Decompress,
) !void {
    const extra = decompress.reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return,
        error.ReadFailed => return decompressReadError(file_reader, decompress),
    };
    _ = extra;
    return error.ZipUncompressedSizeMismatch;
}

fn decompressReadError(
    file_reader: *std.Io.File.Reader,
    decompress: *flate.Decompress,
) anyerror {
    if (file_reader.err) |err| return err;
    if (decompress.err) |err| return err;
    return error.ReadFailed;
}

fn localDataOffset(reader: *std.Io.File.Reader, entry: Entry) !u64 {
    try reader.seekTo(entry.zip_entry.file_offset);
    const local_header = reader.interface.takeStruct(std.zip.LocalFileHeader, .little) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream => return error.UnexpectedEof,
    };
    if (!std.mem.eql(u8, &local_header.signature, &std.zip.local_file_header_sig)) {
        return error.ZipBadFileOffset;
    }
    if (local_header.version_needed_to_extract != entry.zip_entry.version_needed_to_extract) return error.ZipMismatchVersionNeeded;
    if (@as(u16, @bitCast(local_header.flags)) != @as(u16, @bitCast(entry.zip_entry.flags))) return error.ZipMismatchFlags;
    if (local_header.last_modification_time != entry.zip_entry.last_modification_time) return error.ZipMismatchModTime;
    if (local_header.last_modification_date != entry.zip_entry.last_modification_date) return error.ZipMismatchModDate;
    if (local_header.filename_len != entry.zip_entry.filename_len or local_header.filename_len != entry.path.len) return error.ZipMismatchFilenameLen;
    var name_buf: [1024]u8 = undefined;
    var name_offset: usize = 0;
    while (name_offset < entry.path.len) {
        const n = @min(name_buf.len, entry.path.len - name_offset);
        try reader.interface.readSliceAll(name_buf[0..n]);
        if (!std.mem.eql(u8, name_buf[0..n], entry.path[name_offset..][0..n])) return error.ZipMismatchFilename;
        name_offset += n;
    }
    if (local_header.compression_method != entry.zip_entry.compression_method) {
        return error.ZipMismatchCompressionMethod;
    }
    if (local_header.crc32 != 0 and local_header.crc32 != entry.zip_entry.crc32) {
        return error.ZipMismatchCrc32;
    }
    if (local_header.compressed_size != 0 and
        local_header.compressed_size != std.math.maxInt(u32) and
        local_header.compressed_size != entry.zip_entry.compressed_size)
    {
        return error.ZipMismatchCompLen;
    }
    if (local_header.uncompressed_size != 0 and
        local_header.uncompressed_size != std.math.maxInt(u32) and
        local_header.uncompressed_size != entry.zip_entry.uncompressed_size)
    {
        return error.ZipMismatchUncompLen;
    }

    var data_offset = std.math.add(u64, entry.zip_entry.file_offset, @sizeOf(std.zip.LocalFileHeader)) catch return error.ZipBadFileOffset;
    data_offset = std.math.add(u64, data_offset, local_header.filename_len) catch return error.ZipBadFileOffset;
    return std.math.add(u64, data_offset, local_header.extra_len) catch return error.ZipBadFileOffset;
}

pub const Compression = enum { store, deflate };

pub const Builder = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    file: std.Io.File,
    offset: u64 = 0,
    entries: std.ArrayList(WrittenEntry) = .empty,
    compression: Compression,
    deflate_level: u4 = 1,
    publication_blocked: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        root_path: []const u8,
        out_path: []const u8,
        compression: Compression,
    ) !Builder {
        const root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .access_sub_paths = true });
        errdefer root.close(io);
        const file = try std.Io.Dir.cwd().createFile(io, out_path, .{ .exclusive = true });
        return .{
            .allocator = allocator,
            .io = io,
            .root = root,
            .file = file,
            .compression = compression,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.entries.deinit(self.allocator);
        self.root.close(self.io);
        self.file.close(self.io);
    }

    pub fn add(self: *Builder, source: Source, progress: ?*ui.Progress) !void {
        try path_util.validate(source.path);
        const local_offset = self.offset;
        var out_buf: [64 * 1024]u8 = undefined;
        var writer = self.file.writer(self.io, &out_buf);
        try writer.seekTo(self.offset);
        const method: u16 = if (self.compression == .store) 0 else 8;
        try writeLocalHeader(&writer.interface, source.path, source.size, method, local_offset);

        const data_start = writer.logicalPos();
        const needs = HashNeeds.forSource(source);
        const hashes = switch (self.compression) {
            .store => switch (source.data) {
                .file => try streamFile(self.io, self.root, source.path, source.size, &writer.interface, progress, needs, true),
                .external => |path| try streamFile(self.io, std.Io.Dir.cwd(), path, source.size, &writer.interface, progress, needs, false),
                .bytes => |bytes| try streamBytes(bytes, &writer.interface, progress, needs),
            },
            .deflate => switch (source.data) {
                .file => try deflateFile(self.io, self.root, source.path, source.size, &writer.interface, progress, needs, true, self.deflate_level),
                .external => |path| try deflateFile(self.io, std.Io.Dir.cwd(), path, source.size, &writer.interface, progress, needs, false, self.deflate_level),
                .bytes => |bytes| try deflateBytes(bytes, &writer.interface, progress, needs, self.deflate_level),
            },
        };
        try self.finishEntry(source, &writer, local_offset, data_start, hashes, progress);
    }

    pub fn addAll(
        self: *Builder,
        sources: []const Source,
        progress: ?*ui.Progress,
        requested_workers: usize,
        byte_budget: u64,
    ) !void {
        if (self.compression != .deflate or requested_workers <= 1 or sources.len <= 1) {
            for (sources) |source| try self.add(source, progress);
            return;
        }
        if (byte_budget == 0) return error.InvalidBufferSize;

        var first: usize = 0;
        while (first < sources.len) {
            if (sources[first].size > byte_budget) {
                try self.add(sources[first], progress);
                first += 1;
                continue;
            }
            var last = first;
            var bytes: u64 = 0;
            while (last < sources.len) : (last += 1) {
                const next = std.math.add(u64, bytes, sources[last].size) catch
                    return error.ArchiveTooLarge;
                if (last != first and next > byte_budget) break;
                bytes = next;
            }
            const batch = sources[first..last];
            if (batch.len == 1) {
                try self.add(batch[0], progress);
                first = last;
                continue;
            }
            const prepared = try prepareDeflateBatch(
                self.allocator,
                self.io,
                self.root,
                batch,
                requested_workers,
                self.deflate_level,
            );
            {
                defer deinitPreparedBatch(self.allocator, prepared);
                for (batch, prepared) |source, item| {
                    if (item.failed) |err| return err;
                    try self.addPrepared(source, item, progress);
                }
            }
            first = last;
        }
    }

    fn addPrepared(
        self: *Builder,
        source: Source,
        prepared: PreparedEntry,
        progress: ?*ui.Progress,
    ) !void {
        try path_util.validate(source.path);
        const local_offset = self.offset;
        var out_buf: [64 * 1024]u8 = undefined;
        var writer = self.file.writer(self.io, &out_buf);
        try writer.seekTo(self.offset);
        try writeLocalHeader(&writer.interface, source.path, source.size, 8, local_offset);
        const data_start = writer.logicalPos();
        try writer.interface.writeAll(prepared.bytes);
        if (progress) |p| try p.addBytes(source.size);
        try self.finishEntry(source, &writer, local_offset, data_start, prepared.hashes, progress);
    }

    fn finishEntry(
        self: *Builder,
        source: Source,
        writer: *std.Io.File.Writer,
        local_offset: u64,
        data_start: u64,
        hashes: StreamHashes,
        progress: ?*ui.Progress,
    ) !void {
        try writer.interface.flush();
        const data_end = writer.logicalPos();
        const compressed_size = data_end - data_start;
        if (hashes.size != source.size) return error.SizeMismatch;
        if (source.expected_md5) |expected| {
            const actual = hashes.md5 orelse return error.MissingHash;
            if (!std.mem.eql(u8, &actual, &expected)) {
                self.publication_blocked = true;
                return error.Md5Mismatch;
            }
        }
        if (source.expected_digest) |expected| {
            if (!(hashes.digest orelse return error.MissingHash).eql(expected)) {
                self.publication_blocked = true;
                return error.DigestMismatch;
            }
        }

        try writeDataDescriptor(&writer.interface, hashes.crc32, compressed_size, hashes.size);
        try writer.end();
        self.offset = writer.logicalPos();

        try self.entries.append(self.allocator, .{
            .path = source.path,
            .uncompressed_size = hashes.size,
            .compressed_size = compressed_size,
            .crc32 = hashes.crc32,
            .local_offset = local_offset,
            .method = if (self.compression == .store) 0 else 8,
        });
        if (progress) |p| try p.finishFile();
    }

    pub fn finish(self: *Builder) !void {
        if (self.publication_blocked) return error.DigestMismatch;
        var out_buf: [64 * 1024]u8 = undefined;
        var writer = self.file.writer(self.io, &out_buf);
        try writer.seekTo(self.offset);
        const central_start = self.offset;
        for (self.entries.items) |entry| {
            try writeCentralHeader(&writer.interface, entry);
        }
        self.offset = writer.logicalPos();
        const central_size = self.offset - central_start;
        try writeEndRecords(&writer.interface, self.entries.items.len, central_start, central_size);
        try writer.end();
        self.offset = writer.logicalPos();
    }
};

const PreparedEntry = struct {
    bytes: []u8 = &.{},
    hashes: StreamHashes = undefined,
    failed: ?anyerror = null,
};

const PrepareShared = struct {
    io: std.Io,
    root: std.Io.Dir,
    sources: []const Source,
    results: []PreparedEntry,
    level: u4,
    next: std.atomic.Value(usize) = .init(0),
};

fn prepareDeflateWorker(shared: *PrepareShared) void {
    while (true) {
        const index = shared.next.fetchAdd(1, .monotonic);
        if (index >= shared.sources.len) return;
        shared.results[index] = prepareDeflateEntry(
            std.heap.smp_allocator,
            shared.io,
            shared.root,
            shared.sources[index],
            shared.level,
        ) catch |err| .{ .failed = err };
    }
}

fn prepareDeflateEntry(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    source: Source,
    level: u4,
) !PreparedEntry {
    try path_util.validate(source.path);
    // zig deflate writer: destination buffer required
    var output = try std.Io.Writer.Allocating.initCapacity(allocator, 64 * 1024);
    errdefer output.deinit();
    const needs = HashNeeds.forSource(source);
    const hashes = switch (source.data) {
        .file => try deflateFile(io, root, source.path, source.size, &output.writer, null, needs, true, level),
        .external => |path| try deflateFile(io, std.Io.Dir.cwd(), path, source.size, &output.writer, null, needs, false, level),
        .bytes => |bytes| try deflateBytes(bytes, &output.writer, null, needs, level),
    };
    return .{ .bytes = try output.toOwnedSlice(), .hashes = hashes };
}

fn prepareDeflateBatch(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    sources: []const Source,
    requested_workers: usize,
    level: u4,
) ![]PreparedEntry {
    const results = try allocator.alloc(PreparedEntry, sources.len);
    errdefer allocator.free(results);
    for (results) |*result| result.* = .{};
    errdefer for (results) |result| if (result.bytes.len != 0)
        std.heap.smp_allocator.free(result.bytes);

    var shared: PrepareShared = .{
        .io = io,
        .root = root,
        .sources = sources,
        .results = results,
        .level = level,
    };
    const worker_count = @min(@max(@as(usize, 1), requested_workers), sources.len);
    if (worker_count == 1) {
        prepareDeflateWorker(&shared);
    } else {
        const threads = try allocator.alloc(Thread, worker_count);
        defer allocator.free(threads);
        var spawned: usize = 0;
        errdefer for (threads[0..spawned]) |thread| thread.join();
        while (spawned < worker_count) : (spawned += 1) {
            threads[spawned] = try Thread.spawn(.{}, prepareDeflateWorker, .{&shared});
        }
        for (threads) |thread| thread.join();
        spawned = 0;
    }
    return results;
}

fn deinitPreparedBatch(allocator: std.mem.Allocator, prepared: []PreparedEntry) void {
    for (prepared) |item| if (item.bytes.len != 0)
        std.heap.smp_allocator.free(item.bytes);
    allocator.free(prepared);
}

const StreamHashes = struct {
    size: u64,
    crc32: u32,
    md5: ?[16]u8,
    digest: ?ids.Digest,
};

const HashNeeds = struct {
    md5: bool,
    digest: bool,

    fn forSource(source: Source) HashNeeds {
        return .{ .md5 = source.expected_md5 != null, .digest = source.expected_digest != null };
    }
};

fn streamFile(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    expected_size: u64,
    out: *std.Io.Writer,
    progress: ?*ui.Progress,
    needs: HashNeeds,
    comptime beneath_root: bool,
) !StreamHashes {
    var file = if (beneath_root)
        try fs.openReadBeneath(io, dir, path)
    else
        try fs.openRead(io, dir, path);
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;
    if (stat.size != expected_size) return error.SizeMismatch;
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var md5: ?std.crypto.hash.Md5 = if (needs.md5) std.crypto.hash.Md5.init(.{}) else null;
    var digest_hasher: ?std.crypto.hash.Blake3 = if (needs.digest) std.crypto.hash.Blake3.init(.{}) else null;
    var total: u64 = 0;
    var pos: u64 = 0;
    var buf: [1024 * 1024]u8 = undefined;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, pos);
        if (n == 0) break;
        const chunk = buf[0..n];
        crc.update(chunk);
        if (md5) |*hasher| hasher.update(chunk);
        if (digest_hasher) |*hasher| hasher.update(chunk);
        try out.writeAll(chunk);
        pos += n;
        total += n;
        if (progress) |p| try p.addBytes(n);
    }
    var actual_md5: ?[16]u8 = null;
    if (md5) |*hasher| {
        var value: [16]u8 = undefined;
        hasher.final(&value);
        actual_md5 = value;
    }
    var construction_digest: ?ids.Digest = null;
    if (digest_hasher) |*hasher| {
        var value: ids.Digest = undefined;
        hasher.final(&value.bytes);
        construction_digest = value;
    }
    return .{
        .size = total,
        .crc32 = crc.final(),
        .md5 = actual_md5,
        .digest = construction_digest,
    };
}

fn streamBytes(bytes: []const u8, out: *std.Io.Writer, progress: ?*ui.Progress, needs: HashNeeds) !StreamHashes {
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    crc.update(bytes);
    try out.writeAll(bytes);
    if (progress) |p| try p.addBytes(bytes.len);
    var actual_md5: ?[16]u8 = null;
    if (needs.md5) {
        actual_md5 = undefined;
        std.crypto.hash.Md5.hash(bytes, &actual_md5.?, .{});
    }
    const construction_digest: ?ids.Digest = if (needs.digest) ids.Digest.of(bytes) else null;
    return .{
        .size = bytes.len,
        .crc32 = crc.final(),
        .md5 = actual_md5,
        .digest = construction_digest,
    };
}

fn deflateOptions(level: u4) flate.Compress.Options {
    return switch (level) {
        1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        6 => .level_6,
        7 => .level_7,
        8 => .level_8,
        9 => .level_9,
        else => unreachable,
    };
}

fn deflateFile(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    expected_size: u64,
    out: *std.Io.Writer,
    progress: ?*ui.Progress,
    needs: HashNeeds,
    comptime beneath_root: bool,
    level: u4,
) !StreamHashes {
    var deflate_buf: [flate.max_window_len * 2]u8 = undefined;
    var comp = try flate.Compress.init(out, &deflate_buf, .raw, deflateOptions(level));
    const hashes = try streamFile(io, dir, path, expected_size, &comp.writer, progress, needs, beneath_root);
    try comp.finish();
    return hashes;
}

fn deflateBytes(bytes: []const u8, out: *std.Io.Writer, progress: ?*ui.Progress, needs: HashNeeds, level: u4) !StreamHashes {
    var deflate_buf: [flate.max_window_len * 2]u8 = undefined;
    var comp = try flate.Compress.init(out, &deflate_buf, .raw, deflateOptions(level));
    const hashes = try streamBytes(bytes, &comp.writer, progress, needs);
    try comp.finish();
    return hashes;
}

fn writeLocalHeader(out: *std.Io.Writer, path: []const u8, size: u64, method: u16, local_offset: u64) !void {
    const zip64_size = size > std.math.maxInt(u32);
    // offset > 4 GiB: ZIP64 version 4.5 even for small payloads
    const zip64 = zip64_size or local_offset > std.math.maxInt(u32);
    const extra_len: u16 = if (zip64_size) 20 else 0;
    var h: [30]u8 = undefined;
    put32(h[0..4], 0x04034b50);
    put16(h[4..6], if (zip64) 45 else 20);
    put16(h[6..8], 0x0008);
    put16(h[8..10], method);
    put16(h[10..12], 0);
    put16(h[12..14], 0);
    put32(h[14..18], 0);
    put32(h[18..22], if (zip64_size) std.math.maxInt(u32) else 0);
    put32(h[22..26], if (zip64_size) std.math.maxInt(u32) else 0);
    put16(h[26..28], @intCast(path.len));
    put16(h[28..30], extra_len);
    try out.writeAll(&h);
    try out.writeAll(path);
    if (zip64_size) {
        var e: [20]u8 = undefined;
        put16(e[0..2], 1);
        put16(e[2..4], 16);
        put64(e[4..12], size);
        put64(e[12..20], 0);
        try out.writeAll(&e);
    }
}

fn writeDataDescriptor(out: *std.Io.Writer, crc: u32, compressed: u64, uncompressed: u64) !void {
    if (compressed > std.math.maxInt(u32) or uncompressed > std.math.maxInt(u32)) {
        var d: [24]u8 = undefined;
        put32(d[0..4], 0x08074b50);
        put32(d[4..8], crc);
        put64(d[8..16], compressed);
        put64(d[16..24], uncompressed);
        try out.writeAll(&d);
    } else {
        var d: [16]u8 = undefined;
        put32(d[0..4], 0x08074b50);
        put32(d[4..8], crc);
        put32(d[8..12], @intCast(compressed));
        put32(d[12..16], @intCast(uncompressed));
        try out.writeAll(&d);
    }
}

fn writeCentralHeader(out: *std.Io.Writer, entry: WrittenEntry) !void {
    const need_size64 = entry.uncompressed_size > std.math.maxInt(u32) or entry.compressed_size > std.math.maxInt(u32);
    const need_offset64 = entry.local_offset > std.math.maxInt(u32);
    var extra: [28]u8 = undefined;
    var extra_len: usize = 0;
    if (need_size64 or need_offset64) {
        var payload: [24]u8 = undefined;
        var payload_len: usize = 0;
        if (need_size64) {
            put64(payload[payload_len..][0..8], entry.uncompressed_size);
            payload_len += 8;
            put64(payload[payload_len..][0..8], entry.compressed_size);
            payload_len += 8;
        }
        if (need_offset64) {
            put64(payload[payload_len..][0..8], entry.local_offset);
            payload_len += 8;
        }
        put16(extra[0..2], 1);
        put16(extra[2..4], @intCast(payload_len));
        @memcpy(extra[4 .. 4 + payload_len], payload[0..payload_len]);
        extra_len = 4 + payload_len;
    }

    const zip64 = need_size64 or need_offset64;
    var h: [46]u8 = undefined;
    put32(h[0..4], 0x02014b50);
    put16(h[4..6], if (zip64) 45 else 20);
    put16(h[6..8], if (zip64) 45 else 20);
    put16(h[8..10], 0x0008);
    put16(h[10..12], entry.method);
    put16(h[12..14], 0);
    put16(h[14..16], 0);
    put32(h[16..20], entry.crc32);
    put32(h[20..24], if (need_size64) std.math.maxInt(u32) else @intCast(entry.compressed_size));
    put32(h[24..28], if (need_size64) std.math.maxInt(u32) else @intCast(entry.uncompressed_size));
    put16(h[28..30], @intCast(entry.path.len));
    put16(h[30..32], @intCast(extra_len));
    put16(h[32..34], 0);
    put16(h[34..36], 0);
    put16(h[36..38], 0);
    put32(h[38..42], 0);
    put32(h[42..46], if (need_offset64) std.math.maxInt(u32) else @intCast(entry.local_offset));
    try out.writeAll(&h);
    try out.writeAll(entry.path);
    try out.writeAll(extra[0..extra_len]);
}

fn writeEndRecords(out: *std.Io.Writer, count: usize, central_start: u64, central_size: u64) !void {
    const zip64 = count > std.math.maxInt(u16) or central_start > std.math.maxInt(u32) or central_size > std.math.maxInt(u32);
    if (zip64) {
        const record64_offset = central_start + central_size;
        var r: [56]u8 = undefined;
        put32(r[0..4], 0x06064b50);
        put64(r[4..12], 44);
        put16(r[12..14], 45);
        put16(r[14..16], 45);
        put32(r[16..20], 0);
        put32(r[20..24], 0);
        put64(r[24..32], count);
        put64(r[32..40], count);
        put64(r[40..48], central_size);
        put64(r[48..56], central_start);
        try out.writeAll(&r);
        var l: [20]u8 = undefined;
        put32(l[0..4], 0x07064b50);
        put32(l[4..8], 0);
        put64(l[8..16], record64_offset);
        put32(l[16..20], 1);
        try out.writeAll(&l);
    }
    var e: [22]u8 = undefined;
    put32(e[0..4], 0x06054b50);
    put16(e[4..6], 0);
    put16(e[6..8], 0);
    put16(e[8..10], if (count > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(count));
    put16(e[10..12], if (count > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(count));
    put32(e[12..16], if (central_size > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(central_size));
    put32(e[16..20], if (central_start > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(central_start));
    put16(e[20..22], 0);
    try out.writeAll(&e);
}

fn put16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .little);
}
fn put32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .little);
}
fn put64(out: []u8, value: u64) void {
    std.mem.writeInt(u64, out[0..8], value, .little);
}

test "BLAKE3 publication guard preserves ZIP bytes for every source kind" {
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
            compression: Compression,
            guarded: bool,
        ) !void {
            const root_bytes = "root bytes";
            const spool_bytes = "spool bytes";
            const memory_bytes = "memory bytes";
            var builder = try Builder.init(alloc, test_io, root_path, output_path, compression);
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

    for ([_]Compression{ .store, .deflate }, 0..) |compression, index| {
        const plain_name = try allocator.print("plain-{d}.zip", .{index});
        const guarded_name = try allocator.print("guarded-{d}.zip", .{index});
        const plain_path = try std.fs.path.join(allocator, &.{ root, plain_name });
        const guarded_path = try std.fs.path.join(allocator, &.{ root, guarded_name });
        try TestBuilder.build(allocator, io, root, plain_path, spool_path, compression, false);
        try TestBuilder.build(allocator, io, root, guarded_path, spool_path, compression, true);
        const plain = try tmp.dir.readFileAlloc(io, plain_name, allocator, .limited(1024 * 1024));
        const guarded = try tmp.dir.readFileAlloc(io, guarded_name, allocator, .limited(1024 * 1024));
        try std.testing.expectEqualSlices(u8, plain, guarded);
    }
}

test "parallel Deflate preparation is canonical and preserves publication guards" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_bytes: [32 * 1024]u8 = undefined;
    var random: std.Random.DefaultPrng = .init(321);
    random.random().bytes(&root_bytes);
    for (&root_bytes) |*byte| byte.* &= 7;
    try tmp.dir.writeFile(io, .{ .sub_path = "root.bin", .data = &root_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "spool.bin", .data = "spool bytes spool bytes" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const spool_path = try std.fs.path.join(allocator, &.{ root, "spool.bin" });
    const sequential_path = try std.fs.path.join(allocator, &.{ root, "sequential.zip" });
    const parallel_path = try std.fs.path.join(allocator, &.{ root, "parallel.zip" });
    const sources = [_]Source{
        .{ .path = "root.bin", .size = root_bytes.len, .expected_digest = ids.Digest.of(&root_bytes), .data = .file },
        .{ .path = "external.bin", .size = 23, .expected_digest = ids.Digest.of("spool bytes spool bytes"), .data = .{ .external = spool_path } },
        .{ .path = "memory.bin", .size = 25, .expected_digest = ids.Digest.of("memory bytes memory bytes"), .data = .{ .bytes = "memory bytes memory bytes" } },
    };
    var fastest: ?ids.Digest = null;
    for ([_]u4{ 1, 6, 9 }) |level| {
        {
            var builder = try Builder.init(allocator, io, root, sequential_path, .deflate);
            defer builder.deinit();
            builder.deflate_level = level;
            for (sources) |source| try builder.add(source, null);
            try builder.finish();
        }
        {
            var builder = try Builder.init(allocator, io, root, parallel_path, .deflate);
            defer builder.deinit();
            builder.deflate_level = level;
            try builder.addAll(&sources, null, 3, 64 * 1024);
            try builder.finish();
        }
        const sequential = try tmp.dir.readFileAlloc(io, "sequential.zip", allocator, .limited(1024 * 1024));
        const parallel = try tmp.dir.readFileAlloc(io, "parallel.zip", allocator, .limited(1024 * 1024));
        try std.testing.expectEqualSlices(u8, sequential, parallel);
        if (level == 1) fastest = ids.Digest.of(sequential);
        if (level == 9) try std.testing.expect(!fastest.?.eql(ids.Digest.of(sequential)));

        try tmp.dir.deleteFile(io, "sequential.zip");
        try tmp.dir.deleteFile(io, "parallel.zip");
    }

    const rejected_path = try std.fs.path.join(allocator, &.{ root, "rejected.zip" });
    var rejected = try Builder.init(allocator, io, root, rejected_path, .deflate);
    defer rejected.deinit();
    var changed = sources;
    changed[1].expected_digest = ids.Digest.of("different spool content");
    try std.testing.expectError(error.DigestMismatch, rejected.addAll(&changed, null, 3, 64 * 1024));
    try std.testing.expectError(error.DigestMismatch, rejected.finish());
}

test "ZIP64 offsets keep local and central versions equal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "offset64.zip" });

    {
        var builder = try Builder.init(allocator, io, root, zip_path, .store);
        defer builder.deinit();
        builder.offset = @as(u64, std.math.maxInt(u32)) + 4096;
        try builder.add(.{
            .path = "payload.bin",
            .size = 7,
            .data = .{ .bytes = "payload" },
        }, null);
        try builder.finish();
    }

    var file = try fs.openRead(io, std.Io.Dir.cwd(), zip_path);
    defer file.close(io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    const parsed = try readCentral(allocator, &reader);
    const entry = parsed.find("payload.bin") orelse return error.MissingExpectedEntry;
    const bytes = try extractEntryAlloc(allocator, &reader, entry, 7);
    try std.testing.expectEqualStrings("payload", bytes);
}

test "ZIP spool mutation fails the BLAKE3 guard and blocks finalization" {
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
    const zip_path = try std.fs.path.join(allocator, &.{ root, "mutated.zip" });

    var builder = try Builder.init(allocator, io, root, zip_path, .store);
    defer builder.deinit();
    try std.testing.expectError(error.DigestMismatch, builder.add(.{
        .path = "payload.bin",
        .size = 4,
        .expected_digest = expected,
        .data = .{ .external = spool_path },
    }, null));
    try std.testing.expectError(error.DigestMismatch, builder.finish());
}

test "ZIP metadata and payload stay on retained content after pathname replacement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const first_path = try std.fs.path.join(allocator, &.{ root, "first.zip" });
    const second_path = try std.fs.path.join(allocator, &.{ root, "second.zip" });
    {
        var builder = try Builder.init(allocator, io, root, first_path, .store);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = 4, .data = .{ .bytes = "AAAA" } }, null);
        try builder.finish();
    }
    {
        var builder = try Builder.init(allocator, io, root, second_path, .store);
        defer builder.deinit();
        try builder.add(.{ .path = "payload.bin", .size = 4, .data = .{ .bytes = "BBBB" } }, null);
        try builder.finish();
    }

    var retained = try fs.openReadContentAuthority(io, tmp.dir, "first.zip");
    defer retained.close(io);
    const retained_size = (try retained.stat(io)).size;
    var buffer: [64 * 1024]u8 = undefined;
    var reader = retained.reader(io, &buffer);
    const parsed = try readCentral(allocator, &reader);
    try std.testing.expectEqual(@as(usize, 1), parsed.entries.len);

    if (@import("builtin").target.os.tag == .windows) {
        var namespace_mover = try fs.openMutationAuthorityBeneathWindows(
            io,
            tmp.dir,
            "first.zip",
        );
        defer namespace_mover.close(io);
        try fs.renameOpenObjectBeneathWindows(
            io,
            tmp.dir,
            "renamed.zip",
            namespace_mover,
        );
    } else {
        try tmp.dir.rename("first.zip", tmp.dir, "renamed.zip", io);
    }
    try tmp.dir.rename("second.zip", tmp.dir, "first.zip", io);

    const bytes = try extractEntryAlloc(allocator, &reader, parsed.entries[0], 4);
    try std.testing.expectEqualStrings("AAAA", bytes);
    try std.testing.expectEqual(retained_size, (try retained.stat(io)).size);
}

test "Windows ZIP root file refuses a nested escaping junction" {
    if (@import("builtin").target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "install", .default_dir);
    var install = try tmp.dir.openDir(io, "install", .{ .access_sub_paths = true });
    defer install.close(io);
    try install.createDir(io, "nested", .default_dir);
    try tmp.dir.createDir(io, "outside", .default_dir);
    const sentinel_bytes = "outside sentinel must not be archived or changed";
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/sentinel.bin", .data = sentinel_bytes });

    const child = std.process.run(allocator, io, .{
        .argv = &.{ "cmd.exe", "/d", "/c", "mklink", "/J", "install\\nested\\junction", "outside" },
        .cwd = .{ .dir = tmp.dir },
    }) catch return error.SkipZigTest;
    defer allocator.free(child.stdout);
    defer allocator.free(child.stderr);
    switch (child.term) {
        .exited => |code| if (code != 0) return error.SkipZigTest,
        else => return error.SkipZigTest,
    }
    var nested = try tmp.dir.openDir(io, "install/nested", .{ .access_sub_paths = true });
    defer nested.close(io);
    defer nested.deleteDir(io, "junction") catch {};

    const temp_root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(temp_root);
    const install_root = try std.fs.path.join(allocator, &.{ temp_root, "install" });
    defer allocator.free(install_root);
    const zip_path = try std.fs.path.join(allocator, &.{ temp_root, "junction-refusal.zip" });
    defer allocator.free(zip_path);
    {
        var builder = try Builder.init(allocator, io, install_root, zip_path, .store);
        defer builder.deinit();
        try std.testing.expectError(error.UnsafePathAncestor, builder.add(.{
            .path = "nested/junction/sentinel.bin",
            .size = sentinel_bytes.len,
            .data = .file,
        }, null));
    }

    const sentinel = try tmp.dir.readFileAlloc(io, "outside/sentinel.bin", allocator, .limited(1024));
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings(sentinel_bytes, sentinel);
    const partial_archive = try tmp.dir.readFileAlloc(io, "junction-refusal.zip", allocator, .limited(1024));
    defer allocator.free(partial_archive);
    try std.testing.expect(std.mem.indexOf(u8, partial_archive, sentinel_bytes) == null);
}

test "extract rejects local and central flag mismatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "flags.zip" });

    {
        var builder = try Builder.init(allocator, io, root, zip_path, .store);
        defer builder.deinit();
        try builder.add(.{ .path = "a", .size = 1, .data = .{ .bytes = "x" } }, null);
        try builder.finish();
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .mode = .read_write, .allow_directory = false });
    defer file.close(io);
    var flags: [2]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try file.readPositionalAll(io, &flags, 6));
    flags[0] ^= 1;
    try file.writePositionalAll(io, &flags, 6);

    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const parsed = try readCentral(allocator, &reader);
    try std.testing.expectEqual(@as(usize, 1), parsed.entries.len);
    try std.testing.expectError(error.ZipMismatchFlags, extractEntryAlloc(allocator, &reader, parsed.entries[0], 16));
}

test "extract entry prefix reads only requested deflate bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "prefix.zip" });

    var data: [8192]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    {
        var builder = try Builder.init(allocator, io, root, zip_path, .deflate);
        defer builder.deinit();
        try builder.add(.{ .path = "big.bin", .size = data.len, .data = .{ .bytes = &data } }, null);
        try builder.finish();
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const parsed = try readCentral(allocator, &reader);
    const prefix = try extractEntryPrefixAlloc(allocator, &reader, parsed.entries[0], 4096);
    try std.testing.expectEqual(@as(usize, 4096), prefix.len);
    try std.testing.expectEqualSlices(u8, data[0..4096], prefix);
}

test "guarded ZIP extraction preserves caller ownership and rejects unsafe outputs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const payloads = [_][]const u8{ "guarded ZIP bytes", "" };

    for ([_]Compression{ .store, .deflate }, 0..) |compression, archive_index| {
        const archive_name = try allocator.print("guarded-{d}.zip", .{archive_index});
        const archive_path = try std.fs.path.join(allocator, &.{ root, archive_name });
        {
            var builder = try Builder.init(allocator, io, root, archive_path, compression);
            defer builder.deinit();
            for (payloads, 0..) |payload, index| {
                const path = try allocator.print("entry-{d}", .{index});
                try builder.add(.{ .path = path, .size = payload.len, .data = .{ .bytes = payload } }, null);
            }
            try builder.finish();
        }

        var archive_file = try std.Io.Dir.cwd().openFile(io, archive_path, .{ .allow_directory = false });
        defer archive_file.close(io);
        var buffer: [64 * 1024]u8 = undefined;
        var reader = archive_file.reader(io, &buffer);
        const parsed = try readCentral(allocator, &reader);

        for (parsed.entries, payloads, 0..) |entry, payload, entry_index| {
            const output_name = try allocator.print(
                "guarded-{d}-{d}.out",
                .{ archive_index, entry_index },
            );
            var guarded = try fs.createGuardedOutputBeneath(io, tmp.dir, output_name);
            defer guarded.close(io);
            const construction_md5 = try extractEntryToGuardedFileProgressMd5(
                io,
                &reader,
                entry,
                guarded,
                null,
            );
            var expected_md5: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(payload, &expected_md5, .{});
            try std.testing.expectEqualSlices(u8, &expected_md5, &construction_md5);
            try fs.validateGuardedOutput(io, guarded, payload.len);
            if (payload.len != 0) try guarded.writePositionalAll(io, payload[0..1], 0);
            try guarded.sync(io);
            const actual = try allocator.alloc(u8, payload.len);
            try std.testing.expectEqual(payload.len, try guarded.readPositionalAll(io, actual, 0));
            try std.testing.expectEqualSlices(u8, payload, actual);
        }

        const sentinel_name = try allocator.print("sentinel-{d}", .{archive_index});
        try tmp.dir.writeFile(io, .{ .sub_path = sentinel_name, .data = "sentinel" });
        var nonempty = try fs.openReadWrite(io, tmp.dir, sentinel_name);
        defer nonempty.close(io);
        try std.testing.expectError(
            error.UnsafeGuardedOutput,
            extractEntryToGuardedFileProgress(io, &reader, parsed.entries[0], nonempty, null),
        );
        const sentinel = try tmp.dir.readFileAlloc(io, sentinel_name, allocator, .limited(16));
        try std.testing.expectEqualStrings("sentinel", sentinel);

        const read_only_name = try allocator.print("read-only-{d}", .{archive_index});
        try tmp.dir.writeFile(io, .{ .sub_path = read_only_name, .data = "" });
        var read_only = try fs.openRead(io, tmp.dir, read_only_name);
        defer read_only.close(io);
        try std.testing.expectError(
            error.UnsafeGuardedOutput,
            extractEntryToGuardedFileProgress(io, &reader, parsed.entries[0], read_only, null),
        );
    }
}

test "central directory preserves explicit directory records without trailing slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const zip_path = try std.fs.path.join(allocator, &.{ root, "directory.zip" });

    // file-only builder: equal-width directory-name patch for stable offsets
    const placeholder = "manifest_dir";
    const directory_name = "pkg_version/";
    comptime std.debug.assert(placeholder.len == directory_name.len);
    {
        var builder = try Builder.init(allocator, io, root, zip_path, .store);
        defer builder.deinit();
        try builder.add(.{ .path = placeholder, .size = 0, .data = .{ .bytes = "" } }, null);
        try builder.finish();
    }
    {
        var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .mode = .read_write, .allow_directory = false });
        defer file.close(io);
        const size = try file.length(io);
        const bytes = try allocator.alloc(u8, @intCast(size));
        try std.testing.expectEqual(bytes.len, try file.readPositionalAll(io, bytes, 0));
        var found: usize = 0;
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, bytes, from, placeholder)) |at| {
            try file.writePositionalAll(io, directory_name, at);
            found += 1;
            from = at + placeholder.len;
        }
        try std.testing.expectEqual(@as(usize, 2), found);
    }

    var file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const parsed = try readCentral(allocator, &reader);
    try std.testing.expectEqual(@as(usize, 0), parsed.entries.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.directories.len);
    try std.testing.expectEqualStrings("pkg_version", parsed.directories[0]);
}

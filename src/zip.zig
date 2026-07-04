// ZIP writing and extraction helpers
const std = @import("std");
const flate = std.compress.flate;

const fmt = @import("fmt.zig");
const manifest = @import("manifest.zig");

pub const Entry = struct {
    path: []const u8,
    zip_entry: std.zip.Iterator.Entry,
};

pub const Package = struct {
    entries: []Entry,

    pub fn find(self: Package, path: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.path, path)) return entry;
        }
        return null;
    }
};

pub const Source = struct {
    path: []const u8,
    size: u64,
    expected_md5: ?[16]u8 = null,
    data: Data,

    pub const Data = union(enum) {
        file,
        bytes: []const u8,
    };
};

const WrittenEntry = struct {
    path: []const u8,
    size: u64,
    crc32: u32,
    local_offset: u64,
};

const Extracted = struct {
    size: u64,
    crc32: u32,
};

// Central directory reading

pub fn readCentral(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    progress: ?*fmt.Progress,
) !Package {
    var iter = try std.zip.Iterator.init(reader);
    if (progress) |p| {
        p.total_bytes = 0;
        p.total_files = @intCast(iter.cd_record_count);
        try p.start();
    }

    var entries: std.ArrayList(Entry) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;

    while (try iter.next()) |entry| {
        const name = try centralNameAlloc(allocator, reader, entry);
        if (isDirectoryRecord(name)) {
            try validateDirectoryRecord(name, entry);
            if (progress) |p| try p.finishFile();
            continue;
        }
        try manifest.validatePath(name);

        const got = try seen.getOrPut(allocator, name);
        if (got.found_existing) return error.DuplicateZipPath;
        got.value_ptr.* = {};

        try entries.append(allocator, .{
            .path = name,
            .zip_entry = entry,
        });
        if (progress) |p| try p.finishFile();
    }

    if (progress) |p| try p.finish();
    return .{ .entries = try entries.toOwnedSlice(allocator) };
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
    try manifest.validatePath(path[0 .. path.len - 1]);
}

fn centralNameAlloc(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    entry: std.zip.Iterator.Entry,
) ![]const u8 {
    const len: usize = @intCast(entry.filename_len);
    const name = try allocator.alloc(u8, len);
    errdefer allocator.free(name);

    try reader.seekTo(entry.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
    reader.interface.readSliceAll(name) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream => return error.UnexpectedEof,
    };
    return name;
}

// ZIP extraction

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

pub fn extractAll(
    io: std.Io,
    zip_path: []const u8,
    game_path: []const u8,
    entries: []const Entry,
    progress: ?*fmt.Progress,
) !void {
    var zip_file = try std.Io.Dir.cwd().openFile(io, zip_path, .{ .allow_directory = false });
    defer zip_file.close(io);
    var zip_buf: [64 * 1024]u8 = undefined;
    var reader = zip_file.reader(io, &zip_buf);

    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    for (entries) |entry| {
        try extractEntryToDir(io, &reader, game_dir, entry, progress);
        if (progress) |p| try p.finishFile();
    }
}

fn extractEntryToDir(
    io: std.Io,
    reader: *std.Io.File.Reader,
    dest: std.Io.Dir,
    entry: Entry,
    progress: ?*fmt.Progress,
) !void {
    if (std.mem.eql(u8, entry.path, "pkg_version")) {
        // Root-level file, no parent to create.
    } else if (zipDirname(entry.path)) |dir| {
        try dest.createDirPath(io, dir);
    }

    var out_file = try dest.createFile(io, entry.path, .{ .truncate = true });
    defer out_file.close(io);
    var out_buf: [64 * 1024]u8 = undefined;
    var writer = out_file.writer(io, &out_buf);
    try extractEntryToWriterProgress(reader, entry, &writer.interface, progress);
    try writer.end();
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
    progress: ?*fmt.Progress,
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
    progress: ?*fmt.Progress,
) !Extracted {
    var remaining = len;
    var total: u64 = 0;
    var crc = std.hash.crc.Crc32.init();
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
    progress: ?*fmt.Progress,
) !Extracted {
    var remaining = len;
    var total: u64 = 0;
    var crc = std.hash.crc.Crc32.init();
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
    if (local_header.filename_len != entry.zip_entry.filename_len) return error.ZipMismatchFilenameLen;
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

    return entry.zip_entry.file_offset +
        @as(u64, @sizeOf(std.zip.LocalFileHeader)) +
        @as(u64, local_header.filename_len) +
        @as(u64, local_header.extra_len);
}

fn zipDirname(path: []const u8) ?[]const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return null;
    if (slash == 0) return null;
    return path[0..slash];
}

// Store-only ZIP writing

pub fn writeStore(
    allocator: std.mem.Allocator,
    io: std.Io,
    game_path: []const u8,
    out_path: []const u8,
    sources: []const Source,
    progress: ?*fmt.Progress,
) !void {
    var game_dir = try std.Io.Dir.cwd().openDir(io, game_path, .{ .access_sub_paths = true });
    defer game_dir.close(io);

    var out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{ .exclusive = true });
    defer out_file.close(io);

    var out_buf: [64 * 1024]u8 = undefined;
    var writer = out_file.writer(io, &out_buf);
    var offset: u64 = 0;
    var written: std.ArrayList(WrittenEntry) = .empty;

    for (sources) |source| {
        try manifest.validatePath(source.path);
        const local_offset = offset;
        try writeLocalHeader(&writer.interface, source.path, source.size, &offset);

        const hashes = switch (source.data) {
            .file => try streamFile(io, game_dir, source, &writer.interface, &offset, progress),
            .bytes => |bytes| try streamBytes(bytes, &writer.interface, &offset, progress),
        };

        if (hashes.size != source.size) return error.SizeMismatch;
        if (source.expected_md5) |expected| {
            if (!std.mem.eql(u8, &hashes.md5, &expected)) return error.Md5Mismatch;
        }

        try writer.interface.flush();
        var crc_buf: [4]u8 = undefined;
        put32(crc_buf[0..4], hashes.crc32);
        try out_file.writePositionalAll(io, &crc_buf, local_offset + 14);

        try written.append(allocator, .{
            .path = source.path,
            .size = source.size,
            .crc32 = hashes.crc32,
            .local_offset = local_offset,
        });

        if (progress) |p| try p.finishFile();
    }

    const central_start = offset;
    for (written.items) |entry| {
        try writeCentralHeader(&writer.interface, entry, &offset);
    }
    const central_size = offset - central_start;
    try writeEndRecords(&writer.interface, written.items.len, central_start, central_size, &offset);
    try writer.end();
}

const StreamHashes = struct {
    size: u64,
    crc32: u32,
    md5: [16]u8,
};

fn streamFile(
    io: std.Io,
    dir: std.Io.Dir,
    source: Source,
    out: *std.Io.Writer,
    offset: *u64,
    progress: ?*fmt.Progress,
) !StreamHashes {
    var file = try dir.openFile(io, source.path, .{ .allow_directory = false });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;
    if (stat.size != source.size) return error.SizeMismatch;

    var crc = std.hash.crc.Crc32.init();
    var md5 = std.crypto.hash.Md5.init(.{});
    var total: u64 = 0;
    var file_offset: u64 = 0;
    var buf: [1024 * 1024]u8 = undefined;

    while (true) {
        const n = try file.readPositionalAll(io, &buf, file_offset);
        if (n == 0) break;
        const chunk = buf[0..n];
        crc.update(chunk);
        md5.update(chunk);
        try out.writeAll(chunk);
        total += n;
        file_offset += n;
        offset.* += n;
        if (progress) |p| try p.addBytes(n);
    }

    var digest: [16]u8 = undefined;
    md5.final(&digest);
    return .{ .size = total, .crc32 = crc.final(), .md5 = digest };
}

fn streamBytes(bytes: []const u8, out: *std.Io.Writer, offset: *u64, progress: ?*fmt.Progress) !StreamHashes {
    var crc = std.hash.crc.Crc32.init();
    var md5 = std.crypto.hash.Md5.init(.{});
    crc.update(bytes);
    md5.update(bytes);
    try out.writeAll(bytes);
    offset.* += bytes.len;
    if (progress) |p| try p.addBytes(bytes.len);

    var digest: [16]u8 = undefined;
    md5.final(&digest);
    return .{ .size = bytes.len, .crc32 = crc.final(), .md5 = digest };
}

fn writeLocalHeader(out: *std.Io.Writer, path: []const u8, size: u64, offset: *u64) !void {
    const needs_zip64 = size > std.math.maxInt(u32);
    const extra_len: u16 = if (needs_zip64) 20 else 0;

    var header: [30]u8 = undefined;
    put32(header[0..4], 0x04034b50);
    put16(header[4..6], if (needs_zip64) 45 else 20);
    put16(header[6..8], 0);
    put16(header[8..10], 0);
    put16(header[10..12], 0);
    put16(header[12..14], 0);
    put32(header[14..18], 0);
    put32(header[18..22], if (needs_zip64) std.math.maxInt(u32) else @as(u32, @intCast(size)));
    put32(header[22..26], if (needs_zip64) std.math.maxInt(u32) else @as(u32, @intCast(size)));
    put16(header[26..28], @intCast(path.len));
    put16(header[28..30], extra_len);

    try out.writeAll(&header);
    try out.writeAll(path);
    offset.* += header.len + path.len;

    if (needs_zip64) {
        var extra: [20]u8 = undefined;
        put16(extra[0..2], 0x0001);
        put16(extra[2..4], 16);
        put64(extra[4..12], size);
        put64(extra[12..20], size);
        try out.writeAll(&extra);
        offset.* += extra.len;
    }
}

fn writeCentralHeader(out: *std.Io.Writer, entry: WrittenEntry, offset: *u64) !void {
    const needs_size64 = entry.size > std.math.maxInt(u32);
    const needs_offset64 = entry.local_offset > std.math.maxInt(u32);
    const extra_data_len: u16 =
        (if (needs_size64) @as(u16, 16) else 0) +
        (if (needs_offset64) @as(u16, 8) else 0);
    const extra_len: u16 = if (extra_data_len == 0) 0 else extra_data_len + 4;
    const needs_zip64 = extra_len != 0;

    var header: [46]u8 = undefined;
    put32(header[0..4], 0x02014b50);
    put16(header[4..6], if (needs_zip64) 45 else 20);
    put16(header[6..8], if (needs_zip64) 45 else 20);
    put16(header[8..10], 0);
    put16(header[10..12], 0);
    put16(header[12..14], 0);
    put16(header[14..16], 0);
    put32(header[16..20], entry.crc32);
    put32(header[20..24], if (needs_size64) std.math.maxInt(u32) else @as(u32, @intCast(entry.size)));
    put32(header[24..28], if (needs_size64) std.math.maxInt(u32) else @as(u32, @intCast(entry.size)));
    put16(header[28..30], @intCast(entry.path.len));
    put16(header[30..32], extra_len);
    put16(header[32..34], 0);
    put16(header[34..36], 0);
    put16(header[36..38], 0);
    put32(header[38..42], 0);
    put32(header[42..46], if (needs_offset64) std.math.maxInt(u32) else @as(u32, @intCast(entry.local_offset)));

    try out.writeAll(&header);
    try out.writeAll(entry.path);
    offset.* += header.len + entry.path.len;

    if (needs_zip64) {
        var extra: [4 + 16 + 8]u8 = undefined;
        put16(extra[0..2], 0x0001);
        put16(extra[2..4], extra_data_len);
        var index: usize = 4;
        if (needs_size64) {
            put64(extra[index..][0..8], entry.size);
            index += 8;
            put64(extra[index..][0..8], entry.size);
            index += 8;
        }
        if (needs_offset64) {
            put64(extra[index..][0..8], entry.local_offset);
            index += 8;
        }
        try out.writeAll(extra[0..index]);
        offset.* += index;
    }
}

fn writeEndRecords(
    out: *std.Io.Writer,
    count: usize,
    central_start: u64,
    central_size: u64,
    offset: *u64,
) !void {
    const needs_zip64 = count > std.math.maxInt(u16) or
        central_start > std.math.maxInt(u32) or
        central_size > std.math.maxInt(u32);

    if (needs_zip64) {
        const record64_offset = offset.*;
        var record64: [56]u8 = undefined;
        put32(record64[0..4], 0x06064b50);
        put64(record64[4..12], 44);
        put16(record64[12..14], 45);
        put16(record64[14..16], 45);
        put32(record64[16..20], 0);
        put32(record64[20..24], 0);
        put64(record64[24..32], count);
        put64(record64[32..40], count);
        put64(record64[40..48], central_size);
        put64(record64[48..56], central_start);
        try out.writeAll(&record64);
        offset.* += record64.len;

        var locator: [20]u8 = undefined;
        put32(locator[0..4], 0x07064b50);
        put32(locator[4..8], 0);
        put64(locator[8..16], record64_offset);
        put32(locator[16..20], 1);
        try out.writeAll(&locator);
        offset.* += locator.len;
    }

    var end: [22]u8 = undefined;
    put32(end[0..4], 0x06054b50);
    put16(end[4..6], 0);
    put16(end[6..8], 0);
    put16(end[8..10], if (count > std.math.maxInt(u16)) std.math.maxInt(u16) else @as(u16, @intCast(count)));
    put16(end[10..12], if (count > std.math.maxInt(u16)) std.math.maxInt(u16) else @as(u16, @intCast(count)));
    put32(end[12..16], if (central_size > std.math.maxInt(u32)) std.math.maxInt(u32) else @as(u32, @intCast(central_size)));
    put32(end[16..20], if (central_start > std.math.maxInt(u32)) std.math.maxInt(u32) else @as(u32, @intCast(central_start)));
    put16(end[20..22], 0);
    try out.writeAll(&end);
    offset.* += end.len;
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

// ziff framing; metadata opens without payload reads

const std = @import("std");
const builtin = @import("builtin");
const fs = @import("../core/fs.zig");
const ids = @import("../core/ids.zig");
const ziff = @import("ziff.zig");
const zstd_frame = @import("../compression/frame.zig");

pub const max_header_bytes: u64 = 1024 * 1024;
pub const max_directory_stored_bytes: u64 = 256 * 1024 * 1024;
pub const max_directory_plain_bytes: u64 = 256 * 1024 * 1024;
pub const directory_zstd_level: c_int = 5;

pub const Opened = struct {
    arena: std.heap.ArenaAllocator,
    header: ziff.Header,
    directory: ziff.Directory,
    payload_start: u64,
    payload_end: u64,
    file_size: u64,

    pub fn deinit(opened: *Opened) void {
        opened.arena.deinit();
        opened.* = undefined;
    }
};

fn checkedUsize(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.ExtentTooLargeForAddressSpace;
}

fn readExactAt(io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !void {
    if (try fs.readAllAt(io, file, buffer, offset) != buffer.len) return error.TruncatedContainer;
}

fn readPrefix(
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
) !struct { preamble: ziff.Preamble, header: ziff.Header, payload_start: u64 } {
    var preamble_bytes: [ziff.preamble_size]u8 = undefined;
    try readExactAt(io, file, &preamble_bytes, 0);
    const preamble = try ziff.decodePreamble(&preamble_bytes);
    if (preamble.header_len > max_header_bytes) return error.HeaderTooLarge;
    const payload_start = std.math.add(u64, ziff.preamble_size, preamble.header_len) catch return error.HeaderExtentOverflow;

    const header_bytes = try allocator.alloc(u8, try checkedUsize(preamble.header_len));
    defer allocator.free(header_bytes);
    try readExactAt(io, file, header_bytes, ziff.preamble_size);
    return .{
        .preamble = preamble,
        .header = try ziff.decodeHeader(allocator, header_bytes),
        .payload_start = payload_start,
    };
}

fn encodeCheckedHeader(
    allocator: std.mem.Allocator,
    header: ziff.Header,
) ![]u8 {
    const header_bytes = try ziff.encodeHeader(allocator, header);
    errdefer allocator.free(header_bytes);
    if (header_bytes.len > max_header_bytes) return error.HeaderTooLarge;

    // decodeHeader owns schema/option checks
    var checked = try ziff.decodeHeader(allocator, header_bytes);
    defer checked.deinit(allocator);
    return header_bytes;
}

fn beginEncodedFile(
    io: std.Io,
    file: std.Io.File,
    header_bytes: []const u8,
) !u64 {
    try fs.validateGuardedOutput(io, file, 0);

    const payload_start = std.math.add(u64, ziff.preamble_size, header_bytes.len) catch return error.HeaderExtentOverflow;
    const preamble = ziff.encodePreamble(.{ .finalized = false, .header_len = header_bytes.len });
    try file.writePositionalAll(io, &preamble, 0);
    try file.writePositionalAll(io, header_bytes, ziff.preamble_size);
    try file.setLength(io, payload_start);
    try file.sync(io);
    return payload_start;
}

fn verifyCreatedBinding(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    file: std.Io.File,
) !void {
    var rebound = fs.openRead(io, dir, sub_path) catch
        return error.ContainerPathChangedDuringCreate;
    defer rebound.close(io);
    if (!try fs.sameOpenFile(io, file, rebound))
        return error.ContainerPathChangedDuringCreate;
}

fn discardCreatedFile(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    file: std.Io.File,
) !void {
    if (builtin.target.os.tag == .windows) return fs.deleteOpenObjectWindows(file);
    try verifyCreatedBinding(io, dir, sub_path, file);
    try dir.deleteFile(io, sub_path);
}

pub fn begin(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    header: ziff.Header,
) !u64 {
    const header_bytes = try encodeCheckedHeader(allocator, header);
    defer allocator.free(header_bytes);

    var file = try fs.createGuardedOutput(io, dir, sub_path);
    errdefer {
        discardCreatedFile(io, dir, sub_path, file) catch {};
        file.close(io);
    }
    const payload_start = try beginEncodedFile(io, file, header_bytes);
    try verifyCreatedBinding(io, dir, sub_path, file);
    file.close(io);
    return payload_start;
}

// caller-retained handle through payloads and finalization
pub fn beginFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    header: ziff.Header,
) !u64 {
    const header_bytes = try encodeCheckedHeader(allocator, header);
    defer allocator.free(header_bytes);
    return beginEncodedFile(io, file, header_bytes);
}

fn immutableHeaderEqual(old: ziff.Header, new: ziff.Header) bool {
    return old.required_features == new.required_features and
        old.optional_features == new.optional_features and
        old.software_id == new.software_id and
        std.mem.eql(u8, old.source_identity, new.source_identity) and
        std.mem.eql(u8, old.target_identity, new.target_identity) and
        old.source_fingerprint.eql(new.source_fingerprint) and
        old.target_fingerprint.eql(new.target_fingerprint) and
        old.target_bytes == new.target_bytes and
        old.source_bytes == new.source_bytes and
        old.unit_count == new.unit_count;
}

// fixed header length for stable payload offsets; other fields immutable
pub fn rewriteTargetFingerprintFile(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File, new_header: ziff.Header) !void {
    const encoded = try encodeCheckedHeader(allocator, new_header);
    defer allocator.free(encoded);
    const original_length = try file.length(io);
    const prefix = try readPrefix(allocator, io, file);
    var old_header = prefix.header;
    defer old_header.deinit(allocator);
    if (prefix.preamble.finalized) return error.AlreadyFinalized;
    if (prefix.preamble.header_len != encoded.len or
        prefix.payload_start != ziff.preamble_size + encoded.len)
    {
        return error.HeaderLengthChanged;
    }
    old_header.target_fingerprint = new_header.target_fingerprint;
    if (!immutableHeaderEqual(old_header, new_header)) return error.ImmutableHeaderChanged;
    if (original_length < prefix.payload_start) return error.TruncatedContainer;

    try file.writePositionalAll(io, encoded, ziff.preamble_size);
    try file.sync(io);
    if (try file.length(io) != original_length) return error.ContainerChangedDuringHeaderRewrite;
}

// directory/footer durable before finalized flag
pub fn finish(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    directory: ziff.Directory,
) !void {
    var file = try fs.openReadWrite(io, dir, sub_path);
    defer file.close(io);
    return finishFile(allocator, io, file, directory);
}

pub fn finishFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    directory: ziff.Directory,
) !void {
    const payload_end = try file.length(io);

    const prefix = try readPrefix(allocator, io, file);
    var header = prefix.header;
    defer header.deinit(allocator);
    if (prefix.preamble.finalized) return error.AlreadyFinalized;
    if (payload_end < prefix.payload_start) return error.TruncatedContainer;

    try ziff.validate(allocator, header, directory, prefix.payload_start, payload_end);
    const directory_plain = try ziff.encodeDirectory(allocator, directory);
    defer allocator.free(directory_plain);
    if (directory_plain.len == 0) return error.EmptyDirectory;
    if (directory_plain.len > max_directory_plain_bytes) return error.DirectoryPlainTooLarge;

    const directory_stored = try zstd_frame.compressAlloc(allocator, directory_plain, directory_zstd_level);
    defer allocator.free(directory_stored);
    if (directory_stored.len == 0) return error.EmptyDirectoryFrame;
    if (directory_stored.len > max_directory_stored_bytes) return error.DirectoryStoredTooLarge;

    const footer_value: ziff.Footer = .{
        .directory_offset = payload_end,
        .directory_stored_len = directory_stored.len,
        .directory_plain_len = directory_plain.len,
        .directory_digest = ids.Digest.of(directory_stored),
    };
    const footer = ziff.encodeFooter(footer_value);
    const footer_offset = std.math.add(u64, payload_end, directory_stored.len) catch return error.DirectoryExtentOverflow;
    const final_size = std.math.add(u64, footer_offset, ziff.footer_size) catch return error.DirectoryExtentOverflow;

    try file.writePositionalAll(io, directory_stored, payload_end);
    try file.writePositionalAll(io, &footer, footer_offset);
    try file.setLength(io, final_size);
    try file.sync(io);

    var finalized_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &finalized_bytes, ziff.finalized_flag, .little);
    try file.writePositionalAll(io, &finalized_bytes, 6);
    try file.sync(io);
}

pub fn revokeFinalizedFile(io: std.Io, file: std.Io.File) !void {
    var unfinalized_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &unfinalized_bytes, 0, .little);
    try file.writePositionalAll(io, &unfinalized_bytes, 6);
    try file.sync(io);
}

pub fn open(
    backing_allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !Opened {
    var file = try fs.openRead(io, dir, sub_path);
    defer file.close(io);
    return openFile(backing_allocator, io, file);
}

pub fn openFile(
    backing_allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
) !Opened {
    var opened: Opened = .{
        .arena = .init(backing_allocator),
        .header = undefined,
        .directory = undefined,
        .payload_start = 0,
        .payload_end = 0,
        .file_size = 0,
    };
    errdefer opened.arena.deinit();
    const owned_allocator = opened.arena.allocator();

    const file_size = try file.length(io);
    if (file_size < ziff.preamble_size) return error.TruncatedContainer;

    var preamble_bytes: [ziff.preamble_size]u8 = undefined;
    try readExactAt(io, file, &preamble_bytes, 0);
    const preamble = try ziff.decodePreamble(&preamble_bytes);
    if (!preamble.finalized) return error.UnfinalizedContainer;
    if (file_size < ziff.preamble_size + ziff.footer_size) return error.TruncatedContainer;
    if (preamble.header_len > max_header_bytes) return error.HeaderTooLarge;
    const payload_start = std.math.add(u64, ziff.preamble_size, preamble.header_len) catch return error.HeaderExtentOverflow;
    if (payload_start > file_size - ziff.footer_size) return error.TruncatedContainer;

    var footer_bytes: [ziff.footer_size]u8 = undefined;
    try readExactAt(io, file, &footer_bytes, file_size - ziff.footer_size);
    const footer = try ziff.decodeFooter(&footer_bytes);
    if (footer.directory_stored_len > max_directory_stored_bytes) return error.DirectoryStoredTooLarge;
    if (footer.directory_plain_len > max_directory_plain_bytes) return error.DirectoryPlainTooLarge;
    try ziff.validateEnvelope(preamble, footer, file_size);

    opened.header = header: {
        const header_bytes = try backing_allocator.alloc(u8, try checkedUsize(preamble.header_len));
        defer backing_allocator.free(header_bytes);
        try readExactAt(io, file, header_bytes, ziff.preamble_size);
        break :header try ziff.decodeHeader(owned_allocator, header_bytes);
    };

    opened.directory = directory: {
        const directory_plain = plain: {
            const stored_len = try checkedUsize(footer.directory_stored_len);
            const directory_stored = try backing_allocator.alloc(u8, stored_len);
            defer backing_allocator.free(directory_stored);
            try readExactAt(io, file, directory_stored, footer.directory_offset);
            if (!ids.Digest.of(directory_stored).eql(footer.directory_digest)) return error.DirectoryDigestMismatch;
            break :plain try zstd_frame.decompressExact(
                backing_allocator,
                directory_stored,
                try checkedUsize(footer.directory_plain_len),
            );
        };
        defer backing_allocator.free(directory_plain);
        break :directory try ziff.decodeDirectory(owned_allocator, directory_plain);
    };
    // scratch on backing allocator, not the retained metadata arena
    try ziff.validate(backing_allocator, opened.header, opened.directory, payload_start, footer.directory_offset);
    if (try file.length(io) != file_size) return error.ContainerChangedDuringOpen;

    opened.payload_start = payload_start;
    opened.payload_end = footer.directory_offset;
    opened.file_size = file_size;
    return opened;
}

const Fixture = struct {
    header: ziff.Header,
    files: [1]ziff.FileEntry,
    ops: [1]ziff.Op,
    units: [1]ziff.Unit,

    fn init(payload_start: u64, payload_len: u64) Fixture {
        const digest = ids.Digest.of("abc");
        var fixture: Fixture = .{
            .header = .{
                .source_identity = "source",
                .target_identity = "target",
                .source_fingerprint = ids.Digest.of("source-tree"),
                .target_fingerprint = .zero,
                .target_bytes = 3,
                .source_bytes = 0,
                .unit_count = 1,
            },
            .files = .{.{ .path = "new.bin", .size = 3, .digest = digest }},
            .ops = .{.{ .kind = .full, .target = 0, .arg = 0 }},
            .units = .{.{
                .kind = .zstd,
                .payload_offset = payload_start,
                .payload_len = payload_len,
                .target = 0,
                .source_first = 0,
                .source_count = 0,
            }},
        };
        fixture.header.target_fingerprint = ziff.logicalFingerprint(&fixture.files);
        return fixture;
    }

    fn directory(fixture: *Fixture) ziff.Directory {
        return .{
            .files = &fixture.files,
            .ops = &fixture.ops,
            .units = &fixture.units,
            .sources = &.{},
            .removed = &.{},
        };
    }
};

fn makeContainer(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
    var fixture = Fixture.init(0, 7);
    const payload_start = try begin(allocator, io, dir, path, fixture.header);
    fixture.units[0].payload_offset = payload_start;
    var file = try fs.openReadWrite(io, dir, path);
    try file.writePositionalAll(io, "PAYLOAD", payload_start);
    file.close(io);
    try finish(allocator, io, dir, path, fixture.directory());
}

fn readWhole(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) ![]u8 {
    var file = try fs.openRead(io, dir, path);
    defer file.close(io);
    const bytes = try allocator.alloc(u8, try checkedUsize(try file.length(io)));
    errdefer allocator.free(bytes);
    try readExactAt(io, file, bytes, 0);
    return bytes;
}

test "schema 0 file begin finish and metadata-only open round trip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "roundtrip.ziff");

    var result = try open(allocator, io, tmp.dir, "roundtrip.ziff");
    defer result.deinit();
    try std.testing.expectEqualStrings("source", result.header.source_identity);
    try std.testing.expectEqualStrings("new.bin", result.directory.files[0].path);
    try std.testing.expectEqual(@as(u64, 7), result.payload_end - result.payload_start);
}

test "schema 0 file creation is byte deterministic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "one.ziff");
    try makeContainer(allocator, io, tmp.dir, "two.ziff");
    const one = try readWhole(allocator, io, tmp.dir, "one.ziff");
    defer allocator.free(one);
    const two = try readWhole(allocator, io, tmp.dir, "two.ziff");
    defer allocator.free(two);
    try std.testing.expectEqualSlices(u8, one, two);
}

test "unfinalized header rewrite completes only the Target fingerprint" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture = Fixture.init(0, 7);
    const target_fingerprint = fixture.header.target_fingerprint;
    fixture.header.target_fingerprint = ziff.logicalFingerprint(&.{});
    const payload_start = try begin(allocator, io, tmp.dir, "rewrite.ziff", fixture.header);
    fixture.units[0].payload_offset = payload_start;
    var file = try fs.openReadWrite(io, tmp.dir, "rewrite.ziff");
    try file.writePositionalAll(io, "PAYLOAD", payload_start);

    var immutable_changed = fixture.header;
    immutable_changed.software_id += 1;
    try std.testing.expectError(
        error.ImmutableHeaderChanged,
        rewriteTargetFingerprintFile(allocator, io, file, immutable_changed),
    );

    fixture.header.target_fingerprint = target_fingerprint;
    try rewriteTargetFingerprintFile(allocator, io, file, fixture.header);
    file.close(io);
    var still_unfinalized = try fs.openRead(io, tmp.dir, "rewrite.ziff");
    var preamble_bytes: [ziff.preamble_size]u8 = undefined;
    try readExactAt(io, still_unfinalized, &preamble_bytes, 0);
    still_unfinalized.close(io);
    try std.testing.expect(!(try ziff.decodePreamble(&preamble_bytes)).finalized);

    try finish(allocator, io, tmp.dir, "rewrite.ziff", fixture.directory());
    var opened = try open(allocator, io, tmp.dir, "rewrite.ziff");
    defer opened.deinit();
    try std.testing.expect(opened.header.target_fingerprint.eql(target_fingerprint));
    var finalized = try fs.openReadWrite(io, tmp.dir, "rewrite.ziff");
    defer finalized.close(io);
    try std.testing.expectError(
        error.AlreadyFinalized,
        rewriteTargetFingerprintFile(allocator, io, finalized, fixture.header),
    );
}

test "schema 0 file refuses unfinalized containers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "unfinalized.ziff");
    var file = try fs.openReadWrite(io, tmp.dir, "unfinalized.ziff");
    try file.writePositionalAll(io, &[_]u8{ 0, 0 }, 6);
    file.close(io);
    try std.testing.expectError(error.UnfinalizedContainer, open(allocator, io, tmp.dir, "unfinalized.ziff"));
}

test "schema 0 file refuses authenticated metadata and framing corruption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "base.ziff");
    const original = try readWhole(allocator, io, tmp.dir, "base.ziff");
    defer allocator.free(original);

    const Case = struct { name: []const u8, offset: usize, wanted: anyerror };
    const cases = [_]Case{
        .{ .name = "bad-header.ziff", .offset = ziff.preamble_size + 7, .wanted = error.UnsupportedRequiredFeature },
        .{ .name = "bad-digest.ziff", .offset = original.len - ziff.footer_size + 24, .wanted = error.DirectoryDigestMismatch },
        .{ .name = "bad-footer.ziff", .offset = original.len - 1, .wanted = error.InvalidFooterMagic },
    };
    for (cases) |case| {
        const changed = try allocator.dupe(u8, original);
        defer allocator.free(changed);
        changed[case.offset] ^= 1;
        try tmp.dir.writeFile(io, .{ .sub_path = case.name, .data = changed });
        try std.testing.expectError(case.wanted, open(allocator, io, tmp.dir, case.name));
    }
}

test "schema 0 file enforces hostile metadata length caps before allocation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "caps-base.ziff");
    const original = try readWhole(allocator, io, tmp.dir, "caps-base.ziff");
    defer allocator.free(original);
    const footer_start = original.len - ziff.footer_size;

    const Case = struct { name: []const u8, offset: usize, value: u64, wanted: anyerror };
    const cases = [_]Case{
        .{ .name = "huge-header.ziff", .offset = 8, .value = max_header_bytes + 1, .wanted = error.HeaderTooLarge },
        .{ .name = "huge-stored.ziff", .offset = footer_start + 8, .value = max_directory_stored_bytes + 1, .wanted = error.DirectoryStoredTooLarge },
        .{ .name = "huge-plain.ziff", .offset = footer_start + 16, .value = max_directory_plain_bytes + 1, .wanted = error.DirectoryPlainTooLarge },
    };
    for (cases) |case| {
        const changed = try allocator.dupe(u8, original);
        defer allocator.free(changed);
        std.mem.writeInt(u64, changed[case.offset..][0..8], case.value, .little);
        try tmp.dir.writeFile(io, .{ .sub_path = case.name, .data = changed });
        try std.testing.expectError(case.wanted, open(allocator, io, tmp.dir, case.name));
    }
}

fn openAllocationExercise(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
) !void {
    var result = try open(allocator, io, dir, path);
    defer result.deinit();
}

test "schema 0 file open cleans up every arena allocation failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "allocation.ziff");
    try std.testing.checkAllAllocationFailures(
        allocator,
        openAllocationExercise,
        .{ io, tmp.dir, "allocation.ziff" },
    );
}

test "schema 0 file refuses every truncated file prefix" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeContainer(allocator, io, tmp.dir, "complete.ziff");
    const bytes = try readWhole(allocator, io, tmp.dir, "complete.ziff");
    defer allocator.free(bytes);

    for (0..bytes.len) |cut| {
        try tmp.dir.writeFile(io, .{ .sub_path = "prefix.ziff", .data = bytes[0..cut] });
        if (open(allocator, io, tmp.dir, "prefix.ziff")) |unexpected| {
            var result = unexpected;
            result.deinit();
            return error.TruncatedContainerAccepted;
        } else |_| {}
    }
}

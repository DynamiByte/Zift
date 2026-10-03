// ziff schema-0 metadata encoding and validation

const std = @import("std");
const ids = @import("../core/ids.zig");
const ranges = @import("../core/ranges.zig");
const wire = @import("../core/varint.zig");
const logical_path = @import("../path.zig");

pub const magic = "ZIFF";
pub const footer_magic = "ZIFX";
pub const schema: u16 = 0;
pub const preamble_size: usize = 16;
pub const footer_size: usize = 64;
pub const max_identity_bytes: usize = std.math.maxInt(u16);
pub const max_path_bytes: usize = std.math.maxInt(u16);
pub const max_table_entries: usize = 16 * 1024 * 1024;
// front-coded paths: decoded-size bound independent of frame size
pub const max_decoded_directory_bytes: usize = 256 * 1024 * 1024;
// journal-state bound before directory availability
pub const max_unit_count: usize = max_decoded_directory_bytes /
    (@sizeOf(FileEntry) + @sizeOf(Op) + @sizeOf(Unit));

pub const finalized_flag: u16 = 1 << 0;
pub const known_container_flags: u16 = finalized_flag;

pub const Feature = struct {
    pub const inplace_recipe: u64 = 1 << 0;
    pub const zar26_codec: u64 = 1 << 2;
    pub const known_required: u64 = inplace_recipe | zar26_codec;
};

pub const UnitKind = enum(u8) {
    raw = 0,
    zstd = 1,
    // whole-family source coordinates; one target per unit
    patch_zar26 = 3,

    pub fn isPatch(kind: UnitKind) bool {
        return kind == .patch_zar26;
    }
};

pub const OpKind = enum(u8) {
    keep = 0,
    full = 3,
    patch = 4,
};

pub const Preamble = struct {
    finalized: bool,
    header_len: u64,
};

pub const Footer = struct {
    directory_offset: u64,
    directory_stored_len: u64,
    directory_plain_len: u64,
    directory_digest: ids.Digest,
};

pub const Header = struct {
    required_features: u64 = 0,
    optional_features: u64 = 0,
    software_id: u16 = 0,
    source_identity: []const u8 = "",
    target_identity: []const u8 = "",
    // declared inventory only
    source_fingerprint: ids.Digest = .zero,
    target_fingerprint: ids.Digest = .zero,
    target_bytes: u64 = 0,
    source_bytes: u64 = 0,
    // fixed before payloads for resume binding without trailing directory
    unit_count: u32 = 0,
    // decoded-header allocations only
    pub fn deinit(header: *Header, allocator: std.mem.Allocator) void {
        allocator.free(header.source_identity);
        allocator.free(header.target_identity);
        header.* = undefined;
    }
};

pub const FileEntry = struct {
    path: []const u8,
    size: u64,
    // one identity: BLAKE3 or authoritative vendor hash
    digest: ids.Digest,
    verification: ids.VerificationHash = .none,
};

pub const Op = struct {
    kind: OpKind,
    target: u32,
    // full/patch = unit index; keep = 0
    arg: u32,
};

pub const Unit = struct {
    kind: UnitKind,
    payload_offset: u64,
    payload_len: u64,
    target: u32,
    source_first: u32,
    source_count: u32,
};

pub const SourceRef = struct {
    file: u32,
    offset: u64,
    length: u64,
};

pub const Replay = struct {
    // logical source coordinates
    reads: []ranges.Range = &.{},
    // same-target offsets eligible for skip
    skips: []ranges.Range = &.{},

    pub fn deinit(replay: *Replay, allocator: std.mem.Allocator) void {
        allocator.free(replay.reads);
        allocator.free(replay.skips);
        replay.* = .{};
    }
};

pub fn freeReplays(allocator: std.mem.Allocator, replays: []Replay) void {
    for (replays) |*replay| replay.deinit(allocator);
    allocator.free(replays);
}

pub const Directory = struct {
    files: []FileEntry,
    ops: []Op,
    units: []Unit,
    sources: []SourceRef,
    removed: [][]const u8,
    replays: []Replay = &.{},

    pub fn deinit(directory: *Directory, allocator: std.mem.Allocator) void {
        for (directory.files) |file| allocator.free(file.path);
        for (directory.removed) |path| allocator.free(path);
        allocator.free(directory.files);
        allocator.free(directory.ops);
        allocator.free(directory.units);
        allocator.free(directory.sources);
        allocator.free(directory.removed);
        freeReplays(allocator, directory.replays);
        directory.* = undefined;
    }
};

const files_tag: u8 = 0xf1;
const ops_tag: u8 = 0xf2;
const units_tag: u8 = 0xf3;
const sources_tag: u8 = 0xf5;
const removed_tag: u8 = 0xf6;
const replays_tag: u8 = 0xf7;

pub fn encodePreamble(preamble: Preamble) [preamble_size]u8 {
    var bytes: [preamble_size]u8 = @splat(0);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], schema, .little);
    std.mem.writeInt(u16, bytes[6..8], if (preamble.finalized) finalized_flag else 0, .little);
    std.mem.writeInt(u64, bytes[8..16], preamble.header_len, .little);
    return bytes;
}

pub fn decodePreamble(bytes: []const u8) !Preamble {
    if (bytes.len != preamble_size) return error.InvalidPreambleSize;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.InvalidMagic;
    if (std.mem.readInt(u16, bytes[4..6], .little) != schema) return error.UnsupportedSchema;
    const flags = std.mem.readInt(u16, bytes[6..8], .little);
    if (flags & ~known_container_flags != 0) return error.UnsupportedContainerFlags;
    return .{ .finalized = flags & finalized_flag != 0, .header_len = std.mem.readInt(u64, bytes[8..16], .little) };
}

pub fn encodeFooter(footer: Footer) [footer_size]u8 {
    var bytes: [footer_size]u8 = @splat(0);
    std.mem.writeInt(u64, bytes[0..8], footer.directory_offset, .little);
    std.mem.writeInt(u64, bytes[8..16], footer.directory_stored_len, .little);
    std.mem.writeInt(u64, bytes[16..24], footer.directory_plain_len, .little);
    @memcpy(bytes[24..56], &footer.directory_digest.bytes);
    std.mem.writeInt(u16, bytes[56..58], schema, .little);
    @memcpy(bytes[60..64], footer_magic);
    return bytes;
}

pub fn decodeFooter(bytes: []const u8) !Footer {
    if (bytes.len != footer_size) return error.InvalidFooterSize;
    if (!std.mem.eql(u8, bytes[60..64], footer_magic)) return error.InvalidFooterMagic;
    if (std.mem.readInt(u16, bytes[56..58], .little) != schema) return error.FooterSchemaMismatch;
    if (std.mem.readInt(u16, bytes[58..60], .little) != 0) return error.NonzeroFooterReserved;
    var digest: ids.Digest = undefined;
    @memcpy(&digest.bytes, bytes[24..56]);
    return .{
        .directory_offset = std.mem.readInt(u64, bytes[0..8], .little),
        .directory_stored_len = std.mem.readInt(u64, bytes[8..16], .little),
        .directory_plain_len = std.mem.readInt(u64, bytes[16..24], .little),
        .directory_digest = digest,
    };
}

pub fn validateEnvelope(preamble: Preamble, footer: Footer, file_size: u64) !void {
    if (!preamble.finalized) return error.UnfinalizedContainer;
    const payload_start = std.math.add(u64, preamble_size, preamble.header_len) catch return error.HeaderExtentOverflow;
    if (footer.directory_offset < payload_start) return error.DirectoryOverlapsHeader;
    if (footer.directory_stored_len == 0 or footer.directory_plain_len == 0) return error.EmptyDirectory;
    const directory_end = std.math.add(u64, footer.directory_offset, footer.directory_stored_len) catch return error.DirectoryExtentOverflow;
    const expected_file_size = std.math.add(u64, directory_end, footer_size) catch return error.DirectoryExtentOverflow;
    if (expected_file_size != file_size) return error.InvalidFooterExtent;
}

fn appendInt(comptime T: type, out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try out.appendSlice(allocator, &bytes);
}

fn appendDigest(out: *std.ArrayList(u8), allocator: std.mem.Allocator, digest: ids.Digest) !void {
    try out.appendSlice(allocator, &digest.bytes);
}

fn appendVerificationHash(out: *std.ArrayList(u8), allocator: std.mem.Allocator, hash: ids.VerificationHash) !void {
    try out.append(allocator, @backingInt(hash.algorithm));
    switch (hash.algorithm) {
        .none => {},
        .md5 => try out.appendSlice(allocator, &hash.bytes),
        .xxh64 => try out.appendSlice(allocator, hash.bytes[0..8]),
    }
}

pub fn encodeHeader(allocator: std.mem.Allocator, header: Header) ![]u8 {
    if (header.source_identity.len > max_identity_bytes or header.target_identity.len > max_identity_bytes) return error.IdentityTooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendInt(u64, &out, allocator, header.required_features);
    try appendInt(u64, &out, allocator, header.optional_features);
    try appendInt(u16, &out, allocator, header.software_id);
    try appendInt(u16, &out, allocator, @intCast(header.source_identity.len));
    try out.appendSlice(allocator, header.source_identity);
    try appendInt(u16, &out, allocator, @intCast(header.target_identity.len));
    try out.appendSlice(allocator, header.target_identity);
    try appendDigest(&out, allocator, header.source_fingerprint);
    try appendDigest(&out, allocator, header.target_fingerprint);
    try appendInt(u64, &out, allocator, header.target_bytes);
    try appendInt(u64, &out, allocator, header.source_bytes);
    try appendInt(u32, &out, allocator, header.unit_count);
    return out.toOwnedSlice(allocator);
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(cursor: Cursor) usize {
        return cursor.bytes.len - cursor.pos;
    }

    fn take(cursor: *Cursor, count: usize) ![]const u8 {
        if (count > cursor.remaining()) return error.Truncated;
        const result = cursor.bytes[cursor.pos..][0..count];
        cursor.pos += count;
        return result;
    }

    fn byte(cursor: *Cursor) !u8 {
        return (try cursor.take(1))[0];
    }

    fn int(cursor: *Cursor, comptime T: type) !T {
        const bytes = try cursor.take(@sizeOf(T));
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, fixed, .little);
    }

    fn uleb(cursor: *Cursor) !u64 {
        return wire.decodeUleb128(cursor.bytes, &cursor.pos) catch |err| return switch (err) {
            error.Truncated => error.Truncated,
            error.IntegerOverflow => error.IntegerOverflow,
            error.NonCanonical => error.NonCanonicalUleb128,
        };
    }

    fn finish(cursor: Cursor) !void {
        if (cursor.pos != cursor.bytes.len) return error.TrailingBytes;
    }
};

fn readDigest(cursor: *Cursor) !ids.Digest {
    var digest: ids.Digest = undefined;
    @memcpy(&digest.bytes, try cursor.take(32));
    return digest;
}

pub fn decodeHeader(allocator: std.mem.Allocator, bytes: []const u8) !Header {
    var cursor: Cursor = .{ .bytes = bytes };
    var header: Header = .{};
    header.required_features = try cursor.int(u64);
    if (header.required_features & ~Feature.known_required != 0) return error.UnsupportedRequiredFeature;
    header.optional_features = try cursor.int(u64);
    header.software_id = try cursor.int(u16);
    const source_len = try cursor.int(u16);
    header.source_identity = try allocator.dupe(u8, try cursor.take(source_len));
    errdefer allocator.free(header.source_identity);
    const target_len = try cursor.int(u16);
    header.target_identity = try allocator.dupe(u8, try cursor.take(target_len));
    errdefer allocator.free(header.target_identity);
    header.source_fingerprint = try readDigest(&cursor);
    header.target_fingerprint = try readDigest(&cursor);
    header.target_bytes = try cursor.int(u64);
    header.source_bytes = try cursor.int(u64);
    header.unit_count = try cursor.int(u32);
    try cursor.finish();

    if (header.unit_count > max_unit_count) return error.UnitCountTooLarge;
    if (isZeroDigest(header.source_fingerprint)) return error.MissingSourceFingerprint;
    if (isZeroDigest(header.target_fingerprint)) return error.MissingTargetFingerprint;
    return header;
}

fn appendSection(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    section_tag: u8,
    payload: []const u8,
) !void {
    try out.append(allocator, section_tag);
    try wire.appendUleb128(out, allocator, payload.len);
    try out.appendSlice(allocator, payload);
}

fn sharedPrefix(a: []const u8, b: []const u8) usize {
    const limit = @min(a.len, b.len);
    var shared: usize = 0;
    while (shared < limit and a[shared] == b[shared]) : (shared += 1) {}
    return shared;
}

fn appendFrontPath(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    previous: []const u8,
    current: []const u8,
) !void {
    if (current.len > max_path_bytes) return error.PathTooLong;
    const shared = sharedPrefix(previous, current);
    try wire.appendUleb128(out, allocator, shared);
    try wire.appendUleb128(out, allocator, current.len - shared);
    try out.appendSlice(allocator, current[shared..]);
}

pub fn encodeDirectory(allocator: std.mem.Allocator, directory: Directory) ![]u8 {
    try checkDirectoryOwnership(directory);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var section: std.ArrayList(u8) = .empty;
    defer section.deinit(allocator);

    try wire.appendUleb128(&section, allocator, directory.files.len);
    var previous: []const u8 = "";
    for (directory.files) |file| {
        try appendFrontPath(&section, allocator, previous, file.path);
        try wire.appendUleb128(&section, allocator, file.size);
        if (file.verification.isPresent()) {
            try appendVerificationHash(&section, allocator, file.verification);
        } else {
            try section.append(allocator, @backingInt(ids.VerificationAlgorithm.none));
            try appendDigest(&section, allocator, file.digest);
        }
        previous = file.path;
    }
    try appendSection(&out, allocator, files_tag, section.items);

    section.clearRetainingCapacity();
    try wire.appendUleb128(&section, allocator, directory.ops.len);
    for (directory.ops) |op| {
        try section.append(allocator, @backingInt(op.kind));
        try wire.appendUleb128(&section, allocator, op.target);
        try wire.appendUleb128(&section, allocator, op.arg);
    }
    try appendSection(&out, allocator, ops_tag, section.items);

    section.clearRetainingCapacity();
    try wire.appendUleb128(&section, allocator, directory.units.len);
    for (directory.units) |unit| {
        try section.append(allocator, @backingInt(unit.kind));
        inline for (.{
            unit.payload_offset,
            unit.payload_len,
            unit.target,
            unit.source_first,
            unit.source_count,
        }) |value| try wire.appendUleb128(&section, allocator, value);
    }
    try appendSection(&out, allocator, units_tag, section.items);

    section.clearRetainingCapacity();
    try wire.appendUleb128(&section, allocator, directory.sources.len);
    for (directory.sources) |source| {
        try wire.appendUleb128(&section, allocator, source.file);
        try wire.appendUleb128(&section, allocator, source.offset);
        try wire.appendUleb128(&section, allocator, source.length);
    }
    try appendSection(&out, allocator, sources_tag, section.items);

    section.clearRetainingCapacity();
    try wire.appendUleb128(&section, allocator, directory.removed.len);
    previous = "";
    for (directory.removed) |removed| {
        try appendFrontPath(&section, allocator, previous, removed);
        previous = removed;
    }
    try appendSection(&out, allocator, removed_tag, section.items);
    if (directory.replays.len != 0) {
        section.clearRetainingCapacity();
        try wire.appendUleb128(&section, allocator, directory.replays.len);
        for (directory.replays) |replay| {
            inline for (.{ replay.reads, replay.skips }) |list| {
                try wire.appendUleb128(&section, allocator, list.len);
                var previous_end: u64 = 0;
                for (list) |range| {
                    if (range.length == 0 or range.offset < previous_end or
                        range.length > std.math.maxInt(u64) - range.offset)
                        return error.InvalidByteRange;
                    try wire.appendUleb128(&section, allocator, range.offset - previous_end);
                    try wire.appendUleb128(&section, allocator, range.length);
                    previous_end = range.end();
                }
            }
        }
        try appendSection(&out, allocator, replays_tag, section.items);
    }
    return out.toOwnedSlice(allocator);
}

fn badSectionError(wanted: u8) anyerror {
    return switch (wanted) {
        files_tag => error.BadFilesSection,
        ops_tag => error.BadOpsSection,
        units_tag => error.BadUnitsSection,
        sources_tag => error.BadSourcesSection,
        removed_tag => error.BadRemovedSection,
        replays_tag => error.BadReplaysSection,
        else => error.InvalidSectionTag,
    };
}

fn takeSection(directory: *Cursor, wanted: u8) !Cursor {
    if (try directory.byte() != wanted) return badSectionError(wanted);
    const length_u64 = try directory.uleb();
    const length = std.math.cast(usize, length_u64) orelse return error.IntegerOverflow;
    return .{ .bytes = try directory.take(length) };
}

fn readCount(section: *Cursor, minimum_entry_bytes: usize) !usize {
    const value = try section.uleb();
    const count = std.math.cast(usize, value) orelse return error.IntegerOverflow;
    if (count > max_table_entries) return error.EntryCountTooLarge;
    if (minimum_entry_bytes != 0 and count > section.remaining() / minimum_entry_bytes) return error.EntryCountTooLarge;
    return count;
}

fn readU32(section: *Cursor) !u32 {
    return std.math.cast(u32, try section.uleb()) orelse error.IntegerOverflow;
}

fn chargeDecodedBytes(decoded_bytes: *usize, count: usize, comptime T: type) !void {
    const bytes = std.math.mul(usize, count, @sizeOf(T)) catch return error.DecodedDirectoryTooLarge;
    decoded_bytes.* = std.math.add(usize, decoded_bytes.*, bytes) catch return error.DecodedDirectoryTooLarge;
    if (decoded_bytes.* > max_decoded_directory_bytes) return error.DecodedDirectoryTooLarge;
}

fn chargeDecodedPath(decoded_bytes: *usize, length: usize) !void {
    decoded_bytes.* = std.math.add(usize, decoded_bytes.*, length) catch return error.DecodedDirectoryTooLarge;
    if (decoded_bytes.* > max_decoded_directory_bytes) return error.DecodedDirectoryTooLarge;
}

fn checkDirectoryOwnership(directory: Directory) !void {
    if (directory.files.len > max_table_entries or
        directory.ops.len > max_table_entries or
        directory.units.len > max_table_entries or
        directory.sources.len > max_table_entries or
        directory.removed.len > max_table_entries or
        directory.replays.len > max_table_entries)
    {
        return error.EntryCountTooLarge;
    }

    var decoded_bytes: usize = 0;
    try chargeDecodedBytes(&decoded_bytes, directory.files.len, FileEntry);
    try chargeDecodedBytes(&decoded_bytes, directory.ops.len, Op);
    try chargeDecodedBytes(&decoded_bytes, directory.units.len, Unit);
    try chargeDecodedBytes(&decoded_bytes, directory.sources.len, SourceRef);
    try chargeDecodedBytes(&decoded_bytes, directory.removed.len, []const u8);
    try chargeDecodedBytes(&decoded_bytes, directory.replays.len, Replay);
    for (directory.replays) |replay| {
        try chargeDecodedBytes(&decoded_bytes, replay.reads.len, ranges.Range);
        try chargeDecodedBytes(&decoded_bytes, replay.skips.len, ranges.Range);
    }
    for (directory.files) |file| try chargeDecodedPath(&decoded_bytes, file.path.len);
    for (directory.removed) |path| try chargeDecodedPath(&decoded_bytes, path.len);
}

fn readFrontPath(
    allocator: std.mem.Allocator,
    section: *Cursor,
    previous: []const u8,
    decoded_bytes: *usize,
) ![]u8 {
    const shared = std.math.cast(usize, try section.uleb()) orelse return error.IntegerOverflow;
    const suffix_len = std.math.cast(usize, try section.uleb()) orelse return error.IntegerOverflow;
    if (shared > previous.len) return error.InvalidSharedPathPrefix;
    const total = std.math.add(usize, shared, suffix_len) catch return error.IntegerOverflow;
    if (total == 0 or total > max_path_bytes) return error.InvalidPathLength;
    const suffix = try section.take(suffix_len);
    try chargeDecodedPath(decoded_bytes, total);
    const path = try allocator.alloc(u8, total);
    @memcpy(path[0..shared], previous[0..shared]);
    @memcpy(path[shared..], suffix);
    if (shared != sharedPrefix(previous, path)) {
        allocator.free(path);
        return error.NoncanonicalSharedPathPrefix;
    }
    return path;
}

fn freeFiles(allocator: std.mem.Allocator, files: []FileEntry, initialized: usize) void {
    for (files[0..initialized]) |file| allocator.free(file.path);
    allocator.free(files);
}

fn decodeFiles(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]FileEntry {
    // minimum file record: two path lengths, size, algorithm, identity
    const count = try readCount(section, 12);
    try chargeDecodedBytes(decoded_bytes, count, FileEntry);
    const files = try allocator.alloc(FileEntry, count);
    var initialized: usize = 0;
    errdefer freeFiles(allocator, files, initialized);
    var previous: []const u8 = "";
    for (files) |*file| {
        const file_path = try readFrontPath(allocator, section, previous, decoded_bytes);
        // allocation registered before fallible fields for freeFiles
        file.* = .{ .path = file_path, .size = 0, .digest = .zero, .verification = .none };
        initialized += 1;
        file.size = try section.uleb();
        const algorithm = std.enums.fromInt(ids.VerificationAlgorithm, try section.byte()) orelse
            return error.InvalidVerificationAlgorithm;
        switch (algorithm) {
            .none => file.digest = try readDigest(section),
            .md5 => {
                var bytes: [16]u8 = undefined;
                @memcpy(&bytes, try section.take(bytes.len));
                file.verification = .md5(bytes);
            },
            .xxh64 => {
                var bytes: [8]u8 = undefined;
                @memcpy(&bytes, try section.take(bytes.len));
                file.verification = .xxh64(bytes);
            },
        }
        previous = file_path;
    }
    try section.finish();
    return files;
}

fn decodeOps(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]Op {
    // minimum op record: kind, target, arg
    const count = try readCount(section, 3);
    try chargeDecodedBytes(decoded_bytes, count, Op);
    const ops = try allocator.alloc(Op, count);
    errdefer allocator.free(ops);
    for (ops) |*op| {
        const kind = std.enums.fromInt(OpKind, try section.byte()) orelse return error.InvalidOpKind;
        op.* = .{
            .kind = kind,
            .target = try readU32(section),
            .arg = try readU32(section),
        };
    }
    try section.finish();
    return ops;
}

fn decodeUnits(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]Unit {
    // minimum unit record: kind + five ULEBs
    const count = try readCount(section, 6);
    try chargeDecodedBytes(decoded_bytes, count, Unit);
    const units = try allocator.alloc(Unit, count);
    errdefer allocator.free(units);
    for (units) |*unit| {
        unit.* = .{
            .kind = std.enums.fromInt(UnitKind, try section.byte()) orelse return error.InvalidUnitKind,
            .payload_offset = try section.uleb(),
            .payload_len = try section.uleb(),
            .target = try readU32(section),
            .source_first = try readU32(section),
            .source_count = try readU32(section),
        };
    }
    try section.finish();
    return units;
}

fn decodeSources(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]SourceRef {
    const count = try readCount(section, 3);
    try chargeDecodedBytes(decoded_bytes, count, SourceRef);
    const sources = try allocator.alloc(SourceRef, count);
    errdefer allocator.free(sources);
    for (sources) |*source| source.* = .{
        .file = try readU32(section),
        .offset = try section.uleb(),
        .length = try section.uleb(),
    };
    try section.finish();
    return sources;
}

fn freeRemoved(allocator: std.mem.Allocator, removed: [][]const u8, initialized: usize) void {
    for (removed[0..initialized]) |path| allocator.free(path);
    allocator.free(removed);
}

fn decodeRemoved(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![][]const u8 {
    const count = try readCount(section, 2);
    try chargeDecodedBytes(decoded_bytes, count, []const u8);
    const removed = try allocator.alloc([]const u8, count);
    var initialized: usize = 0;
    errdefer freeRemoved(allocator, removed, initialized);
    var previous: []const u8 = "";
    for (removed) |*item| {
        item.* = try readFrontPath(allocator, section, previous, decoded_bytes);
        initialized += 1;
        previous = item.*;
    }
    try section.finish();
    return removed;
}

fn decodeRanges(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]ranges.Range {
    const count = try readCount(section, 2);
    try chargeDecodedBytes(decoded_bytes, count, ranges.Range);
    const result = try allocator.alloc(ranges.Range, count);
    errdefer allocator.free(result);
    var previous_end: u64 = 0;
    for (result, 0..) |*range, index| {
        const gap = try section.uleb();
        const length = try section.uleb();
        if (length == 0 or (index != 0 and gap == 0)) return error.NoncanonicalByteRanges;
        const offset = std.math.add(u64, previous_end, gap) catch return error.InvalidByteRange;
        previous_end = std.math.add(u64, offset, length) catch return error.InvalidByteRange;
        range.* = .{ .offset = offset, .length = length };
    }
    return result;
}

fn decodeReplays(allocator: std.mem.Allocator, section: *Cursor, decoded_bytes: *usize) ![]Replay {
    const count = try readCount(section, 2);
    try chargeDecodedBytes(decoded_bytes, count, Replay);
    const result = try allocator.alloc(Replay, count);
    @memset(result, .{});
    errdefer freeReplays(allocator, result);
    for (result) |*replay| {
        replay.reads = try decodeRanges(allocator, section, decoded_bytes);
        replay.skips = try decodeRanges(allocator, section, decoded_bytes);
    }
    try section.finish();
    return result;
}

pub fn decodeDirectory(allocator: std.mem.Allocator, bytes: []const u8) !Directory {
    var cursor: Cursor = .{ .bytes = bytes };
    var decoded_bytes: usize = 0;
    var files_section = try takeSection(&cursor, files_tag);
    const files = try decodeFiles(allocator, &files_section, &decoded_bytes);
    errdefer freeFiles(allocator, files, files.len);
    var ops_section = try takeSection(&cursor, ops_tag);
    const ops = try decodeOps(allocator, &ops_section, &decoded_bytes);
    errdefer allocator.free(ops);
    var units_section = try takeSection(&cursor, units_tag);
    const units = try decodeUnits(allocator, &units_section, &decoded_bytes);
    errdefer allocator.free(units);
    var sources_section = try takeSection(&cursor, sources_tag);
    const sources = try decodeSources(allocator, &sources_section, &decoded_bytes);
    errdefer allocator.free(sources);
    var removed_section = try takeSection(&cursor, removed_tag);
    const removed = try decodeRemoved(allocator, &removed_section, &decoded_bytes);
    errdefer freeRemoved(allocator, removed, removed.len);
    const replays = if (cursor.remaining() != 0) blk: {
        var section = try takeSection(&cursor, replays_tag);
        break :blk try decodeReplays(allocator, &section, &decoded_bytes);
    } else try allocator.alloc(Replay, 0);
    errdefer freeReplays(allocator, replays);
    try cursor.finish();
    return .{ .files = files, .ops = ops, .units = units, .sources = sources, .removed = removed, .replays = replays };
}

fn isZeroDigest(digest: ids.Digest) bool {
    return digest.eql(.zero);
}

pub fn updateLogicalFingerprint(hasher: *std.crypto.hash.Blake3, file: FileEntry) void {
    hasher.update(file.path);
    hasher.update(&.{0});
    var size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_bytes, file.size, .little);
    hasher.update(&size_bytes);
    hasher.update(&.{@backingInt(file.verification.algorithm)});
    switch (file.verification.algorithm) {
        .none => hasher.update(&file.digest.bytes),
        .md5 => hasher.update(&file.verification.bytes),
        .xxh64 => hasher.update(file.verification.bytes[0..8]),
    }
}

pub fn logicalFingerprint(files: []const FileEntry) ids.Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (files) |file| updateLogicalFingerprint(&hasher, file);
    var digest: ids.Digest = undefined;
    hasher.final(&digest.bytes);
    return digest;
}

fn validatePath(path: []const u8) !void {
    logical_path.validate(path) catch return error.UnsafeLogicalPath;
}

fn isReservedWorkPath(path: []const u8) bool {
    const first_end = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    return std.ascii.eqlIgnoreCase(path[0..first_end], ".zift-work");
}

fn isAncestor(parent: []const u8, child: []const u8) bool {
    return child.len > parent.len and std.mem.startsWith(u8, child, parent) and child[parent.len] == '/';
}

fn hasRoleDescendant(files: []const FileEntry, roles: []const bool, parent_index: usize) bool {
    const parent = files[parent_index].path;
    var low = parent_index + 1;
    var high = files.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const candidate = files[middle].path;
        const prefix_order = std.mem.order(u8, candidate[0..@min(candidate.len, parent.len)], parent);
        const before_key = switch (prefix_order) {
            .lt => true,
            .gt => false,
            .eq => candidate.len <= parent.len or candidate[parent.len] < '/',
        };
        if (before_key) low = middle + 1 else high = middle;
    }
    var index = low;
    while (index < files.len and isAncestor(parent, files[index].path)) : (index += 1) {
        if (roles[index]) return true;
    }
    return false;
}

fn validateRoleTree(files: []const FileEntry, roles: []const bool, conflict: anyerror) !void {
    for (roles, 0..) |present, index| {
        if (present and hasRoleDescendant(files, roles, index)) return conflict;
    }
}

fn unitContainsOutput(directory: Directory, unit_index: usize, file_index: u32) bool {
    return directory.units[unit_index].target == file_index;
}

fn unitAcceptsOp(kind: UnitKind, op: OpKind) bool {
    return switch (op) {
        .full => switch (kind) {
            .raw, .zstd => true,
            else => false,
        },
        .patch => switch (kind) {
            .patch_zar26 => true,
            else => false,
        },
        else => false,
    };
}

fn fileIndexByPath(files: []const FileEntry, wanted: []const u8) ?usize {
    var low: usize = 0;
    var high = files.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, files[middle].path, wanted)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return middle,
        }
    }
    return null;
}

// exact payload partition: [payload_start, payload_end)
pub fn validate(
    allocator: std.mem.Allocator,
    header: Header,
    directory: Directory,
    payload_start: u64,
    payload_end: u64,
) !void {
    if (payload_end < payload_start) return error.PayloadBeforeHeader;
    if (header.unit_count != directory.units.len) return error.UnitCountMismatch;
    if (isZeroDigest(header.source_fingerprint)) return error.MissingSourceFingerprint;

    for (directory.files, 0..) |file, index| {
        try validatePath(file.path);
        if (isReservedWorkPath(file.path)) return error.ReservedWorkPath;
        if (index != 0) {
            const previous = directory.files[index - 1].path;
            switch (std.mem.order(u8, previous, file.path)) {
                .eq => return error.DuplicateFilePath,
                .gt => return error.UnsortedFilePaths,
                .lt => {},
            }
        }
    }

    for (directory.removed, 0..) |removed, index| {
        try validatePath(removed);
        if (isReservedWorkPath(removed)) return error.ReservedWorkPath;
        if (index != 0) {
            const previous = directory.removed[index - 1];
            switch (std.mem.order(u8, previous, removed)) {
                .eq => return error.DuplicateRemovedPath,
                .gt => return error.UnsortedRemovedPaths,
                .lt => {},
            }
        }
    }

    const output_seen = try allocator.alloc(bool, directory.files.len);
    defer allocator.free(output_seen);
    @memset(output_seen, false);
    const op_seen = try allocator.alloc(bool, directory.files.len);
    defer allocator.free(op_seen);
    @memset(op_seen, false);
    const source_role = try allocator.alloc(bool, directory.files.len);
    defer allocator.free(source_role);
    @memset(source_role, false);
    const removed_role = try allocator.alloc(bool, directory.files.len);
    defer allocator.free(removed_role);
    @memset(removed_role, false);
    const unit_op_counts = try allocator.alloc(u32, directory.units.len);
    defer allocator.free(unit_op_counts);
    @memset(unit_op_counts, 0);

    var expected_payload = payload_start;
    var expected_source: u64 = 0;
    var previous_source_first: u32 = 0;
    var previous_source_count: u32 = 0;
    var needs_zar26 = false;

    for (directory.units) |unit| {
        if (unit.payload_offset != expected_payload) return error.NoncontiguousPayload;
        expected_payload = std.math.add(u64, expected_payload, unit.payload_len) catch return error.PayloadExtentOverflow;
        if (expected_payload > payload_end) return error.PayloadExtentOutOfRange;
        if (unit.target >= directory.files.len) return error.OutputFileIndexOutOfRange;
        if (unit.payload_len == 0) {
            if (directory.files[unit.target].size != 0) return error.EmptyPayloadForNonemptyOutput;
            if (unit.kind != .raw) return error.EmptyEncodedPayload;
        }
        if (output_seen[unit.target]) return error.DuplicateUnitOutput;
        output_seen[unit.target] = true;

        const source_end = std.math.add(u64, unit.source_first, unit.source_count) catch return error.SourceSliceOverflow;
        if (source_end > directory.sources.len) return error.SourceSliceOutOfRange;
        const shares_previous = unit.source_count != 0 and
            unit.source_first == previous_source_first and
            unit.source_count == previous_source_count;
        if (!shares_previous) {
            if (unit.source_first != expected_source) return error.NoncanonicalSourceSlice;
            expected_source = source_end;
        }

        const source_first: usize = unit.source_first;
        const source_count: usize = unit.source_count;
        var logical_source_bytes: u64 = 0;
        for (directory.sources[source_first..][0..source_count]) |source| {
            if (source.file >= directory.files.len) return error.SourceFileIndexOutOfRange;
            source_role[source.file] = true;
            _ = std.math.add(u64, source.offset, source.length) catch return error.SourceRangeOverflow;
            logical_source_bytes = std.math.add(u64, logical_source_bytes, source.length) catch return error.SourceBytesOverflow;
        }
        switch (unit.kind) {
            .raw, .zstd => if (unit.source_count != 0) return error.FullUnitHasSources,
            .patch_zar26 => {
                if (unit.source_count == 0) return error.PatchUnitHasNoSources;
            },
        }
        previous_source_first = unit.source_first;
        previous_source_count = unit.source_count;
        switch (unit.kind) {
            .patch_zar26 => needs_zar26 = true,
            .raw, .zstd => {},
        }
        if (unit.kind == .raw and unit.payload_len != directory.files[unit.target].size) return error.RawPayloadLengthMismatch;
    }
    if (expected_payload != payload_end) return error.HiddenPayloadBytes;
    if (expected_source != directory.sources.len) return error.UnclaimedSourceEntries;

    var target_bytes: u64 = 0;
    var previous_target: ?u32 = null;
    var target_fingerprint_hasher = std.crypto.hash.Blake3.init(.{});
    for (directory.ops) |op| {
        if (op.target >= directory.files.len) return error.OpTargetOutOfRange;
        if (previous_target) |previous| if (op.target <= previous) return if (op.target == previous)
            error.DuplicateTargetOp
        else
            error.UnsortedTargetOps;
        previous_target = op.target;
        if (op_seen[op.target]) return error.DuplicateTargetOp;
        op_seen[op.target] = true;
        const target = directory.files[op.target];
        if (isZeroDigest(target.digest) and !target.verification.isPresent()) return error.MissingFileIdentity;
        if (!isZeroDigest(target.digest) and target.verification.isPresent()) return error.MultipleFileIdentities;
        target_bytes = std.math.add(u64, target_bytes, target.size) catch return error.TargetBytesOverflow;
        updateLogicalFingerprint(&target_fingerprint_hasher, target);

        switch (op.kind) {
            .keep => {
                if (op.arg != 0) return error.NoncanonicalKeepArgument;
                source_role[op.target] = true;
            },
            .full, .patch => {
                if (op.arg >= directory.units.len) return error.OpUnitOutOfRange;
                const unit_index: usize = op.arg;
                if (!unitAcceptsOp(directory.units[unit_index].kind, op.kind)) return error.OpUnitKindMismatch;
                if (!unitContainsOutput(directory, unit_index, op.target)) return error.OpTargetNotUnitOutput;
                unit_op_counts[unit_index] = std.math.add(u32, unit_op_counts[unit_index], 1) catch return error.UnitOpCountOverflow;
            },
        }
    }

    var computed_target_fingerprint: ids.Digest = undefined;
    target_fingerprint_hasher.final(&computed_target_fingerprint.bytes);
    if (!computed_target_fingerprint.eql(header.target_fingerprint)) return error.TargetFingerprintMismatch;
    for (unit_op_counts) |count| if (count != 1) return error.UnitOutputMissingOp;

    for (directory.removed) |removed| {
        const file_index = fileIndexByPath(directory.files, removed) orelse return error.RemovedPathMissingFileEntry;
        if (op_seen[file_index]) return error.RemovedPathIsTarget;
        removed_role[file_index] = true;
    }
    for (directory.files, 0..) |_, index| {
        if (!op_seen[index] and !removed_role[index]) return error.UnclassifiedFileEntry;
    }
    for (directory.sources) |source| {
        // shared entries hold target sizes, not source lengths
        if (removed_role[source.file]) {
            const end = std.math.add(u64, source.offset, source.length) catch return error.SourceRangeOverflow;
            if (end > directory.files[source.file].size) return error.SourceRangeOutOfFile;
        }
    }
    try validateRoleTree(directory.files, op_seen, error.TargetPathIsDirectory);
    for (source_role, removed_role) |*source, removed| source.* = source.* or removed;
    try validateRoleTree(directory.files, source_role, error.SourcePathIsDirectory);

    if (target_bytes != header.target_bytes) return error.TargetBytesMismatch;
    if (needs_zar26 and header.required_features & Feature.zar26_codec == 0) return error.MissingNativeCodecFeature;
    if (!needs_zar26 and header.required_features & Feature.zar26_codec != 0) return error.UnexpectedNativeCodecFeature;
    const has_replays = header.required_features & Feature.inplace_recipe != 0;
    if (has_replays and directory.replays.len != directory.units.len) return error.ReplayCountMismatch;
    if (!has_replays and directory.replays.len != 0) return error.UnexpectedReplays;
    if (has_replays) for (directory.units, directory.replays) |unit, replay| {
        var source_size: u64 = 0;
        for (directory.sources[unit.source_first..][0..unit.source_count]) |source|
            source_size = std.math.add(u64, source_size, source.length) catch return error.SourceRangeOverflow;
        try ranges.validate(replay.reads, source_size);
        try ranges.validate(replay.skips, directory.files[unit.target].size);
        if (unit.kind != .patch_zar26 and (replay.reads.len != 0 or replay.skips.len != 0))
            return error.UnexpectedReplayRanges;
        if (replay.skips.len != 0) {
            var self_parts: std.ArrayList(ranges.Range) = .empty;
            defer self_parts.deinit(allocator);
            for (directory.sources[unit.source_first..][0..unit.source_count]) |source| {
                if (source.file == unit.target and source.length != 0)
                    try self_parts.append(allocator, .{ .offset = source.offset, .length = source.length });
            }
            const self_ranges = try ranges.merge(allocator, self_parts.items);
            defer allocator.free(self_ranges);
            var self_index: usize = 0;
            for (replay.skips) |skip| {
                while (self_index < self_ranges.len and self_ranges[self_index].end() <= skip.offset) self_index += 1;
                if (self_index == self_ranges.len or skip.offset < self_ranges[self_index].offset or
                    skip.end() > self_ranges[self_index].end())
                    return error.SkippedOutputHasNoOriginal;
            }
        }
    };
}

const Sample = struct {
    header: Header,
    files: [4]FileEntry,
    ops: [2]Op,
    units: [1]Unit,
    sources: [1]SourceRef,
    removed: [2][]const u8,

    fn init(payload_start: u64) Sample {
        const target_a = ids.Digest.of("new");
        const empty = ids.Digest.of("");
        var sample: Sample = .{
            .header = .{
                .required_features = Feature.zar26_codec,
                .software_id = 1,
                .source_identity = "1.0",
                .target_identity = "1.1",
                .source_fingerprint = ids.Digest.of("source tree"),
                .target_fingerprint = .zero,
                .target_bytes = 3,
                .source_bytes = 12,
                .unit_count = 1,
            },
            .files = .{
                .{ .path = "gone.bin", .size = 4, .digest = ids.Digest.of("gone") },
                .{ .path = "old.bin", .size = 8, .digest = ids.Digest.of("oldbytes") },
                .{ .path = "target/a.bin", .size = 3, .digest = target_a },
                .{ .path = "target/b.bin", .size = 0, .digest = empty },
            },
            .ops = .{
                .{ .kind = .patch, .target = 2, .arg = 0 },
                .{ .kind = .keep, .target = 3, .arg = 0 },
            },
            .units = .{.{
                .kind = .patch_zar26,
                .payload_offset = payload_start,
                .payload_len = 11,
                .target = 2,
                .source_first = 0,
                .source_count = 1,
            }},
            .sources = .{.{ .file = 1, .offset = 0, .length = 8 }},
            .removed = .{ "gone.bin", "old.bin" },
        };
        const targets = [_]FileEntry{ sample.files[2], sample.files[3] };
        sample.header.target_fingerprint = logicalFingerprint(&targets);
        return sample;
    }

    fn directory(sample: *Sample) Directory {
        return .{
            .files = &sample.files,
            .ops = &sample.ops,
            .units = &sample.units,
            .sources = &sample.sources,
            .removed = &sample.removed,
        };
    }
};

test "schema 0 preamble footer and envelope are exact" {
    const preamble_bytes = encodePreamble(.{ .finalized = true, .header_len = 200 });
    const preamble = try decodePreamble(&preamble_bytes);
    try std.testing.expect(preamble.finalized);
    try std.testing.expectEqual(@as(u64, 200), preamble.header_len);

    const footer_value: Footer = .{
        .directory_offset = 300,
        .directory_stored_len = 25,
        .directory_plain_len = 100,
        .directory_digest = ids.Digest.of("stored frame"),
    };
    const footer_bytes = encodeFooter(footer_value);
    const footer = try decodeFooter(&footer_bytes);
    try std.testing.expectEqual(footer_value.directory_offset, footer.directory_offset);
    try std.testing.expect(footer_value.directory_digest.eql(footer.directory_digest));
    try validateEnvelope(preamble, footer, 300 + 25 + footer_size);

    try std.testing.expectError(error.UnfinalizedContainer, validateEnvelope(.{ .finalized = false, .header_len = 200 }, footer, 389));
    var bad_footer = footer_bytes;
    bad_footer[58] = 1;
    try std.testing.expectError(error.NonzeroFooterReserved, decodeFooter(&bad_footer));
    var bad_flags = preamble_bytes;
    bad_flags[7] = 0x80;
    try std.testing.expectError(error.UnsupportedContainerFlags, decodePreamble(&bad_flags));
}

test "schema 0 directory round trip and validation preserve indirection" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 256;
    var sample = Sample.init(payload_start);
    const bytes = try encodeDirectory(allocator, sample.directory());
    defer allocator.free(bytes);
    var decoded = try decodeDirectory(allocator, bytes);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(sample.files.len, decoded.files.len);
    for (sample.files, decoded.files) |wanted, actual| {
        try std.testing.expectEqualStrings(wanted.path, actual.path);
        try std.testing.expectEqual(wanted.size, actual.size);
        try std.testing.expect(wanted.digest.eql(actual.digest));
    }
    try std.testing.expectEqual(sample.units[0].kind, decoded.units[0].kind);
    try std.testing.expectEqual(sample.sources[0], decoded.sources[0]);
    try std.testing.expectEqualStrings(sample.removed[0], decoded.removed[0]);
    try validate(allocator, sample.header, decoded, payload_start, payload_start + 11);
}

test "schema 0 roundtrips authenticated in-place recipes" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 256;
    var sample = Sample.init(payload_start);
    var reads = [_]ranges.Range{.{ .offset = 0, .length = 8 }};
    var replays = [_]Replay{.{ .reads = &reads }};
    var directory = sample.directory();
    directory.replays = &replays;
    sample.header.required_features |= Feature.inplace_recipe;

    const bytes = try encodeDirectory(allocator, directory);
    defer allocator.free(bytes);
    var decoded = try decodeDirectory(allocator, bytes);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), decoded.replays.len);
    try std.testing.expectEqualSlices(ranges.Range, &reads, decoded.replays[0].reads);
    try std.testing.expectEqual(@as(usize, 0), decoded.replays[0].skips.len);
    try validate(allocator, sample.header, decoded, payload_start, payload_start + 11);
}

test "schema 0 shares one consecutive Source family across Target units" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 100;
    const files = [_]FileEntry{
        .{ .path = "old.bin", .size = 1, .digest = ids.Digest.of("o") },
        .{ .path = "target/a.bin", .size = 1, .digest = ids.Digest.of("a") },
        .{ .path = "target/b.bin", .size = 1, .digest = ids.Digest.of("b") },
    };
    const ops = [_]Op{
        .{ .kind = .patch, .target = 1, .arg = 0 },
        .{ .kind = .patch, .target = 2, .arg = 1 },
    };
    const units = [_]Unit{
        .{ .kind = .patch_zar26, .payload_offset = 100, .payload_len = 1, .target = 1, .source_first = 0, .source_count = 1 },
        .{ .kind = .patch_zar26, .payload_offset = 101, .payload_len = 1, .target = 2, .source_first = 0, .source_count = 1 },
    };
    const sources = [_]SourceRef{.{ .file = 0, .offset = 0, .length = 1 }};
    const removed = [_][]const u8{"old.bin"};
    const targets = [_]FileEntry{ files[1], files[2] };
    const header: Header = .{
        .required_features = Feature.zar26_codec,
        .source_fingerprint = ids.Digest.of("source"),
        .target_fingerprint = logicalFingerprint(&targets),
        .target_bytes = 2,
        .source_bytes = 1,
        .unit_count = 2,
    };
    const directory: Directory = .{
        .files = @constCast(&files),
        .ops = @constCast(&ops),
        .units = @constCast(&units),
        .sources = @constCast(&sources),
        .removed = @constCast(&removed),
    };
    try validate(allocator, header, directory, payload_start, payload_start + 2);

    const encoded = try encodeDirectory(allocator, directory);
    defer allocator.free(encoded);
    var decoded = try decodeDirectory(allocator, encoded);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), decoded.sources.len);
    try std.testing.expectEqual(decoded.units[0].source_first, decoded.units[1].source_first);
}

test "schema 0 validation accepts authoritative verification-only keep" {
    const allocator = std.testing.allocator;
    var sample = Sample.init(256);
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("", &md5, .{});
    sample.files[3].digest = .zero;
    sample.files[3].verification = .md5(md5);
    const targets = [_]FileEntry{ sample.files[2], sample.files[3] };
    sample.header.target_fingerprint = logicalFingerprint(&targets);
    try validate(allocator, sample.header, sample.directory(), 256, 267);
}

test "schema 0 validation rejects multiple identities for one file" {
    const allocator = std.testing.allocator;
    var sample = Sample.init(256);
    const md5: [16]u8 = @splat(0x71);
    sample.files[2].verification = .md5(md5);
    const targets = [_]FileEntry{ sample.files[2], sample.files[3] };
    sample.header.target_fingerprint = logicalFingerprint(&targets);
    try std.testing.expectError(error.MultipleFileIdentities, validate(allocator, sample.header, sample.directory(), 256, 267));
}

test "schema 0 file table preserves MD5 and XXH64 verification identities" {
    const allocator = std.testing.allocator;
    const md5: [16]u8 = @splat(0xa7);
    const xxh64: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var files = [_]FileEntry{
        .{ .path = "keep.bin", .size = 123, .digest = .zero, .verification = .md5(md5) },
        .{ .path = "payload.bin", .size = 99, .digest = .zero, .verification = .xxh64(xxh64) },
    };
    const directory: Directory = .{
        .files = &files,
        .ops = &.{},
        .units = &.{},
        .sources = &.{},
        .removed = &.{},
    };
    const bytes = try encodeDirectory(allocator, directory);
    defer allocator.free(bytes);
    var decoded = try decodeDirectory(allocator, bytes);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, files.len), decoded.files.len);
    for (files, decoded.files) |expected, actual| {
        try std.testing.expectEqualStrings(expected.path, actual.path);
        try std.testing.expectEqual(expected.size, actual.size);
        try std.testing.expect(actual.digest.eql(.zero));
        try std.testing.expect(expected.verification.eql(actual.verification));
    }
}

test "schema 0 directory refuses every truncated prefix and malformed section framing" {
    const allocator = std.testing.allocator;
    var sample = Sample.init(256);
    const bytes = try encodeDirectory(allocator, sample.directory());
    defer allocator.free(bytes);

    for (0..bytes.len) |cut| {
        if (decodeDirectory(allocator, bytes[0..cut])) |unexpected| {
            var owned = unexpected;
            owned.deinit(allocator);
            return error.TruncatedDirectoryAccepted;
        } else |_| {}
    }
    try std.testing.expectError(error.NonCanonicalUleb128, decodeDirectory(allocator, &.{ files_tag, 0x80, 0x00 }));

    const wrong_tag = try allocator.dupe(u8, bytes);
    defer allocator.free(wrong_tag);
    wrong_tag[0] = ops_tag;
    try std.testing.expectError(error.BadFilesSection, decodeDirectory(allocator, wrong_tag));

    const bad_enum = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_enum);
    var cursor: Cursor = .{ .bytes = bad_enum };
    _ = try takeSection(&cursor, files_tag);
    _ = try cursor.byte();
    _ = try cursor.uleb();
    const ops_payload = cursor.pos;
    bad_enum[ops_payload + 1] = 0xff;
    try std.testing.expectError(error.InvalidOpKind, decodeDirectory(allocator, bad_enum));
}

test "schema 0 semantic validation returns distinct structural errors" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 500;
    var sample = Sample.init(payload_start);
    try validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11);

    sample.units[0].payload_offset += 1;
    try std.testing.expectError(error.NoncontiguousPayload, validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11));
    sample.units[0].payload_offset = payload_start;

    sample.sources[0].offset = std.math.maxInt(u64);
    sample.sources[0].length = 2;
    try std.testing.expectError(error.SourceRangeOverflow, validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11));
    sample.sources[0] = .{ .file = 1, .offset = 0, .length = 8 };

    sample.sources[0].length = 9;
    try std.testing.expectError(error.SourceRangeOutOfFile, validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11));
    sample.sources[0].length = 8;

    sample.header.required_features = 0;
    try std.testing.expectError(error.MissingNativeCodecFeature, validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11));
    sample.header.required_features = Feature.zar26_codec;
}

test "only raw represents an empty output with zero payload bytes" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 500;
    const empty = ids.Digest.of("");
    var files = [_]FileEntry{.{ .path = "empty.bin", .size = 0, .digest = empty }};
    var ops = [_]Op{.{ .kind = .full, .target = 0, .arg = 0 }};
    var units = [_]Unit{.{
        .kind = .zstd,
        .payload_offset = payload_start,
        .payload_len = 0,
        .target = 0,
        .source_first = 0,
        .source_count = 0,
    }};
    const directory: Directory = .{
        .files = &files,
        .ops = &ops,
        .units = &units,
        .sources = &.{},
        .removed = &.{},
    };
    const header: Header = .{
        .source_identity = "source",
        .target_identity = "target",
        .source_fingerprint = ids.Digest.of("source-tree"),
        .target_fingerprint = logicalFingerprint(&files),
        .target_bytes = 0,
        .source_bytes = 0,
        .unit_count = 1,
    };
    try std.testing.expectError(
        error.EmptyEncodedPayload,
        validate(allocator, header, directory, payload_start, payload_start),
    );
    units[0].kind = .raw;
    try validate(allocator, header, directory, payload_start, payload_start);
}

test "role trees detect interposed descendants and allow file-directory transitions" {
    const digest = ids.Digest.of("x");
    var interposed = [_]FileEntry{
        .{ .path = "a", .size = 1, .digest = digest },
        .{ .path = "a-foo", .size = 1, .digest = digest },
        .{ .path = "a/child", .size = 1, .digest = digest },
    };
    var roles = [_]bool{ true, false, true };
    try std.testing.expectError(
        error.TargetPathIsDirectory,
        validateRoleTree(&interposed, &roles, error.TargetPathIsDirectory),
    );
    try std.testing.expectError(
        error.SourcePathIsDirectory,
        validateRoleTree(&interposed, &roles, error.SourcePathIsDirectory),
    );

    var transition = [_]FileEntry{
        .{ .path = "a", .size = 1, .digest = digest },
        .{ .path = "a/child", .size = 1, .digest = digest },
    };
    var target_roles = [_]bool{ true, false };
    var source_roles = [_]bool{ false, true };
    try validateRoleTree(&transition, &target_roles, error.TargetPathIsDirectory);
    try validateRoleTree(&transition, &source_roles, error.SourcePathIsDirectory);
}

test "schema 0 files table is exactly the classified Source-Target union" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 500;
    var sample = Sample.init(payload_start);

    var incomplete_removed = [_][]const u8{sample.removed[0]};
    var incomplete = sample.directory();
    incomplete.removed = &incomplete_removed;
    try std.testing.expectError(
        error.UnclassifiedFileEntry,
        validate(allocator, sample.header, incomplete, payload_start, payload_start + 11),
    );

    var unknown_removed = [_][]const u8{ "gone.bin", "missing.bin", "old.bin" };
    var unknown = sample.directory();
    unknown.removed = &unknown_removed;
    try std.testing.expectError(
        error.RemovedPathMissingFileEntry,
        validate(allocator, sample.header, unknown, payload_start, payload_start + 11),
    );
}

test "schema 0 reserves its private work tree case-insensitively" {
    const allocator = std.testing.allocator;
    const payload_start: u64 = 500;
    var sample = Sample.init(payload_start);
    const original_file = sample.files[0].path;
    sample.files[0].path = ".ZIFT-WORK/journal";
    try std.testing.expectError(
        error.ReservedWorkPath,
        validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11),
    );
    sample.files[0].path = original_file;

    const original_removed = sample.removed[0];
    sample.removed[0] = ".zift-work/staged";
    try std.testing.expectError(
        error.ReservedWorkPath,
        validate(allocator, sample.header, sample.directory(), payload_start, payload_start + 11),
    );
    sample.removed[0] = original_removed;
}

fn decodeAllocationExercise(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoded = try decodeDirectory(allocator, bytes);
    defer decoded.deinit(allocator);
}

test "schema 0 directory decode cleans up every allocation failure" {
    const allocator = std.testing.allocator;
    var sample = Sample.init(256);
    const bytes = try encodeDirectory(allocator, sample.directory());
    defer allocator.free(bytes);
    try std.testing.checkAllAllocationFailures(allocator, decodeAllocationExercise, .{bytes});
}

test "current schema-0 header has one exact golden representation" {
    const allocator = std.testing.allocator;
    const header: Header = .{
        .required_features = Feature.zar26_codec,
        .optional_features = 2,
        .software_id = 3,
        .source_identity = "S",
        .target_identity = "T",
        .source_fingerprint = .{ .bytes = @splat(0x11) },
        .target_fingerprint = .{ .bytes = @splat(0x22) },
        .target_bytes = 4,
        .source_bytes = 5,
        .unit_count = 6,
    };
    const expected_hex = "040000000000000002000000000000000300010053010054111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220400000000000000050000000000000006000000";
    var expected: [expected_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    const encoded = try encodeHeader(allocator, header);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &expected, encoded);

    var decoded = try decodeHeader(allocator, &expected);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualDeep(header, decoded);

    for (0..expected.len) |cut| {
        if (decodeHeader(allocator, expected[0..cut])) |unexpected| {
            var owned = unexpected;
            owned.deinit(allocator);
            return error.TruncatedHeaderAccepted;
        } else |_| {}
    }

    var unknown_optional = expected;
    std.mem.writeInt(u64, unknown_optional[8..16], 1 << 40, .little);
    var optional = try decodeHeader(allocator, &unknown_optional);
    defer optional.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1 << 40), optional.optional_features);

    var hostile = expected;
    std.mem.writeInt(u32, hostile[104..108], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.UnitCountTooLarge, decodeHeader(allocator, &hostile));
}

test "schema 0 directory has one exact golden representation" {
    const allocator = std.testing.allocator;
    const digest: ids.Digest = .{ .bytes = @splat(0x11) };
    var files = [_]FileEntry{.{ .path = "a", .size = 0, .digest = digest }};
    var ops = [_]Op{.{ .kind = .keep, .target = 0, .arg = 0 }};
    var removed = [_][]const u8{"b"};
    const directory: Directory = .{
        .files = &files,
        .ops = &ops,
        .units = &.{},
        .sources = &.{},
        .removed = &removed,
    };
    const expected_hex = "f1260100016100001111111111111111111111111111111111111111111111111111111111111111f20401000000f30100f50100f60401000162";
    var expected: [expected_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    const encoded = try encodeDirectory(allocator, directory);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &expected, encoded);

    var decoded = try decodeDirectory(allocator, &expected);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("a", decoded.files[0].path);
    try std.testing.expectEqualStrings("b", decoded.removed[0]);
}

test "schema 0 directory refuses non-maximal front coding and aggregate ownership overflow" {
    const allocator = std.testing.allocator;
    const malformed_hex = "f14d0200026162000011111111111111111111111111111111111111111111111111111111111111110002616300002222222222222222222222222222222222222222222222222222222222222222f20100f30100f40100f50100f60100";
    var malformed: [malformed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&malformed, malformed_hex);
    try std.testing.expectError(error.NoncanonicalSharedPathPrefix, decodeDirectory(allocator, &malformed));

    var charged = max_decoded_directory_bytes;
    try std.testing.expectError(error.DecodedDirectoryTooLarge, chargeDecodedPath(&charged, 1));
}

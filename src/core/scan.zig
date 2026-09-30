// digest and vendor hashes in one read pass

const std = @import("std");
const Thread = @import("thread.zig").Thread;
const dirscan = @import("dirscan.zig");
const fs = @import("fs.zig");
const ids = @import("ids.zig");

// limit storage contention
pub const max_workers = 8;
pub const default_buffer_bytes = 4 * 1024 * 1024;
pub const max_buffer_bytes = 64 * 1024 * 1024;

pub const VendorRequest = struct {
    schema: ids.VendorSchema,
    encoding: ids.VendorEncoding,

    pub fn validate(request: VendorRequest) error{InvalidVendorEncoding}!void {
        if (!ids.vendorEncodingAllowed(request.schema, request.encoding)) return error.InvalidVendorEncoding;
    }
};

pub const Entry = struct {
    path: []const u8,
    size: u64,
    digest: ids.Digest = .zero,
    manifest_md5: [16]u8 = @splat(0),
    observed_vendor: ?ids.VendorHash = null,
    hashed: bool = false,
};

pub const Reader = struct {
    context: ?*anyopaque = null,
    read_fn: *const fn (?*anyopaque, std.Io, std.Io.File, []u8, u64) anyerror!usize = directRead,

    pub const direct: Reader = .{};

    pub fn read(reader: Reader, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
        return reader.read_fn(reader.context, io, file, buffer, offset);
    }

    fn directRead(_: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
        return fs.readAllAt(io, file, buffer, offset);
    }
};

pub const Options = struct {
    vendor_requests: []const ?VendorRequest = &.{},
    buffer_bytes: usize = default_buffer_bytes,
    reader: Reader = .direct,
};

pub const Stats = struct {
    files: usize,
    bytes: u64,
    workers: usize,
};

const Shared = struct {
    io: std.Io,
    root: []const u8,
    entries: []Entry,
    options: Options,
    next: std.atomic.Value(usize) = .init(0),
    first_error_code: std.atomic.Value(u16) = .init(0),
};

pub fn workerCount() usize {
    return @max(1, @min(max_workers, Thread.getCpuCount() catch 1));
}

pub fn enumerate(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    ignore_path: ?dirscan.IgnorePath,
) ![]Entry {
    var listing = try dirscan.enumerate(allocator, io, root, ignore_path);
    defer listing.deinit();

    const entries = try allocator.alloc(Entry, listing.entries.len);
    var initialized: usize = 0;
    errdefer {
        for (entries[0..initialized]) |entry| allocator.free(entry.path);
        allocator.free(entries);
    }
    for (listing.entries, entries) |item, *entry| {
        if (item.is_directory or item.is_reparse) return error.UnsupportedFileType;
        entry.* = .{
            .path = try allocator.dupe(u8, item.path),
            .size = item.size,
        };
        initialized += 1;
    }
    return entries;
}

pub fn deinitEntries(allocator: std.mem.Allocator, entries: []Entry) void {
    for (entries) |entry| allocator.free(entry.path);
    allocator.free(entries);
}

pub fn hashAll(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    entries: []Entry,
    options: Options,
) !Stats {
    return hashAllWithWorkers(allocator, io, root, entries, options, workerCount());
}

fn hashAllWithWorkers(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    entries: []Entry,
    options: Options,
    workers: usize,
) !Stats {
    try validateOptions(entries.len, options);
    var total_bytes: u64 = 0;
    for (entries) |entry| total_bytes = std.math.add(u64, total_bytes, entry.size) catch return error.TreeTooLarge;
    if (entries.len == 0) return .{ .files = 0, .bytes = 0, .workers = 0 };

    const count = @min(entries.len, @max(1, workers));
    const storage_len = std.math.mul(usize, count, options.buffer_bytes) catch return error.OutOfMemory;
    const storage = try allocator.alloc(u8, storage_len);
    defer allocator.free(storage);
    var shared: Shared = .{
        .io = io,
        .root = root,
        .entries = entries,
        .options = options,
    };
    if (count == 1) {
        worker(&shared, storage);
    } else {
        const threads = try allocator.alloc(Thread, count);
        defer allocator.free(threads);
        var spawned: usize = 0;
        errdefer for (threads[0..spawned]) |thread| thread.join();
        while (spawned < count) : (spawned += 1) {
            const begin = spawned * options.buffer_bytes;
            threads[spawned] = try Thread.spawn(.{}, worker, .{
                &shared,
                storage[begin .. begin + options.buffer_bytes],
            });
        }
        for (threads) |thread| thread.join();
        spawned = 0;
    }

    const first_error_code = shared.first_error_code.load(.acquire);
    if (first_error_code != 0) return @errorFromInt(first_error_code);
    for (entries) |entry| if (!entry.hashed) return error.ScanIncomplete;
    return .{ .files = entries.len, .bytes = total_bytes, .workers = count };
}

pub fn validateOptions(entry_count: usize, options: Options) !void {
    if (options.buffer_bytes == 0 or options.buffer_bytes > max_buffer_bytes) return error.InvalidBufferSize;
    if (options.vendor_requests.len != 0) {
        if (options.vendor_requests.len != entry_count) return error.InvalidVendorRequests;
        for (options.vendor_requests) |maybe_request| if (maybe_request) |request| try request.validate();
    }
}

fn worker(shared: *Shared, buffer: []u8) void {
    var root_dir = std.Io.Dir.cwd().openDir(shared.io, shared.root, .{ .access_sub_paths = true }) catch |err| {
        _ = shared.first_error_code.cmpxchgStrong(0, @intFromError(err), .release, .monotonic);
        return;
    };
    defer root_dir.close(shared.io);

    while (shared.first_error_code.load(.acquire) == 0) {
        const index = shared.next.fetchAdd(1, .monotonic);
        if (index >= shared.entries.len) return;
        observeOne(
            shared.io,
            root_dir,
            &shared.entries[index],
            if (shared.options.vendor_requests.len == 0) null else shared.options.vendor_requests[index],
            buffer,
            shared.options.reader,
        ) catch |err| {
            _ = shared.first_error_code.cmpxchgStrong(0, @intFromError(err), .release, .monotonic);
            return;
        };
    }
}

pub fn observeOne(
    io: std.Io,
    root_dir: std.Io.Dir,
    entry: *Entry,
    vendor_request: ?VendorRequest,
    buffer: []u8,
    reader: Reader,
) !void {
    if (buffer.len == 0) return error.InvalidBufferSize;
    if (vendor_request) |request| try request.validate();

    var file = try fs.openReadBeneath(io, root_dir, entry.path);
    defer file.close(io);

    var digest_hasher = std.crypto.hash.Blake3.init(.{});
    var md5_hasher = std.crypto.hash.Md5.init(.{});
    var xxh64_hasher = std.hash.XxHash64.init(0);

    var offset: u64 = 0;
    while (true) {
        const remaining = entry.size - offset;
        const wanted: usize = @intCast(@min(buffer.len, remaining +| 1));
        const count = try reader.read(io, file, buffer[0..wanted], offset);
        if (count > wanted) return error.InvalidReadCount;
        if (count > remaining) return error.FileChangedDuringScan;
        if (count == 0) break;
        const bytes = buffer[0..count];
        digest_hasher.update(bytes);
        md5_hasher.update(bytes);
        if (vendor_request) |request| {
            if (ids.vendorAlgorithm(request.schema) == .xxh64) xxh64_hasher.update(bytes);
        }
        offset += count;
    }
    if (offset != entry.size) return error.FileChangedDuringScan;

    var digest: ids.Digest = undefined;
    digest_hasher.final(&digest.bytes);
    var manifest_md5: [16]u8 = undefined;
    md5_hasher.final(&manifest_md5);
    const observed_vendor: ?ids.VendorHash = if (vendor_request) |request| blk: {
        var bytes: [16]u8 = @splat(0);
        switch (ids.vendorAlgorithm(request.schema)) {
            .md5 => bytes = manifest_md5,
            .xxh64 => std.mem.writeInt(u64, bytes[0..8], xxh64_hasher.final(), .big),
        }
        break :blk try ids.VendorHash.init(request.schema, request.encoding, bytes);
    } else null;

    entry.digest = digest;
    entry.manifest_md5 = manifest_md5;
    entry.observed_vendor = observed_vendor;
    entry.hashed = true;
}

pub fn observationsEqual(lhs: Entry, rhs: Entry) bool {
    return lhs.size == rhs.size and
        lhs.digest.eql(rhs.digest) and
        std.mem.eql(u8, &lhs.manifest_md5, &rhs.manifest_md5) and
        vendorEqual(lhs.observed_vendor, rhs.observed_vendor);
}

fn vendorEqual(lhs: ?ids.VendorHash, rhs: ?ids.VendorHash) bool {
    if (lhs == null or rhs == null) return lhs == null and rhs == null;
    return lhs.?.sameClaim(rhs.?);
}

test "scan is deterministic across worker schedules" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for (0..40) |index| {
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "f{d:0>3}.bin", .{index});
        const data = try allocator.alloc(u8, 1000 + index * 997);
        defer allocator.free(data);
        for (data, 0..) |*byte, byte_index| byte.* = @intCast((index * 7 + byte_index * 13) & 0xff);
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
    }
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);

    var baseline: ?[]Entry = null;
    defer if (baseline) |entries| deinitEntries(allocator, entries);
    for ([_]usize{ 1, 4, 8 }) |workers| {
        const entries = try enumerate(allocator, io, root, null);
        errdefer deinitEntries(allocator, entries);
        _ = try hashAllWithWorkers(allocator, io, root, entries, .{ .buffer_bytes = 64 * 1024 }, workers);
        if (baseline) |expected| {
            for (expected, entries) |lhs, rhs| try std.testing.expect(observationsEqual(lhs, rhs));
            deinitEntries(allocator, entries);
        } else baseline = entries;
    }
}

test "scan workers are bounded by the file count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "one" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b", .data = "two" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    for (0..3) |file_count| {
        var entries = [_]Entry{ .{ .path = "a", .size = 3 }, .{ .path = "b", .size = 3 } };
        const stats = try hashAllWithWorkers(allocator, io, root, entries[0..file_count], .{ .buffer_bytes = 64 }, 8);
        try std.testing.expectEqual(file_count, stats.workers);
        try std.testing.expectEqual(@as(u64, file_count * 3), stats.bytes);
        for (entries[0..file_count]) |entry| try std.testing.expect(entry.hashed);
    }
}

test "vendor algorithm is selected by schema during the same read" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a.bin", .data = "abc" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.bin", .data = "abc" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const entries = try enumerate(allocator, io, root, null);
    defer deinitEntries(allocator, entries);
    const requests = [_]?VendorRequest{
        .{ .schema = .hoyo_pkg_version_md5, .encoding = .hex },
        .{ .schema = .genshin_pkg_version_xxh64_hex, .encoding = .hex },
    };
    _ = try hashAllWithWorkers(allocator, io, root, entries, .{ .vendor_requests = &requests, .buffer_bytes = 64 }, 1);
    try std.testing.expectEqual(ids.VendorAlgorithm.md5, entries[0].observed_vendor.?.algorithm);
    try std.testing.expectEqual(ids.VendorAlgorithm.xxh64, entries[1].observed_vendor.?.algorithm);
    try std.testing.expectEqual(@as(u8, 16), entries[0].observed_vendor.?.length);
    try std.testing.expectEqual(@as(u8, 8), entries[1].observed_vendor.?.length);
}

test "an actual read-boundary failure makes the scan fatal" {
    const Fault = struct {
        fn read(_: ?*anyopaque, _: std.Io, _: std.Io.File, _: []u8, _: u64) !usize {
            return error.InjectedReadFailure;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = "must not hash partially" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const entries = try enumerate(allocator, io, root, null);
    defer deinitEntries(allocator, entries);
    try std.testing.expectError(error.InjectedReadFailure, hashAllWithWorkers(
        allocator,
        io,
        root,
        entries,
        .{ .buffer_bytes = 64, .reader = .{ .read_fn = Fault.read } },
        1,
    ));
    try std.testing.expect(!entries[0].hashed);
}

test "scan rejects post-enumeration growth without reading the appended payload" {
    const Budget = struct {
        consumed: usize = 0,

        fn read(context: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = try fs.readAllAt(io, file, buffer, offset);
            self.consumed += count;
            if (self.consumed > 4) return error.ReadBudgetExceeded;
            return count;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = "old" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const entries = try enumerate(allocator, io, root, null);
    defer deinitEntries(allocator, entries);
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = "new and longer" });
    var budget: Budget = .{};
    try std.testing.expectError(
        error.FileChangedDuringScan,
        hashAllWithWorkers(allocator, io, root, entries, .{ .buffer_bytes = 64, .reader = .{ .context = &budget, .read_fn = Budget.read } }, 1),
    );
    try std.testing.expectEqual(@as(usize, 4), budget.consumed);
    try std.testing.expect(!entries[0].hashed);
}

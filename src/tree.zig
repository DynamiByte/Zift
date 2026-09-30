const manifest_mod = @import("core/manifest.zig");
const std = @import("std");
const builtin = @import("builtin");

const ui = @import("ui.zig");
const path_util = @import("path.zig");
const verify = @import("verify.zig");
const dirscan = @import("core/dirscan.zig");
const ids = @import("core/ids.zig");
const observation = @import("core/scan.zig");
const content = @import("core/content.zig");

pub const File = struct {
    path: []const u8,
    size: u64,
    bytes: ?[]const u8 = null,
    // tree-owned content state through comparison/encoding
    content_state: ?*content.State = null,
    md5: ?[16]u8 = null,
    digest: ?ids.Digest = null,
    observed_vendor: ?ids.VendorHash = null,
    claim: ?ids.VendorClaim = null,
};

pub const Tree = struct {
    root: []const u8,
    files: []File,
    map: std.StringHashMapUnmanaged(u32),
    deferred_content: bool = false,

    pub fn findIndex(self: Tree, path: []const u8) ?u32 {
        return self.map.get(path);
    }

    pub fn find(self: Tree, path: []const u8) ?File {
        return self.files[self.findIndex(path) orelse return null];
    }
};

pub const IgnorePath = dirscan.IgnorePath;

pub const ExpectedClaims = struct {
    expected: manifest_mod.Set,
    schema: ids.VendorSchema,
    encoding: ids.VendorEncoding = .hex,
    authority: ids.ClaimAuthority,
};

pub fn scan(allocator: std.mem.Allocator, io: std.Io, root: []const u8, progress: ?*ui.Progress, ignore_path: ?IgnorePath) !Tree {
    return scanWithClaims(allocator, io, root, progress, ignore_path, null);
}

pub fn scanWithClaims(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    progress: ?*ui.Progress,
    ignore_path: ?IgnorePath,
    claims: ?ExpectedClaims,
) !Tree {
    return scanSelected(allocator, io, root, progress, ignore_path, claims, false);
}

// manifest membership only; hashes read from disk
pub fn scanManagedWithClaims(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    progress: ?*ui.Progress,
    ignore_path: ?IgnorePath,
    claims: ExpectedClaims,
) !Tree {
    return scanSelected(allocator, io, root, progress, ignore_path, claims, true);
}

fn scanSelected(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    progress: ?*ui.Progress,
    ignore_path: ?IgnorePath,
    claims: ?ExpectedClaims,
    managed_only: bool,
) !Tree {
    var entries = try observation.enumerate(allocator, io, root, ignore_path);
    var owns_entries = true;
    defer if (owns_entries) observation.deinitEntries(allocator, entries);
    if (managed_only) {
        const filtered = try retainManagedEntries(allocator, entries, claims.?.expected);
        entries = filtered;
    }
    const vendor_requests = try buildVendorRequests(allocator, entries, claims);
    defer allocator.free(vendor_requests);
    {
        var reading: ui.ReadProgress = .{ .progress = progress };
        _ = try observation.hashAll(allocator, io, root, entries, .{ .vendor_requests = vendor_requests, .reader = reading.reader() });
    }
    try validateClaimObservations(allocator, io, root, entries, claims, progress);
    for (entries) |entry| {
        try path_util.validate(entry.path);
        if (progress) |p| try p.finishFile();
    }
    owns_entries = false;
    var result = try fromObservations(allocator, root, entries);
    errdefer deinitOwnedTree(allocator, result);
    try attachClaims(&result, claims);
    return result;
}

fn retainManagedEntries(
    allocator: std.mem.Allocator,
    entries: []observation.Entry,
    expected: manifest_mod.Set,
) ![]observation.Entry {
    var count: usize = 0;
    for (entries) |entry| if (expected.contains(entry.path)) {
        count += 1;
    };
    if (count != expected.entries.len) return error.ManagedMemberMissing;
    const selected = try allocator.alloc(observation.Entry, count);
    var selected_index: usize = 0;
    for (entries) |entry| {
        if (expected.contains(entry.path)) {
            selected[selected_index] = entry;
            selected_index += 1;
        } else {
            allocator.free(entry.path);
        }
    }
    allocator.free(entries);
    return selected;
}

pub fn inventory(allocator: std.mem.Allocator, io: std.Io, root: []const u8, progress: ?*ui.Progress, ignore_path: ?IgnorePath) !Tree {
    return inventoryWithClaims(allocator, io, root, progress, ignore_path, null, false);
}

pub fn inventoryWithClaims(allocator: std.mem.Allocator, io: std.Io, root: []const u8, progress: ?*ui.Progress, ignore_path: ?IgnorePath, claims: ?ExpectedClaims, managed_only: bool) !Tree {
    var entries = try observation.enumerate(allocator, io, root, ignore_path);
    if (managed_only) {
        entries = retainManagedEntries(allocator, entries, claims.?.expected) catch |err| {
            observation.deinitEntries(allocator, entries);
            return err;
        };
    }
    var result = try fromObservations(allocator, root, entries);
    errdefer deinitOwnedTree(allocator, result);
    for (result.files) |*file| {
        file.md5 = null;
        file.digest = null;
        if (progress) |p| try p.finishFile();
    }
    try attachClaims(&result, claims);
    result.deferred_content = claims == null;
    return result;
}

pub fn observeInventory(io: std.Io, value: *Tree, claims: ?ExpectedClaims, progress: ?*ui.Progress) !void {
    const allocator = std.heap.smp_allocator;
    const entries = try allocator.alloc(observation.Entry, value.files.len);
    defer allocator.free(entries);
    var expected_bytes: u64 = 0;
    for (value.files, entries) |file, *entry| {
        entry.* = .{ .path = file.path, .size = file.size };
        expected_bytes +|= file.size;
    }
    const vendor_requests = try buildVendorRequests(allocator, entries, claims);
    defer allocator.free(vendor_requests);
    var reading: ui.ReadProgress = .{ .progress = progress };
    const bytes_before = if (progress) |p| p.done_bytes else 0;
    _ = try observation.hashAll(allocator, io, value.root, entries, .{ .vendor_requests = vendor_requests, .reader = reading.reader() });
    try validateClaimObservations(allocator, io, value.root, entries, claims, progress);
    if (progress) |p| p.reconcileRead(expected_bytes, p.done_bytes - bytes_before);
    for (value.files, entries) |*file, entry| {
        try path_util.validate(file.path);
        file.md5 = entry.manifest_md5;
        file.digest = entry.digest;
        file.observed_vendor = entry.observed_vendor;
        if (progress) |p| try p.finishFile();
    }
    value.deferred_content = false;
}

pub fn contentState(allocator: std.mem.Allocator, file: *File) !*content.State {
    if (file.content_state) |state| return state;
    const state = try allocator.create(content.State);
    state.* = .{ .size = file.size };
    file.content_state = state;
    return state;
}

pub const PairScan = struct {
    source: Tree,
    target: Tree,
};

pub fn scanPairWithClaims(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_root: []const u8,
    target_root: []const u8,
    progress: ?*ui.Progress,
    ignore_path: ?IgnorePath,
    source_claims: ?ExpectedClaims,
    target_claims: ?ExpectedClaims,
) !PairScan {
    return scanPairWithClaimsReader(
        allocator,
        io,
        source_root,
        target_root,
        progress,
        ignore_path,
        source_claims,
        target_claims,
        .direct,
    );
}

fn scanPairWithClaimsReader(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_root: []const u8,
    target_root: []const u8,
    progress: ?*ui.Progress,
    ignore_path: ?IgnorePath,
    source_claims: ?ExpectedClaims,
    target_claims: ?ExpectedClaims,
    reader: observation.Reader,
) !PairScan {
    const source_entries = try observation.enumerate(allocator, io, source_root, ignore_path);
    var owns_source = true;
    defer if (owns_source) observation.deinitEntries(allocator, source_entries);
    const target_entries = try observation.enumerate(allocator, io, target_root, ignore_path);
    var owns_target = true;
    defer if (owns_target) observation.deinitEntries(allocator, target_entries);

    const source_vendor_requests = try buildVendorRequests(allocator, source_entries, source_claims);
    defer allocator.free(source_vendor_requests);
    const target_vendor_requests = try buildVendorRequests(allocator, target_entries, target_claims);
    defer allocator.free(target_vendor_requests);
    var reading: ui.ReadProgress = .{ .progress = progress, .inner = reader };
    {
        _ = try observation.hashAll(allocator, io, source_root, source_entries, .{
            .vendor_requests = source_vendor_requests,
            .reader = reading.reader(),
        });
    }
    {
        _ = try observation.hashAll(allocator, io, target_root, target_entries, .{
            .vendor_requests = target_vendor_requests,
            .reader = reading.reader(),
        });
    }
    try validateClaimObservations(allocator, io, source_root, source_entries, source_claims, progress);
    try validateClaimObservations(allocator, io, target_root, target_entries, target_claims, progress);
    for (source_entries) |entry| {
        try path_util.validate(entry.path);
        if (progress) |p| try p.finishFile();
    }
    for (target_entries) |entry| {
        try path_util.validate(entry.path);
        if (progress) |p| try p.finishFile();
    }

    owns_source = false;
    var source_tree = try fromObservations(allocator, source_root, source_entries);
    errdefer deinitOwnedTree(allocator, source_tree);
    try attachClaims(&source_tree, source_claims);
    owns_target = false;
    var target_tree = try fromObservations(allocator, target_root, target_entries);
    errdefer deinitOwnedTree(allocator, target_tree);
    try attachClaims(&target_tree, target_claims);
    return .{ .source = source_tree, .target = target_tree };
}

fn fromObservations(allocator: std.mem.Allocator, root: []const u8, entries: []observation.Entry) !Tree {
    var owns_entries = true;
    defer if (owns_entries) observation.deinitEntries(allocator, entries);

    const files = try allocator.alloc(File, entries.len);
    errdefer allocator.free(files);
    for (entries, files) |entry, *file| file.* = .{
        .path = entry.path,
        .size = entry.size,
        .md5 = entry.manifest_md5,
        .digest = entry.digest,
        .observed_vendor = entry.observed_vendor,
    };
    const result = try buildTree(allocator, root, files);
    allocator.free(entries);
    owns_entries = false;
    return result;
}

fn buildVendorRequests(
    allocator: std.mem.Allocator,
    entries: []const observation.Entry,
    maybe_claims: ?ExpectedClaims,
) ![]?observation.VendorRequest {
    const claims = maybe_claims orelse return &.{};
    const requests = try allocator.alloc(?observation.VendorRequest, entries.len);
    errdefer allocator.free(requests);
    @memset(requests, null);
    for (entries, requests) |entry, *request| {
        _ = claims.expected.find(entry.path) orelse continue;
        request.* = .{ .schema = claims.schema, .encoding = claims.encoding };
    }
    return requests;
}

fn validateClaimObservations(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    entries: []observation.Entry,
    maybe_claims: ?ExpectedClaims,
    progress: ?*ui.Progress,
) !void {
    const claims = maybe_claims orelse return;
    if (claims.authority != .authoritative) return;
    var root_dir = try std.Io.Dir.cwd().openDir(io, root, .{ .access_sub_paths = true });
    defer root_dir.close(io);
    const buffer = try allocator.alloc(u8, observation.default_buffer_bytes);
    defer allocator.free(buffer);

    for (claims.expected.entries) |expected| {
        const first_index = findObservationIndex(entries, expected.path);
        if (first_index != null and try claimSatisfied(entries[first_index.?], expected, claims)) continue;

        const stat = root_dir.statFile(io, expected.path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return error.AuthoritativeClaimMissing,
            else => |e| return e,
        };
        if (stat.kind != .file) return error.AuthoritativeClaimMissing;
        var reread: observation.Entry = .{ .path = expected.path, .size = stat.size };
        var reading: ui.ReadProgress = .{ .progress = progress };
        observation.observeOne(
            io,
            root_dir,
            &reread,
            .{ .schema = claims.schema, .encoding = claims.encoding },
            buffer,
            reading.reader(),
        ) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return error.AuthoritativeClaimMissing,
            error.FileChangedDuringScan => return error.AuthoritativeClaimContradiction,
            else => |e| return e,
        };
        if (!try claimSatisfied(reread, expected, claims)) return error.AuthoritativeClaimContradiction;
        // excluded paths not authoritative managed members
        if (first_index == null) return error.AuthoritativeClaimMissing;
        reread.path = entries[first_index.?].path;
        entries[first_index.?] = reread;
    }
}

fn findObservationIndex(entries: []const observation.Entry, path: []const u8) ?usize {
    return std.sort.binarySearch(observation.Entry, entries, path, struct {
        fn compare(key: []const u8, entry: observation.Entry) std.math.Order {
            return std.mem.order(u8, key, entry.path);
        }
    }.compare);
}

fn claimSatisfied(entry: observation.Entry, expected: manifest_mod.File, claims: ExpectedClaims) !bool {
    if (entry.size != expected.size) return false;
    const observed = entry.observed_vendor orelse return false;
    const claimed = try ids.VendorHash.init(claims.schema, claims.encoding, expected.md5);
    return observed.sameClaim(claimed);
}

fn attachClaims(value: *Tree, maybe_claims: ?ExpectedClaims) !void {
    const claims = maybe_claims orelse return;
    for (value.files) |*file| {
        const expected = claims.expected.find(file.path) orelse continue;
        file.claim = .{
            .authority = claims.authority,
            .value = try ids.VendorHash.init(claims.schema, claims.encoding, expected.md5),
        };
    }
}

pub fn deinitOwnedTree(allocator: std.mem.Allocator, tree_value: Tree) void {
    var value = tree_value;
    value.map.deinit(allocator);
    for (value.files) |file| {
        allocator.free(file.path);
        if (file.content_state) |state| allocator.destroy(state);
    }
    allocator.free(value.files);
}

pub fn fromExpected(
    allocator: std.mem.Allocator,
    root: []const u8,
    claims: ExpectedClaims,
) !Tree {
    return fromExpectedWithMetadata(allocator, root, claims, &.{});
}

// manifests omit themselves; still needed for version updates
pub fn fromExpectedWithMetadata(
    allocator: std.mem.Allocator,
    root: []const u8,
    claims: ExpectedClaims,
    metadata: []const manifest_mod.MetadataFile,
) !Tree {
    const total = std.math.add(usize, claims.expected.entries.len, metadata.len) catch
        return error.TooManyFiles;
    const files = try allocator.alloc(File, total);
    errdefer allocator.free(files);
    for (claims.expected.entries, files[0..claims.expected.entries.len]) |entry, *file| {
        file.* = .{
            .path = entry.path,
            .size = entry.size,
            .md5 = entry.md5,
            .claim = .{
                .authority = claims.authority,
                .value = try ids.VendorHash.init(claims.schema, claims.encoding, entry.md5),
            },
        };
    }
    for (metadata, files[claims.expected.entries.len..]) |entry, *file| {
        var md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(entry.bytes, &md5, .{});
        file.* = .{ .path = entry.path, .size = entry.bytes.len, .bytes = entry.bytes, .md5 = md5, .digest = ids.Digest.of(entry.bytes) };
    }
    sortFiles(files);
    var result = try buildTree(allocator, root, files);
    result.deferred_content = claims.authority == .authoritative;
    return result;
}

fn sortFiles(files: []File) void {
    std.mem.sortUnstable(File, files, {}, struct {
        fn lessThan(_: void, a: File, b: File) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lessThan);
}

fn buildTree(allocator: std.mem.Allocator, root: []const u8, files: []File) !Tree {
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    errdefer map.deinit(allocator);
    for (files, 0..) |file, index| {
        const got = try map.getOrPut(allocator, file.path);
        if (got.found_existing) return error.DuplicatePath;
        got.value_ptr.* = @intCast(index);
    }
    return .{ .root = root, .files = files, .map = map };
}

pub fn ensureHash(io: std.Io, dir: std.Io.Dir, tree: *Tree, index: u32, progress: ?*ui.Progress) ![16]u8 {
    const file = &tree.files[index];
    if (file.md5) |md5| return md5;
    const actual = try verify.hashFile(io, dir, file.path, progress);
    if (actual.size != file.size) return error.FileChangedDuringScan;
    file.md5 = actual.md5;
    return actual.md5;
}

pub fn matchesSnapshot(io: std.Io, dir: std.Io.Dir, file: File) !bool {
    const expected = file.md5 orelse return error.MissingHash;
    const actual = verify.hashFile(io, dir, file.path, null) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.ExpectedFile => return false,
        else => |e| return e,
    };
    return actual.size == file.size and std.mem.eql(u8, &actual.md5, &expected);
}

pub const DigestObservationOptions = struct {
    // first-read fault injection only
    reader: observation.Reader = .direct,
    buffer_bytes: usize = observation.default_buffer_bytes,
};

// single physical observation; independent construction check still required
pub fn observeDigest(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    value: *Tree,
    index: u32,
    options: DigestObservationOptions,
) !ids.Digest {
    const file_index: usize = @intCast(index);
    if (file_index >= value.files.len) return error.InvalidTreeIndex;
    if (options.buffer_bytes == 0 or options.buffer_bytes > observation.max_buffer_bytes)
        return error.InvalidBufferSize;
    const file = &value.files[file_index];
    const buffer = try allocator.alloc(u8, options.buffer_bytes);
    defer allocator.free(buffer);
    const observed = try observeFileDigest(io, dir, file.*, buffer, options.reader);
    publishDigestObservation(file, observed);
    return observed.digest;
}

pub fn adjudicateDigest(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    value: *Tree,
    index: u32,
    options: DigestObservationOptions,
) !ids.Digest {
    const file_index: usize = @intCast(index);
    if (file_index >= value.files.len) return error.InvalidTreeIndex;
    if (options.buffer_bytes == 0 or options.buffer_bytes > observation.max_buffer_bytes)
        return error.InvalidBufferSize;
    const file = &value.files[file_index];
    const buffer = try allocator.alloc(u8, options.buffer_bytes);
    defer allocator.free(buffer);

    const first = try observeFileDigest(io, dir, file.*, buffer, options.reader);
    const second = try observeFileDigest(io, dir, file.*, buffer, .direct);
    if (first.digest.eql(second.digest)) {
        publishDigestObservation(file, second);
        return second.digest;
    }
    const third = try observeFileDigest(io, dir, file.*, buffer, .direct);
    if (first.digest.eql(third.digest)) {
        publishDigestObservation(file, third);
        return third.digest;
    }
    if (second.digest.eql(third.digest)) {
        publishDigestObservation(file, third);
        return third.digest;
    }
    return error.UnstablePhysicalObservation;
}

// construction identity binding; stable physical change not repairable
pub fn confirmDigest(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    value: *Tree,
    index: u32,
    expected: ids.Digest,
    options: DigestObservationOptions,
) !void {
    const file_index: usize = @intCast(index);
    if (file_index >= value.files.len) return error.InvalidTreeIndex;
    if (options.buffer_bytes == 0 or options.buffer_bytes > observation.max_buffer_bytes)
        return error.InvalidBufferSize;
    const file = &value.files[file_index];
    const buffer = try allocator.alloc(u8, options.buffer_bytes);
    defer allocator.free(buffer);

    const first = try observeFileDigest(io, dir, file.*, buffer, options.reader);
    const second = try observeFileDigest(io, dir, file.*, buffer, .direct);
    if (expected.eql(first.digest) and expected.eql(second.digest)) {
        publishDigestObservation(file, second);
        return;
    }
    if (expected.eql(first.digest) != expected.eql(second.digest)) {
        const third = try observeFileDigest(io, dir, file.*, buffer, .direct);
        if (expected.eql(third.digest)) {
            publishDigestObservation(file, third);
            return;
        }
    }
    return error.FileChangedDuringConstruction;
}

const DigestFileObservation = struct {
    digest: ids.Digest,
    md5: [16]u8,
    observed_vendor: ?ids.VendorHash,
};

fn observeFileDigest(
    io: std.Io,
    dir: std.Io.Dir,
    file: File,
    buffer: []u8,
    reader: observation.Reader,
) !DigestFileObservation {
    const vendor_request: ?observation.VendorRequest = if (file.claim) |claim| .{
        .schema = claim.value.schema,
        .encoding = claim.value.encoding,
    } else null;
    var entry: observation.Entry = .{ .path = file.path, .size = file.size };
    observation.observeOne(io, dir, &entry, vendor_request, buffer, reader) catch |err|
        return mapConstructionObservationError(err);

    if (file.claim) |claim| if (claim.authority == .authoritative) {
        const observed = entry.observed_vendor orelse
            return error.AuthoritativeClaimContradiction;
        if (!observed.sameClaim(claim.value)) {
            var retry: observation.Entry = .{ .path = file.path, .size = file.size };
            observation.observeOne(io, dir, &retry, vendor_request, buffer, .direct) catch |err|
                return mapConstructionObservationError(err);
            const retried = retry.observed_vendor orelse
                return error.AuthoritativeClaimContradiction;
            if (!retried.sameClaim(claim.value))
                return error.AuthoritativeClaimContradiction;
            entry = retry;
        }
    };

    return .{
        .digest = entry.digest,
        .md5 = entry.manifest_md5,
        .observed_vendor = entry.observed_vendor,
    };
}

fn publishDigestObservation(file: *File, observed: DigestFileObservation) void {
    file.digest = observed.digest;
    file.md5 = observed.md5;
    file.observed_vendor = observed.observed_vendor;
}

fn mapConstructionObservationError(err: anyerror) anyerror {
    return switch (err) {
        error.FileChangedDuringScan,
        error.FileNotFound,
        error.NotDir,
        error.ExpectedFile,
        error.IsDir,
        error.PathAncestorNotDirectory,
        error.UnsafePathAncestor,
        error.SymLinkLoop,
        => error.FileChangedDuringConstruction,
        else => err,
    };
}

// candidate only; keep requires independent confirmation
pub fn candidateEqual(source: File, target: File) !bool {
    if (source.size != target.size) return false;
    if (source.digest) |source_digest| if (target.digest) |target_digest| {
        return source_digest.eql(target_digest);
    };
    const source_md5 = source.md5 orelse return error.MissingHash;
    const target_md5 = target.md5 orelse return error.MissingHash;
    return std.mem.eql(u8, &source_md5, &target_md5);
}

test "construction digest adjudication repairs one wrong read and detects later change" {
    const FlipFirst = struct {
        flipped: bool = false,

        fn read(
            context: ?*anyopaque,
            io: std.Io,
            file: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = try observation.Reader.direct.read(io, file, buffer, offset);
            if (!self.flipped and count != 0) {
                buffer[0] ^= 0x40;
                self.flipped = true;
            }
            return count;
        }

        fn reader(self: *@This()) observation.Reader {
            return .{ .context = self, .read_fn = read };
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bytes = "physical construction authority";
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = bytes });

    var files = [_]File{.{ .path = "file.bin", .size = bytes.len }};
    var value: Tree = .{ .root = "", .files = &files, .map = .empty };
    var first_fault: FlipFirst = .{};
    const expected = ids.Digest.of(bytes);
    const adjudicated = try adjudicateDigest(
        allocator,
        io,
        tmp.dir,
        &value,
        0,
        .{ .reader = first_fault.reader(), .buffer_bytes = 7 },
    );
    try std.testing.expect(first_fault.flipped);
    try std.testing.expect(expected.eql(adjudicated));
    try std.testing.expect(expected.eql(value.files[0].digest.?));

    var confirmation_fault: FlipFirst = .{};
    try confirmDigest(
        allocator,
        io,
        tmp.dir,
        &value,
        0,
        expected,
        .{ .reader = confirmation_fault.reader(), .buffer_bytes = 9 },
    );
    try std.testing.expect(confirmation_fault.flipped);

    const changed = try allocator.dupe(u8, bytes);
    defer allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = changed });
    try std.testing.expectError(error.FileChangedDuringConstruction, confirmDigest(
        allocator,
        io,
        tmp.dir,
        &value,
        0,
        expected,
        .{ .buffer_bytes = 8 },
    ));
}

test "construction authority never promotes a stale planning digest from one wrong read" {
    const StaleFirst = struct {
        bytes: []const u8,
        used: bool = false,

        fn read(
            context: ?*anyopaque,
            _: std.Io,
            _: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.used = true;
            if (offset >= self.bytes.len) return 0;
            const start: usize = @intCast(offset);
            const count = @min(buffer.len, self.bytes.len - start);
            @memcpy(buffer[0..count], self.bytes[start .. start + count]);
            return count;
        }

        fn reader(self: *@This()) observation.Reader {
            return .{ .context = self, .read_fn = read };
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const old_bytes = "old planning bytes";
    const new_bytes = "new physical bytes";
    comptime std.debug.assert(old_bytes.len == new_bytes.len);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = new_bytes });

    var files = [_]File{.{
        .path = "file.bin",
        .size = old_bytes.len,
        .digest = ids.Digest.of(old_bytes),
    }};
    var value: Tree = .{ .root = "", .files = &files, .map = .empty };
    var stale: StaleFirst = .{ .bytes = old_bytes };
    const current = try adjudicateDigest(
        allocator,
        io,
        tmp.dir,
        &value,
        0,
        .{ .reader = stale.reader(), .buffer_bytes = 5 },
    );
    try std.testing.expect(stale.used);
    try std.testing.expect(current.eql(ids.Digest.of(new_bytes)));
    try std.testing.expect(value.files[0].digest.?.eql(current));

    try tmp.dir.writeFile(io, .{ .sub_path = "file.bin", .data = new_bytes ++ "!" });
    try std.testing.expectError(error.FileChangedDuringConstruction, confirmDigest(
        allocator,
        io,
        tmp.dir,
        &value,
        0,
        current,
        .{},
    ));
}

test "construction digest options enforce the observation memory cap" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var files = [_]File{.{ .path = "unused", .size = 0 }};
    var value: Tree = .{ .root = "", .files = &files, .map = .empty };
    try std.testing.expectError(error.InvalidBufferSize, adjudicateDigest(
        allocator,
        io,
        std.Io.Dir.cwd(),
        &value,
        0,
        .{ .buffer_bytes = observation.max_buffer_bytes + 1 },
    ));
    try std.testing.expectError(error.InvalidBufferSize, confirmDigest(
        allocator,
        io,
        std.Io.Dir.cwd(),
        &value,
        0,
        .zero,
        .{ .buffer_bytes = observation.max_buffer_bytes + 1 },
    ));
}

test "candidate equality uses BLAKE3 rather than manifest MD5" {
    const md5: [16]u8 = @splat(9);
    const source: File = .{
        .path = "file.bin",
        .size = 4,
        .md5 = md5,
        .digest = ids.Digest.of("aaaa"),
    };
    var target = source;
    target.digest = ids.Digest.of("bbbb");
    try std.testing.expect(!try candidateEqual(source, target));
    target.digest = source.digest;
    try std.testing.expect(try candidateEqual(source, target));
}

test "scan preserves literal backslash on posix" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a\\b", .data = "x" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var scanned = try scan(std.testing.allocator, io, root, null, null);
    defer {
        scanned.map.deinit(std.testing.allocator);
        for (scanned.files) |file| std.testing.allocator.free(file.path);
        std.testing.allocator.free(scanned.files);
    }
    try std.testing.expect(scanned.find("a\\b") != null);
    try std.testing.expect(scanned.find("a/b") == null);
}

test "scan prunes ignored directories" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "skip/nested");
    try tmp.dir.writeFile(io, .{ .sub_path = "skip/nested/file.bin", .data = "ignored" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.bin", .data = "kept" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);

    const ignore = struct {
        fn path(value: []const u8) bool {
            return std.mem.eql(u8, value, "skip") or std.mem.startsWith(u8, value, "skip/");
        }
    }.path;
    var scanned = try scan(allocator, io, root, null, ignore);
    defer {
        scanned.map.deinit(allocator);
        for (scanned.files) |file| allocator.free(file.path);
        allocator.free(scanned.files);
    }
    try std.testing.expectEqual(@as(usize, 1), scanned.files.len);
    try std.testing.expect(scanned.find("keep.bin") != null);
}

test "authoritative claim reread recovers a transient first-pass byte fault" {
    const FlipOnceReader = struct {
        flipped: bool = false,

        fn read(
            context: ?*anyopaque,
            io: std.Io,
            file: std.Io.File,
            buffer: []u8,
            offset: u64,
        ) !usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = try observation.Reader.direct.read(io, file, buffer, offset);
            if (!self.flipped and count != 0) {
                buffer[0] ^= 0x80;
                self.flipped = true;
            }
            return count;
        }

        fn reader(self: *@This()) observation.Reader {
            return .{ .context = self, .read_fn = read };
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bytes = "claimed source bytes for reread " ** 4096;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/unique.bin", .data = bytes });
    const base = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base);
    const source_root = try std.fs.path.join(allocator, &.{ base, "source" });
    defer allocator.free(source_root);
    const target_root = try std.fs.path.join(allocator, &.{ base, "target" });
    defer allocator.free(target_root);

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &md5, .{});
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    defer map.deinit(allocator);
    try map.put(allocator, "unique.bin", 0);
    var expected_entries = [_]manifest_mod.File{.{
        .path = "unique.bin",
        .size = bytes.len,
        .md5 = md5,
    }};
    const claims: ExpectedClaims = .{
        .expected = .{ .entries = &expected_entries, .map = map },
        .schema = .hoyo_pkg_version_md5,
        .authority = .authoritative,
    };

    const clean_pair = try scanPairWithClaims(
        allocator,
        io,
        source_root,
        target_root,
        null,
        null,
        claims,
        null,
    );
    defer {
        deinitOwnedTree(allocator, clean_pair.source);
        deinitOwnedTree(allocator, clean_pair.target);
    }

    var fault: FlipOnceReader = .{};
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Reading contents" };
    const recovered_pair = try scanPairWithClaimsReader(
        allocator,
        io,
        source_root,
        target_root,
        &progress,
        null,
        claims,
        null,
        fault.reader(),
    );
    defer {
        deinitOwnedTree(allocator, recovered_pair.source);
        deinitOwnedTree(allocator, recovered_pair.target);
    }
    try std.testing.expect(fault.flipped);
    try std.testing.expectEqual(@as(u64, bytes.len * 2), progress.done_bytes);

    const clean = clean_pair.source.find("unique.bin").?;
    const recovered = recovered_pair.source.find("unique.bin").?;
    try std.testing.expect(clean.digest.?.eql(recovered.digest.?));
    try std.testing.expectEqualSlices(u8, &clean.md5.?, &recovered.md5.?);
    try std.testing.expectEqual(clean.claim.?.authority, recovered.claim.?.authority);
    try std.testing.expect(clean.claim.?.value.sameClaim(recovered.claim.?.value));
    try std.testing.expect(clean.observed_vendor.?.sameClaim(recovered.observed_vendor.?));
}

test "scan read progress counts parallel reads without changing file identities" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "scan content " ** 4096;
    for (0..12) |index| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{d}.bin", .{index});
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
    }
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Reading contents" };
    const value = try scan(allocator, io, root, &progress, null);
    defer deinitOwnedTree(allocator, value);
    try std.testing.expectEqual(@as(u64, data.len * 12), progress.done_bytes);
    try std.testing.expectEqual(@as(usize, 12), progress.done_files);
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &md5, .{});
    for (value.files) |file| {
        try std.testing.expectEqual(@as(u64, data.len), file.size);
        try std.testing.expectEqualSlices(u8, &md5, &file.md5.?);
    }
}

test "claim-free scans need no vendor request allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = failing.allocator();
    const entries = [_]observation.Entry{
        .{ .path = "a.bin", .size = 1 },
        .{ .path = "b.bin", .size = 2 },
    };
    const requests = try buildVendorRequests(allocator, &entries, null);
    defer allocator.free(requests);
    try std.testing.expectEqual(@as(usize, 0), requests.len);
    try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
}

test "expected metadata trees release their own arrays on allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var entries = [_]manifest_mod.File{
                .{ .path = "z.bin", .size = 3, .md5 = @splat(1) },
                .{ .path = "a.bin", .size = 1, .md5 = @splat(2) },
            };
            const metadata = [_]manifest_mod.MetadataFile{.{ .path = "manifest", .bytes = "metadata" }};
            var value = try fromExpectedWithMetadata(allocator, "root", .{
                .expected = .{ .entries = &entries, .map = .empty },
                .schema = .wuwa_local_resources_md5,
                .authority = .authoritative,
            }, &metadata);
            defer {
                value.map.deinit(allocator);
                allocator.free(value.files);
            }
            try std.testing.expectEqual(@as(usize, 3), value.files.len);
            try std.testing.expectEqualStrings("a.bin", value.files[0].path);
            try std.testing.expectEqualStrings("manifest", value.files[1].path);
            try std.testing.expectEqualStrings("z.bin", value.files[2].path);
            try std.testing.expectEqual(entries[1].path.ptr, value.files[0].path.ptr);
            try std.testing.expectEqual(ids.VendorSchema.wuwa_local_resources_md5, value.files[0].claim.?.value.schema);
            try std.testing.expect(value.files[1].claim == null);
            try std.testing.expectEqual(@as(u64, metadata[0].bytes.len), value.files[1].size);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "partial manifest scans the full tree and adjudicates listed claims" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "listed.bin", .data = "listed bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "unlisted.bin", .data = "physical residue" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("listed bytes", &md5, .{});
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    defer map.deinit(allocator);
    try map.put(allocator, "listed.bin", 0);
    var entries = [_]manifest_mod.File{.{ .path = "listed.bin", .size = "listed bytes".len, .md5 = md5 }};
    const claims: ExpectedClaims = .{
        .expected = .{ .entries = &entries, .map = map },
        .schema = .hoyo_pkg_version_md5,
        .authority = .authoritative,
    };
    var value = try scanWithClaims(allocator, io, root, null, null, claims);
    defer deinitOwnedTree(allocator, value);
    try std.testing.expectEqual(@as(usize, 2), value.files.len);
    try std.testing.expect(value.find("unlisted.bin") != null);
    try std.testing.expect(value.find("unlisted.bin").?.claim == null);
    const listed = value.find("listed.bin").?;
    try std.testing.expectEqual(ids.VendorSchema.hoyo_pkg_version_md5, listed.claim.?.value.schema);
    try std.testing.expect(listed.observed_vendor.?.sameClaim(listed.claim.?.value));

    entries[0].md5 = @splat(0xff);
    try std.testing.expectError(
        error.AuthoritativeClaimContradiction,
        scanWithClaims(allocator, io, root, null, null, claims),
    );
    entries[0].path = "missing.bin";
    map.clearRetainingCapacity();
    try map.put(allocator, "missing.bin", 0);
    try std.testing.expectError(
        error.AuthoritativeClaimMissing,
        scanWithClaims(allocator, io, root, null, null, claims),
    );
}

test "staged inventory observes the retained membership without enumerating again" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "managed.bin", .data = "physical bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "residue.bin", .data = "unmanaged" });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    defer map.deinit(allocator);
    try map.put(allocator, "managed.bin", 0);
    var entries = [_]manifest_mod.File{.{ .path = "managed.bin", .size = 999, .md5 = @splat(0xaa) }};
    const claims: ExpectedClaims = .{
        .expected = .{ .entries = &entries, .map = map },
        .schema = .endfield_game_files_md5,
        .authority = .advisory,
    };
    var value = try inventoryWithClaims(allocator, io, root, null, null, claims, true);
    defer deinitOwnedTree(allocator, value);
    try std.testing.expectEqual(@as(usize, 1), value.files.len);
    try std.testing.expect(value.files[0].md5 == null and value.files[0].digest == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "late.bin", .data = "not inventoried" });
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: ui.Progress = .{ .io = io, .writer = &sink.writer, .label = "Reading contents" };
    try observeInventory(io, &value, claims, &progress);
    try std.testing.expect(value.find("late.bin") == null and value.find("residue.bin") == null);
    const managed = value.files[0];
    try std.testing.expect(managed.digest.?.eql(ids.Digest.of("physical bytes")));
    try std.testing.expect(!managed.observed_vendor.?.sameClaim(managed.claim.?.value));
    try std.testing.expectEqual(@as(u64, "physical bytes".len), progress.done_bytes);
    entries[0].path = "missing.bin";
    map.clearRetainingCapacity();
    try map.put(allocator, "missing.bin", 0);
    try std.testing.expectError(error.ManagedMemberMissing, inventoryWithClaims(allocator, io, root, null, null, claims, true));
}

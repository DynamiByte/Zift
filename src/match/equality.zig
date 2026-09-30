// independent hash checks for unchanged files

const std = @import("std");
const ids = @import("../core/ids.zig");
const scan = @import("../core/scan.zig");

pub const Decision = enum {
    confirmed_equal,
    different,
};

pub const Observation = struct {
    digest: ids.Digest,
    manifest_md5: [16]u8,
    observed_vendor: ?ids.VendorHash,

    pub fn fromEntry(entry: scan.Entry) Observation {
        return .{
            .digest = entry.digest,
            .manifest_md5 = entry.manifest_md5,
            .observed_vendor = entry.observed_vendor,
        };
    }
};

pub const Side = struct {
    path: []const u8,
    size: u64,
    first: ?Observation,
    claim: ?ids.VendorClaim = null,
};

// verified rereads update source.first/target.first
pub fn confirm(
    io: std.Io,
    source_dir: std.Io.Dir,
    target_dir: std.Io.Dir,
    source: *Side,
    target: *Side,
    buffer: []u8,
    reader: scan.Reader,
) !Decision {
    if (source.size != target.size) return .different;

    if (sameAuthoritativeClaim(source.claim, target.claim)) {
        // cached source hash requires an independent reread
        const carried_prior_observation = source.first != null;
        try prepareFirst(io, source_dir, source, buffer, reader);
        if (carried_prior_observation) {
            const fresh = try readSide(io, source_dir, source.*, buffer, reader);
            try requireAuthoritativeClaim(source.*, fresh);
            if (!source.first.?.digest.eql(fresh.digest)) return error.UncorroboratedEquality;
        }
        return .confirmed_equal;
    }
    if (bothAuthoritativeButDifferent(source.claim, target.claim)) return .different;

    try prepareFirst(io, source_dir, source, buffer, reader);
    try prepareFirst(io, target_dir, target, buffer, reader);
    const source_first = source.first.?;
    const target_first = target.first.?;
    if (!source_first.digest.eql(target_first.digest)) return .different;

    const source_second = try readSide(io, source_dir, source.*, buffer, reader);
    const target_second = try readSide(io, target_dir, target.*, buffer, reader);
    try requireAuthoritativeClaim(source.*, source_second);
    try requireAuthoritativeClaim(target.*, target_second);
    if (!source_first.digest.eql(source_second.digest) or
        !target_first.digest.eql(target_second.digest) or
        !source_second.digest.eql(target_second.digest))
    {
        return error.UncorroboratedEquality;
    }
    return .confirmed_equal;
}

fn sameAuthoritativeClaim(source: ?ids.VendorClaim, target: ?ids.VendorClaim) bool {
    const source_claim = source orelse return false;
    const target_claim = target orelse return false;
    return source_claim.authority == .authoritative and
        target_claim.authority == .authoritative and
        source_claim.value.sameClaim(target_claim.value);
}

fn bothAuthoritativeButDifferent(source: ?ids.VendorClaim, target: ?ids.VendorClaim) bool {
    const source_claim = source orelse return false;
    const target_claim = target orelse return false;
    return source_claim.authority == .authoritative and
        target_claim.authority == .authoritative and
        !source_claim.value.sameClaim(target_claim.value);
}

fn prepareFirst(
    io: std.Io,
    dir: std.Io.Dir,
    side: *Side,
    buffer: []u8,
    reader: scan.Reader,
) !void {
    if (side.first == null) side.first = try readSide(io, dir, side.*, buffer, reader);
    const claim = authoritativeClaim(side.claim) orelse return;
    switch (claimStatus(side.first.?, claim)) {
        .satisfied => return,
        .unavailable, .contradicts => {
            const repaired = try readSide(io, dir, side.*, buffer, reader);
            if (claimStatus(repaired, claim) != .satisfied) return error.AuthoritativeClaimContradiction;
            side.first = repaired;
        },
    }
}

fn readSide(
    io: std.Io,
    dir: std.Io.Dir,
    side: Side,
    buffer: []u8,
    reader: scan.Reader,
) !Observation {
    var entry: scan.Entry = .{ .path = side.path, .size = side.size };
    const request: ?scan.VendorRequest = if (authoritativeClaim(side.claim)) |claim| .{
        .schema = claim.schema,
        .encoding = claim.encoding,
    } else null;
    try scan.observeOne(io, dir, &entry, request, buffer, reader);
    return .fromEntry(entry);
}

fn requireAuthoritativeClaim(side: Side, observation: Observation) !void {
    const claim = authoritativeClaim(side.claim) orelse return;
    if (claimStatus(observation, claim) != .satisfied) return error.UncorroboratedEquality;
}

fn authoritativeClaim(claim: ?ids.VendorClaim) ?ids.VendorHash {
    const value = claim orelse return null;
    return if (value.authority == .authoritative) value.value else null;
}

const ClaimStatus = enum { unavailable, satisfied, contradicts };

fn claimStatus(observation: Observation, claim: ids.VendorHash) ClaimStatus {
    if (observation.observed_vendor) |observed| {
        return if (observed.sameClaim(claim)) .satisfied else .contradicts;
    }
    // unscoped MD5 only for generic manifests
    if (claim.schema == .generic_manifest_md5) {
        const observed = ids.VendorHash.init(.generic_manifest_md5, .hex, observation.manifest_md5) catch unreachable;
        return if (observed.sameClaim(claim)) .satisfied else .contradicts;
    }
    return .unavailable;
}

fn observationForBytes(bytes: []const u8, vendor: ?scan.VendorRequest) !Observation {
    var manifest_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &manifest_md5, .{});
    const observed_vendor: ?ids.VendorHash = if (vendor) |request| blk: {
        if (ids.vendorAlgorithm(request.schema) != .md5) return error.UnsupportedTestVendor;
        break :blk try ids.VendorHash.init(request.schema, request.encoding, manifest_md5);
    } else null;
    return .{
        .digest = ids.Digest.of(bytes),
        .manifest_md5 = manifest_md5,
        .observed_vendor = observed_vendor,
    };
}

fn genericManifestClaim(bytes: []const u8) !ids.VendorClaim {
    const observation = try observationForBytes(bytes, null);
    return .{
        .authority = .authoritative,
        .value = try ids.VendorHash.init(.generic_manifest_md5, .hex, observation.manifest_md5),
    };
}

test "generic keep requires two agreeing observations of both sides" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a.bin", .data = "same bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a.bin", .data = "same bytes" });
    var source_dir = try tmp.dir.openDir(io, "source", .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);
    const initial = try observationForBytes("same bytes", null);
    var source: Side = .{ .path = "a.bin", .size = 10, .first = initial };
    var target = source;
    const buffer = try allocator.alloc(u8, 64);
    defer allocator.free(buffer);
    try std.testing.expectEqual(
        Decision.confirmed_equal,
        try confirm(io, source_dir, target_dir, &source, &target, buffer, .direct),
    );
}

test "authoritative target still requires an independent Source re-read" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a.bin", .data = "actual-A" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a.bin", .data = "expected-X" });
    var source_dir = try tmp.dir.openDir(io, "source", .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);

    const claim = try genericManifestClaim("expected-X");
    const fabricated = try observationForBytes("expected-X", null);
    var source: Side = .{ .path = "a.bin", .size = 8, .first = fabricated, .claim = claim };
    var target: Side = .{ .path = "a.bin", .size = 10, .first = null, .claim = claim };
    // matching declared sizes to exercise hash checks
    target.size = source.size;
    const buffer = try allocator.alloc(u8, 64);
    defer allocator.free(buffer);
    try std.testing.expectError(
        error.UncorroboratedEquality,
        confirm(io, source_dir, target_dir, &source, &target, buffer, .direct),
    );
}

test "a fresh same-claim confirmation reads the Source itself, once" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a.bin", .data = "actual-A" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a.bin", .data = "expected-X" });
    var source_dir = try tmp.dir.openDir(io, "source", .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);

    const claim = try genericManifestClaim("expected-X");
    const buffer = try allocator.alloc(u8, 64);
    defer allocator.free(buffer);

    var source: Side = .{ .path = "a.bin", .size = 8, .first = null, .claim = claim };
    var target: Side = .{ .path = "a.bin", .size = 8, .first = null, .claim = claim };
    try std.testing.expectError(
        error.AuthoritativeClaimContradiction,
        confirm(io, source_dir, target_dir, &source, &target, buffer, .direct),
    );

    try tmp.dir.writeFile(io, .{ .sub_path = "source/b.bin", .data = "expected-X" });
    var honest_source: Side = .{ .path = "b.bin", .size = 10, .first = null, .claim = claim };
    var honest_target: Side = .{ .path = "absent.bin", .size = 10, .first = null, .claim = claim };
    try std.testing.expectEqual(
        Decision.confirmed_equal,
        try confirm(io, source_dir, target_dir, &honest_source, &honest_target, buffer, .direct),
    );
    try std.testing.expect(honest_source.first != null);
}

test "generic equality rejects a false target observation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a.bin", .data = "AAAA" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a.bin", .data = "BBBB" });
    var source_dir = try tmp.dir.openDir(io, "source", .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);

    const source_scan = try observationForBytes("AAAA", null);
    const bad_target_scan = source_scan;

    var source: Side = .{ .path = "a.bin", .size = 4, .first = source_scan };
    var target: Side = .{ .path = "a.bin", .size = 4, .first = bad_target_scan };
    const buffer = try allocator.alloc(u8, 64);
    defer allocator.free(buffer);
    try std.testing.expectError(
        error.UncorroboratedEquality,
        confirm(io, source_dir, target_dir, &source, &target, buffer, .direct),
    );
}

test "a claim contradiction is repaired before digest classification" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.createDir(io, "target", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/a.bin", .data = "truth" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target/a.bin", .data = "truth" });
    var source_dir = try tmp.dir.openDir(io, "source", .{ .access_sub_paths = true });
    defer source_dir.close(io);
    var target_dir = try tmp.dir.openDir(io, "target", .{ .access_sub_paths = true });
    defer target_dir.close(io);
    const claim = try genericManifestClaim("truth");
    var source: Side = .{
        .path = "a.bin",
        .size = 5,
        .first = try observationForBytes("wrong", null),
        .claim = claim,
    };
    var target: Side = .{ .path = "a.bin", .size = 5, .first = null, .claim = claim };
    const buffer = try allocator.alloc(u8, 64);
    defer allocator.free(buffer);
    try std.testing.expectEqual(
        Decision.confirmed_equal,
        try confirm(io, source_dir, target_dir, &source, &target, buffer, .direct),
    );
    try std.testing.expect(source.first.?.digest.eql(ids.Digest.of("truth")));
}

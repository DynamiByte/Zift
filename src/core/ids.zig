// digest identity
// vendor hashes scoped to manifest schema

const std = @import("std");

pub const Digest = struct {
    bytes: [32]u8,

    pub const zero: Digest = .{ .bytes = @splat(0) };

    pub fn of(data: []const u8) Digest {
        var result: Digest = undefined;
        std.crypto.hash.Blake3.hash(data, &result.bytes, .{});
        return result;
    }

    pub fn eql(lhs: Digest, rhs: Digest) bool {
        return std.mem.eql(u8, &lhs.bytes, &rhs.bytes);
    }

    pub fn hex(digest: Digest) [64]u8 {
        return std.fmt.bytesToHex(digest.bytes, .lower);
    }
};

pub const VendorSchema = enum(u16) {
    generic_manifest_md5 = 0,
    hoyo_pkg_version_md5 = 1,
    genshin_pkg_version_xxh64_hex = 2,
    zzz_resource_xxh64_decimal = 3,
    endfield_game_files_md5 = 4,
    wuwa_local_resources_md5 = 5,
    filename_md5_sentinel = 6,
};

pub const VendorAlgorithm = enum(u8) {
    md5,
    xxh64,
};

pub const VendorEncoding = enum(u8) {
    hex,
    unsigned_decimal,
    filename_hex,
};

pub fn vendorAlgorithm(schema: VendorSchema) VendorAlgorithm {
    return switch (schema) {
        .genshin_pkg_version_xxh64_hex, .zzz_resource_xxh64_decimal => .xxh64,
        .hoyo_pkg_version_md5,
        .generic_manifest_md5,
        .endfield_game_files_md5,
        .wuwa_local_resources_md5,
        .filename_md5_sentinel,
        => .md5,
    };
}

pub fn vendorEncodingAllowed(schema: VendorSchema, encoding: VendorEncoding) bool {
    return switch (schema) {
        .zzz_resource_xxh64_decimal => encoding == .unsigned_decimal,
        .filename_md5_sentinel => encoding == .filename_hex,
        else => encoding == .hex,
    };
}

pub fn vendorDigestLength(schema: VendorSchema) u8 {
    return switch (vendorAlgorithm(schema)) {
        .md5 => 16,
        .xxh64 => 8,
    };
}

// schema-scoped comparison, even for matching algorithms
pub const VendorHash = struct {
    schema: VendorSchema,
    algorithm: VendorAlgorithm,
    encoding: VendorEncoding,
    length: u8,
    bytes: [16]u8,

    pub fn init(schema: VendorSchema, encoding: VendorEncoding, bytes: [16]u8) error{InvalidVendorEncoding}!VendorHash {
        if (!vendorEncodingAllowed(schema, encoding)) return error.InvalidVendorEncoding;
        return .{
            .schema = schema,
            .algorithm = vendorAlgorithm(schema),
            .encoding = encoding,
            .length = vendorDigestLength(schema),
            .bytes = bytes,
        };
    }

    pub fn sameClaim(lhs: VendorHash, rhs: VendorHash) bool {
        if (lhs.schema != rhs.schema or
            lhs.algorithm != rhs.algorithm or
            lhs.encoding != rhs.encoding or
            lhs.length != rhs.length or
            lhs.length > lhs.bytes.len)
        {
            return false;
        }
        return std.mem.eql(u8, lhs.bytes[0..lhs.length], rhs.bytes[0..rhs.length]);
    }
};

pub const VerificationAlgorithm = enum(u8) {
    none = 0,
    md5 = 1,
    xxh64 = 2,
};

pub const VerificationHash = struct {
    algorithm: VerificationAlgorithm = .none,
    bytes: [16]u8 = @splat(0),

    pub const none: VerificationHash = .{};

    pub fn md5(bytes: [16]u8) VerificationHash {
        return .{ .algorithm = .md5, .bytes = bytes };
    }

    pub fn xxh64(bytes: [8]u8) VerificationHash {
        var padded: [16]u8 = @splat(0);
        @memcpy(padded[0..8], &bytes);
        return .{ .algorithm = .xxh64, .bytes = padded };
    }

    pub fn fromVendor(value: VendorHash) VerificationHash {
        return switch (value.algorithm) {
            .md5 => .md5(value.bytes),
            .xxh64 => .xxh64(value.bytes[0..8].*),
        };
    }

    pub fn isPresent(value: VerificationHash) bool {
        return value.algorithm != .none;
    }

    pub fn eql(lhs: VerificationHash, rhs: VerificationHash) bool {
        if (lhs.algorithm != rhs.algorithm) return false;
        const length: usize = switch (lhs.algorithm) {
            .none => 0,
            .md5 => 16,
            .xxh64 => 8,
        };
        return std.mem.eql(u8, lhs.bytes[0..length], rhs.bytes[0..length]);
    }
};

pub const ClaimAuthority = enum(u8) {
    advisory,
    authoritative,
};

pub const VendorClaim = struct {
    authority: ClaimAuthority,
    value: VendorHash,
};

test "vendor claims never compare across schemas or encodings" {
    const bytes: [16]u8 = @splat(7);
    const a: VendorHash = .{
        .schema = .hoyo_pkg_version_md5,
        .algorithm = .md5,
        .encoding = .hex,
        .length = 16,
        .bytes = bytes,
    };
    var b = a;
    try std.testing.expect(a.sameClaim(b));
    b.schema = .wuwa_local_resources_md5;
    try std.testing.expect(!a.sameClaim(b));
    b = a;
    b.encoding = .filename_hex;
    try std.testing.expect(!a.sameClaim(b));
}

test "vendor algorithm and representation are schema-bound" {
    try std.testing.expectEqual(VendorAlgorithm.md5, vendorAlgorithm(.hoyo_pkg_version_md5));
    try std.testing.expectEqual(VendorAlgorithm.xxh64, vendorAlgorithm(.genshin_pkg_version_xxh64_hex));
    try std.testing.expectEqual(@as(u8, 8), vendorDigestLength(.zzz_resource_xxh64_decimal));
    try std.testing.expectError(
        error.InvalidVendorEncoding,
        VendorHash.init(.zzz_resource_xxh64_decimal, .hex, @splat(0)),
    );
}

test "authoritative XXH64 can be carried as final verification identity" {
    const bytes: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var padded: [16]u8 = @splat(0);
    @memcpy(padded[0..8], &bytes);
    const vendor = try VendorHash.init(.genshin_pkg_version_xxh64_hex, .hex, padded);
    const verification = VerificationHash.fromVendor(vendor);
    try std.testing.expectEqual(VerificationAlgorithm.xxh64, verification.algorithm);
    try std.testing.expectEqualSlices(u8, &bytes, verification.bytes[0..8]);
    try std.testing.expect(verification.eql(.xxh64(bytes)));
}

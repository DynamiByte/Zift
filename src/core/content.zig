// incremental prefix hashing
const std = @import("std");
const ids = @import("ids.zig");
const scan = @import("scan.zig");

pub const pending_digest: ids.Digest = .{ .bytes = @splat(0xa5) };

pub const State = struct {
    size: u64,
    seen: u64 = 0,
    hasher: std.crypto.hash.Blake3 = std.crypto.hash.Blake3.init(.{}),
    md5: std.crypto.hash.Md5 = std.crypto.hash.Md5.init(.{}),
    xxh64: std.hash.XxHash64 = std.hash.XxHash64.init(0),
    verification: ids.VerificationHash = .none,
    digest: ?ids.Digest = null,
    verified: bool = false,
    completion_bytes: u64 = 0,

    pub fn bindVerification(self: *State, verification: ids.VerificationHash) !void {
        if (!verification.isPresent()) return;
        if (self.seen != 0 and !self.verification.eql(verification)) return error.IdentityBoundAfterObservation;
        if (self.verification.isPresent() and !self.verification.eql(verification)) return error.ConflictingContentIdentity;
        self.verification = verification;
    }

    pub fn observe(self: *State, offset: u64, bytes: []const u8) !void {
        if (offset > self.size or bytes.len > self.size - offset) return error.ContentReadOutOfRange;
        if (offset > self.seen) return;
        const end = offset + bytes.len;
        if (end > self.seen) {
            const skip: usize = @intCast(self.seen - offset);
            switch (self.verification.algorithm) {
                .none => self.hasher.update(bytes[skip..]),
                .md5 => self.md5.update(bytes[skip..]),
                .xxh64 => self.xxh64.update(bytes[skip..]),
            }
            self.seen = end;
        }
        if (self.seen == self.size and self.digest == null and !self.verified) {
            switch (self.verification.algorithm) {
                .none => {
                    var digest: ids.Digest = undefined;
                    self.hasher.final(&digest.bytes);
                    self.digest = digest;
                },
                .md5 => {
                    var hash: [16]u8 = undefined;
                    self.md5.final(&hash);
                    if (!std.mem.eql(u8, &hash, &self.verification.bytes)) return error.TargetIdentityMismatch;
                    self.verified = true;
                },
                .xxh64 => {
                    var hash: [8]u8 = undefined;
                    std.mem.writeInt(u64, &hash, self.xxh64.final(), .big);
                    if (!std.mem.eql(u8, &hash, self.verification.bytes[0..8])) return error.TargetIdentityMismatch;
                    self.verified = true;
                },
            }
        }
    }

    // same input handle through finish
    pub fn finish(self: *State, io: std.Io, file: std.Io.File, buffer: []u8, reader: scan.Reader) !?ids.Digest {
        if (buffer.len == 0) return error.InvalidBufferSize;
        if (try file.length(io) != self.size) return error.TargetSizeChanged;
        while (self.seen < self.size) {
            const offset = self.seen;
            const want: usize = @intCast(@min(@as(u64, buffer.len), self.size - offset));
            const got = try reader.read(io, file, buffer[0..want], offset);
            if (got != want) return error.ShortTargetRead;
            try self.observe(offset, buffer[0..got]);
            self.completion_bytes += got;
        }
        try self.observe(self.size, &.{});
        return self.digest;
    }
};

test "content observation ignores gaps and duplicate reads, preserves prefix" {
    const data = "abcdefghijklmnopqrstuv";
    var state: State = .{ .size = data.len };
    try state.observe(8, data[8..]);
    try std.testing.expectEqual(@as(u64, 0), state.seen);
    try state.observe(0, data[0..9]);
    try state.observe(0, data[0..9]);
    try state.observe(4, data[4..16]);
    try state.observe(16, data[16..]);
    try std.testing.expect(state.digest.?.eql(ids.Digest.of(data)));
    try std.testing.expectError(error.ContentReadOutOfRange, state.observe(22, "x"));
}

test "authoritative verification replaces a duplicate BLAKE3 observation" {
    const bytes = "manifest bytes";
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &md5, .{});
    var state: State = .{ .size = bytes.len };
    try state.bindVerification(.md5(md5));
    try state.observe(0, bytes);
    try std.testing.expect(state.verified);
    try std.testing.expect(state.digest == null);
}

test "empty content has an identity without a physical read" {
    var state: State = .{ .size = 0 };
    try state.observe(0, &.{});
    try std.testing.expect(state.digest.?.eql(ids.Digest.of("")));
}

// reusable source index; per-target search state
// matcher based on HDiffPatch; Copyright (c) 2012-2017 HouSisong, MIT
const std = @import("std");
const Thread = @import("../core/thread.zig").Thread;
const rolling = @import("rolling.zig");
const index_allocator = std.heap.page_allocator;
const read_size = 256 * 1024;
const trust_length = 16 * 1024;
pub const Input = struct {
    context: *anyopaque,
    size: u64,
    read_at: *const fn (*anyopaque, u64, []u8) anyerror!void,
};

pub const Cover = struct {
    source_offset: u64,
    target_offset: u64,
    length: u64,
};

fn read(io: std.Io, input: Input, mutex: ?*std.Io.Mutex, offset: u64, bytes: []u8) anyerror!void {
    if (offset > input.size or bytes.len > input.size - offset) return error.ReadFailed;
    if (bytes.len == 0) return;
    if (mutex) |m| m.lockUncancelable(io);
    defer if (mutex) |m| m.unlock(io);
    try input.read_at(input.context, offset, bytes);
}

const Cache = struct {
    io: std.Io,
    input: Input,
    mutex: ?*std.Io.Mutex = null,
    storage: []u8,
    capacity: usize,
    min_capacity: usize,
    backup: usize,
    block: usize,
    start: u64 = 0,
    end: u64 = 0,
    position: u64 = 0,

    fn buffer(self: *Cache) []u8 {
        return self.storage[self.storage.len - self.capacity ..];
    }
    fn data(self: *Cache) []const u8 {
        return self.buffer()[self.capacity - @as(usize, @intCast(self.end - self.position)) ..];
    }
    fn hit(self: *Cache, pos: u64, backup: usize, need: usize) bool {
        return pos <= self.end and need <= self.end - pos and pos >= self.start + backup;
    }
    fn reset(self: *Cache, pos: u64, backup: usize, need: usize) anyerror!bool {
        if (!self.hit(pos, backup, need)) {
            if (pos > self.input.size or need > self.input.size - pos) return false;
            const start = pos - @min(pos, backup);
            const len: usize = @intCast(@min(self.input.size - start, self.capacity));
            const buf = self.buffer();
            const dst = buf[self.capacity - len ..];
            if (self.end > start and self.start <= start) {
                const overlap: usize = @intCast(@min(self.end - start, len));
                const old_offset = self.capacity - @as(usize, @intCast(self.end - start));
                std.mem.copyForwards(u8, dst[0..overlap], buf[old_offset..][0..overlap]);
                try read(self.io, self.input, self.mutex, start + overlap, dst[overlap..]);
            } else if (self.start < start + len and self.end >= start + len) {
                const overlap: usize = @intCast(start + len - self.start);
                std.mem.copyBackwards(u8, dst[len - overlap ..], buf[self.capacity - @as(usize, @intCast(self.end - self.start)) ..][0..overlap]);
                try read(self.io, self.input, self.mutex, start, dst[0 .. len - overlap]);
            } else try read(self.io, self.input, self.mutex, start, dst);
            self.start = start;
            self.end = start + len;
        }
        self.position = pos;
        return true;
    }
    fn resetBlock(self: *Cache, pos: u64) anyerror!bool {
        return self.reset(pos, self.backup, self.block);
    }
    fn resetOld(self: *Cache, pos: u64) anyerror!bool {
        if (!self.hit(pos, self.backup, self.block)) {
            self.capacity = self.min_capacity;
            self.start = @max(self.start, self.end - @min(self.end, self.capacity));
        }
        return self.resetBlock(pos);
    }
    fn refill(self: *Cache) anyerror!void {
        const pos = self.position;
        const start = pos - @min(pos, self.backup);
        const len: usize = @intCast(@min(self.input.size - start, self.capacity));
        try read(self.io, self.input, self.mutex, start, self.buffer()[self.capacity - len ..]);
        self.start = start;
        self.end = start + len;
    }
};

pub const Index = struct {
    io: std.Io,
    source: Input,
    source_mutex: std.Io.Mutex = .init,
    block: usize,
    alternates: bool,
    digests: []u64,
    sorted: []u32,
    bloom: []u32,
    bloom_mask: u64,

    pub fn init(io: std.Io, source: Input, requested_block: usize, alternates: bool, threads: usize) anyerror!*Index {
        if (requested_block < 4 or requested_block > 65536 or threads == 0 or threads > 64)
            return error.InvalidArgument;
        const better = ((source.size +| 63) / 64 +| 63) / 64 * 64;
        const block: usize = @intCast(@max(4, @min(requested_block, better)));
        const count64 = if (source.size < block) 0 else std.math.divCeil(u64, source.size, block) catch return error.InvalidArgument;
        if (count64 > std.math.maxInt(u32)) return error.OutOfMemory;
        const count: usize = @intCast(count64);
        const self = try index_allocator.create(Index);
        errdefer index_allocator.destroy(self);
        const digests = try index_allocator.alloc(u64, count);
        errdefer index_allocator.free(digests);
        const sorted = try index_allocator.alloc(u32, count);
        errdefer index_allocator.free(sorted);
        const bits = std.math.ceilPowerOfTwo(usize, @max(1024, std.math.mul(usize, count, 16) catch return error.OutOfMemory)) catch return error.OutOfMemory;
        const bloom = try index_allocator.alloc(u32, bits / 32);
        errdefer index_allocator.free(bloom);
        @memset(bloom, 0);
        self.* = .{ .io = io, .source = source, .block = block, .alternates = alternates, .digests = digests, .sorted = sorted, .bloom = bloom, .bloom_mask = bits - 1 };
        if (count != 0) {
            var build: Build = .{ .index = self, .step = @max(1, (2 * read_size / threads) / block) };
            const worker_count = @min(threads, 1 + (count - 1) / build.step);
            var handles: [63]?Thread = @splat(null);
            for (handles[0 .. worker_count - 1]) |*handle|
                handle.* = Thread.spawn(.{}, Build.run, .{&build}) catch null;
            build.run();
            for (handles) |handle| if (handle) |h| h.join();
            if (build.failure) |err| return err;
        }
        for (digests, sorted, 0..) |digest, *slot, i| {
            slot.* = @intCast(i);
            for (self.bloomHashes(digest)) |bit| self.bloom[@intCast(bit >> 5)] |= @as(u32, 1) << @intCast(bit & 31);
        }
        self.sort(sorted, threads);
        return self;
    }
    pub fn deinit(self: *Index) void {
        index_allocator.free(self.bloom);
        index_allocator.free(self.sorted);
        index_allocator.free(self.digests);
        index_allocator.destroy(self);
    }
    fn blockPos(self: *const Index, i: usize) u64 {
        return @min(@as(u64, i) * self.block, self.source.size - self.block);
    }
    fn bloomHashes(self: *const Index, digest: u64) [3]u64 {
        var key = (~digest) +% (digest << 18);
        key ^= key >> 31;
        key *%= 21;
        key ^= key >> 11;
        key +%= key << 6;
        key ^= key >> 22;
        return .{ (digest ^ (digest >> 23)) & self.bloom_mask, ((~digest) +% (digest << 20)) & self.bloom_mask, key & self.bloom_mask };
    }
    fn hit(self: *const Index, digest: u64) bool {
        for (self.bloomHashes(digest)) |bit|
            if ((self.bloom[@intCast(bit >> 5)] & (@as(u32, 1) << @intCast(bit & 31))) == 0) return false;
        return true;
    }
    fn less(self: *const Index, x: u32, y: u32) bool {
        return self.lessDepth(x, y, 2 + (trust_length - 1) / self.block);
    }
    fn lessDepth(self: *const Index, x: u32, y: u32, max_depth: usize) bool {
        const available = self.digests.len - @max(x, y);
        for (0..@min(available, max_depth + 1)) |i| {
            const a = self.digests[x + i];
            const b = self.digests[y + i];
            if (a != b) return a < b;
        }
        return x > y;
    }
    fn sort(self: *Index, values: []u32, threads: usize) void {
        if (threads < 2 or values.len < 16384) {
            std.sort.pdq(u32, values, self, less);
            return;
        }
        const pivot = values[values.len / 2];
        var a: usize = 0;
        var b = values.len;
        while (a < b) {
            if (self.less(values[a], pivot)) a += 1 else {
                b -= 1;
                std.mem.swap(u32, &values[a], &values[b]);
            }
        }
        if (a == 0 or a == values.len) {
            std.sort.pdq(u32, values, self, less);
            return;
        }
        const worker = Thread.spawn(.{}, sort, .{ self, values[0..a], threads / 2 }) catch {
            self.sort(values[0..a], 1);
            self.sort(values[a..], threads - threads / 2);
            return;
        };
        self.sort(values[a..], threads - threads / 2);
        worker.join();
    }
    const Build = struct {
        index: *Index,
        step: usize,
        next: std.atomic.Value(usize) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        failure: ?anyerror = null,

        fn fail(self: *Build, err: anyerror) void {
            // first writer only; failure read after all joins
            if (!self.failed.swap(true, .acq_rel)) self.failure = err;
        }

        fn run(self: *Build) void {
            const index = self.index;
            const bytes = index_allocator.alloc(u8, self.step * index.block) catch |err| {
                self.fail(err);
                return;
            };
            defer index_allocator.free(bytes);
            while (!self.failed.load(.acquire)) {
                const begin = self.next.fetchAdd(self.step, .monotonic);
                if (begin >= index.digests.len) break;
                const end = @min(index.digests.len, begin + self.step);
                const pos = index.blockPos(begin);
                const last_pos = index.blockPos(end - 1);
                const len: usize = @intCast(last_pos + index.block - pos);
                read(index.io, index.source, &index.source_mutex, pos, bytes[0..len]) catch |err| {
                    self.fail(err);
                    break;
                };
                for (begin..end) |i| {
                    const relative: usize = @intCast(index.blockPos(i) - pos);
                    index.digests[i] = rolling.start(bytes[relative..][0..index.block]);
                }
            }
        }
    };

    fn range(self: *const Index, values: []const u32, digest: u64, depth: usize) []const u32 {
        var low: usize = 0;
        var high = values.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const i: usize = @as(usize, values[mid]) + depth;
            if (i >= self.digests.len or self.digests[i] < digest) low = mid + 1 else high = mid;
        }
        const begin = low;
        high = values.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const i: usize = @as(usize, values[mid]) + depth;
            if (i < self.digests.len and self.digests[i] > digest) high = mid else low = mid + 1;
        }
        return values[begin..low];
    }

    fn matchLength(self: *Index, old: *Cache, new: *Cache, source_offset: u64, last: Cover) anyerror!?Cover {
        const target_offset = new.position;
        if (!(try old.resetOld(source_offset)) or !std.mem.eql(u8, old.data()[0..self.block], new.data()[0..self.block])) return null;
        var before: usize = 0;
        const limit = @min(@min(source_offset - old.start, target_offset - new.start), target_offset - (last.target_offset + last.length));
        const oldbuf = old.buffer();
        const newbuf = new.buffer();
        const oldoff = old.capacity - @as(usize, @intCast(old.end - source_offset));
        const newoff = new.capacity - @as(usize, @intCast(new.end - target_offset));
        while (before < limit and oldbuf[oldoff - before - 1] == newbuf[newoff - before - 1]) before += 1;
        var after: u64 = self.block;
        while (try old.reset(source_offset + after, 0, 1)) {
            if (!(try new.reset(target_offset + after, 0, 1))) break;
            const a = old.data();
            const b = new.data();
            const len = @min(a.len, b.len);
            var equal: usize = 0;
            while (equal < len and a[equal] == b[equal]) : (equal += 1) {}
            after += equal;
            if (equal != len) break;
            if (len == a.len) old.capacity = @min(old.storage.len, old.capacity * 2);
        }
        return .{ .source_offset = source_offset - before, .target_offset = target_offset - before, .length = before + after };
    }
    pub fn search(self: *Index, allocator: std.mem.Allocator, target: Input) anyerror![]Cover {
        if (self.digests.len == 0 or target.size < self.block) return allocator.alloc(Cover, 0);
        const backup = @max(self.block, 256);
        const new_capacity = std.math.divCeil(usize, self.block * 2 + backup, read_size) catch unreachable;
        const old_capacity = std.math.divCeil(usize, self.block + backup, read_size) catch unreachable;
        const scratch = try index_allocator.alloc(u8, (new_capacity + old_capacity) * read_size);
        defer index_allocator.free(scratch);
        var new: Cache = .{ .io = self.io, .input = target, .storage = scratch[0 .. new_capacity * read_size], .capacity = new_capacity * read_size, .min_capacity = new_capacity * read_size, .backup = backup, .block = self.block };
        const old_min = (std.math.divCeil(usize, self.block + backup, 4096) catch unreachable) * 4096;
        var old: Cache = .{ .io = self.io, .input = self.source, .mutex = &self.source_mutex, .storage = scratch[new_capacity * read_size ..], .capacity = old_min, .min_capacity = old_min, .backup = backup, .block = self.block };
        var covers: std.ArrayList(Cover) = .empty;
        errdefer covers.deinit(allocator);
        var last: Cover = .{ .source_offset = 0, .target_offset = 0, .length = 0 };
        _ = try new.resetBlock(0);
        var digest = rolling.start(new.data()[0..self.block]);
        while (true) {
            const pos = new.position;
            var next = pos + 1;
            if (self.hit(digest)) {
                var matches = self.range(self.sorted, digest, 0);
                if (matches.len != 0) {
                    var best: ?usize = if (matches.len == 1) 0 else null;
                    var depth: usize = 1;
                    const max_depth = @min((trust_length + self.block - 1) / self.block, new.data().len / self.block);
                    if (matches.len > 1) {
                        if (new.data().len * 2 < new.capacity) try new.refill();
                        while (depth < max_depth and matches.len > 1) : (depth += 1) {
                            const narrowed = self.range(matches, rolling.start(new.data()[depth * self.block ..][0..self.block]), depth);
                            if (narrowed.len == 0) break;
                            if (narrowed.len == 1) {
                                best = @intCast((@intFromPtr(narrowed.ptr) - @intFromPtr(matches.ptr)) / @sizeOf(u32));
                                break;
                            }
                            matches = narrowed;
                        }
                    }
                    const link_pos = pos +% last.source_offset -% last.target_offset;
                    const link_index: usize = @intCast(@min((link_pos +| (self.block - 1)) / self.block, self.digests.len - 1));
                    if (best == null) {
                        var attempt: usize = 1;
                        while (attempt <= @min(matches.len * 2 + 1, 64)) : (attempt += 1) {
                            const distance = attempt / 2;
                            const candidate: u32 = @intCast(if (attempt & 1 != 0) blk: {
                                if (link_index < distance) continue;
                                break :blk link_index - distance;
                            } else blk: {
                                if (link_index + distance >= self.digests.len) continue;
                                break :blk link_index + distance;
                            });
                            var low: usize = 0;
                            var high = matches.len;
                            while (low < high) {
                                const mid = low + (high - low) / 2;
                                if (self.lessDepth(matches[mid], candidate, max_depth)) low = mid + 1 else high = mid;
                            }
                            const begin = low;
                            high = matches.len;
                            while (low < high) {
                                const mid = low + (high - low) / 2;
                                if (self.lessDepth(candidate, matches[mid], max_depth)) high = mid else low = mid + 1;
                            }
                            if (begin != low) {
                                best = begin + (low - begin) / 2;
                                for (best.?..low) |i| if (matches[i] == candidate) {
                                    best = i;
                                    break;
                                };
                                break;
                            }
                        }
                    }
                    if (best == null) {
                        var nearest: u64 = std.math.maxInt(u64);
                        for (matches[0..@min(matches.len, 65536)], 0..) |candidate, i| {
                            const distance = if (candidate < link_index) link_index - candidate else candidate - link_index;
                            if (distance < nearest) {
                                nearest = distance;
                                best = i;
                            }
                        }
                    }
                    var chosen: ?Cover = null;
                    var alternatives: [5]Cover = undefined;
                    var alt_count: usize = 0;
                    const center = best.?;
                    var attempt: usize = 1;
                    while (attempt <= @min(matches.len * 2 + 1, 5)) : (attempt += 1) {
                        const distance = attempt / 2;
                        const candidate = if (attempt & 1 != 0) blk: {
                            if (center < distance) continue;
                            break :blk center - distance;
                        } else blk: {
                            if (center + distance >= matches.len) continue;
                            break :blk center + distance;
                        };
                        if (attempt > 1) _ = try new.resetBlock(pos);
                        if (try self.matchLength(&old, &new, self.blockPos(matches[candidate]), last)) |cover| {
                            if (self.alternates and cover.length >= 16) {
                                alternatives[alt_count] = cover;
                                alt_count += 1;
                            }
                            if (chosen == null or cover.length > chosen.?.length) {
                                chosen = cover;
                                if (cover.length >= depth * self.block) break;
                            }
                        }
                    }
                    if (chosen) |initial| {
                        var cover = initial;
                        if (last.length != 0) {
                            const link = cover.target_offset +% last.source_offset -% last.target_offset;
                            if (link != cover.source_offset) {
                                _ = try new.resetBlock(cover.target_offset);
                                if (try self.matchLength(&old, &new, link, last)) |linked|
                                    if (linked.length >= 16 and linked.length + cost(cover.source_offset, last) >= cover.length + cost(linked.source_offset, last)) {
                                        cover = linked;
                                    };
                            }
                        }
                        if (cover.length >= 16) {
                            try covers.append(allocator, cover);
                            for (alternatives[0..alt_count]) |alt|
                                if (alt.source_offset != cover.source_offset or alt.target_offset != cover.target_offset) try covers.append(allocator, alt);
                            last = cover;
                            next = cover.target_offset + cover.length;
                        }
                    }
                    if (!(try new.resetBlock(next))) break;
                    digest = rolling.start(new.data()[0..self.block]);
                    continue;
                }
            }
            if (new.data().len > self.block) {
                digest = rolling.roll(digest, self.block, new.data()[0], new.data()[self.block]);
                new.position += 1;
            } else {
                if (!(try new.resetBlock(next))) break;
                digest = rolling.start(new.data()[0..self.block]);
            }
        }
        return covers.toOwnedSlice(allocator);
    }
};

fn cost(pos: u64, last: Cover) u64 {
    const end = last.source_offset + last.length;
    var value = (if (pos < end) end - pos else pos - end) *% 2;
    var bytes: u64 = 1;
    while (value >= 128) : (value >>= 7) bytes += 1;
    return bytes;
}

const MatcherTestInput = struct {
    bytes: []const u8,
    fail: bool = false,

    fn read(context: *anyopaque, offset: u64, destination: []u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.fail) return error.InjectedReadFailure;
        if (offset > self.bytes.len or destination.len > self.bytes.len - offset) return error.ReadOutOfBounds;
        @memcpy(destination, self.bytes[@intCast(offset)..][0..destination.len]);
    }

    fn input(self: *@This()) Input {
        return .{ .context = self, .size = self.bytes.len, .read_at = MatcherTestInput.read };
    }
};

fn matcherTestRun(allocator: std.mem.Allocator, source: *Input, target: *Input, threads: usize) ![]Cover {
    const index = try Index.init(std.testing.io, source.*, 256, false, threads);
    defer index.deinit();
    return index.search(allocator, target.*);
}

const ConcurrentMatcherTestJob = struct {
    index: *Index,
    target: *Input,
    covers: []Cover = &.{},
    result: ?anyerror = null,

    fn run(self: *@This()) void {
        self.covers = self.index.search(std.heap.smp_allocator, self.target.*) catch |err| {
            self.result = err;
            return;
        };
    }
};

test "parallel reusable matcher index is byte deterministic" {
    const allocator = std.testing.allocator;
    const source_bytes = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(source_bytes);
    var random = std.Random.DefaultPrng.init(0x6d617463686572);
    random.random().bytes(source_bytes);
    const target_bytes = try allocator.dupe(u8, source_bytes[512 * 1024 .. 3 * 1024 * 1024]);
    defer allocator.free(target_bytes);
    @memset(target_bytes[700 * 1024 .. 704 * 1024], 0x5a);

    var source_memory: MatcherTestInput = .{ .bytes = source_bytes };
    var target_memory: MatcherTestInput = .{ .bytes = target_bytes };
    var source = source_memory.input();
    var target = target_memory.input();
    const serial = try matcherTestRun(allocator, &source, &target, 1);
    defer allocator.free(serial);
    const parallel = try matcherTestRun(allocator, &source, &target, 8);
    defer allocator.free(parallel);
    try std.testing.expect(serial.len != 0);
    try std.testing.expectEqualSlices(Cover, serial, parallel);
}

test "small matcher indexes preserve covers at maximum worker count" {
    const allocator = std.testing.allocator;
    var bytes: [4096]u8 = undefined;
    var random = std.Random.DefaultPrng.init(0x736d616c6c);
    random.random().bytes(&bytes);
    var source: MatcherTestInput = .{ .bytes = &bytes };
    var target: MatcherTestInput = .{ .bytes = bytes[1024..3072] };
    const serial_index = try Index.init(std.testing.io, source.input(), 256, false, 1);
    defer serial_index.deinit();
    const parallel_index = try Index.init(std.testing.io, source.input(), 256, false, 64);
    defer parallel_index.deinit();
    const serial = try serial_index.search(allocator, target.input());
    defer allocator.free(serial);
    const parallel = try parallel_index.search(allocator, target.input());
    defer allocator.free(parallel);
    try std.testing.expectEqualSlices(Cover, serial, parallel);
    try std.testing.expectEqual(@as(usize, 1), parallel.len);
    try std.testing.expectEqual(@as(u64, 1024), parallel[0].source_offset);
    try std.testing.expectEqual(@as(u64, 2048), parallel[0].length);
}

test "one reusable matcher index serves concurrent Target searches" {
    const allocator = std.testing.allocator;
    const source_bytes = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(source_bytes);
    var random = std.Random.DefaultPrng.init(0x636f6e6375727265);
    random.random().bytes(source_bytes);
    const target_bytes = source_bytes[1024 * 1024 .. 3 * 1024 * 1024];
    var source_memory: MatcherTestInput = .{ .bytes = source_bytes };
    var target_memory: MatcherTestInput = .{ .bytes = target_bytes };
    var source = source_memory.input();
    var target = target_memory.input();
    const expected = try matcherTestRun(allocator, &source, &target, 1);
    defer allocator.free(expected);

    const index = try Index.init(std.testing.io, source, 256, false, 8);
    defer index.deinit();
    var jobs: [8]ConcurrentMatcherTestJob = undefined;
    var threads: [jobs.len]Thread = undefined;
    for (&jobs, 0..) |*job, position| {
        job.* = .{ .index = index, .target = &target };
        threads[position] = try Thread.spawn(.{}, ConcurrentMatcherTestJob.run, .{job});
    }
    for (threads) |thread| thread.join();
    defer for (jobs) |job| std.heap.smp_allocator.free(job.covers);
    for (jobs) |job| {
        try std.testing.expectEqual(@as(?anyerror, null), job.result);
        try std.testing.expectEqualSlices(Cover, expected, job.covers);
    }
}

test "parallel matcher preserves the source callback error" {
    var source_memory: MatcherTestInput = .{ .bytes = &.{}, .fail = true };
    var source = source_memory.input();
    source.size = 4 * 1024 * 1024;
    try std.testing.expectError(error.InjectedReadFailure, Index.init(std.testing.io, source, 256, false, 8));
}

test "matcher preserves target and allocation errors and permits retry" {
    const allocator = std.testing.allocator;
    const bytes: [16384]u8 = @splat(0x35);
    var source_memory: MatcherTestInput = .{ .bytes = &bytes };
    var target_memory: MatcherTestInput = .{ .bytes = &bytes, .fail = true };
    const index = try Index.init(std.testing.io, source_memory.input(), 256, false, 2);
    defer index.deinit();
    try std.testing.expectError(error.InjectedReadFailure, index.search(allocator, target_memory.input()));
    target_memory.fail = false;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, index.search(failing.allocator(), target_memory.input()));
    const covers = try index.search(allocator, target_memory.input());
    defer allocator.free(covers);
    try std.testing.expect(covers.len > 0);
}

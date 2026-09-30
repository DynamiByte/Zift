const std = @import("std");
const fs = @import("../core/fs.zig");
const match_index = @import("../match/index.zig");
const hooks = @import("hooks.zig");
const zstd = @import("../compression/zstd.zig");
const encoding = @import("encoding.zig");

pub fn match(allocator: std.mem.Allocator, source: *Input, target: *Input, block: usize) ![]match_index.Cover {
    const index = try match_index.Index.init(source.io, source.matchInput(), block, false, 1);
    defer index.deinit();
    return index.search(allocator, target.matchInput());
}

pub fn copy(input: *const Input, sink: *Sink, offset: u64, length: u64, buffer: []u8) !void {
    if (sink.mode == .count) {
        sink.raw_size = try std.math.add(u64, sink.raw_size, length);
        return;
    }
    var done: u64 = 0;
    while (done < length) {
        const take: usize = @intCast(@min(buffer.len, length - done));
        try input.read(offset + done, buffer[0..take]);
        try sink.write(buffer[0..take]);
        done += take;
    }
}

pub const FilePart = struct {
    file: std.Io.File,
    size: u64,
};

pub const Input = struct {
    io: std.Io,
    parts: []const FilePart,
    size: u64,
    progress: ?hooks.ProgressHook = null,

    pub fn init(io: std.Io, parts: []const FilePart) !Input {
        var size: u64 = 0;
        for (parts) |part| {
            const stat = try part.file.stat(io);
            if (stat.kind != .file or stat.size != part.size) return error.InvalidInput;
            size = try std.math.add(u64, size, part.size);
        }
        return .{ .io = io, .parts = parts, .size = size };
    }
    pub fn read(self: *const Input, offset: u64, bytes: []u8) !void {
        if (offset > self.size or bytes.len > self.size - offset) return error.OutOfBounds;
        var start: u64 = 0;
        var pos = offset;
        var done: usize = 0;
        for (self.parts) |part| {
            const end = start + part.size;
            if (pos < end and done < bytes.len) {
                const take: usize = @intCast(@min(bytes.len - done, end - pos));
                const file = part.file;
                if (try fs.readAllAt(self.io, file, bytes[done..][0..take], pos - start) != take) return error.ShortRead;
                pos += take;
                done += take;
                if (self.progress) |progress| if (!try progress.call(take)) return error.Interrupted;
            }
            start = end;
        }
        if (done != bytes.len) return error.ShortRead;
    }
    fn callback(context: *anyopaque, offset: u64, bytes: []u8) !void {
        const self: *Input = @ptrCast(@alignCast(context));
        try self.read(offset, bytes);
    }
    pub fn matchInput(self: *Input) match_index.Input {
        return .{ .size = self.size, .context = self, .read_at = callback };
    }
};
pub const Output = struct {
    io: std.Io,
    parts: []const FilePart = &.{},
    observer: ?hooks.OutputHook = null,
    progress: ?hooks.ProgressHook = null,

    pub fn emit(self: Output, offset: u64, bytes: []const u8) !void {
        if (self.parts.len != 0) {
            var start: u64 = 0;
            var pos = offset;
            var done: usize = 0;
            for (self.parts) |part| {
                const end = try std.math.add(u64, start, part.size);
                if (pos < end and done < bytes.len) {
                    const take: usize = @intCast(@min(bytes.len - done, end - pos));
                    const file = part.file;
                    try file.writePositionalAll(self.io, bytes[done..][0..take], pos - start);
                    pos += take;
                    done += take;
                }
                start = end;
            }
            if (done != bytes.len) return error.OutputOverflow;
        }
        if (self.observer) |observer| if (!try observer.call(offset, bytes)) return error.Interrupted;
        if (self.progress) |progress| if (!try progress.call(bytes.len)) return error.Interrupted;
    }
};
pub const Compare = struct {
    target: *const Input,

    pub fn call(context: ?*anyopaque, offset: u64, bytes: []const u8) !bool {
        const self: *Compare = @ptrCast(@alignCast(context.?));
        var buffer: [64 * 1024]u8 = undefined;
        var done: usize = 0;
        while (done < bytes.len) {
            const take = @min(bytes.len - done, buffer.len);
            try self.target.read(offset + done, buffer[0..take]);
            if (!std.mem.eql(u8, buffer[0..take], bytes[done..][0..take])) return false;
            done += take;
        }
        return true;
    }
};

pub const Sink = struct {
    io: std.Io,
    mode: union(enum) { count, file: std.Io.File, zstd: *zstd.Encoder },
    position: u64,
    raw_size: u64 = 0,

    pub fn write(sink: *Sink, bytes: []const u8) !void {
        switch (sink.mode) {
            .count => {},
            .zstd => |encoder| try encoder.write(bytes),
            .file => |file| {
                try file.writePositionalAll(sink.io, bytes, sink.position);
                sink.position += bytes.len;
            },
        }
        sink.raw_size = try std.math.add(u64, sink.raw_size, bytes.len);
    }
    pub fn uint(sink: *Sink, value: u64, tag: u8, tag_bits: u3) !void {
        var storage: [encoding.max_hdiff_pack_uint_bytes]u8 = undefined;
        try sink.write(encoding.encodeUIntTagged(value, tag, tag_bits, &storage));
    }
};

pub const Written = struct { raw: u64, compressed: u64, end: u64 };

pub fn writeStream(io: std.Io, file: std.Io.File, start: u64, compression_level: ?c_int, emitter: anytype) !Written {
    var sink: Sink = .{ .io = io, .mode = .count, .position = start };
    if (compression_level) |level| {
        // sized frames keep decoder history within the payload budget
        try emitter.emit(&sink);
        if (sink.raw_size == 0) return .{ .raw = 0, .compressed = 0, .end = start };
        var encoder = try zstd.Encoder.init(io, file, start, level, 0, sink.raw_size);
        defer encoder.deinit();
        sink = .{ .io = io, .mode = .{ .zstd = &encoder }, .position = start };
        try emitter.emit(&sink);
        try encoder.finish();
        const compressed = encoder.position - start;
        if (compressed < sink.raw_size) return .{ .raw = sink.raw_size, .compressed = compressed, .end = encoder.position };
        // stored fallback: bounded input replay, no second body retained
    }
    sink = .{ .io = io, .mode = .{ .file = file }, .position = start };
    try emitter.emit(&sink);
    return .{ .raw = sink.raw_size, .compressed = 0, .end = sink.position };
}

pub fn headerSize(magic: []const u8, compress: bool, fields: usize) u64 {
    return magic.len + @as(usize, if (compress) 4 else 0) + 1 + fields * encoding.max_hdiff_pack_uint_bytes;
}

pub fn writeHeader(io: std.Io, file: std.Io.File, offset: u64, magic: []const u8, compress: bool, fields: []const u64) !void {
    var header: [256]u8 = undefined;
    var position: usize = 0;
    @memcpy(header[0..magic.len], magic);
    position += magic.len;
    if (compress) {
        @memcpy(header[position..][0..4], "zstd");
        position += 4;
    }
    header[position] = 0;
    position += 1;
    for (fields) |value| {
        var storage: [encoding.max_hdiff_pack_uint_bytes]u8 = undefined;
        const encoded = encoding.encodeUIntTagged(value, 0, 0, &storage);
        const padding = encoding.max_hdiff_pack_uint_bytes - encoded.len;
        @memset(header[position..][0..padding], 0x80);
        @memcpy(header[position + padding ..][0..encoded.len], encoded);
        position += encoding.max_hdiff_pack_uint_bytes;
    }
    try file.writePositionalAll(io, header[0..position], offset);
}

// Small terminal formatting and progress helpers
const std = @import("std");

pub fn bytes(buf: []u8, value: u64) ![]const u8 {
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var unit_index: usize = 0;
    var divisor: u128 = 1;
    while (unit_index + 1 < units.len and @as(u128, value) >= divisor * 1024) {
        divisor *= 1024;
        unit_index += 1;
    }

    if (unit_index == 0) {
        return std.fmt.bufPrint(buf, "{d} {s}", .{ value, units[unit_index] });
    }

    const scaled = (@as(u128, value) * 100) / divisor;
    return std.fmt.bufPrint(buf, "{d}.{d:0>2} {s}", .{
        scaled / 100,
        scaled % 100,
        units[unit_index],
    });
}

pub fn printSize(w: *std.Io.Writer, label: []const u8, value: u64) !void {
    var buf: [64]u8 = undefined;
    try w.print("{s}: {s}\n", .{ label, try bytes(&buf, value) });
}

pub const Progress = struct {
    io: std.Io,
    writer: *std.Io.Writer,
    label: []const u8,
    total_bytes: u64,
    total_files: usize,
    show_speed: bool = false,
    done_bytes: u64 = 0,
    done_files: usize = 0,
    last_draw_bytes: u64 = 0,
    last_draw_files: usize = 0,
    start_ns: i96 = 0,
    started: bool = false,

    const bar_width = 28;
    const label_width = 11;
    const redraw_bytes = 8 * 1024 * 1024;

    pub fn start(self: *Progress) !void {
        self.start_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.started = true;
        try self.draw();
    }

    pub fn addBytes(self: *Progress, count: u64) !void {
        self.done_bytes += count;
        if (!self.started) return;
        if (self.total_bytes > 0 and self.done_bytes -| self.last_draw_bytes >= redraw_bytes) {
            try self.draw();
        }
    }

    pub fn finishFile(self: *Progress) !void {
        self.done_files += 1;
        if (!self.started) return;
        const file_step = self.fileStep();
        const at_end = self.total_files != 0 and self.done_files >= self.total_files;
        if (at_end or self.done_files -| self.last_draw_files >= file_step) {
            try self.draw();
        }
    }

    pub fn finish(self: *Progress) !void {
        const needs_final_draw = self.done_bytes != self.total_bytes or self.done_files != self.total_files;
        if (self.total_bytes > 0) self.done_bytes = self.total_bytes;
        if (self.total_files > 0) self.done_files = self.total_files;
        if (needs_final_draw or !self.started) try self.draw();
        try self.writer.writeByte('\n');
        try self.writer.flush();
    }

    fn draw(self: *Progress) !void {
        self.last_draw_bytes = self.done_bytes;
        self.last_draw_files = self.done_files;

        const percent_u128: u128 = if (self.total_bytes > 0)
            @min(100, (@as(u128, @min(self.done_bytes, self.total_bytes)) * 100) / self.total_bytes)
        else if (self.total_files > 0)
            @min(100, (@as(u128, @min(self.done_files, self.total_files)) * 100) / self.total_files)
        else
            100;
        const percent: usize = @intCast(percent_u128);
        const filled = (percent * bar_width) / 100;

        var bar: [bar_width]u8 = undefined;
        for (&bar, 0..) |*ch, i| {
            ch.* = if (i < filled) '#' else '-';
        }

        var done_buf: [64]u8 = undefined;
        var total_buf: [64]u8 = undefined;
        try self.writer.writeByte('\r');
        try self.writeLabel();
        if (self.total_bytes > 0) {
            try self.writer.print("[{s}] {d: >3}%  {s}/{s}  files {d}/{d}", .{
                &bar,
                percent,
                try bytes(&done_buf, @min(self.done_bytes, self.total_bytes)),
                try bytes(&total_buf, self.total_bytes),
                @min(self.done_files, self.total_files),
                self.total_files,
            });
            if (self.show_speed) {
                var speed_buf: [64]u8 = undefined;
                try self.writer.print("  {s}", .{try self.speed(&speed_buf)});
            }
            try self.writer.writeAll("        ");
        } else {
            try self.writer.print("[{s}] {d: >3}%  files {d}/{d}        ", .{
                &bar,
                percent,
                @min(self.done_files, self.total_files),
                self.total_files,
            });
        }
        try self.writer.flush();
    }

    fn writeLabel(self: *Progress) !void {
        try self.writer.print("{s}:", .{self.label});
        const used = self.label.len + 1;
        const spaces = if (used < label_width) label_width - used else 1;
        for (0..spaces) |_| try self.writer.writeByte(' ');
    }

    fn speed(self: *Progress, buf: []u8) ![]const u8 {
        if (self.done_bytes == 0 or self.start_ns == 0) return "0 B/s";

        const now_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const elapsed_ns_signed = @max(@as(i96, 1), now_ns - self.start_ns);
        const elapsed_ns: u128 = @intCast(elapsed_ns_signed);
        const bytes_per_second: u64 = @intCast(@min(
            std.math.maxInt(u64),
            (@as(u128, self.done_bytes) * std.time.ns_per_s) / elapsed_ns,
        ));
        return bytesPerSecond(buf, bytes_per_second);
    }

    fn fileStep(self: Progress) usize {
        if (self.total_files <= 100) return 1;
        return @max(1, self.total_files / 100);
    }
};

fn bytesPerSecond(buf: []u8, value: u64) ![]const u8 {
    const units = [_][]const u8{ "B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s" };
    var unit_index: usize = 0;
    var divisor: u128 = 1;
    while (unit_index + 1 < units.len and @as(u128, value) >= divisor * 1024) {
        divisor *= 1024;
        unit_index += 1;
    }

    if (unit_index == 0) {
        return std.fmt.bufPrint(buf, "{d} {s}", .{ value, units[unit_index] });
    }

    const scaled = (@as(u128, value) * 100) / divisor;
    return std.fmt.bufPrint(buf, "{d}.{d:0>2} {s}", .{
        scaled / 100,
        scaled % 100,
        units[unit_index],
    });
}

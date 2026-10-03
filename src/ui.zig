const std = @import("std");
const builtin = @import("builtin");
const interrupt = @import("interrupt.zig");
const Thread = std.Thread;
const scan = @import("core/scan.zig");

const StreamState = struct {
    writer: ?*std.Io.Writer = null,
    mode: std.Io.Terminal.Mode = .no_color,
    live: bool = false,
    file: ?std.Io.File = null,
};

var streams: [2]StreamState = .{ .{}, .{} };

pub const completed_with_errors = "Completed with errors (shown above).";
const writeFileError = fileError;

pub fn initStream(io: std.Io, file: std.Io.File, writer: *std.Io.Writer, no_color: bool) void {
    const state = for (&streams) |*candidate| {
        if (candidate.writer == null or candidate.writer == writer) break candidate;
    } else return;
    state.writer = writer;
    state.file = file;
    state.live = file.isTty(io) catch false;
    state.mode = std.Io.Terminal.Mode.detect(io, file, no_color, false) catch .no_color;
    if (state.live) file.enableAnsiEscapeCodes(io) catch {
        state.live = false;
    };
}

fn streamState(w: *std.Io.Writer) StreamState {
    for (streams) |state| if (state.writer == w) return state;
    return .{};
}

fn liveProgress(w: *std.Io.Writer) bool {
    return streamState(w).live;
}

fn setColor(w: *std.Io.Writer, color: std.Io.Terminal.Color) !void {
    var terminal: std.Io.Terminal = .{ .writer = w, .mode = streamState(w).mode };
    try terminal.setColor(color);
}

pub fn success(w: *std.Io.Writer) !void {
    try setColor(w, .green);
}
pub fn failure(w: *std.Io.Writer) !void {
    try setColor(w, .red);
}
pub fn reset(w: *std.Io.Writer) !void {
    try setColor(w, .reset);
}

pub fn warning(w: *std.Io.Writer) !void {
    try setColor(w, .yellow);
}

pub fn writeOption(w: *std.Io.Writer, number: []const u8, text: []const u8) !void {
    try w.writeAll("    ");
    try w.writeAll(number);
    try w.writeAll(". ");
    try w.writeAll(text);
    try w.writeByte('\n');
}

pub fn writeHeading(w: *std.Io.Writer, text: []const u8) !void {
    try setColor(w, .bold);
    try w.writeAll(text);
    try reset(w);
}

pub fn writeField(w: *std.Io.Writer, label: []const u8, value: []const u8) !void {
    try w.writeAll(label);
    try w.writeByte(' ');
    try w.writeAll(value);
    try w.writeByte('\n');
}

pub fn writeDeltaField(w: *std.Io.Writer, source: []const u8, target: []const u8) !void {
    try w.writeAll("    Delta: ");
    try w.writeAll(source);
    try w.writeAll(" -> ");
    try w.writeAll(target);
    try w.writeByte('\n');
}

pub fn writeCount(w: *std.Io.Writer, label: []const u8, count: anytype) !void {
    try w.writeAll(label);
    try w.writeByte(' ');
    try w.print("{d}", .{count});
    try w.writeByte('\n');
}

pub fn writeCountSize(w: *std.Io.Writer, label: []const u8, count: usize, byte_count: u64) !void {
    var buf: [64]u8 = undefined;
    try w.writeAll(label);
    try w.writeByte(' ');
    try w.print("{d}", .{count});
    try w.writeAll(" (");
    try w.writeAll(try bytes(&buf, byte_count));
    try w.writeAll(")\n");
}

pub fn writePromptLabel(w: *std.Io.Writer, label: []const u8) !void {
    try setColor(w, .bold);
    try w.writeAll(label);
    try reset(w);
}

pub fn writeChoice(w: *std.Io.Writer, value: []const u8) !void {
    try w.writeByte('[');
    try w.writeAll(value);
    try w.writeByte(']');
}

pub fn writePromptDefault(w: *std.Io.Writer, value: []const u8) !void {
    try w.writeByte('(');
    try w.writeAll(value);
    try w.writeByte(')');
}

pub fn writeErrorPrefix(w: *std.Io.Writer) !void {
    try failure(w);
    try w.writeAll("Error:");
    try reset(w);
}

pub fn complete(w: *std.Io.Writer, had_errors: bool) !void {
    if (had_errors) {
        try writeWarningLine(w, completed_with_errors);
        return error.CompletedWithErrors;
    }
    try writeSuccessLine(w, "Complete!");
}

pub fn fileError(w: *std.Io.Writer, action: []const u8, path: []const u8, err: anyerror) !void {
    try writeErrorPrefix(w);
    try w.print(" {s}: {s} ({s})\n", .{ action, path, @errorName(err) });
}

pub fn writeSuccessLabel(w: *std.Io.Writer, label: []const u8) !void {
    try success(w);
    try w.writeAll(label);
    try reset(w);
}

pub fn writeWarningLine(w: *std.Io.Writer, text: []const u8) !void {
    try warning(w);
    try w.writeAll(text);
    try reset(w);
    try w.writeByte('\n');
}

pub fn writeSuccessLine(w: *std.Io.Writer, text: []const u8) !void {
    try success(w);
    try w.writeAll(text);
    try reset(w);
    try w.writeByte('\n');
}

pub fn bytes(buf: []u8, value: u64) ![]const u8 {
    return formatBytes(buf, value, &.{ "B", "KiB", "MiB", "GiB", "TiB" });
}

pub const Progress = struct {
    io: std.Io,
    writer: *std.Io.Writer,
    label: []const u8,
    label_columns: usize = 13,
    byte_columns: ?ByteColumns = null,
    total_bytes: u64 = 0,
    total_files: usize = 0,
    show_speed: bool = false,
    indeterminate: bool = false,
    nested: bool = false,
    item_label: ?[]const u8 = "files",
    done_bytes: u64 = 0,
    done_files: usize = 0,
    activity_bytes: u64 = 0,
    last_draw_bytes: u64 = 0,
    last_draw_files: usize = 0,
    start_ns: i96 = 0,
    last_pulse_ns: i96 = 0,
    started: bool = false,
    operation: ?*Operation = null,
    committed_bytes: u64 = 0,

    const min_bar_width = 10;
    const max_bar_width = 25;
    const redraw_bytes = 8 * 1024 * 1024;
    const pulse_ns = 100 * std.time.ns_per_ms;
    const blink_ns = 500 * std.time.ns_per_ms;

    pub fn start(self: *Progress) !void {
        try interrupt.check();
        if (self.operation) |operation| {
            operation.start(self.label);
            operation.mutex.lockUncancelable(self.io);
            operation.overall.total_bytes = self.total_bytes;
            operation.overall.total_files = self.total_files;
            operation.overall.indeterminate = self.indeterminate;
            operation.overall.item_label = self.item_label;
            operation.overall.byte_columns = self.byte_columns;
            operation.overall.label_columns = @max(operation.overall.label_columns, self.label_columns);
            operation.refresh();
            operation.mutex.unlock(self.io);
            self.started = true;
            return;
        }
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.start_ns = now;
        self.last_pulse_ns = now;
        self.started = true;
        if (liveProgress(self.writer)) {
            try self.draw(now);
        } else {
            if (self.nested) try self.writer.writeAll("    ");
            try self.writer.print("{s}...\n", .{self.label});
            try self.writer.flush();
        }
    }

    pub fn startReading(self: *Progress, task_count: usize, byte_count: u64) !void {
        try self.finish();
        if (task_count == 0) return;
        const widths = byteColumns(byte_count);
        self.* = .{
            .io = self.io,
            .writer = self.writer,
            .label = "Reading contents",
            .label_columns = "Reading contents: ".len,
            .total_files = task_count,
            .total_bytes = byte_count,
            .byte_columns = if (byte_count != 0) .{ .current = widths.current, .total = widths.current } else null,
            .item_label = null,
            .show_speed = true,
        };
        try self.start();
    }

    pub fn reconcileRead(self: *Progress, expected_bytes: u64, actual_bytes: u64) void {
        if (self.total_bytes == 0) return;
        if (actual_bytes < expected_bytes) {
            self.total_bytes -|= expected_bytes - actual_bytes;
        } else self.total_bytes +|= actual_bytes - expected_bytes;
    }

    pub fn addBytes(self: *Progress, count: u64) !void {
        try interrupt.check();
        self.done_bytes +|= count;
        self.activity_bytes +|= count;
        if (self.operation) |creation| {
            creation.advanceWork(count, 0);
            return;
        }
        if (!self.started or !liveProgress(self.writer)) return;
        if (self.total_bytes > 0 or self.indeterminate or self.show_speed) {
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            if (self.done_bytes -| self.last_draw_bytes >= redraw_bytes or now - self.last_pulse_ns >= pulse_ns) {
                self.last_pulse_ns = now;
                self.draw(now) catch {};
            }
        }
    }

    pub fn addActivity(self: *Progress, count: u64) !void {
        try interrupt.check();
        self.activity_bytes +|= count;
        if (self.operation) |creation| creation.advanceWork(count, 0);
    }

    pub fn completeBytes(self: *Progress, count: u64) !void {
        try interrupt.check();
        self.done_bytes +|= count;
        if (!self.started or !liveProgress(self.writer)) return;
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        try self.draw(now);
    }

    pub fn finishFile(self: *Progress) !void {
        try interrupt.check();
        self.done_files += 1;
        if (self.operation) |creation| {
            creation.complete(self.done_bytes - self.committed_bytes, 1);
            creation.advanceWork(0, 1);
            self.committed_bytes = self.done_bytes;
            return;
        }
        if (!self.started or !liveProgress(self.writer)) return;
        if (self.indeterminate) {
            try self.pulse();
            return;
        }
        const at_end = self.total_files != 0 and self.done_files >= self.total_files;
        if (at_end or self.done_files -| self.last_draw_files >= self.fileStep()) {
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            try self.draw(now);
        }
    }

    pub fn pulse(self: *Progress) !void {
        try interrupt.check();
        if (self.operation != null) return;
        if (!self.started or !liveProgress(self.writer)) return;
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        if (now - self.last_pulse_ns < pulse_ns) return;
        self.last_pulse_ns = now;
        try self.draw(now);
    }

    pub fn finish(self: *Progress) !void {
        if (!self.started) return;
        if (self.operation) |operation| {
            operation.finish();
            self.started = false;
            return;
        }
        if (self.total_bytes > 0) self.done_bytes = self.total_bytes;
        if (self.total_files > 0) self.done_files = self.total_files;
        try self.drawFinal();
        try self.writer.writeByte('\n');
        try self.writer.flush();
        self.started = false;
    }

    pub fn abort(self: *Progress) void {
        if (self.operation) |operation| {
            operation.stop();
            self.started = false;
            return;
        }
        self.breakLine();
        self.started = false;
    }

    pub fn breakLine(self: *Progress) void {
        if (!self.started) return;
        if (self.operation) |operation| {
            operation.breakLine();
            return;
        }
        if (liveProgress(self.writer)) {
            reset(self.writer) catch {};
            self.writer.writeByte('\n') catch {};
            self.writer.flush() catch {};
        }
    }

    pub fn fileError(self: *Progress, action: []const u8, path: []const u8, err: anyerror) !void {
        if (self.operation) |operation| return operation.fileError(action, path, err);
        self.breakLine();
        try writeFileError(self.writer, action, path, err);
    }

    fn drawFinal(self: *Progress) !void {
        self.last_draw_bytes = self.done_bytes;
        self.last_draw_files = self.done_files;
        if (liveProgress(self.writer)) try self.writer.writeAll("\r\x1b[2K");
        var row = self.*;
        row.indeterminate = false;
        try writeProgressRow(self.writer, row, std.Io.Timestamp.now(self.io, .awake).nanoseconds, 100, false);
        try self.writer.flush();
    }

    fn draw(self: *Progress, now: i96) !void {
        self.last_draw_bytes = self.done_bytes;
        self.last_draw_files = self.done_files;
        try self.writer.writeAll("\r\x1b[2K");
        try writeProgressRow(self.writer, self.*, now, null, true);
        try self.writer.flush();
    }

    fn writeLine(self: *Progress, active: bool, now: i96, percent_override: ?usize, width: usize, mode: std.Io.Terminal.Mode) !void {
        self.last_draw_bytes = self.done_bytes;
        self.last_draw_files = self.done_files;
        const pct = percent_override orelse self.percent();
        const filled = if (self.indeterminate) 0 else (pct * width) / 100;
        const arrow: ?usize = if (active) self.arrowPosition(filled, width, now) else null;

        try self.writeLabel(mode);
        try self.writeBarWidth(filled, arrow, width, mode);
        if (!self.indeterminate) {
            try self.writer.writeByte(' ');
            try self.writer.print("{d: >3}%", .{pct});
        }
        if (self.total_bytes > 0 or self.byte_columns != null) {
            var done_buf: [64]u8 = undefined;
            var total_buf: [64]u8 = undefined;
            const widths = self.byteLayout();
            try self.writer.writeAll("  ");
            try self.writer.print("{[0]s: >[1]}/{[2]s: >[3]}", .{
                try bytes(&done_buf, @min(self.done_bytes, self.total_bytes)),
                widths.current,
                try bytes(&total_buf, self.total_bytes),
                widths.total,
            });
        } else if ((self.indeterminate or self.show_speed) and self.done_bytes != 0) {
            var done_buf: [64]u8 = undefined;
            try self.writer.writeAll("  ");
            try self.writer.print("{s: >11}", .{try bytes(&done_buf, self.done_bytes)});
        }
        if (self.item_label) |label| if (self.total_files != 0 or self.done_files != 0) {
            try self.writer.writeAll("  ");
            try self.writer.writeAll(label);
            try self.writer.writeByte(' ');
            if (self.total_files != 0) {
                try self.writer.print("{[0]d: >[1]}/{[2]d}", .{ @min(self.done_files, self.total_files), std.fmt.count("{d}", .{self.total_files}), self.total_files });
            } else try self.writer.print("{d}", .{self.done_files});
        };
        if (self.show_speed and self.activity_bytes != 0) {
            var speed_buf: [64]u8 = undefined;
            try self.writer.writeAll("  ");
            try self.writer.print("{s: >13}", .{try self.speed(&speed_buf)});
        }
    }

    fn arrowPosition(self: *Progress, filled: usize, width: usize, now: i96) ?usize {
        const first_empty = if (self.indeterminate) 0 else filled;
        if (first_empty >= width) return null;
        const remaining = width - first_empty;
        const elapsed: u128 = @intCast(@max(@as(i96, 0), now - self.start_ns));
        if (remaining == 1) {
            return if ((elapsed / blink_ns) % 2 == 0) first_empty else null;
        }
        return first_empty + @as(usize, @intCast((elapsed / pulse_ns) % remaining));
    }

    fn writeBarWidth(self: *Progress, filled: usize, arrow: ?usize, width: usize, mode: std.Io.Terminal.Mode) !void {
        var terminal: std.Io.Terminal = .{ .writer = self.writer, .mode = mode };
        try self.writer.writeByte('[');
        try terminal.setColor(.cyan);
        for (0..width) |i| {
            if (i < filled) {
                try self.writer.writeByte('#');
            } else if (arrow != null and arrow.? == i) {
                try self.writer.writeByte('>');
            } else {
                try self.writer.writeByte('-');
            }
        }
        try terminal.setColor(.reset);
        try self.writer.writeByte(']');
    }

    fn percent(self: Progress) usize {
        const value: u128 = if (self.total_bytes > 0)
            @min(100, (@as(u128, @min(self.done_bytes, self.total_bytes)) * 100) / self.total_bytes)
        else if (self.total_files > 0)
            @min(100, (@as(u128, @min(self.done_files, self.total_files)) * 100) / self.total_files)
        else
            0;
        return @intCast(if (self.total_files != 0 and self.done_files < self.total_files) @min(99, value) else value);
    }

    fn writeLabel(self: *Progress, mode: std.Io.Terminal.Mode) !void {
        var terminal: std.Io.Terminal = .{ .writer = self.writer, .mode = mode };
        if (self.nested) try self.writer.writeAll("    ");
        try terminal.setColor(.bold);
        try self.writer.print("{s}:", .{self.label});
        try terminal.setColor(.reset);
        const used = self.label.len + 1 + if (self.nested) @as(usize, 4) else 0;
        const spaces = self.labelColumns() - used;
        for (0..spaces) |_| try self.writer.writeByte(' ');
    }

    fn labelColumns(self: Progress) usize {
        const used = self.label.len + 2 + if (self.nested) @as(usize, 4) else 0;
        return @max(used, self.label_columns);
    }

    fn barWidth(self: Progress, columns: usize) usize {
        var reserved = self.labelColumns() + 2 + 5 + 1;
        if (self.total_bytes != 0 or self.byte_columns != null) {
            const widths = self.byteLayout();
            reserved += 2 + widths.current + 1 + widths.total;
        } else if (self.indeterminate or self.show_speed) {
            reserved += 2 + 11;
        }
        if (self.item_label) |label| if (self.total_files != 0) {
            reserved += 2 + label.len + 1 + std.fmt.count("{d}", .{self.total_files}) * 2 + 1;
        };
        if (self.show_speed) reserved += 2 + 13;
        return std.math.clamp(columns -| reserved, min_bar_width, max_bar_width);
    }

    fn byteLayout(self: Progress) ByteColumns {
        const current = byteColumns(self.total_bytes);
        const reserved = self.byte_columns orelse return current;
        return .{ .current = @max(current.current, reserved.current), .total = @max(current.total, reserved.total) };
    }

    fn speed(self: *Progress, buf: []u8) ![]const u8 {
        if (self.activity_bytes == 0 or self.start_ns == 0) return "0 B/s";
        const now_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const elapsed_ns: u128 = @intCast(@max(@as(i96, 1), now_ns - self.start_ns));
        const bytes_per_second: u64 = @intCast(@min(
            std.math.maxInt(u64),
            (@as(u128, self.activity_bytes) * std.time.ns_per_s) / elapsed_ns,
        ));
        return bytesPerSecond(buf, bytes_per_second);
    }

    fn fileStep(self: Progress) usize {
        if (self.total_files <= 100) return 1;
        return @max(1, self.total_files / 100);
    }
};

pub const Operation = struct {
    io: std.Io,
    writer: *std.Io.Writer,
    overall: Progress = undefined,
    work: ?Progress = null,
    mutex: std.Io.Mutex = .init,
    stopped: std.Io.Event = .unset,
    renderer: ?Thread = null,
    started: bool = false,
    drawn_rows: u2 = 0,
    last_draw_ns: i96 = 0,

    pub fn start(self: *Operation, label: []const u8) void {
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.overall = .{ .io = self.io, .writer = self.writer, .label = label, .label_columns = "Creating file delta: ".len, .indeterminate = true, .start_ns = now };
        self.work = null;
        self.stopped = .unset;
        self.drawn_rows = 0;
        self.started = true;
        if (!liveProgress(self.writer)) {
            self.writer.print("{s}...\n", .{if (std.mem.eql(u8, label, "Creating")) "Creating delta" else label}) catch {};
            self.writer.flush() catch {};
            return;
        }
        self.draw(false) catch {};
        self.renderer = Thread.spawn(.{}, render, .{self}) catch null;
    }

    pub fn totals(self: *Operation, byte_count: u64, file_count: usize) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.overall.total_bytes = byte_count;
        self.overall.total_files = file_count;
        self.overall.indeterminate = false;
        self.refresh();
    }

    pub fn phase(self: *Operation, label: []const u8, byte_count: u64, file_count: usize) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const first_work = self.work == null;
        self.overall.label_columns = @max(self.overall.label_columns, label.len + 2);
        self.work = .{
            .io = self.io,
            .writer = self.writer,
            .label = label,
            .label_columns = self.overall.label_columns,
            .total_bytes = byte_count,
            .total_files = file_count,
            .indeterminate = byte_count == 0 and file_count == 0,
            .show_speed = byte_count != 0,
            .item_label = if (byte_count == 0) "files" else null,
            .start_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds,
        };
        if (first_work and self.started and liveProgress(self.writer)) self.draw(false) catch {} else self.refresh();
    }

    pub fn advanceWork(self: *Operation, byte_count: u64, file_count: usize) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.work) |*work| {
            work.done_bytes +|= byte_count;
            work.activity_bytes +|= byte_count;
            work.done_files +|= file_count;
        }
        self.refresh();
    }

    pub fn breakLine(self: *Operation) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.separateOutput();
    }

    pub fn fileError(self: *Operation, action: []const u8, path: []const u8, err: anyerror) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.separateOutput();
        try writeFileError(self.writer, action, path, err);
        try self.writer.flush();
    }

    fn separateOutput(self: *Operation) void {
        if (self.drawn_rows == 0 or !liveProgress(self.writer)) return;
        self.writer.writeByte('\n') catch {};
        self.writer.flush() catch {};
        self.drawn_rows = 0;
    }

    pub fn complete(self: *Operation, byte_count: u64, file_count: usize) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.overall.done_bytes +|= byte_count;
        self.overall.done_files +|= file_count;
        self.refresh();
    }

    pub fn finish(self: *Operation) void {
        self.end(true);
    }

    pub fn stop(self: *Operation) void {
        self.end(false);
    }

    fn end(self: *Operation, finished: bool) void {
        if (!self.started) return;
        self.stopped.set(self.io);
        if (self.renderer) |renderer| renderer.join();
        self.renderer = null;
        self.started = false;
        self.draw(finished) catch {};
        self.writer.writeByte('\n') catch {};
        self.writer.flush() catch {};
    }

    fn refresh(self: *Operation) void {
        if (!self.started or self.renderer != null or !liveProgress(self.writer)) return;
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        if (now - self.last_draw_ns >= Progress.pulse_ns) self.draw(false) catch {};
    }

    fn render(self: *Operation) void {
        while (true) {
            self.stopped.waitTimeout(self.io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } }) catch |err| switch (err) {
                error.Timeout => {},
                error.Canceled => return,
            };
            if (self.stopped.isSet()) return;
            self.mutex.lockUncancelable(self.io);
            self.draw(false) catch {};
            self.mutex.unlock(self.io);
        }
    }

    fn draw(self: *Operation, finished: bool) !void {
        const live = liveProgress(self.writer);
        if (!live and self.started) return;
        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.last_draw_ns = now;
        if (live and self.drawn_rows != 0) {
            if (self.drawn_rows == 2) try self.writer.writeAll("\x1b[1A");
            try self.writer.writeAll("\r\x1b[2K");
        }
        try self.writeRow(self.overall, now, if (finished) 100 else @min(99, self.overall.percent()));
        const show_work = live and self.started and self.work != null;
        if (show_work or (live and self.drawn_rows == 2)) {
            try self.writer.writeAll("\n\r\x1b[2K");
            if (show_work) {
                try self.writeRow(self.work.?, now, null);
            }
        }
        self.drawn_rows = if (show_work) 2 else 1;
        try self.writer.flush();
    }

    fn writeRow(self: *Operation, row: Progress, now: i96, percent: ?usize) !void {
        try writeProgressRow(self.writer, row, now, percent, self.started);
    }
};

fn writeProgressRow(writer: *std.Io.Writer, row: Progress, now: i96, percent: ?usize, active: bool) !void {
    var buffer: [512]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    var view = row;
    view.writer = &output;
    const columns = if (liveProgress(writer)) terminalColumns(row.io, streamState(writer).file) else std.math.maxInt(usize);
    try view.writeLine(active, now, percent, row.barWidth(columns), streamState(writer).mode);
    const line = output.buffered();
    var end: usize = 0;
    var visible: usize = 0;
    while (end < line.len) {
        if (line[end] == '\x1b') {
            end = (std.mem.indexOfScalarPos(u8, line, end, 'm') orelse unreachable) + 1;
        } else {
            if (visible >= columns -| 1) break;
            end += 1;
            visible += 1;
        }
    }
    try writer.writeAll(line[0..end]);
    try reset(writer);
}

const ByteColumns = struct { current: usize, total: usize };

fn byteColumns(maximum: u64) ByteColumns {
    var buffer: [64]u8 = undefined;
    const total = (bytes(&buffer, maximum) catch unreachable).len;
    var current = total;
    for ([_]u64{ 1024 - 1, 1024 * 1024 - 1, 1024 * 1024 * 1024 - 1, 1024 * 1024 * 1024 * 1024 - 1 }) |boundary| {
        if (boundary <= maximum) current = @max(current, (bytes(&buffer, boundary) catch unreachable).len);
    }
    return .{ .current = current, .total = total };
}

pub const ReadProgress = struct {
    progress: ?*Progress,
    inner: scan.Reader = .direct,
    mutex: std.Io.Mutex = .init,

    pub fn reader(self: *ReadProgress) scan.Reader {
        if (self.progress == null) return self.inner;
        return .{ .context = self, .read_fn = read };
    }

    fn read(raw: ?*anyopaque, io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
        const self: *ReadProgress = @ptrCast(@alignCast(raw.?));
        const count = try self.inner.read(io, file, buffer, offset);
        if (count != 0) {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            try self.progress.?.addBytes(count);
        }
        return count;
    }
};

fn terminalColumns(io: std.Io, file: ?std.Io.File) usize {
    const terminal = file orelse return 80;
    switch (builtin.target.os.tag) {
        .linux => {
            var size: std.posix.winsize = undefined;
            const rc = std.os.linux.syscall3(.ioctl, @bitCast(@as(isize, terminal.handle)), std.os.linux.T.IOCGWINSZ, @intFromPtr(&size));
            if (std.os.linux.errno(rc) == .SUCCESS and size.col != 0) return size.col;
        },
        .windows => {
            var info = std.os.windows.CONSOLE.USER_IO.GET_SCREEN_BUFFER_INFO;
            const result = info.operate(io, terminal) catch return 80;
            if (result == .SUCCESS and info.Data.dwWindowSize.X > 0) return @intCast(info.Data.dwWindowSize.X);
        },
        else => {},
    }
    return 80;
}

fn bytesPerSecond(buf: []u8, value: u64) ![]const u8 {
    return formatBytes(buf, value, &.{ "B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s" });
}

fn formatBytes(buf: []u8, value: u64, units: []const []const u8) ![]const u8 {
    var unit_index: usize = 0;
    var divisor: u128 = 1;
    while (unit_index + 1 < units.len and @as(u128, value) >= divisor * 1024) {
        divisor *= 1024;
        unit_index += 1;
    }
    if (unit_index == 0) return std.fmt.bufPrint(buf, "{d} {s}", .{ value, units[unit_index] });
    const scaled = (@as(u128, value) * 100) / divisor;
    return std.fmt.bufPrint(buf, "{d}.{d:0>2} {s}", .{ scaled / 100, scaled % 100, units[unit_index] });
}

pub fn printCreated(io: std.Io, path: []const u8, out: *std.Io.Writer) !void {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    var buf: [64]u8 = undefined;
    try writeSuccessLabel(out, "Created:");
    try out.writeByte(' ');
    try out.writeAll(path);
    try out.writeAll(" (");
    try out.writeAll(try bytes(&buf, stat.size));
    try out.writeAll(")\n");
}

test "creation separates current work from committed target bytes and coalesces redirected phases" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var creation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    creation.start("Creating");
    defer creation.stop();
    creation.totals(1024, 2);
    for (0..50) |_| {
        creation.phase("Indexing source", 0, 0);
        creation.advanceWork(1024, 0);
        creation.phase("Matching", 0, 2);
        creation.advanceWork(0, 2);
    }
    try std.testing.expectEqual(@as(u64, 0), creation.overall.done_bytes);
    try std.testing.expectEqualStrings("Creating delta...\n", output.written());
    creation.phase("Archiving", 1024, 2);
    var progress: Progress = .{
        .io = std.testing.io,
        .writer = &output.writer,
        .label = "Archiving",
        .operation = &creation,
    };
    try progress.addBytes(256);
    try std.testing.expectEqual(@as(u64, 0), creation.overall.done_bytes);
    try progress.finishFile();
    try progress.addBytes(768);
    try progress.finishFile();
    try std.testing.expectEqual(@as(u64, 1024), creation.overall.done_bytes);
    try std.testing.expectEqual(@as(usize, 2), creation.overall.done_files);
    creation.finish();
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "100%") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "2/2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b") == null);
}

test "creation redraws two rows and does not show overall completion before publication" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    var creation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    const now = std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds;
    creation.overall = .{
        .io = std.testing.io,
        .writer = &output.writer,
        .label = "Creating",
        .total_bytes = 1024,
        .done_bytes = 1024,
        .total_files = 1,
        .done_files = 1,
    };
    creation.work = .{
        .io = std.testing.io,
        .writer = &output.writer,
        .label = "Publishing",
        .indeterminate = true,
        .start_ns = now,
    };
    creation.started = true;
    try creation.draw(false);
    try creation.draw(false);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b[1A\r\x1b[2KCreating") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "99%") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "100%") == null);
    creation.stop();
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "100%") == null);
    try std.testing.expect(std.mem.endsWith(u8, output.written(), "\n\r\x1b[2K\n"));
}

test "operation animates overall and streamed work until it stops" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var creation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    creation.start("Creating");
    defer creation.stop();
    creation.totals(1024, 2);
    creation.phase("Archiving", 1024, 2);
    creation.advanceWork(512, 0);
    creation.complete(256, 0);
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };

    var offsets: [3]usize = undefined;
    offsets[0] = output.written().len;
    for (0..2) |index| {
        creation.overall.start_ns -= Progress.pulse_ns;
        creation.work.?.start_ns -= Progress.pulse_ns;
        try creation.draw(false);
        offsets[index + 1] = output.written().len;
    }
    const frames = [_][]const u8{ output.written()[offsets[0]..offsets[1]], output.written()[offsets[1]..offsets[2]] };
    for (frames) |frame| {
        const overall = frame[std.mem.indexOf(u8, frame, "Creating:").?..];
        const work = frame[std.mem.indexOf(u8, frame, "Archiving:").?..];
        try std.testing.expect(std.mem.indexOfScalar(u8, overall[0..std.mem.indexOfScalar(u8, overall, '\n').?], '>') != null);
        try std.testing.expect(std.mem.indexOfScalar(u8, work, '>') != null);
        try std.testing.expect(std.mem.indexOf(u8, overall, "25%") != null);
        try std.testing.expect(std.mem.indexOf(u8, work, "50%") != null);
    }
    try std.testing.expect(!std.mem.eql(u8, frames[0], frames[1]));

    creation.phase("Matching", 0, 2);
    const matching_offset = output.written().len;
    try creation.draw(false);
    const matching = output.written()[matching_offset..];
    const work = matching[std.mem.indexOf(u8, matching, "Matching:").?..];
    try std.testing.expect(std.mem.indexOfScalar(u8, work, '>') != null);
    creation.stop();
    const stopped = output.written()[std.mem.lastIndexOf(u8, output.written(), "Creating:").?..];
    try std.testing.expect(std.mem.indexOfScalar(u8, stopped, '>') == null);
}

test "deletion-only creation can complete with no payload bytes" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var creation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    creation.start("Creating");
    creation.totals(0, 0);
    creation.finish();
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "100%") != null);
}

test "operation rows appear only for active work and preserve item labels on reuse" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var operation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Cleaning", .item_label = "directories", .total_files = 12, .operation = &operation };
    try progress.start();
    try std.testing.expectEqualStrings("directories", operation.overall.item_label.?);
    try std.testing.expect(operation.work == null);
    try progress.finishFile();
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    try operation.draw(false);
    try std.testing.expectEqual(@as(u2, 1), operation.drawn_rows);
    operation.phase("Writing", 1024, 0);
    try operation.draw(false);
    try std.testing.expectEqual(@as(u2, 2), operation.drawn_rows);
    try operation.fileError("Writing", "broken.bin", error.AccessDenied);
    try std.testing.expectEqual(@as(u2, 0), operation.drawn_rows);
    const error_end = output.written().len;
    try operation.draw(false);
    try std.testing.expect(!std.mem.startsWith(u8, output.written()[error_end..], "\x1b[1A"));
    operation.finish();
    streams = .{ .{}, .{} };
    operation.start("Applying");
    try std.testing.expect(operation.work == null);
    operation.stop();
}

test "terminal formatting keeps values plain and status colors conventional" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .mode = .escape_codes }, .{} };

    try writeHeading(&output.writer, "Create delta:");
    try output.writer.writeByte('\n');
    try writeDeltaField(&output.writer, "1.0", "1.1");
    try writeField(&output.writer, "Source:", "/source");
    try writeField(&output.writer, "Target:", "/target");
    try writeCount(&output.writer, "Changed:", 2);
    try writeCountSize(&output.writer, "Added:", 1, 1024);
    try writeOption(&output.writer, "1", "Ziff");
    try writePromptLabel(&output.writer, "Method");
    try output.writer.writeByte(' ');
    try writeChoice(&output.writer, "1-3");
    try output.writer.writeByte(' ');
    try writePromptDefault(&output.writer, "1");
    try output.writer.writeByte('\n');
    try writeErrorPrefix(&output.writer);
    try output.writer.writeAll(" failed\n");
    try writeWarningLine(&output.writer, "Warning");
    try writeSuccessLine(&output.writer, "Complete");
    try std.testing.expectEqualStrings(
        "\x1b[1mCreate delta:\x1b[0m\n" ++
            "    Delta: 1.0 -> 1.1\n" ++
            "Source: /source\nTarget: /target\nChanged: 2\nAdded: 1 (1.00 KiB)\n" ++
            "    1. Ziff\n\x1b[1mMethod\x1b[0m [1-3] (1)\n" ++
            "\x1b[31mError:\x1b[0m failed\n\x1b[33mWarning\x1b[0m\n\x1b[32mComplete\x1b[0m\n",
        output.written(),
    );
}

test "completion distinguishes success from errors and points to their diagnostics" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    try complete(&output.writer, false);
    try std.testing.expectError(error.CompletedWithErrors, complete(&output.writer, true));
    try std.testing.expectEqualStrings("Complete!\nCompleted with errors (shown above).\n", output.written());
}

test "terminal stream detection preserves plain output and no-color progress" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile(io, "redirected", .{});
    defer file.close(io);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var no_color_output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer no_color_output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };

    initStream(io, file, &output.writer, false);
    try std.testing.expect(streamState(&output.writer).mode == .no_color);
    try std.testing.expect(!liveProgress(&output.writer));
    try writeHeading(&output.writer, "Heading");
    try output.writer.writeByte('\n');
    try writeErrorPrefix(&output.writer);
    try output.writer.writeByte('\n');
    try std.testing.expectEqualStrings("Heading\nError:\n", output.written());

    const terminal = std.Io.File.stderr();
    initStream(io, terminal, &no_color_output.writer, true);
    const live = terminal.isTty(io) catch false;
    try std.testing.expect(streamState(&no_color_output.writer).mode == .no_color);
    try std.testing.expectEqual(live, liveProgress(&no_color_output.writer));
    try writeWarningLine(&no_color_output.writer, "Warning");
    try writeSuccessLine(&no_color_output.writer, "Complete");
    try std.testing.expectEqualStrings("Warning\nComplete\n", no_color_output.written());
    initStream(io, terminal, &no_color_output.writer, true);
    try std.testing.expectEqual(&no_color_output.writer, streamState(&no_color_output.writer).writer.?);
}

test "terminal progress uses one accent without coloring counts or speed" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .mode = .escape_codes }, .{} };
    var progress: Progress = .{
        .io = std.testing.io,
        .writer = &output.writer,
        .label = "Testing",
        .total_bytes = 1024,
        .total_files = 2,
        .show_speed = true,
        .activity_bytes = 1024,
        .started = true,
    };
    try progress.finish();
    try std.testing.expectEqualStrings(
        "\x1b[1mTesting:\x1b[0m     [\x1b[36m#########################\x1b[0m] 100%  1.00 KiB/1.00 KiB  files 2/2          0 B/s\x1b[0m\n",
        output.written(),
    );
    try std.testing.expect(!progress.started);
}

test "terminal redirected progress announces work before any bytes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile(io, "progress.log", .{ .read = true });
    defer file.close(io);
    var buffer: [512]u8 = undefined;
    var output = file.writer(io, &buffer);
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var progress: Progress = .{
        .io = io,
        .writer = &output.interface,
        .label = "Checking target file sizes",
        .total_files = 2,
    };
    try progress.start();
    var observed: [256]u8 = undefined;
    const started = try file.readPositionalAll(io, &observed, 0);
    try std.testing.expectEqualStrings("Checking target file sizes...\n", observed[0..started]);
    try std.testing.expectEqual(@as(usize, 0), progress.done_files);
    try std.testing.expectEqual(@as(u64, 0), progress.done_bytes);
    try progress.finish();
    const finished = try file.readPositionalAll(io, &observed, 0);
    try std.testing.expectEqualStrings(
        "Checking target file sizes...\nChecking target file sizes: [#########################] 100%  files 2/2\n",
        observed[0..finished],
    );
}

test "reading starts after metadata progress completes and never resets between tasks" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .label_columns = "Reading contents: ".len, .total_files = 2 };
    try progress.start();
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "Reading") == null);
    try progress.finishFile();
    try progress.finishFile();
    try progress.startReading(2, 16 * 1024 * 1024);
    const reading_start = std.mem.indexOf(u8, output.written(), "Reading contents:").?;
    try std.testing.expect(std.mem.indexOf(u8, output.written()[0..reading_start], "100%  files 2/2") != null);
    try std.testing.expectEqual(@as(usize, 0), progress.done_files);
    try progress.addBytes(8 * 1024 * 1024);
    try progress.finishFile();
    try std.testing.expectEqual(@as(usize, 50), progress.percent());
    try progress.addBytes(8 * 1024 * 1024);
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), progress.done_bytes);
    try std.testing.expectEqual(@as(usize, 99), progress.percent());
    try progress.finishFile();
    try progress.finish();
    try std.testing.expect(std.mem.indexOf(u8, output.written()[reading_start..], "100%    16.00 MiB/  16.00 MiB") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b[1A") == null);
    try std.testing.expect(std.mem.endsWith(u8, output.written(), "\n"));
}

test "comparison and content reading animate without changing their counters" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .indeterminate = true };
    try progress.start();
    defer progress.abort();
    const comparing_start = output.written().len;
    progress.start_ns -= Progress.pulse_ns;
    progress.last_pulse_ns = 0;
    try progress.pulse();
    try std.testing.expect(std.mem.indexOfScalar(u8, output.written()[comparing_start..], '>') != null);
    try std.testing.expectEqual(@as(usize, 0), progress.done_files);
    try std.testing.expectEqual(@as(u64, 0), progress.done_bytes);
    progress.indeterminate = false;
    progress.total_files = 2;
    try progress.finishFile();
    try progress.startReading(2, 16 * 1024 * 1024);
    try progress.addBytes(8 * 1024 * 1024);
    const reading_start = output.written().len;
    progress.start_ns -= Progress.pulse_ns;
    progress.last_pulse_ns = 0;
    try progress.pulse();
    try std.testing.expect(std.mem.indexOfScalar(u8, output.written()[reading_start..], '>') != null);
    try std.testing.expectEqual(@as(usize, 0), progress.done_files);
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024), progress.done_bytes);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "Reading contents:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "50%") != null);
}

test "reading abort leaves unfinished progress above errors" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .total_files = 1 };
    try progress.start();
    try progress.finishFile();
    try progress.startReading(2, 8);
    try progress.addBytes(4);
    try progress.finishFile();
    const last_read = std.mem.lastIndexOf(u8, output.written(), "Reading contents:").?;
    progress.abort();
    try std.testing.expect(!progress.started);
    try std.testing.expect(std.mem.endsWith(u8, output.written(), "\n"));
    try std.testing.expect(std.mem.indexOf(u8, output.written()[last_read..], "100%") == null);
}

test "redirected stages are sequential and empty reading work emits no bar" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .total_files = 2 };
    try progress.start();
    try progress.finishFile();
    try progress.finishFile();
    try progress.startReading(2, 32 * 1024 * 1024);
    for (0..2) |_| {
        try progress.addBytes(16 * 1024 * 1024);
        try progress.finishFile();
    }
    try progress.finish();
    const text = output.written();
    const metadata_end = std.mem.indexOf(u8, text, "100%  files 2/2").?;
    const reading_start = std.mem.indexOf(u8, text, "Reading contents...\n").?;
    try std.testing.expect(metadata_end < reading_start);
    try std.testing.expect(std.mem.indexOf(u8, text, "100%    32.00 MiB/  32.00 MiB") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b") == null);
    progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .total_files = 1 };
    const start = output.written().len;
    try progress.start();
    try progress.finishFile();
    try progress.startReading(0, 0);
    try std.testing.expect(!progress.started);
    try std.testing.expect(std.mem.indexOf(u8, output.written()[start..], "Reading") == null);
}

test "bounded progress rows preserve terminal colors without counting escapes as columns" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &output.writer, .live = true, .mode = .escape_codes }, .{} };
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing", .label_columns = "Reading contents: ".len, .total_files = 1 };
    try progress.start();
    defer progress.abort();
    try progress.finishFile();
    try progress.startReading(1, 8 * 1024 * 1024);
    try progress.addBytes(8 * 1024 * 1024);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b[1mComparing:\x1b[0m        [\x1b[36m>------------------------\x1b[0m]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\x1b[1mReading contents:\x1b[0m [\x1b[36m>-------------\x1b[0m]") != null);
}

test "early read exits preserve stage geometry and report only physical bytes" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var progress: Progress = .{ .io = std.testing.io, .writer = &output.writer, .label = "Comparing" };
    try progress.startReading(2, 1024 * 1024);
    const width = progress.barWidth(80);
    try progress.addBytes(128 * 1024);
    progress.reconcileRead(768 * 1024, 128 * 1024);
    try progress.finishFile();
    try std.testing.expectEqual(@as(usize, 33), progress.percent());
    try std.testing.expectEqual(width, progress.barWidth(80));
    try progress.addBytes(256 * 1024);
    try std.testing.expectEqual(@as(usize, 99), progress.percent());
    try progress.finishFile();
    try progress.finish();
    try std.testing.expectEqual(@as(u64, 384 * 1024), progress.done_bytes);
    try std.testing.expectEqual(progress.done_bytes, progress.total_bytes);
    try std.testing.expectEqual(width, progress.barWidth(80));
}

test "progress reserves the complete count field from its total" {
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: Progress = .{ .io = std.testing.io, .writer = &sink.writer, .label = "Comparing", .label_columns = 17, .total_files = 19827 };
    try std.testing.expectEqual(@as(usize, 25), progress.barWidth(120));
    try std.testing.expectEqual(@as(usize, 16), progress.barWidth(60));
    try std.testing.expectEqual(@as(usize, 10), progress.barWidth(40));
    for ([_]usize{ 0, 10000, 19827 }) |count| {
        var buffer: [160]u8 = undefined;
        var output: std.Io.Writer = .fixed(&buffer);
        progress.writer = &output;
        progress.done_files = count;
        try progress.writeLine(false, 0, null, progress.barWidth(60), .no_color);
        const field = output.buffered()[(std.mem.indexOf(u8, output.buffered(), "files ").? + "files ".len)..];
        try std.testing.expectEqual(@as(usize, 11), field.len);
        try std.testing.expect(std.mem.endsWith(u8, field, "/19827"));
        try std.testing.expectEqual(@as(usize, 16), progress.barWidth(60));
        if (count == 0) try std.testing.expectEqualStrings("    0/19827", field);
    }
}

test "progress reserves byte unit boundaries and speed without counter-dependent resizing" {
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: Progress = .{ .io = std.testing.io, .writer = &sink.writer, .label = "Reading targets", .total_bytes = 1024 * 1024, .show_speed = true };
    try std.testing.expectEqual(@as(usize, 11), byteColumns(progress.total_bytes).current);
    try std.testing.expectEqual(@as(usize, 8), byteColumns(progress.total_bytes).total);
    const width = progress.barWidth(80);
    for ([_]u64{ 0, 1023, 1024 * 1024 - 1, 1024 * 1024 }) |count| {
        var buffer: [160]u8 = undefined;
        var output: std.Io.Writer = .fixed(&buffer);
        progress.writer = &output;
        progress.done_bytes = count;
        progress.activity_bytes = count;
        try progress.writeLine(false, 0, null, width, .no_color);
        try std.testing.expectEqual(width, progress.barWidth(80));
        const slash = std.mem.indexOfScalar(u8, output.buffered(), '/').?;
        try std.testing.expectEqualStrings("1.00 MiB", output.buffered()[slash + 1 .. slash + 9]);
    }
}

test "creation rows keep their bars aligned across phase labels" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const previous = streams;
    defer streams = previous;
    streams = .{ .{}, .{} };
    var creation: Operation = .{ .io = std.testing.io, .writer = &output.writer };
    creation.start("Creating");
    defer creation.stop();
    streams = .{ .{ .writer = &output.writer, .live = true }, .{} };
    for ([_][]const u8{ "Matching", "Reading identities", "Creating file delta", "a longer phase label remains supported", "Publishing" }) |label| {
        const offset = output.written().len;
        creation.phase(label, 1024, 2);
        try creation.draw(false);
        const rendered = output.written()[offset..];
        const overall = rendered[std.mem.indexOf(u8, rendered, "Creating:").?..];
        const work = rendered[std.mem.lastIndexOf(u8, rendered, label).?..];
        try std.testing.expectEqual(std.mem.indexOfScalar(u8, overall, '[').?, std.mem.indexOfScalar(u8, work, '[').?);
    }
}

test "read progress preserves reader results and errors and only counts returned bytes" {
    const Reader = struct {
        fn read(_: ?*anyopaque, _: std.Io, _: std.Io.File, buffer: []u8, offset: u64) !usize {
            if (offset != 0) return error.ReadFault;
            @memcpy(buffer[0..2], "ok");
            return 2;
        }
    };
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "read.bin", .{});
    defer file.close(io);
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var progress: Progress = .{ .io = io, .writer = &sink.writer, .label = "Reading contents" };
    var reading: ReadProgress = .{ .progress = &progress, .inner = .{ .read_fn = Reader.read } };
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try reading.reader().read(io, file, &buffer, 0));
    try std.testing.expectEqualStrings("ok", buffer[0..2]);
    try std.testing.expectError(error.ReadFault, reading.reader().read(io, file, &buffer, 2));
    try std.testing.expectEqual(@as(u64, 2), progress.done_bytes);
    reading.progress = null;
    try std.testing.expectEqual(Reader.read, reading.reader().read_fn);
    _ = try reading.reader().read(io, file, &buffer, 0);
    try std.testing.expectEqual(@as(u64, 2), progress.done_bytes);
    var broken: std.Io.Writer = .failing;
    const previous = streams;
    defer streams = previous;
    streams = .{ .{ .writer = &broken, .live = true }, .{} };
    progress.writer = &broken;
    progress.started = true;
    progress.show_speed = true;
    progress.done_bytes = Progress.redraw_bytes;
    reading.progress = &progress;
    try std.testing.expectEqual(@as(usize, 2), try reading.reader().read(io, file, &buffer, 0));
    try std.testing.expectEqual(@as(u64, Progress.redraw_bytes + 2), progress.done_bytes);
    try std.testing.expectError(error.ReadFault, reading.reader().read(io, file, &buffer, 2));
}

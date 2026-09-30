// borrowed bytes, callback after physical write; false = cancel
pub const OutputHook = struct {
    context: ?*anyopaque = null,
    call_fn: *const fn (?*anyopaque, u64, []const u8) anyerror!bool,

    pub fn call(self: OutputHook, offset: u64, bytes: []const u8) !bool {
        return self.call_fn(self.context, offset, bytes);
    }
};

// incremental counts; false = cancel
pub const ProgressHook = struct {
    context: ?*anyopaque = null,
    call_fn: *const fn (?*anyopaque, u64) anyerror!bool,

    pub fn call(self: ProgressHook, count: u64) !bool {
        return self.call_fn(self.context, count);
    }
};

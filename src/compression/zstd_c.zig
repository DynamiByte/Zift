pub const ZstdDStream = opaque {};
pub const ZstdCCtx = opaque {};
pub const ZstdCStream = ZstdCCtx;

pub const ZstdInBuffer = extern struct {
    src: ?*const anyopaque,
    size: usize,
    pos: usize,
};

pub const ZstdOutBuffer = extern struct {
    dst: ?*anyopaque,
    size: usize,
    pos: usize,
};

pub extern fn ZSTD_createDStream() ?*ZstdDStream;
pub extern fn ZSTD_freeDStream(stream: *ZstdDStream) usize;
pub extern fn ZSTD_DCtx_setParameter(stream: *ZstdDStream, parameter: c_int, value: c_int) usize;
pub extern fn ZSTD_initDStream(stream: *ZstdDStream) usize;
pub extern fn ZSTD_decompressStream(stream: *ZstdDStream, output: *ZstdOutBuffer, input: *ZstdInBuffer) usize;
pub const zstd_d_window_log_max: c_int = 100;

pub extern fn ZSTD_createCStream() ?*ZstdCStream;
pub extern fn ZSTD_freeCStream(stream: *ZstdCStream) usize;
pub extern fn ZSTD_createCCtx() ?*ZstdCCtx;
pub extern fn ZSTD_freeCCtx(context: *ZstdCCtx) usize;
pub extern fn ZSTD_compressCCtx(context: *ZstdCCtx, dst: ?*anyopaque, dst_capacity: usize, src: ?*const anyopaque, src_size: usize, compression_level: c_int) usize;
pub extern fn ZSTD_initCStream(stream: *ZstdCStream, compression_level: c_int) usize;
pub extern fn ZSTD_CCtx_setParameter(stream: *ZstdCStream, parameter: c_int, value: c_int) usize;
pub extern fn ZSTD_CCtx_setPledgedSrcSize(stream: *ZstdCStream, pledged_src_size: u64) usize;
pub extern fn ZSTD_compressStream2(stream: *ZstdCStream, output: *ZstdOutBuffer, input: *ZstdInBuffer, end_directive: c_int) usize;
pub const zstd_c_window_log: c_int = 101;
pub extern fn ZSTD_maxCLevel() c_int;
pub extern fn ZSTD_compressBound(src_size: usize) usize;
pub extern fn ZSTD_compress(dst: ?*anyopaque, dst_capacity: usize, src: ?*const anyopaque, src_size: usize, compression_level: c_int) usize;
pub extern fn ZSTD_isError(code: usize) c_uint;
pub extern fn ZSTD_getErrorCode(code: usize) c_int;
pub const zstd_error_checksum_wrong: c_int = 22;

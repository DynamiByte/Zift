// shared output-affecting defaults

// larger blocks: worse compression in dense-family corpus
pub const matcher_block_size: u32 = 64;

pub const matcher_alternates: bool = true;

// nearby source offsets for smaller encoded deltas
pub const matcher_locality: bool = true;

// 0 = whole-family index
pub const matcher_slice_budget: u64 = 0;

// -m: repeated target scans for smaller retained source index
pub const minimum_memory_slice_budget: u64 = 6 * 1024 * 1024 * 1024;

pub const zstd_level_full: c_int = 5;
pub const zstd_level_patch: c_int = 12;

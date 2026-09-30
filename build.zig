const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize_override = b.option(std.builtin.OptimizeMode, "optimize", "Build optimization mode");
    const optimize = optimizeOption(b, optimize_override, .ReleaseSmall);
    const test_optimize = optimizeOption(b, optimize_override, .ReleaseSafe);
    const debug_linker: ?bool = if (optimize == .Debug) true else null;
    const test_debug_linker: ?bool = if (test_optimize == .Debug) true else null;

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addDependencies(root_module);

    const exe = b.addExecutable(.{
        .name = "zift",
        .root_module = root_module,
        .use_llvm = debug_linker,
        .use_lld = debug_linker,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run zift");
    run_step.dependOn(&run_cmd.step);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = test_optimize,
        .link_libc = true,
    });
    const test_options = b.addOptions();
    test_options.addOption(bool, "codec_interop", false);
    test_module.addOptions("test_options", test_options);
    addDependencies(test_module);
    const test_filter = b.option([]const u8, "test-filter", "Run only tests whose names contain this text");
    const tests = b.addTest(.{
        .root_module = test_module,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
        .use_llvm = test_debug_linker,
        .use_lld = test_debug_linker,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    const flow_module = b.createModule(.{
        .root_source_file = b.path("src/tools_flow.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addDependencies(flow_module);
    const flow = b.addExecutable(.{ .name = "zift-flow", .root_module = flow_module, .use_llvm = debug_linker, .use_lld = debug_linker });
    const flow_install = b.addInstallArtifact(flow, .{});
    b.step("flow-build", "Build isolated create/in-place development harness").dependOn(&flow_install.step);
    const flow_run = b.addRunArtifact(flow);
    if (b.args) |args| flow_run.addArgs(args);
    b.step("flow", "Run isolated create/in-place development harness").dependOn(&flow_run.step);

    const interop_options = b.addOptions();
    interop_options.addOption(bool, "codec_interop", true);
    const interop_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = test_optimize,
        .link_libc = true,
    });
    interop_module.addOptions("test_options", interop_options);
    addDependencies(interop_module);
    const interop = b.addTest(.{ .root_module = interop_module, .filters = &.{"independent HDiff interoperability"}, .use_llvm = test_debug_linker, .use_lld = test_debug_linker });
    const run_interop = b.addRunArtifact(interop);
    run_interop.setCwd(b.path("."));
    b.step("test-codec-interop", "Check codecs against independent external HDiff tools").dependOn(&run_interop.step);
}

fn optimizeOption(
    b: *std.Build,
    override: ?std.builtin.OptimizeMode,
    default: std.builtin.OptimizeMode,
) std.builtin.OptimizeMode {
    if (override) |mode| return mode;
    return switch (b.release_mode) {
        .off => default,
        .any, .small => .ReleaseSmall,
        .fast => .ReleaseFast,
        .safe => .ReleaseSafe,
    };
}

fn addDependencies(module: *std.Build.Module) void {
    module.addIncludePath(module.owner.path("zstd/lib"));
    module.addIncludePath(module.owner.path("zstd/lib/common"));
    module.addIncludePath(module.owner.path("zstd/lib/compress"));
    module.addIncludePath(module.owner.path("zstd/lib/decompress"));
    module.addCSourceFiles(.{
        .files = &.{
            "zstd/lib/common/entropy_common.c",
            "zstd/lib/common/error_private.c",
            "zstd/lib/common/fse_decompress.c",
            "zstd/lib/common/pool.c",
            "zstd/lib/common/threading.c",
            "zstd/lib/common/xxhash.c",
            "zstd/lib/common/zstd_common.c",
            "zstd/lib/decompress/huf_decompress.c",
            "zstd/lib/decompress/zstd_ddict.c",
            "zstd/lib/decompress/zstd_decompress.c",
            "zstd/lib/decompress/zstd_decompress_block.c",
            "zstd/lib/compress/fse_compress.c",
            "zstd/lib/compress/hist.c",
            "zstd/lib/compress/huf_compress.c",
            "zstd/lib/compress/zstd_compress.c",
            "zstd/lib/compress/zstd_compress_literals.c",
            "zstd/lib/compress/zstd_compress_sequences.c",
            "zstd/lib/compress/zstd_compress_superblock.c",
            "zstd/lib/compress/zstd_preSplit.c",
            "zstd/lib/compress/zstd_double_fast.c",
            "zstd/lib/compress/zstd_fast.c",
            "zstd/lib/compress/zstd_lazy.c",
            "zstd/lib/compress/zstd_ldm.c",
            "zstd/lib/compress/zstd_opt.c",
            "zstd/lib/compress/zstdmt_compress.c",
        },
        .flags = &.{
            "-O3",
            "-DNDEBUG",
            "-DZSTD_NO_TRACE=1",
            "-DZSTD_DISABLE_ASM=1",
            "-DZSTD_LEGACY_SUPPORT=0",
            "-DZSTD_LIB_DEPRECATED=0",
            "-DZSTD_MULTITHREAD=1",
        },
    });
}

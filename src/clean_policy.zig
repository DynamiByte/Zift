const std = @import("std");

pub const Verdict = enum {
    managed,
    runtime_state,
    overlay,
    set_incomplete,
    software_forbids,
    no_authority,
    generic_no_basis,
    removable,

    pub fn authorizesDeletion(self: Verdict) bool {
        return self == .removable;
    }
};

pub const Capabilities = struct {
    integration_basis: bool,
    managed_set_complete: bool,
    software_permits_removals: bool,
    user_authority: bool,
};

pub const PathFacts = struct {
    managed: bool,
    runtime_state: bool,
    overlay: bool,
};

pub const Input = struct {
    capabilities: Capabilities,
    path: PathFacts,
};

pub fn evaluate(input: Input) Verdict {
    if (input.path.managed) return .managed;
    if (input.path.runtime_state) return .runtime_state;
    if (input.path.overlay) return .overlay;

    const capabilities = input.capabilities;
    if (!capabilities.integration_basis) return .generic_no_basis;
    if (!capabilities.managed_set_complete) return .set_incomplete;
    if (!capabilities.software_permits_removals) return .software_forbids;
    if (!capabilities.user_authority) return .no_authority;
    return .removable;
}

const fully_authorized: Capabilities = .{
    .integration_basis = true,
    .managed_set_complete = true,
    .software_permits_removals = true,
    .user_authority = true,
};

const unmanaged_path: PathFacts = .{
    .managed = false,
    .runtime_state = false,
    .overlay = false,
};

test "clean verdict preservation reasons have conservative precedence" {
    const Case = struct {
        name: []const u8,
        capabilities: Capabilities,
        path: PathFacts,
        expected: Verdict,
    };
    const cases = [_]Case{
        .{
            .name = "managed beats every other preservation condition",
            .capabilities = .{
                .integration_basis = false,
                .managed_set_complete = false,
                .software_permits_removals = false,
                .user_authority = false,
            },
            .path = .{ .managed = true, .runtime_state = true, .overlay = true },
            .expected = .managed,
        },
        .{
            .name = "runtime state beats overlay and capability failures",
            .capabilities = .{
                .integration_basis = false,
                .managed_set_complete = false,
                .software_permits_removals = false,
                .user_authority = false,
            },
            .path = .{ .managed = false, .runtime_state = true, .overlay = true },
            .expected = .runtime_state,
        },
        .{
            .name = "overlay beats capability failures",
            .capabilities = .{
                .integration_basis = false,
                .managed_set_complete = false,
                .software_permits_removals = false,
                .user_authority = false,
            },
            .path = .{ .managed = false, .runtime_state = false, .overlay = true },
            .expected = .overlay,
        },
        .{
            .name = "generic mode cannot acquire a basis from unrelated flags",
            .capabilities = .{
                .integration_basis = false,
                .managed_set_complete = true,
                .software_permits_removals = true,
                .user_authority = true,
            },
            .path = unmanaged_path,
            .expected = .generic_no_basis,
        },
        .{
            .name = "a present partial set is incomplete",
            .capabilities = .{
                .integration_basis = true,
                .managed_set_complete = false,
                .software_permits_removals = true,
                .user_authority = true,
            },
            .path = unmanaged_path,
            .expected = .set_incomplete,
        },
        .{
            .name = "software prohibition beats user authority",
            .capabilities = .{
                .integration_basis = true,
                .managed_set_complete = true,
                .software_permits_removals = false,
                .user_authority = false,
            },
            .path = unmanaged_path,
            .expected = .software_forbids,
        },
        .{
            .name = "complete permitted set still needs user authority",
            .capabilities = .{
                .integration_basis = true,
                .managed_set_complete = true,
                .software_permits_removals = true,
                .user_authority = false,
            },
            .path = unmanaged_path,
            .expected = .no_authority,
        },
        .{
            .name = "all gates satisfied",
            .capabilities = fully_authorized,
            .path = unmanaged_path,
            .expected = .removable,
        },
    };

    for (cases) |case| {
        errdefer std.debug.print("failed Clean policy case: {s}\n", .{case.name});
        try std.testing.expectEqual(case.expected, evaluate(.{
            .capabilities = case.capabilities,
            .path = case.path,
        }));
    }
}

// filesystem access and file-handle operations

const std = @import("std");
const builtin = @import("builtin");
const logical_path = @import("../path.zig");
const windows = std.os.windows;

pub fn openExisting(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    mode: std.Io.Dir.OpenFileOptions.Mode,
) std.Io.File.OpenError!std.Io.File {
    return dir.openFile(io, sub_path, .{
        .mode = mode,
        .allow_directory = false,
        .follow_symlinks = false,
    });
}

// linux O_PATH: no sync; windows directory flush: write access required
pub fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    if (builtin.target.os.tag == .windows) {
        const path_space = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, ".", .{});
        const wide = path_space.span();
        var handle: windows.HANDLE = undefined;
        var block: windows.IO_STATUS_BLOCK = undefined;
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .SPECIFIC = .{ .FILE_DIRECTORY = .{
                    .ADD_FILE = true,
                    .ADD_SUBDIRECTORY = true,
                    .READ_ATTRIBUTES = true,
                    .WRITE_ATTRIBUTES = true,
                    .WRITE_EA = true,
                    .TRAVERSE = true,
                } },
                .STANDARD = .{ .RIGHTS = .WRITE, .SYNCHRONIZE = true },
            },
            &.{ .RootDirectory = dir.handle, .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)) },
            &block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            .OPEN,
            .{ .DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT, .OPEN_FOR_BACKUP_INTENT = true, .OPEN_REPARSE_POINT = true },
            null,
            0,
        );
        switch (status) {
            .SUCCESS => {},
            .ACCESS_DENIED => return error.AccessDenied,
            .SHARING_VIOLATION, .DELETE_PENDING => return error.FileBusy,
            .NOT_A_DIRECTORY => return error.NotDir,
            else => return error.DirectorySyncUnsupported,
        }
        const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
        defer file.close(io);
        switch (windows.ntdll.NtFlushBuffersFile(handle, &block)) {
            .SUCCESS => {},
            .ACCESS_DENIED => return error.AccessDenied,
            else => return error.DirectorySyncUnsupported,
        }
        return;
    }
    var readable = try dir.openDir(io, ".", .{ .iterate = true, .access_sub_paths = true, .follow_symlinks = false });
    defer readable.close(io);
    const file: std.Io.File = .{ .handle = readable.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

pub fn openRead(io: std.Io, dir: std.Io.Dir, sub_path: []const u8) std.Io.File.OpenError!std.Io.File {
    return openExisting(io, dir, sub_path, .read_only);
}

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    max_size: u64,
) ![]u8 {
    var file = try openRead(io, dir, path);
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;
    if (stat.size > max_size) return error.FileTooLarge;
    const len: usize = @intCast(stat.size);
    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);
    const n = try file.readPositionalAll(io, bytes, 0);
    if (n != len) return error.UnexpectedEof;
    if (try file.length(io) != stat.size) return error.FileChangedDuringRead;
    return bytes;
}

pub fn readOptionalFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, max_size: u64) !?[]u8 {
    return readFileAlloc(allocator, io, dir, path, max_size) catch |err| switch (err) {
        error.FileNotFound => null,
        else => |e| return e,
    };
}

// windows: write/namespace exclusion; posix: identity pin only
pub fn openReadAuthority(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    return openRetainedReadAuthority(io, dir, sub_path, false);
}

// package below destination: read handle retained, namespace changes allowed
pub fn openReadContentAuthority(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    return openRetainedReadAuthority(io, dir, sub_path, true);
}

fn openRetainedReadAuthority(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    allow_namespace_changes: bool,
) !std.Io.File {
    var file = if (builtin.target.os.tag == .windows)
        try openReadAuthorityWindows(io, dir, sub_path, allow_namespace_changes)
    else
        try openRead(io, dir, sub_path);
    errdefer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.ExpectedFile;
    return file;
}

pub fn openMetadataNoFollow(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    if (std.mem.eql(u8, sub_path, ".") or std.mem.eql(u8, sub_path, "..")) return error.BadPathName;

    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const wide = path_space.span();
    const root: ?windows.HANDLE = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) null else dir.handle;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    var attempt: u5 = 0;
    while (true) {
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .SPECIFIC = .{ .FILE = .{ .READ_ATTRIBUTES = true } },
                .STANDARD = .{ .SYNCHRONIZE = true },
            },
            &.{
                .RootDirectory = root,
                .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            .OPEN,
            .{
                .IO = .SYNCHRONOUS_NONALERT,
                .OPEN_FOR_BACKUP_INTENT = true,
                .OPEN_REPARSE_POINT = true,
            },
            null,
            0,
        );

        switch (status) {
            .SUCCESS => return .{ .handle = handle, .flags = .{ .nonblocking = false } },
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
            .NO_MEDIA_IN_DEVICE, .PIPE_NOT_AVAILABLE => return error.NoDevice,
            .PIPE_BUSY => return error.PipeBusy,
            .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
            .NOT_A_DIRECTORY => return error.NotDir,
            .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            .SHARING_VIOLATION, .DELETE_PENDING => {
                if (attempt >= 13) return error.FileBusy;
                try std.Io.sleep(io, .fromMilliseconds((@as(u32, 1) << attempt) >> 1), .awake);
                attempt += 1;
            },
            else => return error.Unexpected,
        }
    }
}

pub const WindowsFileIdentity = struct {
    volume_serial_number: u32,
    index_number: i64,

    pub fn eql(a: WindowsFileIdentity, b: WindowsFileIdentity) bool {
        return a.volume_serial_number == b.volume_serial_number and
            a.index_number == b.index_number;
    }
};

pub fn windowsFileIdentity(file: std.Io.File) !WindowsFileIdentity {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    return windowsHandleIdentity(file.handle);
}

pub fn windowsDirIdentity(dir: std.Io.Dir) !WindowsFileIdentity {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    return windowsHandleIdentity(dir.handle);
}

// on-disk casing for case-insensitive aliases
pub fn windowsOpenedBasenameAlloc(
    allocator: std.mem.Allocator,
    file: std.Io.File,
) ![]u8 {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    const wide_buffer = try allocator.alloc(u16, windows.PATH_MAX_WIDE);
    defer allocator.free(wide_buffer);
    const full = try std.Io.Threaded.GetFinalPathNameByHandle(file.handle, .{}, wide_buffer);
    const slash = std.mem.lastIndexOfAny(u16, full, &.{ '\\', '/' }) orelse return error.Unexpected;
    const basename = full[slash + 1 ..];
    if (basename.len == 0) return error.Unexpected;
    const encoded = try allocator.alloc(u8, basename.len * 3);
    errdefer allocator.free(encoded);
    const len = std.unicode.wtf16LeToWtf8(encoded, basename);
    return allocator.realloc(encoded, len);
}

pub const ObjectIdentity = union(enum) {
    windows: WindowsFileIdentity,
    posix: PosixFileIdentity,

    pub fn eql(a: ObjectIdentity, b: ObjectIdentity) bool {
        return switch (a) {
            .windows => |left| switch (b) {
                .windows => |right| left.eql(right),
                .posix => false,
            },
            .posix => |left| switch (b) {
                .windows => false,
                .posix => |right| left.device == right.device and left.inode == right.inode,
            },
        };
    }
};

pub fn openFileIdentity(file: std.Io.File) !ObjectIdentity {
    if (builtin.target.os.tag == .windows) return .{ .windows = try windowsFileIdentity(file) };
    return .{ .posix = try posixHandleIdentity(file.handle) };
}

pub fn openDirIdentity(dir: std.Io.Dir) !ObjectIdentity {
    if (builtin.target.os.tag == .windows) return .{ .windows = try windowsDirIdentity(dir) };
    return .{ .posix = try posixHandleIdentity(dir.handle) };
}

pub fn sameOpenFile(io: std.Io, left: std.Io.File, right: std.Io.File) !bool {
    _ = io;
    return (try openFileIdentity(left)).eql(try openFileIdentity(right));
}

pub const PosixFileIdentity = struct {
    device: u128,
    inode: u128,
};

fn posixHandleIdentity(handle: anytype) !PosixFileIdentity {
    if (builtin.target.os.tag == .linux) return linuxHandleIdentity(handle);

    var stat = std.mem.zeroes(std.c.Stat);
    while (true) switch (std.c.errno(std.c.fstat(handle, &stat))) {
        .SUCCESS => return .{
            .device = unsignedIntegerBits(stat.dev),
            .inode = unsignedIntegerBits(stat.ino),
        },
        .INTR => continue,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

fn linuxHandleIdentity(handle: anytype) !PosixFileIdentity {
    const linux = std.os.linux;
    var statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(
        handle,
        "",
        linux.AT.EMPTY_PATH,
        .{ .INO = true },
        &statx,
    ))) {
        .SUCCESS => {
            if (!statx.mask.INO) return error.Unexpected;
            return .{
                .device = (@as(u128, statx.dev_major) << 32) |
                    @as(u128, statx.dev_minor),
                .inode = statx.ino,
            };
        },
        .INTR => continue,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

fn unsignedIntegerBits(value: anytype) u128 {
    const Unsigned = @Int(.unsigned, @bitSizeOf(@TypeOf(value)));
    return @as(Unsigned, @bitCast(value));
}

pub fn validateGuardedOutputAuthority(io: std.Io, file: std.Io.File) !std.Io.File.Stat {
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.nlink != 1) return error.UnsafeGuardedOutput;
    if (!try guardedOutputIsWritable(file)) return error.UnsafeGuardedOutput;
    return stat;
}

pub fn validateGuardedOutput(io: std.Io, file: std.Io.File, expected_size: u64) !void {
    const stat = try validateGuardedOutputAuthority(io, file);
    if (stat.size != expected_size) return error.UnsafeGuardedOutput;
}

fn guardedOutputIsWritable(file: std.Io.File) !bool {
    if (builtin.target.os.tag == .windows) {
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var access: windows.FILE.ACCESS_INFORMATION = undefined;
        switch (windows.ntdll.NtQueryInformationFile(
            file.handle,
            &io_status,
            &access,
            @sizeOf(windows.FILE.ACCESS_INFORMATION),
            .Access,
        )) {
            .SUCCESS => {},
            else => |status| return windows.unexpectedStatus(status),
        }
        return access.AccessFlags.SPECIFIC.FILE.WRITE_DATA or
            access.AccessFlags.GENERIC.WRITE;
    }

    while (true) {
        const rc = std.posix.system.fcntl(
            file.handle,
            std.posix.F.GETFL,
            @as(usize, 0),
        );
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const FlagsInt = @Int(.unsigned, @bitSizeOf(std.posix.O));
                const flags: std.posix.O = @bitCast(@as(FlagsInt, @intCast(rc)));
                return flags.ACCMODE != .RDONLY;
            },
            .INTR => continue,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn windowsHandleIdentity(handle: windows.HANDLE) !WindowsFileIdentity {
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var volume_info: windows.FILE.FS_VOLUME_INFORMATION = undefined;
    switch (windows.ntdll.NtQueryVolumeInformationFile(
        handle,
        &io_status,
        &volume_info,
        @sizeOf(windows.FILE.FS_VOLUME_INFORMATION),
        .Volume,
    )) {
        .SUCCESS, .BUFFER_OVERFLOW => {},
        else => |status| return windows.unexpectedStatus(status),
    }

    var internal_info: windows.FILE.INTERNAL_INFORMATION = undefined;
    switch (windows.ntdll.NtQueryInformationFile(
        handle,
        &io_status,
        &internal_info,
        @sizeOf(windows.FILE.INTERNAL_INFORMATION),
        .Internal,
    )) {
        .SUCCESS => {},
        else => |status| return windows.unexpectedStatus(status),
    }
    return .{
        .volume_serial_number = volume_info.VolumeSerialNumber,
        .index_number = internal_info.IndexNumber,
    };
}

pub fn openReadBeneath(io: std.Io, root: std.Io.Dir, sub_path: []const u8) !std.Io.File {
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openRead(io, parent.dir, parent.basename);
}

pub fn openReadAuthorityBeneath(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openReadAuthority(io, parent.dir, parent.basename);
}

pub fn openMetadataBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openMetadataNoFollow(io, parent.dir, parent.basename);
}

// backup: write/delete exclusion until exact-object rename
pub fn openBackupAuthorityBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openNamespaceAuthorityWindows(io, parent.dir, parent.basename, .{ .READ = true }, false);
}

// mutation: content writes allowed, DELETE sharing denied
pub fn openMutationAuthorityBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openNamespaceAuthorityWindows(io, parent.dir, parent.basename, .{
        .READ = true,
        .WRITE = true,
    }, false);
}

// write sharing only after DIRECTORY_FILE check
pub fn openMutationDirectoryAuthorityBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return openNamespaceAuthorityWindows(io, parent.dir, parent.basename, .{
        .READ = true,
        .WRITE = true,
    }, true);
}

pub const BeneathParent = struct {
    dir: std.Io.Dir,
    basename: []const u8,
    owned: bool,

    pub fn close(parent: *BeneathParent, io: std.Io) void {
        if (parent.owned) parent.dir.close(io);
        parent.* = undefined;
    }
};

pub const EntryInfo = struct {
    kind: std.Io.File.Kind,
    size: u64,
};

// windows statFile: extra open per entry; pinned-parent query instead
pub fn queryEntryBeneath(io: std.Io, dir: std.Io.Dir, name: []const u8) !EntryInfo {
    if (builtin.target.os.tag != .windows) {
        const stat = try dir.statFile(io, name, .{ .follow_symlinks = false });
        return .{ .kind = stat.kind, .size = stat.size };
    }
    var wide: [std.fs.max_path_bytes]u16 = undefined;
    const wide_len = std.unicode.utf8ToUtf16Le(&wide, name) catch return error.BadPathName;
    if (wide_len == 0) return error.BadPathName;
    const filter = windows.UNICODE_STRING.init(wide[0..wide_len]);

    var buffer: [@sizeOf(windows.FILE_BOTH_DIR_INFORMATION) + windows.NAME_MAX * 2]u8 align(@alignOf(windows.FILE_BOTH_DIR_INFORMATION)) = undefined;
    var block: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtQueryDirectoryFile(
        dir.handle,
        null,
        null,
        null,
        &block,
        &buffer,
        buffer.len,
        .BothDirectory,
        windows.BOOLEAN.TRUE, // ReturnSingleEntry
        &filter,
        windows.BOOLEAN.TRUE, // RestartScan: independent query
    );
    switch (status) {
        .SUCCESS => {},
        .NO_SUCH_FILE, .NO_MORE_FILES, .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_PARAMETER => return error.BadPathName,
        else => return error.Unexpected,
    }
    const info: *const windows.FILE_BOTH_DIR_INFORMATION = @ptrCast(@alignCast(&buffer));
    const attributes = info.FileAttributes;
    const kind: std.Io.File.Kind = if (attributes.REPARSE_POINT)
        .sym_link
    else if (attributes.DIRECTORY)
        .directory
    else
        .file;
    const end = info.EndOfFile;
    if (end < 0) return error.Unexpected;
    return .{ .kind = kind, .size = @intCast(end) };
}

// pinned no-follow parents against ancestor redirection
pub fn openParentBeneath(io: std.Io, root: std.Io.Dir, sub_path: []const u8) !BeneathParent {
    try logical_path.validate(sub_path);

    var current = root;
    var owned_current: ?std.Io.Dir = null;
    errdefer if (owned_current) |dir| dir.close(io);

    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, sub_path, start, '/')) |slash| {
        const component = sub_path[start..slash];
        const component_stat = current.statFile(io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.NotDir => return error.PathAncestorNotDirectory,
            else => |other| return other,
        };
        if (component_stat.kind != .directory) {
            if (component_stat.kind == .file) return error.PathAncestorNotDirectory;
            return error.UnsafePathAncestor;
        }
        const next = current.openDir(io, component, .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.NotDir => return error.PathAncestorNotDirectory,
            error.SymLinkLoop => return error.UnsafePathAncestor,
            else => |other| return other,
        };
        errdefer next.close(io);
        const stat = try next.stat(io);
        if (stat.kind != .directory) {
            if (stat.kind == .file) return error.PathAncestorNotDirectory;
            return error.UnsafePathAncestor;
        }

        if (owned_current) |dir| dir.close(io);
        owned_current = next;
        current = next;
        start = slash + 1;
    }
    return .{
        .dir = current,
        .basename = sub_path[start..],
        .owned = owned_current != null,
    };
}

pub fn createDirPathBeneath(io: std.Io, root: std.Io.Dir, sub_path: []const u8) !void {
    try logical_path.validate(sub_path);

    var current = root;
    var owned_current: ?std.Io.Dir = null;
    defer if (owned_current) |dir| dir.close(io);

    var iterator = std.mem.splitScalar(u8, sub_path, '/');
    while (iterator.next()) |component| {
        current.createDir(io, component, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |other| return other,
        };
        const component_stat = current.statFile(io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.NotDir => return error.PathAncestorNotDirectory,
            else => |other| return other,
        };
        if (component_stat.kind != .directory) {
            if (component_stat.kind == .file) return error.PathAncestorNotDirectory;
            return error.UnsafePathAncestor;
        }
        const next = current.openDir(io, component, .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.NotDir => return error.PathAncestorNotDirectory,
            error.SymLinkLoop => return error.UnsafePathAncestor,
            else => |other| return other,
        };
        errdefer next.close(io);
        const stat = try next.stat(io);
        if (stat.kind != .directory) {
            if (stat.kind == .file) return error.PathAncestorNotDirectory;
            return error.UnsafePathAncestor;
        }

        if (owned_current) |dir| dir.close(io);
        owned_current = next;
        current = next;
    }
}

pub fn createParentPathBeneath(io: std.Io, root: std.Io.Dir, sub_path: []const u8) !void {
    try logical_path.validate(sub_path);
    const slash = std.mem.lastIndexOfScalar(u8, sub_path, '/') orelse return;
    if (slash != 0) try createDirPathBeneath(io, root, sub_path[0..slash]);
}

// windows: retained DELETE authority for exact rollback
pub fn createGuardedDirectory(
    io: std.Io,
    parent: std.Io.Dir,
    basename: []const u8,
) !std.Io.Dir {
    try logical_path.validate(basename);
    if (std.mem.indexOfScalar(u8, basename, '/') != null) return error.UnsafePath;
    if (builtin.target.os.tag != .windows) {
        // owner-only access to transaction objects
        try parent.createDir(io, basename, @fromBackingInt(0o700));
        return parent.openDir(io, basename, .{
            .access_sub_paths = true,
            .follow_symlinks = false,
        });
    }
    return createGuardedDirectoryWindows(parent, basename);
}

// delete pending on success; close immediately
pub fn deleteOpenDirectoryWindows(directory: std.Io.Dir) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    return deleteOpenHandleWindows(directory.handle);
}

// atomic rejection of nonempty directories
pub fn deleteOpenObjectWindows(object: std.Io.File) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    return deleteOpenHandleWindows(object.handle);
}

// no pathname-delete fallback: possible replacement object
pub fn discardOpenObjectWindows(io: std.Io, object: std.Io.File) !void {
    defer object.close(io);
    try deleteOpenObjectWindows(object);
}

fn deleteOpenHandleWindows(handle: windows.HANDLE) !void {
    var disposition: windows.FILE.DISPOSITION.INFORMATION = .{ .DeleteFile = .TRUE };
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtSetInformationFile(
        handle,
        &io_status_block,
        &disposition,
        @sizeOf(windows.FILE.DISPOSITION.INFORMATION),
        .Disposition,
    );
    switch (status) {
        .SUCCESS => {},
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .ACCESS_DENIED, .CANNOT_DELETE, .MEDIA_WRITE_PROTECTED => return error.AccessDenied,
        .SHARING_VIOLATION, .DELETE_PENDING => return error.FileBusy,
        .INVALID_HANDLE, .INVALID_PARAMETER => |bug| return windows.statusBug(bug),
        else => return windows.unexpectedStatus(status),
    }
}

pub fn createFileBeneath(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
    options: std.Io.Dir.CreateFileOptions,
) !std.Io.File {
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return parent.dir.createFile(io, parent.basename, options);
}

// windows: DELETE-shared verification; duplicated writer guards
pub fn createGuardedOutput(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) {
        return dir.createFile(io, sub_path, .{
            .read = true,
            .truncate = false,
            .exclusive = true,
        });
    }
    return createGuardedOutputWindows(io, dir, sub_path);
}

// duplicated writer handles; read-only identity reopens
pub fn createConstructionOutput(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) {
        return dir.createFile(io, sub_path, .{
            .read = true,
            .truncate = false,
            .exclusive = true,
            .permissions = @fromBackingInt(0o600),
        });
    }
    return createGuardedOutputWindows(io, dir, sub_path);
}

const private_construction_candidates = 1024;
const private_construction_file = "package";

pub const PrivateConstructionOutput = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    parent: std.Io.Dir,
    directory_name: []u8,
    directory: ?std.Io.Dir,
    // file() borrows this handle
    output: ?std.Io.File,
    published: bool = false,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        parent: std.Io.Dir,
    ) !PrivateConstructionOutput {
        for (0..private_construction_candidates) |_| {
            var random: [16]u8 = undefined;
            try io.randomSecure(&random);
            const encoded = std.fmt.bytesToHex(random, .lower);
            const directory_name = try allocator.print(
                ".zift-create-{s}",
                .{&encoded},
            );
            errdefer allocator.free(directory_name);

            const directory = createGuardedDirectory(io, parent, directory_name) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(directory_name);
                    continue;
                },
                else => |other| return other,
            };
            var directory_owned = true;
            errdefer if (directory_owned) {
                if (builtin.target.os.tag == .windows)
                    deleteOpenDirectoryWindows(directory) catch {}
                else if (privateDirectoryBindingMatches(io, parent, directory_name, directory))
                    parent.deleteDir(io, directory_name) catch {};
                directory.close(io);
            };

            const output = try createConstructionOutput(io, directory, private_construction_file);
            directory_owned = false;
            return .{
                .allocator = allocator,
                .io = io,
                .parent = parent,
                .directory_name = directory_name,
                .directory = directory,
                .output = output,
            };
        }
        return error.NoAvailableConstructionWorkspace;
    }

    pub fn file(self: *const PrivateConstructionOutput) !std.Io.File {
        return self.output orelse error.ConstructionOutputClosed;
    }

    pub fn requireBinding(self: *const PrivateConstructionOutput, expected_size: u64) !void {
        const directory = self.directory orelse return error.ConstructionOutputClosed;
        const output = self.output orelse return error.ConstructionOutputClosed;
        try requireConstructionOutputBinding(
            self.io,
            directory,
            private_construction_file,
            output,
            expected_size,
        );
    }

    pub fn publish(self: *PrivateConstructionOutput, final_name: []const u8, expected_size: u64) !void {
        const directory = self.directory orelse return error.ConstructionOutputClosed;
        const output = self.output orelse return error.ConstructionOutputClosed;
        try publishConstructionOutput(
            self.io,
            directory,
            private_construction_file,
            self.parent,
            final_name,
            output,
            expected_size,
        );
        self.published = true;
    }

    pub fn deinit(self: *PrivateConstructionOutput) void {
        const directory = self.directory;
        if (self.output) |output| {
            if (!self.published) {
                if (builtin.target.os.tag == .windows)
                    deleteOpenObjectWindows(output) catch {}
                else if (directory) |dir| {
                    // contamination: preserve workspace
                    if (constructionOutputBindingMatches(
                        self.io,
                        dir,
                        private_construction_file,
                        output,
                    )) dir.deleteFile(self.io, private_construction_file) catch {};
                }
            }
            output.close(self.io);
            self.output = null;
        }

        if (directory) |dir| {
            if (builtin.target.os.tag == .windows)
                deleteOpenDirectoryWindows(dir) catch {}
            else if (privateDirectoryBindingMatches(self.io, self.parent, self.directory_name, dir))
                self.parent.deleteDir(self.io, self.directory_name) catch {};
            dir.close(self.io);
            self.directory = null;
        }
        if (self.directory_name.len != 0) self.allocator.free(self.directory_name);
        self.directory_name = &.{};
    }
};

fn constructionOutputBindingMatches(
    io: std.Io,
    directory: std.Io.Dir,
    name: []const u8,
    output: std.Io.File,
) bool {
    var rebound = openRead(io, directory, name) catch return false;
    defer rebound.close(io);
    return sameOpenFile(io, output, rebound) catch false;
}

fn privateDirectoryBindingMatches(
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
    directory: std.Io.Dir,
) bool {
    var rebound = parent.openDir(io, name, .{
        .access_sub_paths = true,
        .follow_symlinks = false,
    }) catch return false;
    defer rebound.close(io);
    const expected = openDirIdentity(directory) catch return false;
    const actual = openDirIdentity(rebound) catch return false;
    return expected.eql(actual);
}

pub fn requireConstructionOutputBinding(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    authority: std.Io.File,
    expected_size: u64,
) !void {
    try validateGuardedOutput(io, authority, expected_size);
    var rebound = try openRead(io, dir, sub_path);
    defer rebound.close(io);
    if (!try sameOpenFile(io, authority, rebound))
        return error.ConstructionOutputBindingChanged;
    try validateGuardedOutput(io, authority, expected_size);
}

pub fn publishConstructionOutput(
    io: std.Io,
    staging_dir: std.Io.Dir,
    staging_name: []const u8,
    final_dir: std.Io.Dir,
    final_name: []const u8,
    authority: std.Io.File,
    expected_size: u64,
) !void {
    try requireConstructionOutputBinding(io, staging_dir, staging_name, authority, expected_size);
    if (builtin.target.os.tag == .windows) {
        renameGuardedOutputBeneath(io, final_dir, final_name, authority, expected_size) catch |err| {
            if (err != error.PublishedBindingChanged) return err;
            // rename complete; rollback by retained object
            renameOpenFileBeneathWindows(io, staging_dir, staging_name, authority) catch
                return error.PublicationOutcomeUnknown;
            return error.PublishedBindingChanged;
        };
        return;
    }

    try staging_dir.renamePreserve(staging_name, final_dir, final_name, io);
    var rebound = openRead(io, final_dir, final_name) catch
        return error.PublishedBindingChanged;
    defer rebound.close(io);
    if (!(sameOpenFile(io, authority, rebound) catch
        return error.PublishedBindingChanged))
        return error.PublishedBindingChanged;
    validateGuardedOutput(io, authority, expected_size) catch
        return error.PublishedBindingChanged;
}

pub fn createGuardedOutputBeneath(
    io: std.Io,
    root: std.Io.Dir,
    sub_path: []const u8,
) !std.Io.File {
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return createGuardedOutput(io, parent.dir, parent.basename);
}

// PublishedBindingChanged after completed rename
pub fn renameGuardedOutputBeneath(
    io: std.Io,
    root: std.Io.Dir,
    target_sub_path: []const u8,
    guarded: std.Io.File,
    expected_size: u64,
) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    try validateGuardedOutput(io, guarded, expected_size);

    var parent = try openParentBeneath(io, root, target_sub_path);
    defer parent.close(io);
    try renameGuardedOutputWindows(guarded, parent.dir, parent.basename);

    validateGuardedOutput(io, guarded, expected_size) catch
        return error.PublishedBindingChanged;
    var rebound = openReadBeneath(io, root, target_sub_path) catch
        return error.PublishedBindingChanged;
    defer rebound.close(io);
    if (!(sameOpenFile(io, guarded, rebound) catch
        return error.PublishedBindingChanged))
        return error.PublishedBindingChanged;
    validateGuardedOutput(io, guarded, expected_size) catch
        return error.PublishedBindingChanged;
}

// rollback by retained object, even after new hard links
pub fn renameOpenFileBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    target_sub_path: []const u8,
    file: std.Io.File,
) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, target_sub_path);
    defer parent.close(io);
    try renameGuardedOutputWindows(file, parent.dir, parent.basename);

    var rebound = openReadBeneath(io, root, target_sub_path) catch
        return error.PublishedBindingChanged;
    defer rebound.close(io);
    if (!(sameOpenFile(io, file, rebound) catch
        return error.PublishedBindingChanged))
        return error.PublishedBindingChanged;
}

pub fn renameOpenObjectBeneathWindows(
    io: std.Io,
    root: std.Io.Dir,
    target_sub_path: []const u8,
    object: std.Io.File,
) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    var parent = try openParentBeneath(io, root, target_sub_path);
    defer parent.close(io);
    try renameGuardedOutputWindows(object, parent.dir, parent.basename);

    var rebound = openMetadataBeneathWindows(io, root, target_sub_path) catch
        return error.PublishedBindingChanged;
    defer rebound.close(io);
    if (!(sameOpenFile(io, object, rebound) catch
        return error.PublishedBindingChanged))
        return error.PublishedBindingChanged;
}

pub fn deleteFileBeneath(io: std.Io, root: std.Io.Dir, sub_path: []const u8) !void {
    var parent = try openParentBeneath(io, root, sub_path);
    defer parent.close(io);
    return parent.dir.deleteFile(io, parent.basename);
}

pub fn openWrite(io: std.Io, dir: std.Io.Dir, sub_path: []const u8) std.Io.File.OpenError!std.Io.File {
    return openExisting(io, dir, sub_path, .write_only);
}

pub fn openReadWrite(io: std.Io, dir: std.Io.Dir, sub_path: []const u8) std.Io.File.OpenError!std.Io.File {
    return openExisting(io, dir, sub_path, .read_write);
}

// no truncation before protected-input alias checks
pub fn openOrCreateReadWrite(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) std.Io.File.OpenError!std.Io.File {
    if (builtin.target.os.tag != .windows) {
        return dir.createFile(io, sub_path, .{ .read = true, .truncate = false });
    }
    if (std.mem.eql(u8, sub_path, ".") or std.mem.eql(u8, sub_path, "..")) return error.IsDir;

    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const wide = path_space.span();
    const root: ?windows.HANDLE = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) null else dir.handle;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    var attempt: u5 = 0;
    while (true) {
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true, .WRITE = true },
            },
            &.{
                .RootDirectory = root,
                .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            .OPEN_IF,
            .{
                .IO = .SYNCHRONOUS_NONALERT,
                .NON_DIRECTORY_FILE = true,
                .OPEN_REPARSE_POINT = true,
            },
            null,
            0,
        );

        switch (status) {
            .SUCCESS => return .{ .handle = handle, .flags = .{ .nonblocking = false } },
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
            .NO_MEDIA_IN_DEVICE, .PIPE_NOT_AVAILABLE => return error.NoDevice,
            .PIPE_BUSY => return error.PipeBusy,
            .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
            .FILE_IS_A_DIRECTORY => return error.IsDir,
            .NOT_A_DIRECTORY => return error.NotDir,
            .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            .DISK_FULL => return error.NoSpaceLeft,
            .SHARING_VIOLATION, .DELETE_PENDING => {
                if (attempt >= 13) return error.FileBusy;
                try std.Io.sleep(io, .fromMilliseconds((@as(u32, 1) << attempt) >> 1), .awake);
                attempt += 1;
            },
            else => return error.Unexpected,
        }
    }
}

fn openReadAuthorityWindows(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    allow_namespace_changes: bool,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    if (std.mem.eql(u8, sub_path, ".") or std.mem.eql(u8, sub_path, ".."))
        return error.IsDir;

    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const wide = path_space.span();
    const root: ?windows.HANDLE = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) null else dir.handle;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    var attempt: u5 = 0;
    while (true) {
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true },
            },
            &.{
                .RootDirectory = root,
                .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            // source: pinned name; package: retained reads across rename
            if (allow_namespace_changes)
                .{ .READ = true, .DELETE = true }
            else
                .{ .READ = true },
            .OPEN,
            .{
                .IO = .SYNCHRONOUS_NONALERT,
                .NON_DIRECTORY_FILE = true,
                .OPEN_REPARSE_POINT = true,
            },
            null,
            0,
        );

        switch (status) {
            .SUCCESS => return .{ .handle = handle, .flags = .{ .nonblocking = false } },
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
            .NO_MEDIA_IN_DEVICE, .PIPE_NOT_AVAILABLE => return error.NoDevice,
            .PIPE_BUSY => return error.PipeBusy,
            .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
            .FILE_IS_A_DIRECTORY => return error.IsDir,
            .NOT_A_DIRECTORY => return error.NotDir,
            .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            .SHARING_VIOLATION, .DELETE_PENDING => {
                if (attempt >= 13) return error.FileBusy;
                try std.Io.sleep(io, .fromMilliseconds((@as(u32, 1) << attempt) >> 1), .awake);
                attempt += 1;
            },
            else => return error.Unexpected,
        }
    }
}

fn createGuardedOutputWindows(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) std.Io.File.OpenError!std.Io.File {
    _ = io;
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    if (std.mem.eql(u8, sub_path, ".") or std.mem.eql(u8, sub_path, "..")) return error.IsDir;

    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const wide = path_space.span();
    const root: ?windows.HANDLE = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) null else dir.handle;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{
            .STANDARD = .{
                .RIGHTS = .{ .DELETE = true },
                .SYNCHRONIZE = true,
            },
            .GENERIC = .{ .READ = true, .WRITE = true },
        },
        &.{
            .RootDirectory = root,
            .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
        },
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .{ .READ = true },
        .CREATE,
        .{
            .IO = .SYNCHRONOUS_NONALERT,
            .NON_DIRECTORY_FILE = true,
            .OPEN_REPARSE_POINT = true,
        },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => return .{ .handle = handle, .flags = .{ .nonblocking = false } },
        .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
        .NO_MEDIA_IN_DEVICE, .PIPE_NOT_AVAILABLE => return error.NoDevice,
        .PIPE_BUSY => return error.PipeBusy,
        .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
        .DISK_FULL => return error.NoSpaceLeft,
        .SHARING_VIOLATION, .DELETE_PENDING => return error.FileBusy,
        else => return error.Unexpected,
    }
}

fn openNamespaceAuthorityWindows(
    io: std.Io,
    parent: std.Io.Dir,
    basename: []const u8,
    share: windows.FILE.SHARE,
    directory_only: bool,
) !std.Io.File {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(parent.handle, basename, .{});
    const wide = path_space.span();
    if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) return error.BadPathName;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    var attempt: u5 = 0;
    while (true) {
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .SPECIFIC = .{ .FILE = .{ .READ_ATTRIBUTES = true } },
                .STANDARD = .{
                    .RIGHTS = .{ .DELETE = true },
                    .SYNCHRONIZE = true,
                },
            },
            &.{
                .RootDirectory = parent.handle,
                .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            share,
            .OPEN,
            .{
                .IO = .SYNCHRONOUS_NONALERT,
                .DIRECTORY_FILE = directory_only,
                .OPEN_FOR_BACKUP_INTENT = true,
                .OPEN_REPARSE_POINT = true,
            },
            null,
            0,
        );
        switch (status) {
            .SUCCESS => return .{ .handle = handle, .flags = .{ .nonblocking = false } },
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
            .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
            .NOT_A_DIRECTORY => return error.NotDir,
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            .SHARING_VIOLATION, .DELETE_PENDING => {
                if (attempt >= 13) return error.FileBusy;
                try std.Io.sleep(io, .fromMilliseconds((@as(u32, 1) << attempt) >> 1), .awake);
                attempt += 1;
            },
            else => return error.Unexpected,
        }
    }
}

fn createGuardedDirectoryWindows(
    parent: std.Io.Dir,
    basename: []const u8,
) !std.Io.Dir {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;
    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(parent.handle, basename, .{});
    const wide = path_space.span();
    if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) return error.BadPathName;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{
            .SPECIFIC = .{ .FILE_DIRECTORY = .{
                .LIST = true,
                .ADD_FILE = true,
                .ADD_SUBDIRECTORY = true,
                .READ_EA = true,
                .TRAVERSE = true,
                .DELETE_CHILD = true,
                .READ_ATTRIBUTES = true,
            } },
            .STANDARD = .{
                .RIGHTS = .{ .DELETE = true },
                .SYNCHRONIZE = true,
            },
        },
        &.{
            .RootDirectory = parent.handle,
            .ObjectName = @constCast(&windows.UNICODE_STRING.init(wide)),
        },
        &io_status_block,
        null,
        .{ .NORMAL = true },
        // child mutations allowed; exact rollback through retained DELETE authority
        .{ .READ = true, .WRITE = true },
        .CREATE,
        .{
            .DIRECTORY_FILE = true,
            .IO = .SYNCHRONOUS_NONALERT,
            .OPEN_FOR_BACKUP_INTENT = true,
            .OPEN_REPARSE_POINT = true,
        },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => return .{ .handle = handle },
        .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
        .ACCESS_DENIED, .USER_MAPPED_FILE => return error.AccessDenied,
        .NOT_A_DIRECTORY => return error.NotDir,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
        .DISK_FULL => return error.NoSpaceLeft,
        .SHARING_VIOLATION, .DELETE_PENDING => return error.FileBusy,
        else => return error.Unexpected,
    }
}

fn renameGuardedOutputWindows(
    guarded: std.Io.File,
    target_parent: std.Io.Dir,
    target_basename: []const u8,
) !void {
    if (builtin.target.os.tag != .windows) return error.OperationUnsupported;

    const path_space = try std.Io.Threaded.sliceToPrefixedFileW(
        target_parent.handle,
        target_basename,
        .{},
    );
    const wide = path_space.span();
    if (std.Io.Dir.path.isAbsoluteWindowsWtf16(wide)) return error.BadPathName;

    var rename_info: windows.FILE.RENAME_INFORMATION = .init(.{
        .Flags = .{},
        .RootDirectory = target_parent.handle,
        .FileName = wide,
    });
    const rename_buffer = rename_info.toBuffer();
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtSetInformationFile(
        guarded.handle,
        &io_status_block,
        rename_buffer.ptr,
        @intCast(rename_buffer.len),
        .Rename,
    );
    switch (status) {
        .SUCCESS => {},
        .INVALID_HANDLE, .INVALID_PARAMETER, .OBJECT_PATH_SYNTAX_BAD => |bug| return windows.statusBug(bug),
        .ACCESS_DENIED, .CANNOT_DELETE, .USER_MAPPED_FILE => return error.AccessDenied,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .OBJECT_NAME_INVALID => return error.BadPathName,
        .NOT_SAME_DEVICE => return error.CrossDevice,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        .MEDIA_WRITE_PROTECTED => return error.ReadOnlyFileSystem,
        .DISK_FULL => return error.NoSpaceLeft,
        .QUOTA_EXCEEDED, .DISK_QUOTA_EXCEEDED => return error.DiskQuota,
        .SHARING_VIOLATION, .DELETE_PENDING, .FILE_DELETED => return error.FileBusy,
        .NO_MEDIA_IN_DEVICE => return error.NoDevice,
        .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
        .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
        .CANCELLED => return error.Canceled,
        else => return windows.unexpectedStatus(status),
    }
}

// single read boundary for fault injection
pub fn readAllAt(io: std.Io, file: std.Io.File, buffer: []u8, offset: u64) !usize {
    return file.readPositionalAll(io, buffer, offset);
}

test "entry query matches a no-follow stat without opening the object" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "plain.bin", .data = "0123456789" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "empty.bin", .data = "" });
    var dir = try tmp.dir.openDir(io, ".", .{ .iterate = true, .access_sub_paths = true, .follow_symlinks = false });
    defer dir.close(io);

    const observed = try queryEntryBeneath(io, dir, "plain.bin");
    const stat = try dir.statFile(io, "plain.bin", .{ .follow_symlinks = false });
    try std.testing.expectEqual(stat.kind, observed.kind);
    try std.testing.expectEqual(stat.size, observed.size);
    try std.testing.expectEqual(@as(u64, 10), observed.size);

    const empty = try queryEntryBeneath(io, dir, "empty.bin");
    try std.testing.expectEqual(@as(u64, 0), empty.size);
    try std.testing.expectEqual(std.Io.File.Kind.file, empty.kind);
    const dir_entry = try queryEntryBeneath(io, dir, "sub");
    try std.testing.expectEqual(std.Io.File.Kind.directory, dir_entry.kind);

    try std.testing.expectError(error.FileNotFound, queryEntryBeneath(io, dir, "absent.bin"));

    for (0..3) |_| {
        const again = try queryEntryBeneath(io, dir, "plain.bin");
        try std.testing.expectEqual(@as(u64, 10), again.size);
    }
}

test "Windows-safe no-follow open reports a missing path" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.FileNotFound, openRead(io, tmp.dir, "missing.bin"));
}

test "open-or-create read-write preserves bytes until the caller truncates" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "existing.bin", .data = "sentinel" });

    var existing = try openOrCreateReadWrite(io, tmp.dir, "existing.bin");
    defer existing.close(io);
    var bytes: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, bytes.len), try existing.readPositionalAll(io, &bytes, 0));
    try std.testing.expectEqualStrings("sentinel", &bytes);

    var created = try openOrCreateReadWrite(io, tmp.dir, "created.bin");
    defer created.close(io);
    try std.testing.expectEqual(@as(u64, 0), try created.length(io));
    try created.writePositionalAll(io, "new", 0);
}

test "open handles compare by physical identity" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "left.bin", .data = "left" });
    try tmp.dir.writeFile(io, .{ .sub_path = "right.bin", .data = "right" });

    var left = try openRead(io, tmp.dir, "left.bin");
    defer left.close(io);
    var left_again = try openRead(io, tmp.dir, "left.bin");
    defer left_again.close(io);
    var right = try openRead(io, tmp.dir, "right.bin");
    defer right.close(io);

    try std.testing.expect(try sameOpenFile(io, left, left_again));
    try std.testing.expect(!try sameOpenFile(io, left, right));
}

test "Windows hard links compare as one physical file" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "original.bin", .data = "identity" });
    try hardLinkInTmp(allocator, &tmp, "original.bin", "alias.bin");

    var original = try openRead(io, tmp.dir, "original.bin");
    defer original.close(io);
    var alias = try openRead(io, tmp.dir, "alias.bin");
    defer alias.close(io);
    try std.testing.expect(try sameOpenFile(io, original, alias));
}

test "Windows read authority pins the selected Source name until close" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "source-authority.bin", .data = "stable" });

    var authority: ?std.Io.File = try openReadAuthorityBeneath(
        io,
        tmp.dir,
        "source-authority.bin",
    );
    defer if (authority) |file| file.close(io);

    var renamed = true;
    tmp.dir.rename(
        "source-authority.bin",
        tmp.dir,
        "moved-authority.bin",
        io,
    ) catch {
        renamed = false;
    };
    try std.testing.expect(!renamed);
    var rebound = try openRead(io, tmp.dir, "source-authority.bin");
    defer rebound.close(io);
    try std.testing.expect(try sameOpenFile(io, authority.?, rebound));

    authority.?.close(io);
    authority = null;
    try tmp.dir.rename(
        "source-authority.bin",
        tmp.dir,
        "moved-authority.bin",
        io,
    );
}

test "Windows content authority denies writers but permits pathname replacement" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const original = "immutable package";
    const replacement = "replacement package";
    try tmp.dir.writeFile(io, .{ .sub_path = "package.bin", .data = original });

    {
        var existing_writer = try openReadWrite(io, tmp.dir, "package.bin");
        defer existing_writer.close(io);
        if (openReadContentAuthority(io, tmp.dir, "package.bin")) |unexpected_file| {
            var unexpected = unexpected_file;
            unexpected.close(io);
            return error.ContentAuthorityAdmittedExistingWriter;
        } else |err| try std.testing.expect(err == error.FileBusy);
    }

    var authority: ?std.Io.File = try openReadContentAuthority(io, tmp.dir, "package.bin");
    defer if (authority) |file| file.close(io);

    if (openReadWrite(io, tmp.dir, "package.bin")) |unexpected_file| {
        var unexpected = unexpected_file;
        unexpected.close(io);
        return error.ContentAuthorityAdmittedNewWriter;
    } else |err| try std.testing.expect(err == error.FileBusy);

    {
        var namespace_mover = try openMutationAuthorityBeneathWindows(
            io,
            tmp.dir,
            "package.bin",
        );
        defer namespace_mover.close(io);
        try renameOpenObjectBeneathWindows(
            io,
            tmp.dir,
            "moved-package.bin",
            namespace_mover,
        );
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "package.bin", .data = replacement });
    try std.testing.expectEqual(@as(u64, original.len), (try authority.?.stat(io)).size);
    var observed: [original.len]u8 = undefined;
    try std.testing.expectEqual(
        observed.len,
        try authority.?.readPositionalAll(io, &observed, 0),
    );
    try std.testing.expectEqualStrings(original, &observed);

    authority.?.close(io);
    authority = null;
    var later_writer = try openReadWrite(io, tmp.dir, "moved-package.bin");
    later_writer.close(io);
}

test "Windows guarded output pins its name and detects hard-link growth" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var guarded = try createGuardedOutputBeneath(io, tmp.dir, "guarded.bin");
    defer guarded.close(io);
    var hard_link_created = true;
    hardLinkInTmp(
        allocator,
        &tmp,
        "guarded.bin",
        "alias.bin",
    ) catch {
        hard_link_created = false;
    };
    if (hard_link_created) {
        // windows share denial: no protection against new hard links
        try std.testing.expectError(
            error.UnsafeGuardedOutput,
            validateGuardedOutput(io, guarded, 0),
        );
    } else {
        try validateGuardedOutput(io, guarded, 0);
    }
    // variable sharing-error spellings; object binding checked instead
    tmp.dir.deleteFile(io, "guarded.bin") catch {};
    var rebound = try openRead(io, tmp.dir, "guarded.bin");
    defer rebound.close(io);
    try std.testing.expect(try sameOpenFile(io, guarded, rebound));
}

test "private construction publishes its exact object and removes its workspace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var construction = try PrivateConstructionOutput.create(allocator, io, tmp.dir);
    const workspace_name = try allocator.dupe(u8, construction.directory_name);
    defer allocator.free(workspace_name);
    const output = try construction.file();
    try output.writePositionalAll(io, "private payload", 0);
    try output.setLength(io, 15);
    try construction.requireBinding(15);
    if (builtin.target.os.tag == .windows) {
        try std.testing.expectError(error.FileBusy, openReadWrite(io, construction.directory.?, private_construction_file));
    }
    try construction.publish("artifact.bin", 15);
    try std.testing.expectError(error.FileNotFound, construction.directory.?.statFile(io, private_construction_file, .{}));

    var published = try openRead(io, tmp.dir, "artifact.bin");
    defer published.close(io);
    try std.testing.expect(try sameOpenFile(io, output, published));
    construction.deinit();
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, workspace_name, .{}));
    const bytes = try tmp.dir.readFileAlloc(io, "artifact.bin", allocator, .limited(16));
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("private payload", bytes);
}

test "private construction failure preserves a raced final and removes only its workspace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var construction = try PrivateConstructionOutput.create(allocator, io, tmp.dir);
    const workspace_name = try allocator.dupe(u8, construction.directory_name);
    defer allocator.free(workspace_name);
    const output = try construction.file();
    try output.writePositionalAll(io, "candidate", 0);
    try output.setLength(io, 9);
    try tmp.dir.writeFile(io, .{ .sub_path = "artifact.bin", .data = "sentinel" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        construction.publish("artifact.bin", 9),
    );
    try construction.requireBinding(9);
    construction.deinit();

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, workspace_name, .{}));
    const sentinel = try tmp.dir.readFileAlloc(io, "artifact.bin", allocator, .limited(9));
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings("sentinel", sentinel);
}

test "POSIX private construction cleanup never deletes a replaced child name" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var construction = try PrivateConstructionOutput.create(allocator, io, tmp.dir);
    const workspace_name = try allocator.dupe(u8, construction.directory_name);
    defer allocator.free(workspace_name);
    const directory = construction.directory.?;
    const output = try construction.file();
    try output.writePositionalAll(io, "owned", 0);
    try output.setLength(io, 5);
    try directory.rename("package", directory, "owned-moved", io);
    try directory.writeFile(io, .{ .sub_path = "package", .data = "foreign" });

    construction.deinit();
    var preserved = try tmp.dir.openDir(io, workspace_name, .{});
    defer preserved.close(io);
    const foreign = try preserved.readFileAlloc(io, "package", allocator, .limited(8));
    defer allocator.free(foreign);
    try std.testing.expectEqualStrings("foreign", foreign);
    const owned = try preserved.readFileAlloc(io, "owned-moved", allocator, .limited(6));
    defer allocator.free(owned);
    try std.testing.expectEqualStrings("owned", owned);
}

test "construction output pins Windows staging and detects POSIX replacement" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var authority = try createConstructionOutput(io, tmp.dir, "selected.part");
    defer authority.close(io);
    try authority.writePositionalAll(io, "selected", 0);
    try authority.setLength(io, 8);

    if (builtin.target.os.tag == .windows) {
        tmp.dir.rename("selected.part", tmp.dir, "moved.part", io) catch {};
        try requireConstructionOutputBinding(io, tmp.dir, "selected.part", authority, 8);
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "moved.part", .{}));
        return;
    }

    try tmp.dir.rename("selected.part", tmp.dir, "moved.part", io);
    try tmp.dir.writeFile(io, .{ .sub_path = "selected.part", .data = "hostile!" });
    try std.testing.expectError(
        error.ConstructionOutputBindingChanged,
        requireConstructionOutputBinding(io, tmp.dir, "selected.part", authority, 8),
    );
}

test "Windows guarded output publishes by retained handle and stays owned" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "published/nested");

    const payload = "same-handle publication";
    var guarded = try createGuardedOutputBeneath(io, tmp.dir, "staging.bin");
    defer guarded.close(io);
    try guarded.writePositionalAll(io, payload, 0);
    try guarded.sync(io);
    const original_identity = try windowsFileIdentity(guarded);

    try renameGuardedOutputBeneath(
        io,
        tmp.dir,
        "published/nested/final.bin",
        guarded,
        payload.len,
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "staging.bin", .{}),
    );

    var rebound = try openReadBeneath(io, tmp.dir, "published/nested/final.bin");
    defer rebound.close(io);
    try std.testing.expect(original_identity.eql(try windowsFileIdentity(guarded)));
    try std.testing.expect(try sameOpenFile(io, guarded, rebound));
    try validateGuardedOutput(io, guarded, payload.len);

    try guarded.writePositionalAll(io, payload[0..1], 0);
    try guarded.sync(io);
    var actual: [payload.len]u8 = undefined;
    try std.testing.expectEqual(
        actual.len,
        try guarded.readPositionalAll(io, &actual, 0),
    );
    try std.testing.expectEqualStrings(payload, &actual);

    tmp.dir.deleteFile(io, "published/nested/final.bin") catch {};
    tmp.dir.rename(
        "published/nested/final.bin",
        tmp.dir,
        "published/nested/moved.bin",
        io,
    ) catch {};
    var pinned = try openReadBeneath(io, tmp.dir, "published/nested/final.bin");
    defer pinned.close(io);
    try std.testing.expect(try sameOpenFile(io, guarded, pinned));
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "published/nested/moved.bin", .{}),
    );
}

test "Windows exact rollback rename survives post-publication hard-link growth" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var guarded = try createGuardedOutputBeneath(io, tmp.dir, "staging.bin");
    defer guarded.close(io);
    try guarded.writePositionalAll(io, "payload", 0);
    try guarded.sync(io);
    try renameGuardedOutputBeneath(io, tmp.dir, "final.bin", guarded, 7);
    hardLinkInTmp(allocator, &tmp, "final.bin", "alias.bin") catch
        return error.SkipZigTest;
    try std.testing.expectError(error.UnsafeGuardedOutput, validateGuardedOutput(io, guarded, 7));

    try renameOpenFileBeneathWindows(io, tmp.dir, "rollback.bin", guarded);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "final.bin", .{}));
    var rollback = try openRead(io, tmp.dir, "rollback.bin");
    defer rollback.close(io);
    var alias = try openRead(io, tmp.dir, "alias.bin");
    defer alias.close(io);
    try std.testing.expect(try sameOpenFile(io, guarded, rollback));
    try std.testing.expect(try sameOpenFile(io, guarded, alias));
}

test "Windows guarded handle rename refuses a raced destination" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "published", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "published/final.bin", .data = "sentinel" });

    const payload = "guarded bytes";
    var guarded = try createGuardedOutputBeneath(io, tmp.dir, "staging.bin");
    defer guarded.close(io);
    try guarded.writePositionalAll(io, payload, 0);
    try guarded.sync(io);

    try std.testing.expectError(
        error.PathAlreadyExists,
        renameGuardedOutputBeneath(
            io,
            tmp.dir,
            "published/final.bin",
            guarded,
            payload.len,
        ),
    );
    try validateGuardedOutput(io, guarded, payload.len);
    var staging = try openReadBeneath(io, tmp.dir, "staging.bin");
    defer staging.close(io);
    try std.testing.expect(try sameOpenFile(io, guarded, staging));

    const sentinel = try tmp.dir.readFileAlloc(
        io,
        "published/final.bin",
        allocator,
        .limited("sentinel".len + 1),
    );
    defer allocator.free(sentinel);
    try std.testing.expectEqualStrings("sentinel", sentinel);

    try guarded.writePositionalAll(io, payload[0..1], 0);
    try guarded.sync(io);
}

test "guarded output validation requires write access" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "guarded.bin", .data = "" });

    var read_only = try openRead(io, tmp.dir, "guarded.bin");
    defer read_only.close(io);
    try std.testing.expectError(
        error.UnsafeGuardedOutput,
        validateGuardedOutput(io, read_only, 0),
    );

    var read_write = try openReadWrite(io, tmp.dir, "guarded.bin");
    defer read_write.close(io);
    try validateGuardedOutput(io, read_write, 0);
}

test "Windows-safe open requests synchronous non-alert I/O" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "probe.bin", .data = "probe" });

    var file = try openRead(io, tmp.dir, "probe.bin");
    defer file.close(io);
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var mode: windows.FILE.MODE = undefined;
    const status = windows.ntdll.NtQueryInformationFile(
        file.handle,
        &io_status_block,
        &mode,
        @sizeOf(windows.FILE.MODE),
        .Mode,
    );
    try std.testing.expectEqual(windows.NTSTATUS.SUCCESS, status);
    try std.testing.expectEqual(@as(u2, 0b10), @backingInt(mode.IO));
}

test "Windows-safe open does not follow a final file reparse point" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "target.bin", .data = "must-not-be-read" });
    tmp.dir.symLink(io, "target.bin", "link.bin", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => |e| return e,
    };

    var file = openRead(io, tmp.dir, "link.bin") catch |err| switch (err) {
        // valid no-follow refusal; invalid target resolution
        error.AccessDenied, error.FileNotFound => return,
        else => |e| return e,
    };
    defer file.close(io);
    var buffer: [32]u8 = undefined;
    const count = readAllAt(io, file, &buffer, 0) catch return;
    try std.testing.expect(!std.mem.eql(u8, "must-not-be-read", buffer[0..count]));
}

test "Windows-safe no-follow open remains exact across many positional reads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const size = 3 * 1024 * 1024 + 4321;
    const bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    for (bytes, 0..) |*byte, index| byte.* = @intCast((index * 31) & 0xff);
    try tmp.dir.writeFile(io, .{ .sub_path = "large.bin", .data = bytes });

    var file = try openRead(io, tmp.dir, "large.bin");
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    var hasher = std.crypto.hash.Blake3.init(.{});
    while (true) {
        const count = try readAllAt(io, file, &buffer, offset);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    try std.testing.expectEqual(@as(u64, size), offset);

    var actual: [32]u8 = undefined;
    hasher.final(&actual);
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "beneath create and delete refuse an ancestor reparse without touching outside" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "outside", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/sentinel", .data = "unchanged" });
    tmp.dir.symLink(io, "outside", "link", .{ .is_directory = true }) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => |other| return other,
    };

    try std.testing.expectError(
        error.UnsafePathAncestor,
        createFileBeneath(io, tmp.dir, "link/created", .{ .exclusive = true }),
    );
    try std.testing.expectError(
        error.UnsafePathAncestor,
        deleteFileBeneath(io, tmp.dir, "link/sentinel"),
    );
    try std.testing.expectError(
        error.UnsafePathAncestor,
        createDirPathBeneath(io, tmp.dir, "link/nested"),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "outside/created", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "outside/nested", .{}));
    var sentinel = try openRead(io, tmp.dir, "outside/sentinel");
    defer sentinel.close(io);
    var bytes: [9]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try readAllAt(io, sentinel, &bytes, 0));
    try std.testing.expectEqualStrings("unchanged", &bytes);
}

test "beneath directory creation constructs ordinary nested parents" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try createDirPathBeneath(io, tmp.dir, "one/two/three");
    const stat = try tmp.dir.statFile(io, "one/two/three", .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.directory, stat.kind);
    try createParentPathBeneath(io, tmp.dir, "four/five/output.bin");
    const parent = try tmp.dir.statFile(io, "four/five", .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.directory, parent.kind);
}

extern "kernel32" fn CreateHardLinkW(
    new_file_name: windows.LPCWSTR,
    existing_file_name: windows.LPCWSTR,
    security_attributes: ?*windows.SECURITY_ATTRIBUTES,
) callconv(.winapi) windows.BOOL;

// Io.Threaded.dirHardLink is unsupported on windows
pub fn hardLinkInTmp(
    allocator: std.mem.Allocator,
    tmp: *const std.testing.TmpDir,
    existing: []const u8,
    new: []const u8,
) !void {
    if (comptime builtin.target.os.tag != .windows) return error.OperationUnsupported;

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const existing_path = try std.fs.path.join(allocator, &.{ root, existing });
    defer allocator.free(existing_path);
    const new_path = try std.fs.path.join(allocator, &.{ root, new });
    defer allocator.free(new_path);
    const existing_w = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, existing_path);
    defer allocator.free(existing_w);
    const new_w = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, new_path);
    defer allocator.free(new_w);

    if (!CreateHardLinkW(new_w.ptr, existing_w.ptr, null).toBool()) {
        return windows.unexpectedError(windows.GetLastError());
    }
}

const positioned_file_len = 256 * 1024;
const positioned_write_at = 4096;
const positioned_read_at = 128 * 1024;
const positioned_wrong_at = positioned_read_at + 4096;
const positioned_patch = "positioned-output-must-land-at-4096";

fn seedPositioned(io: std.Io, file: std.Io.File, bytes: []u8) !void {
    for (bytes, 0..) |*byte, i| byte.* = @truncate((i *% 17) ^ (i >> 9));
    try file.writePositionalAll(io, bytes, 0);
}

fn perturbPosition(io: std.Io, shared: std.Io.File, expected: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    try std.testing.expectEqual(buffer.len, try readAllAt(io, shared, &buffer, positioned_read_at));
    try std.testing.expectEqualSlices(u8, expected[positioned_read_at .. positioned_read_at + buffer.len], &buffer);
    try io.vtable.fileSeekTo(io.userdata, shared, positioned_wrong_at);
}

test "in-place primitives: explicit output offset survives interleaved shared-position changes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "inplace.bin", .data = "" });
    var output = try openReadWrite(io, tmp.dir, "inplace.bin");
    defer output.close(io);
    const shared_reader = output;
    const expected = try std.testing.allocator.alloc(u8, positioned_file_len);
    defer std.testing.allocator.free(expected);
    try seedPositioned(io, output, expected);
    try io.vtable.fileSeekTo(io.userdata, output, positioned_write_at);
    try perturbPosition(io, shared_reader, expected);
    try output.writePositionalAll(io, positioned_patch, positioned_write_at);
    @memcpy(expected[positioned_write_at .. positioned_write_at + positioned_patch.len], positioned_patch);
    const actual = try std.testing.allocator.alloc(u8, positioned_file_len);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqual(actual.len, try readAllAt(io, output, actual, 0));
    try std.testing.expectEqualSlices(u8, expected, actual);
    try std.testing.expectEqual(@as(u64, positioned_file_len), try output.length(io));
}

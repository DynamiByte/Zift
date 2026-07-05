# Zift

Small update tool for Zenless Zone Zero.

![Version](https://img.shields.io/badge/version-0.1.2-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-green)

## Usage

```bash
zift game
zift update.zip game
zift old new
zift old new out.zip
```

- One folder: clean
- Two folders: make an update ZIP
- Folder + ZIP: apply
- Two folders + ZIP path: make with that output path
- Argument order does not matter
- `-y` skips the confirmation prompt
- `-v` additionally verifies MD5 hashes

## Notes

- Created update packages are full-file, store-only ZIPs
- Files are determined by `pkg_version`
- Apply extracts, removes stale files, then verifies
- Clean removes extra files, then verifies

## Building

Zift uses Zig 0.16.0.

- [Windows x86_64](https://ziglang.org/download/0.16.0/zig-x86_64-windows-0.16.0.zip)
- [Linux x86_64](https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz)

<details>
<summary>Other Zig 0.16.0 downloads</summary>

Files are signed with [minisign](https://jedisct1.github.io/minisign/) using this public key:

```text
RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
```

- 2026-04-13
- [Release Notes](https://ziglang.org/download/0.16.0/release-notes.html)
- [Language Reference](https://ziglang.org/documentation/0.16.0/)
- [Standard Library Documentation](https://ziglang.org/documentation/0.16.0/std/)

<table>
<thead>
<tr><th>OS</th><th>Arch</th><th>Filename</th><th>Signature</th><th>Size</th></tr>
</thead>
<tbody>
<tr><td colspan="2" rowspan="2" align="center">Source</td><td><a href="https://ziglang.org/download/0.16.0/zig-0.16.0.tar.xz">zig-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-0.16.0.tar.xz.minisig">minisig</a></td><td>21MiB</td></tr>
<tr><td><a href="https://ziglang.org/download/0.16.0/zig-bootstrap-0.16.0.tar.xz">zig-bootstrap-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-bootstrap-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="3" align="center">Windows</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-windows-0.16.0.zip">zig-x86_64-windows-0.16.0.zip</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-windows-0.16.0.zip.minisig">minisig</a></td><td>93MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-windows-0.16.0.zip">zig-aarch64-windows-0.16.0.zip</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-windows-0.16.0.zip.minisig">minisig</a></td><td>89MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-windows-0.16.0.zip">zig-x86-windows-0.16.0.zip</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-windows-0.16.0.zip.minisig">minisig</a></td><td>94MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="2" align="center">macOS</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-macos-0.16.0.tar.xz">zig-x86_64-macos-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-macos-0.16.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-macos-0.16.0.tar.xz">zig-aarch64-macos-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-macos-0.16.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="8" align="center">Linux</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz">zig-x86_64-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-linux-0.16.0.tar.xz">zig-aarch64-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>49MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-linux-0.16.0.tar.xz">zig-arm-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-linux-0.16.0.tar.xz">zig-riscv64-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>powerpc64le</td><td><a href="https://ziglang.org/download/0.16.0/zig-powerpc64le-linux-0.16.0.tar.xz">zig-powerpc64le-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-powerpc64le-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-linux-0.16.0.tar.xz">zig-x86-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>56MiB</td></tr>
<tr><td>loongarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-loongarch64-linux-0.16.0.tar.xz">zig-loongarch64-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-loongarch64-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>s390x</td><td><a href="https://ziglang.org/download/0.16.0/zig-s390x-linux-0.16.0.tar.xz">zig-s390x-linux-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-s390x-linux-0.16.0.tar.xz.minisig">minisig</a></td><td>52MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="5" align="center">FreeBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-freebsd-0.16.0.tar.xz">zig-aarch64-freebsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-freebsd-0.16.0.tar.xz.minisig">minisig</a></td><td>49MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-freebsd-0.16.0.tar.xz">zig-arm-freebsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-freebsd-0.16.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>powerpc64le</td><td><a href="https://ziglang.org/download/0.16.0/zig-powerpc64le-freebsd-0.16.0.tar.xz">zig-powerpc64le-freebsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-powerpc64le-freebsd-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-freebsd-0.16.0.tar.xz">zig-riscv64-freebsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-freebsd-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-freebsd-0.16.0.tar.xz">zig-x86_64-freebsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-freebsd-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="4" align="center">NetBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-netbsd-0.16.0.tar.xz">zig-aarch64-netbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-netbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>49MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-netbsd-0.16.0.tar.xz">zig-arm-netbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-netbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>51MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-netbsd-0.16.0.tar.xz">zig-x86-netbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86-netbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>56MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-netbsd-0.16.0.tar.xz">zig-x86_64-netbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-netbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="4" align="center">OpenBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-openbsd-0.16.0.tar.xz">zig-aarch64-openbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-aarch64-openbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>49MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-openbsd-0.16.0.tar.xz">zig-arm-openbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-arm-openbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-openbsd-0.16.0.tar.xz">zig-riscv64-openbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-riscv64-openbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-openbsd-0.16.0.tar.xz">zig-x86_64-openbsd-0.16.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.16.0/zig-x86_64-openbsd-0.16.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
</tbody>
</table>

</details>

Build with:

```bash
zig build
```

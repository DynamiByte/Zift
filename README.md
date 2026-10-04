# Zift

A swift sifter, written in Zig. Create and apply directory deltas with a focus on small patches, fast apply, and low memory use.

![Version](https://img.shields.io/badge/version-1.0.0--dev.2-orange)
![License](https://img.shields.io/badge/license-AGPL--3.0-green)

## Usage

```sh
zift directory           # clean supported software
zift delta directory     # apply a delta
zift source target       # create a delta
zift source target out   # create at an output path
zift source target out.ziff -a -y --source-version 1.0 --target-version 1.1
```

Ziff (`.ziff`) is the default format. File Delta and HDiff are also available in ZIP or tar.zst containers.

Integrations are an optional feature let Zift understand manifests and version information for supported software. Zift uses this to compare directories faster, verify files, clean up extra files, and warn when a delta expects different software or a different source version.

Currently supported integrations: Zenless Zone Zero, Genshin Impact, Arknights: Endfield, and Wuthering Waves.

## Options

- `-a` Accept defaults automatically. Explicit choices take priority.
- `-c` Perform a Complete Clean.
- `-m` Reduce matching memory. Creation may take longer.
- `-y` Skip the final confirmation.
- `-v` Verify finished file hashes. Takes more time.
- `-f` Force even if issues arise, such as source/target issues, low disk space, or software/source-version mismatches.
- `-h`, `--help` Show usage.

Creation choices:

- `--integration y|n` Use or skip the detected integration.
- `--prefix text|n` Set the output-name prefix. Use `n` to omit it.
- `--source-version text`, `--target-version text` Set the version names.
- `--method ziff|hdiff[:w26|h13|sf20]|file` Default: Ziff. HDiff defaults to W26. Also accepts `1|2|3`.
- `--format zip-store|zip-deflate[:N]|tar-zstd[:N]` File Delta/HDiff only. Deflate: `1`–`9` (default `1`). Zstd: `1`–`22` (default `3`).
- `--correct-target-manifest y|n` Correct reported target entries in the delta.

Ctrl+C cancels active work. Interrupted Ziff applies resume on the next run.

## Building

Zift uses Zig 0.17.0.

- [Windows x86_64](https://ziglang.org/download/0.17.0/zig-x86_64-windows-0.17.0.zip)
- [Linux x86_64](https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz)

<details>
<summary>Other Zig 0.17.0 downloads</summary>

Files are signed with [minisign](https://jedisct1.github.io/minisign/) using this public key:

```text
RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
```

- 2026-10-01
- [Release Notes](https://ziglang.org/download/0.17.0/release-notes.html)
- [Language Reference](https://ziglang.org/documentation/0.17.0/)
- [Standard Library Documentation](https://ziglang.org/documentation/0.17.0/std/)

<table>
<thead>
<tr><th>OS</th><th>Arch</th><th>Filename</th><th>Signature</th><th>Size</th></tr>
</thead>
<tbody>
<tr><td colspan="2" rowspan="2" align="center">Source</td><td><a href="https://ziglang.org/download/0.17.0/zig-0.17.0.tar.xz">zig-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-0.17.0.tar.xz.minisig">minisig</a></td><td>22MiB</td></tr>
<tr><td><a href="https://ziglang.org/download/0.17.0/zig-bootstrap-0.17.0.tar.xz">zig-bootstrap-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-bootstrap-0.17.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="3" align="center">Windows</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-windows-0.17.0.zip">zig-x86_64-windows-0.17.0.zip</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-windows-0.17.0.zip.minisig">minisig</a></td><td>96MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-windows-0.17.0.zip">zig-aarch64-windows-0.17.0.zip</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-windows-0.17.0.zip.minisig">minisig</a></td><td>92MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-windows-0.17.0.zip">zig-x86-windows-0.17.0.zip</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-windows-0.17.0.zip.minisig">minisig</a></td><td>97MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="2" align="center">macOS</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-macos-0.17.0.tar.xz">zig-x86_64-macos-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-macos-0.17.0.tar.xz.minisig">minisig</a></td><td>57MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-macos-0.17.0.tar.xz">zig-aarch64-macos-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-macos-0.17.0.tar.xz.minisig">minisig</a></td><td>51MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="8" align="center">Linux</td><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz">zig-x86_64-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
<tr><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-linux-0.17.0.tar.xz">zig-aarch64-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-linux-0.17.0.tar.xz">zig-arm-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>51MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-linux-0.17.0.tar.xz">zig-riscv64-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
<tr><td>powerpc64le</td><td><a href="https://ziglang.org/download/0.17.0/zig-powerpc64le-linux-0.17.0.tar.xz">zig-powerpc64le-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-powerpc64le-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-linux-0.17.0.tar.xz">zig-x86-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>57MiB</td></tr>
<tr><td>loongarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-loongarch64-linux-0.17.0.tar.xz">zig-loongarch64-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-loongarch64-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>52MiB</td></tr>
<tr><td>s390x</td><td><a href="https://ziglang.org/download/0.17.0/zig-s390x-linux-0.17.0.tar.xz">zig-s390x-linux-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-s390x-linux-0.17.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="5" align="center">FreeBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-freebsd-0.17.0.tar.xz">zig-aarch64-freebsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-freebsd-0.17.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-freebsd-0.17.0.tar.xz">zig-arm-freebsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-freebsd-0.17.0.tar.xz.minisig">minisig</a></td><td>52MiB</td></tr>
<tr><td>powerpc64le</td><td><a href="https://ziglang.org/download/0.17.0/zig-powerpc64le-freebsd-0.17.0.tar.xz">zig-powerpc64le-freebsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-powerpc64le-freebsd-0.17.0.tar.xz.minisig">minisig</a></td><td>54MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-freebsd-0.17.0.tar.xz">zig-riscv64-freebsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-freebsd-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-freebsd-0.17.0.tar.xz">zig-x86_64-freebsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-freebsd-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="5" align="center">NetBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-netbsd-0.17.0.tar.xz">zig-aarch64-netbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-netbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>50MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-netbsd-0.17.0.tar.xz">zig-arm-netbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-netbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>53MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-netbsd-0.17.0.tar.xz">zig-riscv64-netbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-netbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
<tr><td>x86</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-netbsd-0.17.0.tar.xz">zig-x86-netbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86-netbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>58MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-netbsd-0.17.0.tar.xz">zig-x86_64-netbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-netbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
</tbody>
<tbody>
<tr><td rowspan="4" align="center">OpenBSD</td><td>aarch64</td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-openbsd-0.17.0.tar.xz">zig-aarch64-openbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-aarch64-openbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>51MiB</td></tr>
<tr><td>arm</td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-openbsd-0.17.0.tar.xz">zig-arm-openbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-arm-openbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>52MiB</td></tr>
<tr><td>riscv64</td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-openbsd-0.17.0.tar.xz">zig-riscv64-openbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-riscv64-openbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>55MiB</td></tr>
<tr><td>x86_64</td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-openbsd-0.17.0.tar.xz">zig-x86_64-openbsd-0.17.0.tar.xz</a></td><td><a href="https://ziglang.org/download/0.17.0/zig-x86_64-openbsd-0.17.0.tar.xz.minisig">minisig</a></td><td>56MiB</td></tr>
</tbody>
</table>

</details>

Build with:

```sh
zig build
```

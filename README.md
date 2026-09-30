# Zift

A swift sifter, written in Zig. Create and apply directory deltas with a focus on small patches, fast apply, and low memory use.

![Version](https://img.shields.io/badge/version-0.1.2-blue)
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

Optional integrations: Zenless Zone Zero, Genshin Impact, Arknights: Endfield, and Wuthering Waves. Other directories work without an integration. Clean requires a supported integration and its manifest.

## Options

- `-a` Accept defaults automatically.
- `-c` Perform a Complete Clean.
- `-m` Reduce matching memory; creation may take longer.
- `-y` Skip the final confirmation.
- `-v` Verify finished file hashes where available; takes more time.
- `-f` Override Ziff software/version guards and free-space preflight.
- `-h`, `--help` Show usage.

Creation choices:

- `--integration y|n` Use or skip the detected integration.
- `--prefix text|n` Set the output-name prefix; `n` omits it.
- `--source-version text`, `--target-version text` Set the version names.
- `--method ziff|hdiff[:w26|h13|sf20]|file` Default: Ziff; HDiff variant: W26. Also accepts `1|2|3`.
- `--format zip-store|zip-deflate[:N]|tar-zstd[:N]` File Delta/HDiff only. Deflate: `1`–`9` (default `1`); Zstd: `1`–`22` (default `3`).
- `--continue-on-errors y|n` Continue or abort on reported source/target issues.
- `--correct-target-manifest y|n` Correct reported target entries in the delta.

Explicit choices override `-a`; omitted choices prompt without it. `-a` and `-y` do not approve content issues.

Ctrl+C cancels active work. Interrupted Ziff applies resume on the next run.

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

```sh
zig build
```

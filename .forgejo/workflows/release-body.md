# Zift

Small update tool for Zenless Zone Zero.

Zift uses pkg_version files to create, apply, and clean full-file update packages.

## Usage

Apply an update package:
```sh
zift <game-folder> <update.zip>
```

Clean extra files:
```sh
zift <game-folder>
```

Create an update package:
```sh
zift <old-folder> <new-folder> [out.zip]
```

- `-y` skips the confirmation prompt
- `-v` additionally verifies MD5 hashes

## Changelog

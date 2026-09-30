# Zift

A swift sifter, written in Zig. Create and apply directory deltas with a focus on small patches, fast apply, and low memory use.
## Usage

```sh
zift <directory>              # clean supported software
zift <source> <target> [out]  # create a delta
zift <delta> <directory>      # apply a delta
```

- `-a` accepts detected values and defaults automatically
- `-c` performs a Complete Clean of supported software
- `-m` reduces matching memory at the cost of creation time
- `-y` skips the confirmation prompt
- `-v` verifies finished file hashes where available
- `-f` overrides Ziff software/version guards and free-space preflight

## Changelog

# MachP

MachP is a command‑line tool for parsing Mach‑O binaries on macOS. It extracts information such as headers, load commands, segments, symbols and code signatures, then outputs the result as structured JSON. If you need to inspect executables, static libraries or frameworks, MachP provides a programmatic way to explore their contents without manually digging through the Mach‑O format.

## Why MachP?
- **Comprehensive parsing** – MachP walks the file, handling fat binaries and thin slices to reveal the key pieces of a Mach‑O image.
- **JSON output** – The parsed information is formatted in a consistent JSON structure, ideal for automated analysis or feeding into other tools.
- **Optional recursion** – You can parse a single file or recursively process a directory of files in parallel.
- **Logging** – Use the `--debug` flag for verbose logs to help diagnose parsing issues.

## Obtaining
You can get MachP in two ways:

- **Download a release** – Visit the project's GitHub releases page and grab the latest zip archive, then extract the binary.
- **Build from source** – MachP uses Swift Package Manager. Build the release executable with:

```bash
swift build -c release
```

The resulting binary will be located in `.build/release/MachP`.

## Using MachP
Once built, run MachP with a Mach‑O file or directory:

```bash
./MachP <file_or_directory> [--recursive|-r] [--output <path>] [--debug]
```

If macOS Gatekeeper quarantines the binary, remove the quarantine attribute before running:

```bash
xattr -d com.apple.quarantine ./MachP
```

When no `--output` path is specified, JSON is printed to standard output. If an output directory is provided, results for each file are written there instead.

## Disclaimer
Made with robots 🤖. While care was taken to verify its behaviour, use it at your own risk.


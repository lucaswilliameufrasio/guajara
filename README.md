# Guajará

A guided CLI and TUI for managing `~/.ssh/config` and `/etc/hosts`.

## Why "Guajará"

Guajará Bay (Baía do Guajará) is a large river estuary in Pará, Brazil, formed by
the confluence of the Guamá and Acará rivers. It borders Belém and provides
passage to the Amazon delta—a natural junction where multiple routes converge.
The name mirrors the tool's purpose: a meeting point for host definitions and
SSH destinations.

## Features

- **Lossless editing:** reads, parses, and writes back your files preserving
  every comment, blank line, indentation, and ordering. Only the lines you
  explicitly change are reconstructed.
- **SSH config management:** understands `Host`, `Match`, `Include`, global
  directives, all pattern forms (wildcards, negation, multi-alias), and unknown
  directives. Operates on parsed blocks rather than raw lines.
- **Hosts file management:** understands IPv4, IPv6, inline comments, and
  multiple hostnames per record.
- **Guided TUI:** list blocks, select entries, and inspect details without
  exposing raw text editing.
- **CLI commands:** use from scripts or quick terminal actions.
- **Diff preview:** all mutating commands show the exact diff before writing.
- **`--dry-run`:** preview without writing.
- **Atomic writes:** content is written to a temp file, then renamed over the
  target.

## Requirements

- Rust toolchain (edition 2024)
- Recommended: `cargo-nextest`, `cargo-llvm-cov` (install via `make setup`)

## Build and Run

```bash
cargo build --release
./target/release/guajara
```

Or directly:

```bash
cargo run
```

## Usage

### TUI (default)

```bash
guajara
```

Opens a guided dashboard. Navigate with arrow keys, select with Enter, go back
with Esc, reload files with `r`, quit with `q`.

### SSH CLI commands

```bash
guajara ssh list
guajara ssh show <selector>
guajara ssh set <selector> <key> <value>
guajara ssh unset <selector> <key>
guajara ssh add <pattern>... [--hostname <h>] [--user <u>] [--port <p>]
guajara ssh remove <selector>
guajara ssh validate
```

The selector matches host patterns. If multiple blocks match, you'll be shown
the candidates and asked to use a more specific selector.

### Hosts CLI commands

```bash
guajara hosts list
guajara hosts add <ip> <hostname>...
guajara hosts set-ip <hostname> <ip>
guajara hosts remove <hostname>
guajara hosts validate
```

### Global options

```bash
guajara --dry-run <command>   # Preview without writing
guajara --yes <command>       # Skip confirmation prompts
guajara --ssh-config <path>   # Use alternate SSH config
guajara --hosts-file <path>   # Use alternate hosts file
```

## Makefile

| Command | Description |
|---------|-------------|
| `make setup` | Install required tools |
| `make tools` | Show installed versions |
| `make fmt` | Format code |
| `make fmt-check` | Check formatting (CI) |
| `make check` | cargo check |
| `make clippy` | clippy with -D warnings |
| `make test` | cargo nextest run |
| `make coverage` | Run tests with LLVM coverage |
| `make test-ci` | fmt + clippy + tests + coverage (CI) |
| `make build` | Debug build |
| `make release` | Release build |
| `make run` | Run guajara |
| `make upgrade` | Update dependencies |
| `make audit` | cargo audit |
| `make clean` | Remove artifacts |

```bash
# Full CI locally
make test-ci

# With coverage threshold enforcement
make test-ci COVERAGE_FAIL=1 COVERAGE_MIN=80
```

## Testing

```bash
cargo nextest run
```

Or with coverage:

```bash
cargo llvm-cov nextest --html --lcov
```
## CI

A GitHub Actions workflow runs on pushes and PRs to `main`. It checks formatting,
runs clippy, executes all tests with `cargo-nextest`, generates LLVM coverage,
and uploads the reports as artifacts.

## Safety

- Files are saved atomically via temp-file + rename.
- `/etc/hosts` requires elevated privileges. The tool will **never** attempt
  to invoke `sudo` automatically.
- All mutating commands show a diff before writing.
- Use `--dry-run` to preview without writing.
- Ambiguous SSH selectors produce an error listing the matching blocks rather
  than silently modifying the wrong one.

## License

MIT

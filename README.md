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
- **Port forwarding:** start SSH tunnels (`ssh -N -L`) for one or many hosts at
  once, queueing multiple rules before starting. Active tunnels are tracked
  with their PID, shown live in the TUI, and can be stopped from there.
  Tunnels survive terminal close and are pruned automatically when the ssh
  process dies.
- **Guided TUI:** list blocks, select entries, and inspect details without
  exposing raw text editing.
- **CLI commands:** use from scripts or quick terminal actions.
- **Diff preview:** all mutating commands show the exact diff before writing.
- **`--dry-run`:** preview without writing.
- **Atomic writes:** content is written to a temp file, then renamed over the
  target.

## Install a release

Prebuilt binaries are available for Apple Silicon macOS and ARM64 and x64 Linux.
Installing a release does not require Rust.

macOS and Linux:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/lucaswilliameufrasio/guajara/releases/latest/download/guajara-installer.sh | sh
```

## Requirements

- Rust toolchain (edition 2024) to build from source
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

In SSH host forms, press Enter on **IdentityFile** to select a private key from
`~/.ssh`, create an Ed25519 key, enter a custom path, or clear the selection.
Creation requires `ssh-keygen` and asks for a passphrase directly in the terminal.
Save the host afterward; cancelling the form does not delete the new key. Install
the generated `.pub` file on the server before connecting.

Press **`t`** in the SSH host list or details to test a saved host's connection
and authentication. The test runs `true` remotely, then disconnects, without
starting configured tunnels. Password and host-key prompts remain in the
terminal; press Enter afterward to return to the TUI. Save form changes first.

Press **`o`** in SSH hosts, active tunnels, or forwarding host selection to switch
between name and most-recent-use ordering while keeping the same item selected.
Host usage is recorded for tunnel starts and successful SSH tests (TUI or CLI).
Without recorded usage, hosts remain alphabetical; `r` reloads usage history.

Press **`u`** in the SSH host list or details to **duplicate a host locally**.
The form suggests a unique `-copy` alias; change it and the `HostName` (for
example, from a public IP to a Tailscale address), then select Save. User, port,
identity references, comments, repeated identity directives and custom options
are preserved unless you change the corresponding field. The original remains
unchanged, no key is created or copied, and cancelling writes nothing. A new
alias is required; the duplicate is inserted after the source block to keep
its position relative to later wildcard defaults. This is separate from `c`,
which copies hosts to another machine.

### Remote SSH hosts and batch copy

In the local SSH host list:

- Select a saved destination and press **`m`** to manage that machine's SSH hosts.
- Mark one or more local hosts with **Space**, then press **`c`** to copy them.
  With no marked hosts, `c` copies the selected host. Choose the destination,
  then choose an existing remote key, create a remote Ed25519 key, enter a remote
  path, or use remote SSH defaults for each copied host.

The remote manager offers **`a`** add, **`e`** edit, **`d`** delete, **`t`** test
from the remote machine, and **`r`** reload. **Esc** returns to the local list.
Every write shows a diff: **`y`** confirms, **`n`** or **Esc** cancels. Batch
copy is one combined write and refuses duplicate aliases. If the config changes
externally, reload and review instead of overwriting it.

Private keys are never copied. Local identity/agent/certificate bindings are
removed from copied blocks and replaced by the chosen remote identity. Review
other paths, `Include`, wildcard defaults and `ProxyJump` dependencies in the
preview; included files are preserved but not expanded or managed. Newly created
keys remain remote if you cancel, and their public keys still need installing
on the servers you want that machine to access.

Destinations need SSH access, a POSIX shell and standard Linux/macOS utilities;
key creation needs `ssh-keygen`. **No Python or remote Guajará installation.**
Only the connected user's `~/.ssh/config` is managed, without sudo. Writes are
atomic, mode 600, and refuse symlink configs. Limit: 2 MiB per config.

Port forwards live under **Port forwards** in the main menu: first select an
existing SSH host, then fill in the forwarding rule. If no host is configured,
press `n` to open SSH host management. The list shows every active tunnel
(including tunnels started outside Guajará), refreshes every 2 seconds, and
uses `x` to stop the selected tunnel. Press `a` to queue forwarding rules and
start them together.

### Forward CLI commands

```bash
guajara forward list
guajara forward add --host <h> --local-port <p> --target-host <h> --target-port <p>
guajara forward stop <host>
guajara forward stop-all
```

Each tunnel runs one `ssh` process per host carrying all its `-L` rules. State
is kept in `~/.config/guajara/forwards.json`; dead tunnels are pruned on every
read, so `list` only ever shows what is actually running.

### SSH CLI commands

```bash
guajara ssh list
guajara ssh show <selector>
guajara ssh test <selector>
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

The remote integration suite starts its own loopback-only OpenSSH server with
temporary keys, pinned host keys and an isolated remote home. It never connects
to user-configured hosts. It requires `/usr/sbin/sshd` and `ssh-keygen` (included
with macOS; on Linux, install the OpenSSH client/server packages and ensure the
system's privilege-separation directory exists, usually `/run/sshd`). No root
privileges are required to run the test server. CI installs these prerequisites.

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

See [docs/releasing.md](docs/releasing.md) for the release and installation
workflow.

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

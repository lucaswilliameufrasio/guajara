# Remote SSH host management and batch copy

## Confirmed scope

Manage the connected user's `~/.ssh/config` on another Linux/macOS machine:
list, inspect, add, edit, remove, and test hosts. Select multiple local blocks
and copy them to one remote machine, assigning identities from that machine
or creating keys there. Private keys must never be transferred. No Python or
remote Guajará installation is required (user-confirmed).

## Journeys and ownership

- The local SSH list selects a saved destination alias. `m` opens its remote
  manager. Space marks source blocks; `c` selects a destination for batch copy.
- The remote manager owns its own snapshot, navigation, form and confirmation
  state; leaving it returns to the unchanged local list. Local `/etc/hosts`
  and forwarding management are never repointed at a remote machine.
- Batch copy checks all aliases for conflicts first, assigns a remote identity
  to each source block, then previews and confirms one combined write. It never
  overwrites an existing alias silently or applies half a batch.
- Remote forms preserve unsupported directives and comments. Identity pickers
  show remote key paths only. New keys are Ed25519, generated remotely with
  ssh-keygen handling passphrases directly in the terminal. Cancelling a copy
  does not delete a key already created.

## Boundaries and decisions

- Rust owns parsing, validation, copying and rendering. A named SSH adapter
  invokes small fixed shell operations for snapshots, key discovery, atomic
  writes, creation and connection tests. Shell quoting is centralized; file
  contents travel over stdin, not command arguments. The remote requirements
  are OpenSSH, a POSIX shell, and standard Linux/macOS utilities.
- Read responses and writes are bounded to 2 MiB. Key discovery reads format
  prefixes remotely and sends only paths; no private key contents leave the
  destination. Existing host-key verification and authentication prompts remain
  enabled. Agent forwarding and configured port forwards are disabled.
- Every config mutation requires a diff confirmation. A write uses an exclusive
  lock directory, compares the original snapshot (including file existence),
  writes a mode-600 temporary file in the same directory, then renames it.
  Missing SSH directories are mode 700. Symlink configs are refused for writes.
  A changed file requires reload/review, not force overwrite or automatic retry.
  The lock coordinates Guajará writers; unrelated editors do not honor it, so
  this is optimistic conflict detection, not a distributed transaction.
- Local identity bindings (IdentityFile, CertificateFile, IdentityAgent,
  PKCS11Provider, SecurityKeyProvider) are not copied. Other machine-specific
  settings, includes and jump-host dependencies must be reviewed in the preview.
  Copy preserves block ordering, appending new entries; earlier wildcard
  defaults in the destination can still affect OpenSSH's first-value semantics.
- No sudo, remote daemon, shell-history inspection, or key installation on
  third-party servers. Connection tests execute `true` from the remote machine.

## Verification

Exercise the real shell operations against isolated temporary homes, including
conflicts, missing files, lock ownership, permissions, symlinks, key metadata,
and batch all-or-nothing behavior. Exercise SSH transport with an isolated local
server when available; never connect to saved user destinations during tests.
Run the full repository quality gate after the UI and adapter are integrated.

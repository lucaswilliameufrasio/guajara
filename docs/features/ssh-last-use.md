# SSH last-use tracking

## Current behavior

The application records successful connection tests and tunnel starts that it
initiates. It does not currently observe `ssh alias` launched independently.

## Opt-in OpenSSH integration

Run `guajara ssh enable-usage <alias>` to review the proposed change and confirm
it. Use `--dry-run` before `ssh` to preview without saving. The command refuses
an existing effective `LocalCommand`, including one from an `Include`, and
checks the proposed configuration using `ssh -G`. This inspection can execute
existing `Match exec` clauses. It currently supports a single concrete ASCII
alias per `Host` block and an executable path with letters, numbers, `/`, `-`,
`_`, or `.`. Other configurations are refused rather than rewritten.

The hook records an alias after OpenSSH authentication in a separate per-alias
file under `~/.config/guajara/ssh-use`; it never records shell commands or
rewrites tunnel state. Reopen Guajará or press `r`, then use `o` to select last
used ordering. A connection that reuses an existing OpenSSH multiplexed session
may not execute `LocalCommand` again. Changes to aliases or the Guajará binary
path require reviewing and re-enabling the hook.

To disable tracking for the alias, remove the `LocalCommand` and
`PermitLocalCommand yes` lines that the enable command added to that alias's
block. Existing usage files are not automatically deleted.

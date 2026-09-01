# Feature: Port Forwarding

## Scope

- Manage SSH local port forwarding (tunnels) started by guajara via `ssh -N -L`.
- Support starting several rules at once, across several SSH hosts.
- TUI shows active tunnels with live status, allows stopping them.
- CLI subcommands: `guajara forward list|add|stop|stop-all`.

Out of scope: remote/dynamic forwarding (`-R`, `-D`), editing non-guajara
tunnels started elsewhere, auto-restart on failure.

## Confirmed Rules

- Only tunnels started by guajara are tracked (user request: "se tiver algum
  ativo tem que mostrar na tui pra desligar ou saber que está ativo").

## Local Decisions

- **Spawn strategy**: `nohup ssh -N -o ExitOnForwardFailure=yes -o
  ServerAliveInterval=30 -o ServerAliveCountMax=3 -L <rule>... <host>` with all
  stdio redirected to null, spawned via `std::process::Command`. **Why**: the
  spawned PID is the real ssh PID (nohup execs ssh), and nohup makes the tunnel
  survive terminal/session close without extra crates. `ssh -f` was rejected
  because ssh backgrounds itself with a different PID, making tracking
  unreliable. **Source**: design session 2026-09-01.
- **One ssh process per host**: rules for the same host are grouped into a
  single tunnel with multiple `-L` flags. **Why**: fewer connections, fewer
  auth prompts. **Source**: design session 2026-09-01.
- **One host per rule, no multi-host shortcut**: the TUI "add rule" form and
  `forward add` take a single SSH host per rule; "several at once" is achieved
  by queuing several rules and starting them together. A multi-host shortcut
  (same local port applied to N hosts) was rejected because two tunnels cannot
  bind the same local port on 127.0.0.1 — such input is always invalid.
  **Source**: design session 2026-09-01 (surfaced by a failing test).
- **Host selection**: the TUI selects the SSH alias from the parsed SSH host
  blocks before opening the forwarding form. The selected alias is copied into
  the rule automatically; users do not retype it. If no alias exists, the TUI
  links back to SSH host management to add one. **Source**: user feedback.
- **External tunnel discovery**: active `ssh` processes containing local
  forwarding flags are discovered from `ps`, displayed with an `external`
  marker, and can be terminated. External processes are never written to the
  Guajará state file. **Why**: a state file cannot know about tunnels created
  outside Guajará, but the TUI must still show and control them. **Source**:
  user feedback.
- **State persistence**: JSON file at `~/.config/guajara/forwards.json`
  (serde/serde_json). Lists tunnels with pid, host, rules, started_at. Dead
  PIDs (checked via `kill -0`) are pruned automatically on load/list. **Why**:
  active tunnels must be visible in later TUI sessions. **Source**: user
  request.
- **Duplicate protection**: starting a tunnel fails if the same host already
  has an active tunnel, or if a local port collides with an active/pending
  rule. **Source**: design session 2026-09-01.
- **TUI flow**: new main-menu entry "Port forwards". List screen shows active
  tunnels (green = up) with `x` to stop, `a` to add. Add form fields:
  Host, Local Port, Target Host, Target Port, plus "Add Rule" to queue
  multiple rules (any mix of hosts) before "Save" starts them all. **Source**:
  user request ("vários de uma vez de vários hosts").
- **Live status in TUI**: the forwards list re-checks tunnel liveness every 2s
  (and on entry / `r`), so dead tunnels disappear and survivors keep showing
  `UP`. **Source**: user request ("saber que está ativo").
- **Sorting**: SSH hosts and forwarding tunnels are sorted by name by default;
  `o` toggles to descending last-used order. Last-used means the last
  forwarding started through Guajará and is persisted in the forwarding state.
  SSH login history is not inferred from shell history or other private files.
  **Why**: `~/.ssh/config` has no reliable last-access field, and reading shell
  history would expose unrelated user activity. **Source**: user feedback.

## Open Questions

- [ ] Remote forwarding (`-R`) support — deferred until requested.

## Dependencies

- `ssh` binary available on PATH (already implicit for a SSH config tool).

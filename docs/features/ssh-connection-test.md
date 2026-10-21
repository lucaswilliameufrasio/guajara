# SSH connection test

The SSH host list and details expose `t` to test a saved host; the CLI exposes
`guajara ssh test <selector>`. A concrete positive alias is required, not a
wildcard or negated pattern. The test uses the selected SSH config with `-F`.

The installed OpenSSH client authenticates and runs `true`, then disconnects.
The terminal is restored temporarily so passwords, key passphrases, and normal
host-key verification remain under OpenSSH's control. Host-key checks are never
disabled. Connection establishment has a ten-second timeout and one attempt;
interactive prompts still wait for the user. Forwarding and connection sharing
are disabled for the test, so success requires a fresh connection and cannot
start configured tunnels. The application reports the exit status, while SSH
prints diagnostics directly to the terminal. This tests saved configuration,
not unsaved form edits, and requires permission to execute `true` remotely.
Successful tests update the persisted host last-use history for sorting; failed
tests do not count as usage. A history write failure is reported separately
from successful authentication.

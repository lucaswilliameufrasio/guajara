# SSH identity selection

The SSH add/edit form opens a picker for IdentityFile instead of requiring a
path. It discovers private keys in `~/.ssh` (OpenSSH and PEM headers), without
displaying or retaining their contents. Manual paths remain available for keys
elsewhere, and clearing the field restores SSH's default identity behavior.

New keys use the installed `ssh-keygen` and Ed25519. The user supplies a filename
inside `~/.ssh`; existing private or public files are rejected. The TUI is
suspended while ssh-keygen asks for a passphrase directly in the terminal, so
the application does not handle passwords. A successful creation selects the
key but does not save the host automatically. Cancelling the host form does not
delete a newly created key. No dependency or automatic server installation is
introduced.

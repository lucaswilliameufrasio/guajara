# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-10-21

### Bug Fixes

- Run Windows artifact build with Bash
- Create SSH key directory on Windows

### CI / Build

- Configure cargo-dist release automation
- Limit release targets to macOS and Linux
## [0.2.0] - 2026-10-21

### Bug Fixes

- Quit option works via menu Enter and 'q' key
- Preserve file permissions, remove eprintln from TUI, fix SSH pattern edit, preserve hosts formatting
- Transient status messages expire after 3s, use event::poll for non-blocking loop
- ESC navigation respects history stack instead of jumping to main menu

### Chores

- Use Rust 1.98.0

### Documentation

- Remove project structure from README

### Features

- Initial guajara — SSH config and hosts file manager with TUI + CLI
- Popup overlay for validation, success, and error messages
- SSH port forwarding with live tracking in TUI
- Manage remote SSH hosts and identities

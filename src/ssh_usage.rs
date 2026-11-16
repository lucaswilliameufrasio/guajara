//! Safe preparation for opt-in OpenSSH last-use tracking.
use crate::connection::is_concrete_host;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Combine historical tunnel/test timestamps (seconds) with direct SSH usage (milliseconds).
pub fn last_used_millis(
    alias: &str,
    legacy: &std::collections::HashMap<String, u64>,
    usage: &std::collections::HashMap<String, u64>,
) -> u64 {
    let previous = legacy.get(alias).copied().unwrap_or(0).saturating_mul(1000);
    previous.max(usage.get(alias).copied().unwrap_or(0))
}

/// Record only the alias, in a separate per-alias file rather than rewriting tunnel state.
pub fn record_use(directory: &Path, alias: &str) -> Result<(), String> {
    if !is_concrete_host(alias) || alias.len() > 128 {
        return Err("Invalid SSH alias".into());
    }
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("Cannot create usage directory: {error}"))?;
    let encoded: String = alias
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let target = directory.join(encoded);
    let temporary = directory.join(format!(
        ".event-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("Cannot create usage record: {error}"))?;
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, &target) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("Cannot save usage record: {error}"));
    }
    Ok(())
}

/// Return recorded modification times in milliseconds, ignoring malformed entries.
pub fn load_usage(directory: &Path) -> std::collections::HashMap<String, u64> {
    let mut result = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return result;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || name.len() > 256 || name.len() % 2 != 0 {
            continue;
        }
        let mut bytes = Vec::new();
        for pair in name.as_bytes().as_chunks::<2>().0 {
            let Ok(text) = std::str::from_utf8(pair) else {
                bytes.clear();
                break;
            };
            let Ok(byte) = u8::from_str_radix(text, 16) else {
                bytes.clear();
                break;
            };
            bytes.push(byte);
        }
        let Ok(alias) = String::from_utf8(bytes) else {
            continue;
        };
        if !is_concrete_host(&alias) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() || entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(elapsed) = modified.duration_since(std::time::UNIX_EPOCH) else {
            continue;
        };
        if let Ok(milliseconds) = u64::try_from(elapsed.as_millis()) {
            result.insert(alias, milliseconds);
        }
    }
    result
}

/// Query OpenSSH rather than approximating its Include, Match and precedence rules.
/// This operation can execute existing `Match exec` clauses in the supplied config.
pub fn ensure_no_local_command(config: &Path, alias: &str) -> Result<(), String> {
    if !is_concrete_host(alias) {
        return Err("Select a concrete SSH alias".into());
    }
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(config)
        .arg("--")
        .arg(alias)
        .output()
        .map_err(|error| format!("Cannot inspect OpenSSH configuration: {error}"))?;
    if !output.status.success() {
        return Err("OpenSSH could not evaluate the configuration; nothing was changed".into());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "OpenSSH returned non-UTF-8 configuration")?;
    for line in text.lines() {
        let Some((key, _)) = line.split_once(' ') else {
            continue;
        };
        if key.eq_ignore_ascii_case("localcommand") {
            return Err(
                "An effective LocalCommand already exists; it will not be overwritten".into(),
            );
        }
    }
    Ok(())
}

/// Build and validate a per-alias opt-in change without modifying the config.
pub fn prepare_enable(
    config: &Path,
    alias: &str,
    executable: &Path,
) -> Result<(String, String), String> {
    if alias.is_empty()
        || !alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("Usage tracking requires an ASCII alias containing only letters, numbers, dots, hyphens or underscores".into());
    }
    let executable = executable.to_str().ok_or("Executable path is not UTF-8")?;
    if !executable.starts_with('/')
        || !executable
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
    {
        return Err("Executable path contains unsupported characters".into());
    }
    let metadata = std::fs::symlink_metadata(config)
        .map_err(|error| format!("Cannot inspect SSH config: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("SSH config must be a regular file, not a symlink".into());
    }
    let original = std::fs::read_to_string(config)
        .map_err(|error| format!("Cannot read SSH config: {error}"))?;
    ensure_no_local_command(config, alias)?;
    let mut parsed = crate::ssh::SshConfig::parse(&original);
    let hosts = parsed.hosts();
    let matches: Vec<_> = hosts
        .iter()
        .filter(|host| host.patterns.iter().any(|p| p == alias))
        .collect();
    if matches.len() != 1 || matches[0].patterns.len() != 1 {
        return Err("Select an alias in exactly one single-alias Host block".into());
    }
    let host = matches[0];
    if host
        .directives
        .iter()
        .any(|directive| directive.key.eq_ignore_ascii_case("PermitLocalCommand"))
    {
        return Err("Host already sets PermitLocalCommand; it will not be changed".into());
    }
    let start = host.start_idx;
    let command = format!("{executable} record-ssh-use {alias}");
    parsed.set(start, "LocalCommand", &command)?;
    parsed.set(start, "PermitLocalCommand", "yes")?;
    let updated = parsed.to_string();
    let temp = temporary_config(config, &updated, &metadata.permissions())?;
    let checked = effective_config(&temp.0, alias);
    let text = checked?;
    let expected = format!("localcommand {command}");
    if !text.lines().any(|line| line == expected)
        || !text.lines().any(|line| line == "permitlocalcommand yes")
    {
        return Err(
            "OpenSSH would not use the proposed hook; configuration was not changed".into(),
        );
    }
    Ok((original, updated))
}

struct TemporaryConfig(std::path::PathBuf);
impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temporary_config(
    config: &Path,
    content: &str,
    permissions: &std::fs::Permissions,
) -> Result<TemporaryConfig, String> {
    let path = config.with_file_name(format!(
        ".guajara-usage-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("Cannot create temporary config: {error}"))?;
    let temporary = TemporaryConfig(path);
    file.set_permissions(permissions.clone())
        .map_err(|error| format!("Cannot set temporary config permissions: {error}"))?;
    file.write_all(content.as_bytes())
        .map_err(|error| format!("Cannot write temporary config: {error}"))?;
    Ok(temporary)
}

/// Save only the reviewed version after rechecking the live config and conflict.
pub fn commit_enable(
    config: &Path,
    alias: &str,
    original: &str,
    updated: &str,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(config)
        .map_err(|error| format!("Cannot inspect SSH config: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || std::fs::read_to_string(config)
            .map_err(|error| format!("Cannot read SSH config: {error}"))?
            != original
    {
        return Err("SSH config changed; review again".into());
    }
    ensure_no_local_command(config, alias)?;
    let temp = temporary_config(config, updated, &metadata.permissions())?;
    if std::fs::read_to_string(config)
        .map_err(|error| format!("Cannot recheck SSH config: {error}"))?
        != original
    {
        return Err("SSH config changed; review again".into());
    }
    std::fs::rename(&temp.0, config).map_err(|error| format!("Cannot save SSH config: {error}"))?;
    Ok(())
}

fn effective_config(config: &Path, alias: &str) -> Result<String, String> {
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(config)
        .arg("--")
        .arg(alias)
        .output()
        .map_err(|error| format!("Cannot inspect OpenSSH configuration: {error}"))?;
    if !output.status.success() {
        return Err("OpenSSH could not evaluate the configuration; nothing was changed".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "OpenSSH returned non-UTF-8 configuration".into())
}

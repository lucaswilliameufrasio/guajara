use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Inspect a bounded format prefix without retaining or displaying key material.
pub fn discover(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("Cannot list SSH keys: {error}")),
    };
    let mut keys = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("Cannot list SSH keys: {error}"))?;
        let path = entry.path();
        if path
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
        {
            continue;
        }
        if !entry.metadata().is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        let mut header = [0; 40];
        let Ok(length) = file.read(&mut header) else {
            continue;
        };
        let header = String::from_utf8_lossy(&header[..length]);
        if [
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ]
        .iter()
        .any(|marker| header.starts_with(marker))
        {
            keys.push(path);
        }
    }
    keys.sort();
    Ok(keys)
}

pub fn new_key_path(directory: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with(".pub")
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(
            "Use a filename with letters, numbers, dots, hyphens or underscores (not .pub)".into(),
        );
    }
    let path = directory.join(name);
    let public_path = directory.join(format!("{name}.pub"));
    for candidate in [&path, &public_path] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Err("A private or public key with this name already exists".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Cannot check key path: {error}")),
        }
    }
    Ok(path)
}

/// Inherits the terminal so ssh-keygen handles passphrase input itself.
pub fn generate(directory: &Path, name: &str) -> Result<PathBuf, String> {
    let path = new_key_path(directory, name)?;
    if !directory.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|error| format!("Cannot create SSH directory: {error}"))?;
    }
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&path)
        .status()
        .map_err(|error| format!("Cannot run ssh-keygen: {error}"))?;
    if !status.success() {
        return Err("Key creation failed or was cancelled; IdentityFile was not changed".into());
    }
    Ok(path)
}

//! Remote operations send config text and key paths, never private key material.
use crate::{connection, ssh::SshConfig};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const READ_SCRIPT: &str = include_str!("remote/read.sh");
const KEYS_SCRIPT: &str = include_str!("remote/keys.sh");
const WRITE_SCRIPT: &str = include_str!("remote/write.sh");

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub exists: bool,
    pub content: String,
}

#[derive(Clone, Debug)]
pub struct Client {
    config: PathBuf,
    pub destination: String,
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl Client {
    pub fn new(config: &Path, destination: &str) -> Result<Self, String> {
        if !connection::is_concrete_host(destination) {
            return Err("Choose a concrete destination SSH alias".into());
        }
        Ok(Self {
            config: config.to_path_buf(),
            destination: destination.into(),
        })
    }

    fn command(&self, script: &str, interactive: bool) -> Command {
        let mut command = Command::new("ssh");
        command
            .arg("-F")
            .arg(&self.config)
            .arg(if interactive { "-tt" } else { "-T" })
            .args([
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ForwardAgent=no",
                "-o",
                "RemoteCommand=none",
                "-o",
                "SessionType=default",
                "-o",
                "ForkAfterAuthentication=no",
                "-o",
                "StdinNull=no",
                "-o",
                "ControlPath=none",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=2",
                "--",
                &self.destination,
            ])
            .arg(format!("sh -c {}", shell_quote(script)));
        command
    }

    fn request(&self, script: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut child = self
            .command(script, false)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("Cannot start SSH: {error}"))?;
        let mut stdin = child.stdin.take().ok_or("SSH stdin unavailable")?;
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let mut output = Vec::new();
        let read_result = child
            .stdout
            .take()
            .ok_or("SSH stdout unavailable")?
            .take((MAX_CONFIG_BYTES + 3) as u64)
            .read_to_end(&mut output);
        if read_result.is_err() || output.len() > MAX_CONFIG_BYTES + 2 {
            let _ = child.kill();
        }
        let status = child
            .wait()
            .map_err(|error| format!("Cannot wait for SSH: {error}"))?;
        let write_result = writer.join().map_err(|_| "SSH input writer failed")?;
        read_result.map_err(|error| format!("Cannot read SSH response: {error}"))?;
        if output.len() > MAX_CONFIG_BYTES + 2 {
            return Err("Remote response exceeds 2 MiB".into());
        }
        if !status.success() {
            return Err(format!(
                "Remote SSH operation failed ({status}). See terminal diagnostics; reload before retrying a write."
            ));
        }
        write_result.map_err(|error| format!("Cannot send SSH request: {error}"))?;
        Ok(output)
    }

    pub fn read(&self) -> Result<Snapshot, String> {
        decode_snapshot(self.request(READ_SCRIPT, Vec::new())?)
    }

    pub fn keys(&self) -> Result<Vec<PathBuf>, String> {
        let output = self.request(KEYS_SCRIPT, Vec::new())?;
        let mut keys = Vec::new();
        for bytes in output
            .split(|byte| *byte == 0)
            .filter(|bytes| !bytes.is_empty())
        {
            let value = std::str::from_utf8(bytes).map_err(|_| "Remote key path is not UTF-8")?;
            if value.starts_with('/') && !value.chars().any(char::is_control) {
                keys.push(PathBuf::from(value));
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub fn write(&self, original: &Snapshot, updated: &str) -> Result<(), String> {
        let response = self.request(WRITE_SCRIPT, write_frame(original, updated)?)?;
        if response != b"GUAJARA_SAVED\n" {
            return Err(
                "Remote write was not acknowledged. Reload and inspect the config before retrying."
                    .into(),
            );
        }
        Ok(())
    }

    pub fn create_key(&self, name: &str) -> Result<PathBuf, String> {
        // Reuse filename validation without consulting any local key directory.
        validate_key_name(name)?;
        let script = format!(
            r#"set -eu
umask 077
mkdir -p "$HOME/.ssh"
key="$HOME/.ssh/"{}
[ ! -e "$key" ] && [ ! -L "$key" ] && [ ! -e "$key.pub" ] && [ ! -L "$key.pub" ] || {{ echo 'Key name already exists' >&2; exit 1; }}
exec ssh-keygen -t ed25519 -f "$key"
"#,
            shell_quote(name)
        );
        let status = self
            .command(&script, true)
            .status()
            .map_err(|error| format!("Cannot start SSH key creation: {error}"))?;
        if !status.success() {
            return Err("Remote key creation failed or was cancelled".into());
        }
        Ok(PathBuf::from(format!("~/.ssh/{name}")))
    }

    pub fn test_host(&self, alias: &str) -> Result<(), String> {
        if !connection::is_concrete_host(alias) {
            return Err("Choose a concrete remote host alias".into());
        }
        let script = format!(
            "exec ssh -F \"$HOME/.ssh/config\" -T -n -o ConnectTimeout=10 -o ConnectionAttempts=1 -o ClearAllForwardings=yes -o ForwardAgent=no -o ControlPath=none -o RemoteCommand=none -o RequestTTY=no -o ForkAfterAuthentication=no -o SessionType=default -- {} true",
            shell_quote(alias)
        );
        let status = self
            .command(&script, true)
            .status()
            .map_err(|error| format!("Cannot start remote connection test: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "SSH test from '{}' to '{alias}' failed ({status})",
                self.destination
            ))
        }
    }
}

pub fn validate_key_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with(".pub")
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(
            "Use a filename containing letters, numbers, dots, hyphens or underscores (not .pub)"
                .into(),
        );
    }
    Ok(())
}

fn decode_snapshot(bytes: Vec<u8>) -> Result<Snapshot, String> {
    let text = String::from_utf8(bytes).map_err(|_| "Remote config is not UTF-8")?;
    let (flag, content) = text
        .split_once('\n')
        .ok_or("Invalid remote snapshot response")?;
    if !matches!(flag, "0" | "1") || content.contains('\0') || (flag == "0" && !content.is_empty())
    {
        return Err("Invalid remote snapshot response".into());
    }
    Ok(Snapshot {
        exists: flag == "1",
        content: content.into(),
    })
}

fn write_frame(original: &Snapshot, updated: &str) -> Result<Vec<u8>, String> {
    if original.content.len() > MAX_CONFIG_BYTES
        || updated.len() > MAX_CONFIG_BYTES
        || (!original.exists && !original.content.is_empty())
        || original.content.contains('\0')
        || updated.contains('\0')
    {
        return Err("Invalid SSH config or config exceeds 2 MiB".into());
    }
    let mut bytes = format!(
        "{} {} {}\n",
        u8::from(original.exists),
        original.content.len(),
        updated.len()
    )
    .into_bytes();
    bytes.extend_from_slice(original.content.as_bytes());
    bytes.extend_from_slice(updated.as_bytes());
    Ok(bytes)
}

/// Validate the whole batch before modifying a destination or creating keys.
pub fn check_copy(
    source: &SshConfig,
    indices: &[usize],
    destination: &SshConfig,
) -> Result<(), String> {
    if indices.is_empty() {
        return Err("Select at least one local host".into());
    }
    let mut aliases: HashSet<String> = destination
        .hosts()
        .into_iter()
        .flat_map(|host| host.patterns)
        .collect();
    let hosts = source.hosts();
    for index in indices {
        let host = hosts.get(*index).ok_or("Source host no longer exists")?;
        if host.patterns.is_empty() {
            return Err("A selected source block has no host patterns".into());
        }
        for alias in &host.patterns {
            if !aliases.insert(alias.clone()) {
                return Err(format!(
                    "Alias '{alias}' already exists in the destination or batch. Rename it before copying; nothing was written."
                ));
            }
        }
    }
    Ok(())
}

pub fn copy_hosts(
    source: &SshConfig,
    assignments: &[(usize, Option<String>)],
    destination: &SshConfig,
) -> Result<SshConfig, String> {
    let indices: Vec<usize> = assignments.iter().map(|(index, _)| *index).collect();
    check_copy(source, &indices, destination)?;
    let mut result = destination.clone();
    let hosts = source.hosts();
    for (index, selected_identity) in assignments {
        let host = &hosts[*index];
        let mut block = SshConfig {
            lines: source.lines[host.start_idx..host.end_idx].to_vec(),
        };
        let start = block
            .hosts()
            .first()
            .ok_or("Invalid source host block")?
            .start_idx;
        for directive in [
            "IdentityFile",
            "CertificateFile",
            "IdentityAgent",
            "PKCS11Provider",
            "SecurityKeyProvider",
        ] {
            let _ = block.unset(start, directive);
        }
        if let Some(path) = selected_identity {
            if path.chars().any(char::is_control) {
                return Err("Invalid remote identity path".into());
            }
            block.set(start, "IdentityFile", &config_path(path))?;
        }
        if !result.lines.is_empty() && !result.lines.last().is_some_and(String::is_empty) {
            result.lines.push(String::new());
        }
        result.lines.extend(block.lines);
    }
    Ok(result)
}

pub fn config_path(path: &str) -> String {
    format!("\"{}\"", path.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn shell(home: &Path, script: &str, input: &[u8]) -> std::process::Output {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn should_read_missing_and_existing_snapshots_without_changing_files() {
        let home = tempfile::tempdir().unwrap();
        let missing = decode_snapshot(shell(home.path(), READ_SCRIPT, &[]).stdout).unwrap();
        assert!(!missing.exists);
        assert!(!home.path().join(".ssh").exists());
        fs::create_dir(home.path().join(".ssh")).unwrap();
        fs::write(home.path().join(".ssh/config"), "# comment\nHost example\n").unwrap();
        let snapshot = decode_snapshot(shell(home.path(), READ_SCRIPT, &[]).stdout).unwrap();
        assert!(snapshot.exists);
        assert_eq!(snapshot.content, "# comment\nHost example\n");
        assert!(decode_snapshot(b"login banner\n1\nHost example".to_vec()).is_err());
        assert!(decode_snapshot(b"0\nnot empty".to_vec()).is_err());
    }

    #[test]
    fn should_atomically_create_and_update_remote_config_with_private_permissions() {
        let home = tempfile::tempdir().unwrap();
        let missing = Snapshot {
            exists: false,
            content: String::new(),
        };
        let content = "# Keep this comment\nHost first\n    User alice\n";
        let result = shell(
            home.path(),
            WRITE_SCRIPT,
            &write_frame(&missing, content).unwrap(),
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let path = home.path().join(".ssh/config");
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(home.path().join(".ssh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let original = Snapshot {
            exists: true,
            content: content.into(),
        };
        let updated = format!("{content}\nHost second\n");
        assert!(
            shell(
                home.path(),
                WRITE_SCRIPT,
                &write_frame(&original, &updated).unwrap()
            )
            .status
            .success()
        );
        assert_eq!(fs::read_to_string(path).unwrap(), updated);
        assert!(!home.path().join(".ssh/.guajara-config.lock").exists());
        assert_eq!(fs::read_dir(home.path().join(".ssh")).unwrap().count(), 1);
    }

    #[test]
    fn should_refuse_changed_appeared_symlinked_locked_and_incomplete_writes() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join(".ssh")).unwrap();
        let path = home.path().join(".ssh/config");
        fs::write(&path, "Host external\n").unwrap();
        for original in [
            Snapshot {
                exists: false,
                content: String::new(),
            },
            Snapshot {
                exists: true,
                content: "Host stale\n".into(),
            },
        ] {
            assert!(
                !shell(
                    home.path(),
                    WRITE_SCRIPT,
                    &write_frame(&original, "Host new\n").unwrap()
                )
                .status
                .success()
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), "Host external\n");
        }
        assert!(
            !shell(home.path(), WRITE_SCRIPT, b"1 100 100\nshort")
                .status
                .success()
        );
        fs::create_dir(home.path().join(".ssh/.guajara-config.lock")).unwrap();
        assert!(!shell(home.path(), WRITE_SCRIPT, &[]).status.success());
        assert!(home.path().join(".ssh/.guajara-config.lock").exists());
        fs::remove_dir(home.path().join(".ssh/.guajara-config.lock")).unwrap();
        fs::rename(&path, home.path().join("original")).unwrap();
        std::os::unix::fs::symlink(home.path().join("original"), &path).unwrap();
        let original = Snapshot {
            exists: true,
            content: "Host external\n".into(),
        };
        assert!(
            !shell(
                home.path(),
                WRITE_SCRIPT,
                &write_frame(&original, "Host new\n").unwrap()
            )
            .status
            .success()
        );
        assert_eq!(
            fs::read_to_string(home.path().join("original")).unwrap(),
            "Host external\n"
        );
    }

    #[test]
    fn should_return_only_remote_key_paths_not_their_contents() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join(".ssh")).unwrap();
        let key = home.path().join(".ssh/key with spaces");
        fs::write(
            &key,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-payload-not-a-key",
        )
        .unwrap();
        fs::write(
            home.path().join(".ssh/key.pub"),
            "ssh-ed25519 public fixture",
        )
        .unwrap();
        fs::write(home.path().join(".ssh/config"), "Host example\n").unwrap();
        let result = shell(home.path(), KEYS_SCRIPT, &[]);
        assert!(result.status.success());
        assert_eq!(
            result.stdout,
            [key.to_str().unwrap().as_bytes(), &[0]].concat()
        );
    }

    #[test]
    fn should_copy_multiple_lossless_blocks_and_replace_all_local_identity_bindings() {
        let source = SshConfig::parse(
            "Host first alias\n    # keep me\n    HostName one.example\n    IdentityFile /local/private\n    IdentityFile /local/other\n    CertificateFile /local/cert\n    IdentityAgent /local/agent\n    CustomOption value\n\nHost second\n    User bob\n",
        );
        let destination =
            SshConfig::parse("# destination comment\nHost existing\n    User alice\n");
        let result = copy_hosts(
            &source,
            &[(0, Some("/remote/key with spaces".into())), (1, None)],
            &destination,
        )
        .unwrap()
        .to_string();
        assert!(result.starts_with(&destination.to_string()));
        assert!(result.contains("# keep me"));
        assert!(result.contains("CustomOption value"));
        assert!(result.contains("Host first alias"));
        assert!(result.contains("Host second"));
        assert!(!result.contains("/local/"));
        assert!(result.contains("IdentityFile \"/remote/key with spaces\""));
        assert_eq!(result.matches("IdentityFile").count(), 1);
        assert!(copy_hosts(&source, &[(0, None), (0, None)], &destination).is_err());
        let collision = SshConfig::parse("Host alias\n");
        assert!(copy_hosts(&source, &[(0, None), (1, None)], &collision).is_err());
        assert_eq!(collision.to_string(), "Host alias\n");
    }

    #[test]
    fn should_bound_config_frames_and_validate_remote_names() {
        let original = Snapshot {
            exists: false,
            content: String::new(),
        };
        assert!(write_frame(&original, &"x".repeat(MAX_CONFIG_BYTES + 1)).is_err());
        assert!(write_frame(&original, "bad\0config").is_err());
        for name in [
            "../escape",
            "",
            "/absolute",
            "key.pub",
            "two words",
            "$(command)",
        ] {
            assert!(validate_key_name(name).is_err());
        }
        assert!(validate_key_name("id_remote-1").is_ok());
        let result = Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", shell_quote("a'; echo bad; 'b")))
            .output()
            .unwrap();
        assert_eq!(result.stdout, b"a'; echo bad; 'b");
    }
}

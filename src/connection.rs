use std::path::Path;
use std::process::Command;

pub fn is_concrete_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && !host.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '*' | '?' | '!')
        })
}

/// Keep authentication and host-key prompts in OpenSSH, not in application state.
pub fn test_command(config: &Path, host: &str) -> Result<Command, String> {
    if !is_concrete_host(host) {
        return Err("Select a concrete SSH host alias, not a wildcard or negated pattern".into());
    }
    let mut command = Command::new("ssh");
    command.arg("-F").arg(config).args([
        "-T",
        "-n",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "RemoteCommand=none",
        "-o",
        "RequestTTY=no",
        "-o",
        "ForkAfterAuthentication=no",
        "-o",
        "SessionType=default",
        "--",
        host,
        "true",
    ]);
    Ok(command)
}

pub fn test(config: &Path, host: &str) -> Result<(), String> {
    let status = test_command(config, host)?
        .status()
        .map_err(|error| format!("Cannot run ssh: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "SSH connection test for '{host}' failed ({status}).\nSee the SSH diagnostics in the terminal.\nCheck the address, port, user, identity and server host key."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_build_fresh_connection_without_forwarding_or_shell_interpolation() {
        let command = test_command(Path::new("/config with spaces/ssh"), "example").unwrap();
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_str().unwrap())
            .collect();
        assert_eq!(&arguments[..2], ["-F", "/config with spaces/ssh"]);
        assert_eq!(&arguments[arguments.len() - 3..], ["--", "example", "true"]);
        for option in [
            "ConnectTimeout=10",
            "ClearAllForwardings=yes",
            "ControlPath=none",
            "RemoteCommand=none",
            "ForkAfterAuthentication=no",
        ] {
            assert!(arguments.contains(&option));
        }
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("StrictHostKeyChecking=no"))
        );
    }

    #[test]
    fn should_reject_patterns_and_option_injection() {
        for host in [
            "",
            "*",
            "host?",
            "!excluded",
            "-oProxyCommand=bad",
            "two hosts",
            "host\nother",
        ] {
            assert!(test_command(Path::new("config"), host).is_err());
        }
        assert!(is_concrete_host("production"));
    }
}

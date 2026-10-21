use std::fs;
use std::net::TcpListener;
use std::process::Command;
use std::thread;

#[test]
fn should_report_real_ssh_handshake_failure_through_cli() {
    let directory = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = directory.path().join("ssh config");
    fs::write(&config, format!("Host local-test\n    HostName 127.0.0.1\n    Port {port}\n    IdentityFile none\n    IdentitiesOnly yes\n")).unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((connection, _)) => {
                    drop(connection);
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("Local SSH test listener failed: {error}"),
            }
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_guajara"))
        .arg("--ssh-config")
        .arg(&config)
        .args(["ssh", "test", "local-test"])
        .output()
        .unwrap();
    assert!(
        server.join().unwrap(),
        "SSH did not reach the configured local port"
    );
    assert!(!output.status.success());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains("SSH connection test for 'local-test' failed"));
    assert!(diagnostics.contains("Connection closed") || diagnostics.contains("Connection reset"));
}

#[test]
fn should_preview_without_connecting_and_reject_unknown_or_wildcard_hosts() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    fs::write(&config, "Host example\n    HostName 127.0.0.1\nHost *\n").unwrap();
    let preview = Command::new(env!("CARGO_BIN_EXE_guajara"))
        .arg("--ssh-config")
        .arg(&config)
        .args(["--dry-run", "ssh", "test", "example"])
        .output()
        .unwrap();
    assert!(preview.status.success());
    assert!(String::from_utf8_lossy(&preview.stdout).contains("Would test SSH connection"));
    for host in ["unknown", "*"] {
        let output = Command::new(env!("CARGO_BIN_EXE_guajara"))
            .arg("--ssh-config")
            .arg(&config)
            .args(["ssh", "test", host])
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

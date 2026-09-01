use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_forward_list_shows_external_ssh_tunnel() {
    let home = TempDir::new().unwrap();
    let bin = TempDir::new().unwrap();
    let ps_path = bin.path().join("ps");
    fs::write(
        &ps_path,
        "#!/bin/sh\nprintf '%s\\n' '4242 /usr/bin/ssh -N -L 127.0.0.1:5432:db.internal:5432 production'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&ps_path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&ps_path, permissions).unwrap();

    let original_path = std::env::var("PATH").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_guajara"))
        .args(["forward", "list"])
        .env("HOME", home.path())
        .env(
            "PATH",
            format!("{}:{}", bin.path().display(), original_path),
        )
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("production"));
    assert!(stdout.contains("5432→db.internal:5432"));
}

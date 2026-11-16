use guajara::ssh_usage::ensure_no_local_command;
use std::fs;

#[test]
fn concurrent_usage_records_preserve_each_alias_and_ignore_other_files() {
    let directory = tempfile::tempdir().unwrap();
    let events = directory.path().join("events");
    let mut threads = Vec::new();
    for alias in ["alpha", "beta", "café"] {
        let events = events.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..10 {
                guajara::ssh_usage::record_use(&events, alias).unwrap();
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    fs::write(events.join("not-hex"), "ignored").unwrap();
    let actual = guajara::ssh_usage::load_usage(&events);
    assert_eq!(actual.len(), 3);
    for alias in ["alpha", "beta", "café"] {
        assert!(actual[alias] > 0);
    }
    assert!(guajara::ssh_usage::record_use(&events, "../bad").is_ok());
    assert!(guajara::ssh_usage::record_use(&events, "bad\nalias").is_err());
    assert!(!directory.path().join("bad").exists());
}

#[test]
fn internal_recorder_writes_only_usage_files_under_isolated_home() {
    let home = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_guajara"))
        .env("HOME", home.path())
        .args(["record-ssh-use", "example"])
        .status()
        .unwrap();
    assert!(status.success());
    let base = home.path().join(".config/guajara");
    assert!(guajara::ssh_usage::load_usage(&base.join("ssh-use")).contains_key("example"));
    assert!(!base.join("forwards.json").exists());
}

#[test]
fn detects_effective_local_command_in_included_config_without_modifying_files() {
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("included");
    let config = directory.path().join("config");
    let included = "Host example\n LocalCommand existing-command\n";
    fs::write(&include, included).unwrap();
    let original = format!(
        "Include {}\nHost example\n HostName localhost\n",
        include.display()
    );
    fs::write(&config, &original).unwrap();

    let error = ensure_no_local_command(&config, "example").unwrap_err();
    assert!(error.contains("LocalCommand"));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    assert_eq!(fs::read_to_string(&include).unwrap(), included);
    assert!(ensure_no_local_command(&config, "other").is_ok());
}

#[test]
fn rejects_invalid_alias_and_invalid_openssh_config_without_changes() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    let original = "Host example\n UnsupportedGuajaraTestDirective yes\n";
    fs::write(&config, original).unwrap();
    assert!(ensure_no_local_command(&config, "-option").is_err());
    assert!(ensure_no_local_command(&config, "example").is_err());
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
}

#[test]
fn enable_usage_previews_conflicts_and_detects_changed_config() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    let included = directory.path().join("included");
    fs::write(&included, "Host example\n LocalCommand keep-this\n").unwrap();
    let original = format!(
        "Include {}\nHost example\n HostName localhost\n",
        included.display()
    );
    fs::write(&config, &original).unwrap();
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_guajara"));
    assert!(guajara::ssh_usage::prepare_enable(&config, "example", exe).is_err());
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    fs::write(&included, "# no hook\n").unwrap();
    let (old, new) = guajara::ssh_usage::prepare_enable(&config, "example", exe).unwrap();
    assert_eq!(fs::read_to_string(&config).unwrap(), old);
    assert!(new.contains("record-ssh-use example"));
    fs::write(&config, "# changed externally\n").unwrap();
    assert!(guajara::ssh_usage::commit_enable(&config, "example", &old, &new).is_err());
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "# changed externally\n"
    );
}

#[test]
fn cli_dry_run_and_existing_hook_leave_the_original_config_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    let original = "Host example\n HostName localhost\n";
    fs::write(&config, original).unwrap();
    let binary = env!("CARGO_BIN_EXE_guajara");
    let preview = std::process::Command::new(binary)
        .arg("--ssh-config")
        .arg(&config)
        .args(["--dry-run", "ssh", "enable-usage", "example"])
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(String::from_utf8_lossy(&preview.stdout).contains("record-ssh-use example"));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    let existing = "Host example\n LocalCommand echo existing\n";
    fs::write(&config, existing).unwrap();
    let output = std::process::Command::new(binary)
        .arg("--ssh-config")
        .arg(&config)
        .args(["--yes", "ssh", "enable-usage", "example"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&config).unwrap(), existing);
}

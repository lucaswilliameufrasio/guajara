use guajara::SshConfig;
use std::fs;
use std::process::Command;

#[test]
fn should_duplicate_losslessly_without_modifying_original_or_identity_files() {
    let original = "# public endpoint\nHost server server-public\n    HostName 203.0.113.10 # public address\n    User alice\n    Port 2222\n    IdentityFile ~/.ssh/server-key\n    IdentityFile ~/.ssh/backup-key\n    # keep the tunnel\n    LocalForward 9000 localhost:9000\n    ServerAliveInterval 30\n\nHost *\n    HostName 203.0.113.99\n";
    let mut config = SshConfig::parse(original);
    config
        .duplicate_host(
            0,
            &["server-tailscale".into()],
            &[
                ("HostName".into(), "100.64.0.10".into()),
                ("User".into(), "alice".into()),
                ("Port".into(), "2222".into()),
                ("IdentityFile".into(), "~/.ssh/server-key".into()),
            ],
        )
        .unwrap();
    let hosts = config.hosts();
    assert_eq!(hosts.len(), 3);
    assert_eq!(hosts[0].patterns, vec!["server", "server-public"]);
    assert_eq!(hosts[1].patterns, vec!["server-tailscale"]);
    assert_eq!(hosts[2].patterns, vec!["*"]);
    let original_block = &original[..original.find("Host *").unwrap()];
    assert!(config.to_string().starts_with(original_block));
    let duplicate = config.lines[hosts[1].start_idx..hosts[1].end_idx].join("\n");
    assert!(duplicate.contains("IdentityFile ~/.ssh/server-key"));
    assert!(duplicate.contains("IdentityFile ~/.ssh/backup-key"));
    assert!(duplicate.contains("# keep the tunnel"));
    assert!(duplicate.contains("LocalForward 9000 localhost:9000"));
    assert!(duplicate.contains("ServerAliveInterval 30"));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    fs::write(&path, config.to_string()).unwrap();
    // OpenSSH's own config evaluation verifies that the duplicate precedes later
    // wildcard defaults. -G evaluates this isolated fixture without connecting.
    for (alias, hostname) in [
        ("server", "203.0.113.10"),
        ("server-tailscale", "100.64.0.10"),
    ] {
        let output = Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(&path)
            .arg(alias)
            .output()
            .unwrap();
        assert!(output.status.success());
        let evaluated = String::from_utf8(output.stdout).unwrap();
        assert!(
            evaluated
                .lines()
                .any(|line| line == format!("hostname {hostname}"))
        );
        assert!(evaluated.contains("user alice\n"));
        assert!(evaluated.contains("port 2222\n"));
        assert!(evaluated.contains("identityfile ~/.ssh/server-key\n"));
        assert!(evaluated.contains("identityfile ~/.ssh/backup-key\n"));
    }
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn should_reject_conflicting_or_invalid_aliases_and_leave_document_unchanged() {
    let original = "Host server alias\n    HostName 203.0.113.10\nHost existing\n";
    for aliases in [
        vec![],
        vec!["server"],
        vec!["ALIAS"],
        vec!["existing"],
        vec!["new", "new"],
        vec!["*"],
        vec!["bad\nname"],
    ] {
        let mut config = SshConfig::parse(original);
        let patterns: Vec<String> = aliases.into_iter().map(String::from).collect();
        assert!(config.duplicate_host(0, &patterns, &[]).is_err());
        assert_eq!(config.to_string(), original);
    }
    let mut config = SshConfig::parse(original);
    assert!(config.duplicate_host(10, &["new".into()], &[]).is_err());
    assert!(
        config
            .duplicate_host(0, &["new".into()], &[("Port".into(), "70000".into())])
            .is_err()
    );
    assert_eq!(config.to_string(), original);
}

#[test]
fn should_allow_clearing_or_replacing_a_field_only_on_the_duplicate() {
    let mut config = SshConfig::parse(
        "Host server\n    HostName 203.0.113.10\n    User alice\n    IdentityFile /keys/first\n    IdentityFile /keys/second\n",
    );
    config
        .duplicate_host(
            0,
            &["server-public".into()],
            &[
                ("User".into(), String::new()),
                ("IdentityFile".into(), "\"/keys/other key\"".into()),
            ],
        )
        .unwrap();
    let hosts = config.hosts();
    assert_eq!(
        hosts[0]
            .directives
            .iter()
            .filter(|directive| directive.key == "IdentityFile")
            .count(),
        2
    );
    assert!(
        hosts[0]
            .directives
            .iter()
            .any(|directive| directive.key == "User")
    );
    assert_eq!(
        hosts[1]
            .directives
            .iter()
            .filter(|directive| directive.key == "IdentityFile")
            .count(),
        1
    );
    assert!(
        !hosts[1]
            .directives
            .iter()
            .any(|directive| directive.key == "User")
    );
    assert!(
        hosts[1]
            .directives
            .iter()
            .any(|directive| directive.value == "\"/keys/other key\"")
    );
}

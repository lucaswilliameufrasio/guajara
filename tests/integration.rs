use guajara::hosts::HostsFile;
use guajara::ssh::SshConfig;
use guajara::write_file;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

// ── SSH integration tests ─────────────────────────────────

#[test]
fn test_ssh_roundtrip_realistic() {
    let content = r#"Host production
    HostName prod.example.com
    User deploy
    Port 22
    IdentityFile ~/.ssh/prod-key

Host staging
    HostName staging.example.com
    User deploy
    Port 2222

Host *.internal
    HostName 10.0.0.%h
    User admin
"#;

    let config = SshConfig::parse(content);
    assert_eq!(config.to_string(), content);
    assert_eq!(config.hosts().len(), 3);
}

#[test]
fn test_ssh_set_after_load() {
    let content = r#"Host dev
    HostName dev.example.com
    User dev
"#;
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    config.set(start, "Port", "8080").unwrap();
    let result = config.to_string();
    assert!(result.contains("Port 8080"));
    assert!(result.contains("HostName dev.example.com"));
    assert!(!result.contains("Port 22"));
}

#[test]
fn test_ssh_add_roundtrip() {
    let content = "Host a\n    HostName a.com\n";
    let mut config = SshConfig::parse(content);
    config.add(
        &["b".to_string()],
        &[("HostName".to_string(), "b.com".to_string())],
    );
    let result = config.to_string();
    assert!(result.contains("Host b"));
    assert!(result.contains("HostName b.com"));
    assert_eq!(config.hosts().len(), 2);
}

#[test]
fn test_ssh_remove_block() {
    let content = "Host a\n    HostName a.com\nHost b\n    HostName b.com\n";
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    config.remove_block(start).unwrap();
    assert_eq!(config.hosts().len(), 1);
    assert_eq!(config.hosts()[0].patterns, vec!["b"]);
}

#[test]
fn test_ssh_select() {
    let content = "Host prod\n    HostName prod.com\nHost staging\n    HostName staging.com\n";
    let config = SshConfig::parse(content);
    let prod = config.select("prod");
    assert!(matches!(prod, guajara::ssh::SelectResult::Single(_)));
    let missing = config.select("nonexistent");
    assert!(matches!(missing, guajara::ssh::SelectResult::None));
}

#[test]
fn test_ssh_with_match_and_include() {
    let content = r#"Include ~/.ssh/config.d/*

Host a
    HostName a.com

Match host bastion exec "true"
    User admin

Host b
    HostName b.com
"#;
    let config = SshConfig::parse(content);
    assert_eq!(config.hosts().len(), 2);
    assert_eq!(config.matches().len(), 1);
    assert_eq!(config.to_string(), content);
}

#[test]
fn test_ssh_validate_ok() {
    let content = "Host a\n    HostName a.com\n";
    let config = SshConfig::parse(content);
    assert!(config.validate().is_empty());
}

#[test]
fn test_ssh_globals_preserved() {
    let content = "StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\n\nHost test\n    HostName test.com\n";
    let config = SshConfig::parse(content);
    assert!(config.to_string().contains("StrictHostKeyChecking"));
    assert_eq!(config.hosts().len(), 1);
}

// ── Hosts integration tests ────────────────────────────────

#[test]
fn test_hosts_roundtrip() {
    let content = "127.0.0.1\tlocalhost\n192.168.1.1\tnas home-server\n::1\tip6-localhost\n";
    let hosts = HostsFile::parse(content);
    assert_eq!(hosts.to_string(), content);
    assert_eq!(hosts.records().len(), 3);
}

#[test]
fn test_hosts_add_record() {
    let content = "127.0.0.1\tlocalhost\n";
    let mut hosts = HostsFile::parse(content);
    hosts.add("10.0.0.1", &["server".to_string()]);
    let records = hosts.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].ip, "10.0.0.1");
}

#[test]
fn test_hosts_remove_record() {
    let content = "127.0.0.1\tlocalhost\n10.0.0.1\tserver\n";
    let mut hosts = HostsFile::parse(content);
    hosts.remove(0).unwrap();
    assert_eq!(hosts.records().len(), 1);
    assert_eq!(hosts.records()[0].ip, "10.0.0.1");
}

#[test]
fn test_hosts_set_ip() {
    let content = "192.168.1.1\tnas\n";
    let mut hosts = HostsFile::parse(content);
    hosts.set_ip(0, "192.168.1.100").unwrap();
    assert_eq!(hosts.records()[0].ip, "192.168.1.100");
}

#[test]
fn test_hosts_find() {
    let content = "127.0.0.1\tlocalhost\n192.168.1.1\tnas\n";
    let hosts = HostsFile::parse(content);
    let found = hosts.find("nas");
    assert_eq!(found.len(), 1);
    assert_eq!(hosts.records()[found[0]].ip, "192.168.1.1");
}

#[test]
fn test_hosts_with_comments() {
    let content = "# This is a comment\n127.0.0.1\tlocalhost  # loopback\n";
    let hosts = HostsFile::parse(content);
    assert_eq!(hosts.records().len(), 1);
    assert_eq!(hosts.records()[0].comment.as_deref(), Some("loopback"));
}

#[test]
fn test_hosts_inline_comment_preserved_on_edit() {
    let content = "127.0.0.1\tlocalhost  # loopback\n";
    let mut hosts = HostsFile::parse(content);
    hosts.set_ip(0, "127.0.0.2").unwrap();
    let result = hosts.to_string();
    assert!(result.contains("127.0.0.2"));
    assert!(result.contains("loopback"));
}

#[test]
fn test_hosts_empty_file() {
    let hosts = HostsFile::parse("");
    assert!(hosts.is_empty());
    assert_eq!(hosts.records().len(), 0);
}

#[test]
fn test_hosts_validate() {
    let content = "127.0.0.1\tlocalhost\ninvalid_line\n";
    let hosts = HostsFile::parse(content);
    let errors = hosts.validate();
    assert!(!errors.is_empty());
}

#[test]
fn test_hosts_add_does_not_lose_blank_lines() {
    let content = "127.0.0.1\tlocalhost\n\n192.168.1.1\tnas\n";
    let mut hosts = HostsFile::parse(content);
    hosts.add("10.0.0.1", &["server".to_string()]);
    assert!(hosts.to_string().contains("\n\n"));
    assert!(hosts.to_string().contains("10.0.0.1"));
}

#[test]
fn test_ssh_preserves_tab_indentation() {
    let content = "Host test\n\tHostName test.com\n";
    let config = SshConfig::parse(content);
    assert_eq!(config.to_string(), content);
}

#[test]
fn test_hosts_ipv6_preserved() {
    let content = "::1\tlocalhost ip6-localhost ip6-loopback\n";
    let hosts = HostsFile::parse(content);
    assert_eq!(hosts.records().len(), 1);
    assert_eq!(hosts.records()[0].ip, "::1");
}

#[test]
fn test_ssh_unset_nonexistent() {
    let content = "Host a\n    HostName a.com\n";
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    assert!(config.unset(start, "Port").is_err());
}

#[test]
fn test_ssh_remove_pattern_from_host() {
    let content = "Host a b\n    HostName a.com\n";
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    config.remove_pattern(start, "b").unwrap();
    assert_eq!(config.hosts()[0].patterns, vec!["a"]);
}

// ── Write / permissions tests ──────────────────────────────

#[test]
fn test_write_file_preserves_permissions() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ssh_config");
    let original = "Host test\n    HostName test.com\n";
    std::fs::write(&path, original).unwrap();

    // Set restrictive permissions (0600)
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&path, perms).unwrap();

    let new_content = "Host test\n    HostName test2.com\n";
    write_file(&path, new_content).unwrap();

    let saved_perms = std::fs::metadata(&path).unwrap().permissions();
    assert_eq!(saved_perms.mode() & 0o777, 0o600);
    let saved = std::fs::read_to_string(&path).unwrap();
    assert_eq!(saved, new_content);
}

// ── SSH header replacement tests ───────────────────────────

#[test]
fn test_ssh_header_direct_replacement() {
    let content = "Host a b\n    HostName old.com\n";
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    // Simulate what the TUI does: replace the header line directly
    let indent: String = config.lines[start]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    config.lines[start] = format!("{}Host new-name", indent);
    let hosts = config.hosts();
    assert_eq!(hosts[0].patterns, vec!["new-name"]);
    assert_eq!(config.to_string(), "Host new-name\n    HostName old.com\n");
}

#[test]
fn test_ssh_header_replacement_preserves_indentation() {
    let content = "  Host a\n    HostName a.com\n";
    let mut config = SshConfig::parse(content);
    let start = config.hosts()[0].start_idx;
    let indent: String = config.lines[start]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    config.lines[start] = format!("{}Host b", indent);
    assert_eq!(config.hosts()[0].patterns, vec!["b"]);
    // Indentation preserved
    assert!(config.to_string().starts_with("  Host b"));
}

// ── Hosts edit formatting preservation tests ───────────────

#[test]
fn test_hosts_edit_preserves_indentation() {
    let content = "  127.0.0.1\tlocalhost\n";
    let mut hosts = HostsFile::parse(content);
    let records = hosts.records();
    let idx = records[0].line_idx;
    // Simulate TUI edit: preserve indentation
    let indent: String = hosts.lines[idx]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    hosts.lines[idx] = format!("{}127.0.0.2\tlocalhost", indent);
    assert!(hosts.to_string().starts_with("  127.0.0.2"));
}

#[test]
fn test_hosts_edit_preserves_comment_style() {
    let content = "192.168.1.1\tnas\t# My NAS device\n";
    let mut hosts = HostsFile::parse(content);
    let records = hosts.records();
    let idx = records[0].line_idx;
    let indent: String = hosts.lines[idx]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    // Preserve original comment marker (with tab before #)
    let raw = &hosts.lines[idx];
    let comment_str = if let Some(pos) = raw.find('#') {
        format!(" {}", &raw[pos..])
    } else {
        String::new()
    };
    hosts.lines[idx] = format!("{}10.0.0.1\tnew-host{}", indent, comment_str);
    assert!(hosts.to_string().contains("10.0.0.1"));
    assert!(hosts.to_string().contains("# My NAS device"));
}

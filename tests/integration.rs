use guajara::forward;
use guajara::hosts::HostsFile;
use guajara::ssh::SshConfig;
use guajara::{ForwardRule, ForwardState, Tunnel, write_file};
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

// ── Forward integration tests ──────────────────────────────

fn fwd_rule(host: &str, local_port: u16, target_host: &str, target_port: u16) -> ForwardRule {
    ForwardRule {
        host: host.to_string(),
        local_port,
        target_host: target_host.to_string(),
        target_port,
    }
}

fn alive_pid() -> u32 {
    std::process::id()
}

#[test]
fn test_forward_state_save_and_load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let state = ForwardState {
        tunnels: vec![Tunnel {
            host: "web1".to_string(),
            pid: alive_pid(),
            started_at: 1700000000,
            rules: vec![
                fwd_rule("web1", 5432, "db.internal", 5432),
                fwd_rule("web1", 8080, "web", 80),
            ],
            managed: true,
        }],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();
    let loaded = forward::load(&path);
    assert_eq!(loaded, state);
}

#[test]
fn test_forward_state_persists_last_used_host_times() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let mut last_used = std::collections::HashMap::new();
    last_used.insert("web1".to_string(), 20);
    last_used.insert("web2".to_string(), 10);
    let state = ForwardState {
        tunnels: vec![],
        last_used,
    };

    forward::save(&path, &state).unwrap();
    let loaded = forward::load(&path);
    assert_eq!(loaded.last_used.get("web1"), Some(&20));
    assert_eq!(loaded.last_used.get("web2"), Some(&10));
}

#[test]
fn test_forward_state_survives_across_sessions() {
    // Simulates two guajara sessions sharing the same state file
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");

    let rules = vec![
        fwd_rule("web1", 5432, "db.internal", 5432),
        fwd_rule("web2", 5433, "db2.internal", 5432),
    ];
    forward::validate_start(&path, &rules).unwrap();

    let state = ForwardState {
        tunnels: rules
            .chunks(1)
            .map(|chunk| Tunnel {
                host: chunk[0].host.clone(),
                pid: alive_pid(),
                started_at: 1700000000,
                rules: chunk.to_vec(),
                managed: true,
            })
            .collect(),
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    let next_session = forward::load(&path);
    assert_eq!(next_session.tunnels.len(), 2);
    assert_eq!(next_session.tunnels[0].host, "web1");
    assert_eq!(next_session.tunnels[1].host, "web2");
}

#[test]
fn test_forward_validate_rejects_conflicts_before_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let state = ForwardState {
        tunnels: vec![Tunnel {
            host: "web1".to_string(),
            pid: alive_pid(),
            started_at: 0,
            rules: vec![fwd_rule("web1", 5432, "db.internal", 5432)],
            managed: true,
        }],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    let err = forward::validate_start(&path, &[fwd_rule("web2", 5432, "db", 5432)]).unwrap_err();
    assert!(err.contains("5432"));

    let err = forward::validate_start(&path, &[fwd_rule("web1", 6000, "db", 5432)]).unwrap_err();
    assert!(err.contains("already active"));
}

#[test]
fn test_forward_stop_tunnel_removes_from_state() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let state = ForwardState {
        tunnels: vec![
            Tunnel {
                host: "web1".to_string(),
                pid: 4_000_000_000,
                started_at: 0,
                rules: vec![fwd_rule("web1", 5432, "db", 5432)],
                managed: true,
            },
            Tunnel {
                host: "web2".to_string(),
                pid: 4_000_000_001,
                started_at: 0,
                rules: vec![fwd_rule("web2", 5433, "db", 5433)],
                managed: true,
            },
        ],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    // Both pids are dead, so load() prunes everything
    let loaded = forward::load(&path);
    assert!(loaded.tunnels.is_empty());

    // Stopping a pruned host reports not-found
    assert!(!forward::stop_tunnel(&path, "web1").unwrap());
}

// ── Forward process-control integration (real processes) ──

/// Spawns a detached `sleep 60` and returns its PID. The shell exits right
/// away, so the sleeper is reparented and reaped when killed — the same
/// lifecycle a nohup'd ssh tunnel has. The sleeper's output is redirected so
/// it does not hold the capture pipe open.
fn spawn_orphan_sleeper() -> u32 {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 60 >/dev/null 2>&1 & echo $!")
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn test_forward_stop_tunnel_kills_process_and_updates_state() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let pid = spawn_orphan_sleeper();
    let state = ForwardState {
        tunnels: vec![Tunnel {
            host: "web1".to_string(),
            pid,
            started_at: 0,
            rules: vec![fwd_rule("web1", 5432, "db.internal", 5432)],
            managed: true,
        }],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    // Alive at load time, so the tunnel is listed
    assert_eq!(forward::load(&path).tunnels.len(), 1);

    assert!(forward::stop_tunnel(&path, "web1").unwrap());
    assert!(!forward::is_alive(pid));
    assert!(forward::load(&path).tunnels.is_empty());
    assert!(!forward::stop_tunnel(&path, "web1").unwrap());
}

#[test]
fn test_forward_terminate_handles_unreaped_child_zombie() {
    let child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let pid = child.id();
    std::mem::forget(child);

    assert!(forward::terminate(pid).is_ok());
    assert!(!forward::is_alive(pid));
}

#[test]
fn test_forward_stop_all_stops_every_tunnel() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let pid_a = spawn_orphan_sleeper();
    let pid_b = spawn_orphan_sleeper();
    let state = ForwardState {
        tunnels: vec![
            Tunnel {
                host: "web1".to_string(),
                pid: pid_a,
                started_at: 0,
                rules: vec![fwd_rule("web1", 5432, "db", 5432)],
                managed: true,
            },
            Tunnel {
                host: "web2".to_string(),
                pid: pid_b,
                started_at: 0,
                rules: vec![fwd_rule("web2", 5433, "db", 5433)],
                managed: true,
            },
        ],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    let stopped = forward::stop_all(&path).unwrap();
    assert_eq!(stopped, 2);
    assert!(!forward::is_alive(pid_a));
    assert!(!forward::is_alive(pid_b));
    assert!(forward::load(&path).tunnels.is_empty());

    // Stopping again with an empty state is a no-op
    assert_eq!(forward::stop_all(&path).unwrap(), 0);
}

#[test]
fn test_forward_stop_all_with_no_state_returns_zero() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("missing.json");
    assert_eq!(forward::stop_all(&path).unwrap(), 0);
}

#[test]
fn test_forward_lifecycle_validate_start_stop_revalidate() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let pid = spawn_orphan_sleeper();
    let state = ForwardState {
        tunnels: vec![Tunnel {
            host: "web1".to_string(),
            pid,
            started_at: 0,
            rules: vec![fwd_rule("web1", 5432, "db.internal", 5432)],
            managed: true,
        }],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();

    // Same host busy
    let err = forward::validate_start(&path, &[fwd_rule("web1", 6000, "x", 1)]).unwrap_err();
    assert!(err.contains("already active"));

    // Same local port busy on another host
    let err = forward::validate_start(&path, &[fwd_rule("web2", 5432, "x", 1)]).unwrap_err();
    assert!(err.contains("already in use"));

    // A different host with a free port is fine while web1 runs
    forward::validate_start(&path, &[fwd_rule("web2", 5433, "x", 1)]).unwrap();

    // After stopping web1, its host and port free up
    assert!(forward::stop_tunnel(&path, "web1").unwrap());
    forward::validate_start(&path, &[fwd_rule("web1", 5432, "db.internal", 5432)]).unwrap();
}

#[test]
fn test_forward_state_file_is_pretty_json() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("forwards.json");
    let state = ForwardState {
        tunnels: vec![Tunnel {
            host: "web1".to_string(),
            pid: 4_000_000_000,
            started_at: 1700000000,
            rules: vec![fwd_rule("web1", 5432, "db.internal", 5432)],
            managed: true,
        }],
        last_used: std::collections::HashMap::new(),
    };
    forward::save(&path, &state).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.starts_with("{\n"));
    assert!(content.ends_with('\n'));
    assert!(content.contains("\"local_port\": 5432"));
}

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

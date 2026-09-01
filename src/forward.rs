use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const STATE_PATH: &str = "~/.config/guajara/forwards.json";

// ── Data model ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRule {
    pub host: String,
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl ForwardRule {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("SSH host is required".to_string());
        }
        if self.target_host.trim().is_empty() {
            return Err("Target host is required".to_string());
        }
        if self.local_port == 0 {
            return Err(format!("Invalid local port for '{}'", self.host));
        }
        if self.target_port == 0 {
            return Err(format!("Invalid target port for '{}'", self.host));
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        format!(
            "{}→{}:{}",
            self.local_port, self.target_host, self.target_port
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tunnel {
    pub host: String,
    pub pid: u32,
    pub started_at: u64,
    pub rules: Vec<ForwardRule>,
    #[serde(default = "default_managed")]
    pub managed: bool,
}

fn default_managed() -> bool {
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardState {
    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
    #[serde(default)]
    pub last_used: HashMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortConflict {
    pub port: u16,
    pub owner: String,
}

// ── State file ─────────────────────────────────────────────

pub fn state_path() -> PathBuf {
    crate::expand_path(STATE_PATH)
}

/// Loads the state file and drops tunnels whose ssh process is gone.
pub fn load(path: &Path) -> ForwardState {
    let Ok(content) = std::fs::read_to_string(path) else {
        return ForwardState::default();
    };
    let Ok(mut state) = serde_json::from_str::<ForwardState>(&content) else {
        return ForwardState::default();
    };
    state.tunnels.retain(|t| is_alive(t.pid));
    state
}

/// Returns managed tunnels plus active local forwards started outside Guajará.
pub fn active(path: &Path) -> ForwardState {
    let mut state = load(path);
    let managed_pids: Vec<u32> = state.tunnels.iter().map(|tunnel| tunnel.pid).collect();
    for tunnel in discover_external() {
        if !managed_pids.contains(&tunnel.pid) {
            state.tunnels.push(tunnel);
        }
    }
    state
}

pub fn save(path: &Path, state: &ForwardState) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {}", parent.display(), e))?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(path, json + "\n").map_err(|e| format!("Cannot write {}: {}", path.display(), e))
}

// ── Process control ────────────────────────────────────────

pub fn is_alive(pid: u32) -> bool {
    let kill_status = Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !kill_status {
        return false;
    }

    // A child that exited while its parent did not reap it is a zombie.
    // kill -0 still succeeds for that PID, but there is no live tunnel left.
    let Ok(output) = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
    else {
        return true;
    };
    let process_state = String::from_utf8_lossy(&output.stdout);
    !process_state.trim_start().starts_with('Z')
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_ssh_args(host: &str, rules: &[ForwardRule]) -> Vec<String> {
    let mut args = vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=30".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
    ];
    for rule in rules {
        args.push("-L".to_string());
        args.push(format!(
            "127.0.0.1:{}:{}:{}",
            rule.local_port, rule.target_host, rule.target_port
        ));
    }
    args.push(host.to_string());
    args
}

fn spawn_tunnel(host: &str, rules: &[ForwardRule]) -> Result<Tunnel, String> {
    let mut cmd = Command::new("nohup");
    cmd.arg("ssh");
    for arg in build_ssh_args(host, rules) {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd
        .spawn()
        .map_err(|e| format!("Cannot start ssh for '{}': {}", host, e))?;
    Ok(Tunnel {
        host: host.to_string(),
        pid: child.id(),
        started_at: unix_now(),
        rules: rules.to_vec(),
        managed: true,
    })
}

/// Finds local `ssh -L` processes, including ones not started by Guajará.
pub fn discover_external() -> Vec<Tunnel> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,command="]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_external_process)
        .collect()
}

fn parse_external_process(line: &str) -> Option<Tunnel> {
    let mut tokens = line.split_whitespace();
    let pid = tokens.next()?.parse::<u32>().ok()?;
    let executable = tokens.next()?;
    let executable_name = Path::new(executable).file_name()?.to_str()?;
    if executable_name != "ssh" {
        return None;
    }

    let arguments: Vec<&str> = tokens.collect();
    let mut rules = Vec::new();
    let mut host = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if argument == "-L" {
            let value = arguments.get(index + 1)?;
            rules.push(parse_forward_spec(value, "external")?);
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("-L") {
            if !value.is_empty() {
                rules.push(parse_forward_spec(value, "external")?);
            }
            index += 1;
            continue;
        }
        if argument == "--" {
            host = arguments.get(index + 1).map(|value| (*value).to_string());
            break;
        }
        if !argument.starts_with('-') {
            host = Some(argument.to_string());
        } else if matches!(
            argument,
            "-o" | "-p"
                | "-i"
                | "-F"
                | "-J"
                | "-l"
                | "-b"
                | "-c"
                | "-D"
                | "-W"
                | "-S"
                | "-B"
                | "-E"
        ) {
            index += 1;
        }
        index += 1;
    }
    let host = host?;
    if rules.is_empty() {
        return None;
    }
    Some(Tunnel {
        host: host.clone(),
        pid,
        started_at: 0,
        rules: rules
            .into_iter()
            .map(|mut rule| {
                rule.host = host.clone();
                rule
            })
            .collect(),
        managed: false,
    })
}

fn parse_forward_spec(value: &str, host: &str) -> Option<ForwardRule> {
    let parts: Vec<&str> = value.split(':').collect();
    let (local_port, target_host, target_port) = match parts.as_slice() {
        [local_port, target_host, target_port] => (*local_port, *target_host, *target_port),
        [_, local_port, target_host, target_port] => (*local_port, *target_host, *target_port),
        _ => return None,
    };
    Some(ForwardRule {
        host: host.to_string(),
        local_port: local_port.parse().ok()?,
        target_host: target_host.to_string(),
        target_port: target_port.parse().ok()?,
    })
}

/// Sends SIGTERM, waits up to 2s, then falls back to SIGKILL.
pub fn terminate(pid: u32) -> Result<(), String> {
    if !is_alive(pid) {
        return Ok(());
    }
    let _ = Command::new("kill").arg(pid.to_string()).status();
    for _ in 0..20 {
        if !is_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    if is_alive(pid) {
        Err(format!("Cannot stop process {}", pid))
    } else {
        Ok(())
    }
}

// ── Validation ─────────────────────────────────────────────

/// Groups rules by SSH host preserving first-seen order.
pub fn group_by_host(rules: &[ForwardRule]) -> Vec<(String, Vec<ForwardRule>)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<ForwardRule>> = HashMap::new();
    for rule in rules {
        if !groups.contains_key(&rule.host) {
            order.push(rule.host.clone());
        }
        groups
            .entry(rule.host.clone())
            .or_default()
            .push(rule.clone());
    }
    order
        .into_iter()
        .map(|host| {
            let host_rules = groups.remove(&host).unwrap_or_default();
            (host, host_rules)
        })
        .collect()
}

/// Returns local ports from `rules` that collide with active tunnels.
pub fn find_port_conflicts(rules: &[ForwardRule], tunnels: &[Tunnel]) -> Vec<PortConflict> {
    let mut conflicts: Vec<PortConflict> = Vec::new();
    for rule in rules {
        for tunnel in tunnels {
            for active in &tunnel.rules {
                if active.local_port == rule.local_port {
                    let owner = format!(
                        "'{}' ({}→{}:{})",
                        tunnel.host, active.local_port, active.target_host, active.target_port
                    );
                    if !conflicts
                        .iter()
                        .any(|c| c.port == rule.local_port && c.owner == owner)
                    {
                        conflicts.push(PortConflict {
                            port: rule.local_port,
                            owner,
                        });
                    }
                }
            }
        }
    }
    conflicts
}

/// Validates rules against each other and against active tunnels.
pub fn validate_rules(rules: &[ForwardRule], tunnels: &[Tunnel]) -> Result<(), String> {
    for rule in rules {
        rule.validate()?;
    }
    for (i, rule) in rules.iter().enumerate() {
        for other in &rules[i + 1..] {
            if other.local_port == rule.local_port {
                return Err(format!(
                    "Local port {} used twice (hosts '{}' and '{}')",
                    rule.local_port, rule.host, other.host
                ));
            }
        }
    }
    for tunnel in tunnels {
        if rules.iter().any(|r| r.host == tunnel.host) {
            return Err(format!(
                "Tunnel for host '{}' is already active (pid {})",
                tunnel.host, tunnel.pid
            ));
        }
    }
    let conflicts = find_port_conflicts(rules, tunnels);
    if let Some(conflict) = conflicts.first() {
        return Err(format!(
            "Local port {} already in use by tunnel for {}",
            conflict.port, conflict.owner
        ));
    }
    Ok(())
}

pub fn validate_start(path: &Path, rules: &[ForwardRule]) -> Result<(), String> {
    let state = active(path);
    validate_rules(rules, &state.tunnels)
}

// ── High-level operations ──────────────────────────────────

/// Validates rules, spawns one ssh per host, and persists the state.
pub fn start_all(path: &Path, rules: &[ForwardRule]) -> Result<Vec<Tunnel>, String> {
    if rules.is_empty() {
        return Err("No forwarding rules provided".to_string());
    }
    validate_start(path, rules)?;
    let mut state = load(path);
    let mut started = Vec::new();
    for (host, host_rules) in group_by_host(rules) {
        let tunnel = spawn_tunnel(&host, &host_rules)?;
        state.last_used.insert(host.clone(), tunnel.started_at);
        started.push(tunnel.clone());
        state.tunnels.push(tunnel);
    }
    save(path, &state)?;
    Ok(started)
}

/// Stops the tunnel for `host`. Returns false when no tunnel exists.
pub fn stop_tunnel(path: &Path, host: &str) -> Result<bool, String> {
    let mut state = load(path);
    let external = discover_external();
    let Some(managed_pos) = state.tunnels.iter().position(|t| t.host == host) else {
        let Some(tunnel) = external.iter().find(|tunnel| tunnel.host == host) else {
            return Ok(false);
        };
        terminate(tunnel.pid)?;
        return Ok(true);
    };
    let pos = managed_pos;
    if !state.tunnels[pos].managed {
        terminate(state.tunnels[pos].pid)?;
        state.tunnels.remove(pos);
        save(path, &state)?;
        return Ok(true);
    }
    if pos >= state.tunnels.len() {
        return Ok(false);
    }
    let pid = state.tunnels.remove(pos).pid;
    terminate(pid)?;
    save(path, &state)?;
    Ok(true)
}

/// Stops every tunnel. Returns how many were stopped.
pub fn stop_all(path: &Path) -> Result<usize, String> {
    let mut state = load(path);
    let tunnels = std::mem::take(&mut state.tunnels);
    let count = tunnels.len();
    for tunnel in &tunnels {
        terminate(tunnel.pid)?;
    }
    if count > 0 {
        save(path, &state)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str, local_port: u16, target_host: &str, target_port: u16) -> ForwardRule {
        ForwardRule {
            host: host.to_string(),
            local_port,
            target_host: target_host.to_string(),
            target_port,
        }
    }

    // ── build_ssh_args ─────────────────────────────────────

    #[test]
    fn test_build_ssh_args_single_rule() {
        let args = build_ssh_args("web1", &[rule("web1", 5432, "db.internal", 5432)]);
        assert_eq!(
            args,
            vec![
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ServerAliveCountMax=3",
                "-L",
                "127.0.0.1:5432:db.internal:5432",
                "web1"
            ]
        );
    }

    #[test]
    fn test_build_ssh_args_multiple_rules() {
        let args = build_ssh_args(
            "web1",
            &[
                rule("web1", 5432, "db.internal", 5432),
                rule("web1", 8080, "web", 80),
            ],
        );
        let l_count = args.iter().filter(|a| *a == "-L").count();
        assert_eq!(l_count, 2);
        assert_eq!(args.last().unwrap(), "web1");
    }

    #[test]
    fn test_parse_external_process_detects_local_forward() {
        let tunnel =
            parse_external_process("1234 /usr/bin/ssh -N -L 127.0.0.1:5432:db.internal:5432 web1")
                .unwrap();
        assert_eq!(tunnel.pid, 1234);
        assert_eq!(tunnel.host, "web1");
        assert!(!tunnel.managed);
        assert_eq!(tunnel.rules[0].local_port, 5432);
        assert_eq!(tunnel.rules[0].target_host, "db.internal");
    }

    #[test]
    fn test_parse_external_process_ignores_non_ssh() {
        assert!(parse_external_process("1234 /usr/bin/curl -L example.com").is_none());
    }

    #[test]
    fn test_parse_external_process_supports_multiple_forwards() {
        let tunnel =
            parse_external_process("1234 ssh -N -L 5432:db:5432 -L 8080:web:80 web1").unwrap();
        assert_eq!(tunnel.rules.len(), 2);
        assert_eq!(tunnel.rules[1].local_port, 8080);
        assert_eq!(tunnel.rules[1].target_port, 80);
    }

    // ── group_by_host ──────────────────────────────────────

    #[test]
    fn test_group_by_host_preserves_order() {
        let rules = vec![
            rule("b", 1, "t", 1),
            rule("a", 2, "t", 2),
            rule("b", 3, "t", 3),
        ];
        let groups = group_by_host(&rules);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, "b");
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].0, "a");
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn test_group_by_host_empty() {
        assert!(group_by_host(&[]).is_empty());
    }

    #[test]
    fn test_group_by_host_keeps_rule_order_within_group() {
        let rules = vec![
            rule("a", 1, "t", 1),
            rule("a", 2, "t", 2),
            rule("a", 3, "t", 3),
        ];
        let groups = group_by_host(&rules);
        let ports: Vec<u16> = groups[0].1.iter().map(|r| r.local_port).collect();
        assert_eq!(ports, vec![1, 2, 3]);
    }

    #[test]
    fn test_validate_rules_empty_is_ok() {
        assert!(validate_rules(&[], &[]).is_ok());
    }

    // ── validate_rules ─────────────────────────────────────

    #[test]
    fn test_validate_rules_rejects_invalid_port() {
        let rules = vec![rule("web1", 0, "db", 5432)];
        assert!(validate_rules(&rules, &[]).is_err());
    }

    #[test]
    fn test_validate_rules_rejects_empty_target() {
        let rules = vec![rule("web1", 5432, "", 5432)];
        assert!(validate_rules(&rules, &[]).is_err());
    }

    #[test]
    fn test_validate_rules_rejects_duplicate_local_port_among_rules() {
        let rules = vec![rule("a", 5432, "db", 5432), rule("b", 5432, "db2", 5432)];
        let err = validate_rules(&rules, &[]).unwrap_err();
        assert!(err.contains("5432"));
    }

    #[test]
    fn test_validate_rules_rejects_existing_tunnel_for_host() {
        let tunnel = Tunnel {
            host: "web1".to_string(),
            pid: std::process::id(),
            started_at: 0,
            rules: vec![rule("web1", 9999, "x", 80)],
            managed: true,
        };
        let rules = vec![rule("web1", 5432, "db", 5432)];
        let err = validate_rules(&rules, &[tunnel]).unwrap_err();
        assert!(err.contains("already active"));
    }

    #[test]
    fn test_validate_rules_rejects_port_conflict_with_tunnel() {
        let tunnel = Tunnel {
            host: "other".to_string(),
            pid: std::process::id(),
            started_at: 0,
            rules: vec![rule("other", 5432, "db", 5432)],
            managed: true,
        };
        let rules = vec![rule("web1", 5432, "db", 5432)];
        let err = validate_rules(&rules, &[tunnel]).unwrap_err();
        assert!(err.contains("already in use"));
    }

    #[test]
    fn test_validate_rules_accepts_valid_set() {
        let rules = vec![
            rule("web1", 5432, "db", 5432),
            rule("web1", 8080, "web", 80),
            rule("web2", 5433, "db", 5432),
        ];
        assert!(validate_rules(&rules, &[]).is_ok());
    }

    // ── find_port_conflicts ────────────────────────────────

    #[test]
    fn test_find_port_conflicts_reports_owner() {
        let tunnel = Tunnel {
            host: "other".to_string(),
            pid: 1,
            started_at: 0,
            rules: vec![rule("other", 5432, "db", 5432)],
            managed: true,
        };
        let conflicts = find_port_conflicts(&[rule("web1", 5432, "db", 5432)], &[tunnel]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].port, 5432);
        assert!(conflicts[0].owner.contains("other"));
    }

    #[test]
    fn test_find_port_conflicts_empty_when_free() {
        let tunnel = Tunnel {
            host: "other".to_string(),
            pid: 1,
            started_at: 0,
            rules: vec![rule("other", 5432, "db", 5432)],
            managed: true,
        };
        let conflicts = find_port_conflicts(&[rule("web1", 5433, "db", 5432)], &[tunnel]);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_find_port_conflicts_deduplicates_same_owner() {
        let tunnel = Tunnel {
            host: "other".to_string(),
            pid: 1,
            started_at: 0,
            rules: vec![rule("other", 5432, "db", 5432)],
            managed: true,
        };
        let rules = vec![rule("a", 5432, "db", 5432), rule("b", 5432, "db", 5432)];
        let conflicts = find_port_conflicts(&rules, &[tunnel]);
        assert_eq!(conflicts.len(), 1);
    }

    // ── State persistence ──────────────────────────────────

    #[test]
    fn test_state_roundtrip_serialization() {
        let state = ForwardState {
            tunnels: vec![Tunnel {
                host: "web1".to_string(),
                pid: 1234,
                started_at: 1700000000,
                rules: vec![
                    rule("web1", 5432, "db.internal", 5432),
                    rule("web1", 8080, "web", 80),
                ],
                managed: true,
            }],
            last_used: HashMap::new(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: ForwardState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_state_missing_backwards_compat_fields() {
        let parsed: ForwardState = serde_json::from_str("{}").unwrap();
        assert!(parsed.tunnels.is_empty());
    }

    #[test]
    fn test_save_creates_missing_directories() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("forwards.json");
        let state = ForwardState::default();
        save(&path, &state).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_load_prunes_dead_tunnels() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("forwards.json");
        let state = ForwardState {
            tunnels: vec![
                Tunnel {
                    host: "dead".to_string(),
                    pid: 4_000_000_000,
                    started_at: 0,
                    rules: vec![rule("dead", 5432, "db", 5432)],
                    managed: true,
                },
                Tunnel {
                    host: "alive".to_string(),
                    pid: std::process::id(),
                    started_at: 0,
                    rules: vec![rule("alive", 8080, "web", 80)],
                    managed: true,
                },
            ],
            last_used: HashMap::new(),
        };
        save(&path, &state).unwrap();
        let loaded = load(&path);
        assert_eq!(loaded.tunnels.len(), 1);
        assert_eq!(loaded.tunnels[0].host, "alive");
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let loaded = load(Path::new("/nonexistent/__guajara_forwards"));
        assert!(loaded.tunnels.is_empty());
    }

    #[test]
    fn test_load_corrupt_file_returns_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("forwards.json");
        std::fs::write(&path, "not json at all").unwrap();
        let loaded = load(&path);
        assert!(loaded.tunnels.is_empty());
    }

    // ── is_alive ───────────────────────────────────────────

    #[test]
    fn test_is_alive_detects_current_process() {
        assert!(is_alive(std::process::id()));
    }

    #[test]
    fn test_is_alive_false_for_missing_pid() {
        assert!(!is_alive(4_000_000_000));
    }

    // ── rule.validate / describe ───────────────────────────

    #[test]
    fn test_rule_validate_rejects_empty_host() {
        assert!(rule("", 5432, "db", 5432).validate().is_err());
    }

    #[test]
    fn test_rule_validate_rejects_whitespace_host() {
        assert!(rule("   ", 5432, "db", 5432).validate().is_err());
    }

    #[test]
    fn test_rule_validate_accepts_valid_rule() {
        assert!(rule("web1", 5432, "db.internal", 5432).validate().is_ok());
    }

    #[test]
    fn test_rule_describe_format() {
        assert_eq!(
            rule("web1", 5432, "db.internal", 5432).describe(),
            "5432→db.internal:5432"
        );
    }

    // ── state_path ─────────────────────────────────────────

    #[test]
    fn test_state_path_points_to_config_dir() {
        let path = state_path();
        assert!(path.ends_with(".config/guajara/forwards.json"));
    }

    // ── terminate ──────────────────────────────────────────

    #[test]
    fn test_terminate_on_dead_pid_is_noop() {
        assert!(terminate(4_000_000_000).is_ok());
    }
}

use clap::{Parser, Subcommand};
mod remote_ui;
use std::io::Write;
use std::path::{Path, PathBuf};

use guajara::{
    ForwardRule, ForwardState, HOSTS_PATH, SSH_PATH, diff, expand_path, forward, hosts::HostsFile,
    read_file, ssh::SshConfig, write_file,
};

fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

/// Used to tell the TUI which screen to open initially
enum InitScreen {
    SshEdit(usize),
    HostsEdit(usize),
}

// ── CLI structure ──────────────────────────────────────────

#[derive(Parser)]
#[command(name = "guajara", version, about = "Manage SSH config and /etc/hosts")]
struct Cli {
    #[arg(long, global = true)]
    ssh_config: Option<PathBuf>,
    #[arg(long, global = true)]
    hosts_file: Option<PathBuf>,
    #[arg(long, global = true)]
    yes: bool,
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Tui,
    Ssh(SshCli),
    Hosts(HostsCli),
    Forward(ForwardCli),
}

#[derive(clap::Args)]
struct SshCli {
    #[command(subcommand)]
    command: SshCommand,
}

#[derive(Subcommand)]
enum SshCommand {
    List,
    /// Test authentication using a fresh SSH connection and the saved config
    Test {
        selector: String,
    },
    Show {
        selector: String,
    },
    Add {
        pattern: Vec<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        identity_file: Option<String>,
    },
    Set {
        selector: String,
        key: String,
        value: String,
    },
    Unset {
        selector: String,
        key: String,
    },
    Remove {
        selector: String,
    },
    Edit {
        selector: String,
    },
    Validate,
}

#[derive(clap::Args)]
struct HostsCli {
    #[command(subcommand)]
    command: HostsCommand,
}

#[derive(Subcommand)]
enum HostsCommand {
    List,
    Add { ip: String, hostnames: Vec<String> },
    SetIp { selector: String, ip: String },
    Remove { selector: String },
    Edit { selector: String },
    Validate,
}

#[derive(clap::Args)]
struct ForwardCli {
    #[command(subcommand)]
    command: ForwardCommand,
}

#[derive(Subcommand)]
enum ForwardCommand {
    /// List active port forwarding tunnels
    List,
    /// Start a port forwarding tunnel for one host
    Add {
        #[arg(long)]
        host: String,
        #[arg(long)]
        local_port: u16,
        #[arg(long)]
        target_host: String,
        #[arg(long)]
        target_port: u16,
    },
    /// Stop the tunnel running for a host
    Stop { selector: String },
    /// Stop all active tunnels
    StopAll,
}

// ── Main ───────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let ssh_path = cli
        .ssh_config
        .as_ref()
        .cloned()
        .unwrap_or_else(|| expand_path(SSH_PATH));
    let hosts_path = cli
        .hosts_file
        .as_ref()
        .cloned()
        .unwrap_or_else(|| expand_path(HOSTS_PATH));

    match &cli.command {
        None | Some(Commands::Tui) => run_tui(&ssh_path, &hosts_path, None),
        Some(Commands::Ssh(ssh)) => run_ssh(ssh, &ssh_path, &hosts_path, &cli),
        Some(Commands::Hosts(h)) => run_hosts(h, &hosts_path, &ssh_path, &cli),
        Some(Commands::Forward(f)) => run_forward(f, &cli),
    }
}

// ── Forward CLI ────────────────────────────────────────────

fn run_forward(fwd: &ForwardCli, cli: &Cli) {
    let path = forward::state_path();
    match &fwd.command {
        ForwardCommand::List => cmd_forward_list(&path),
        ForwardCommand::Add {
            host,
            local_port,
            target_host,
            target_port,
        } => cmd_forward_add(&path, host, *local_port, target_host, *target_port, cli),
        ForwardCommand::Stop { selector } => cmd_forward_stop(&path, selector),
        ForwardCommand::StopAll => cmd_forward_stop_all(&path),
    }
}

fn cmd_forward_list(path: &Path) {
    let state = forward::active(path);
    if state.tunnels.is_empty() {
        println!("No active tunnels.");
        return;
    }
    let host_width = state
        .tunnels
        .iter()
        .map(|t| t.host.len())
        .max()
        .unwrap_or(4)
        .min(40);
    println!("{:<hw$}  {:<8}  RULES", "HOST", "PID", hw = host_width);
    println!("{:-<hw$}  --------  -----", "", hw = host_width);
    for t in &state.tunnels {
        let rules = t
            .rules
            .iter()
            .map(|r| r.describe())
            .collect::<Vec<_>>()
            .join(", ");
        println!("{:<hw$}  {:<8}  {}", t.host, t.pid, rules, hw = host_width);
    }
}

fn cmd_forward_add(
    path: &Path,
    host: &str,
    local_port: u16,
    target_host: &str,
    target_port: u16,
    cli: &Cli,
) {
    let rules: Vec<forward::ForwardRule> = vec![forward::ForwardRule {
        host: host.to_string(),
        local_port,
        target_host: target_host.to_string(),
        target_port,
    }];
    if let Err(e) = forward::validate_start(path, &rules) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    println!("Tunnel to start: {}: {}", host, rules[0].describe());
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Start?") {
        return;
    }
    match forward::start_all(path, &rules) {
        Ok(tunnels) => println!("Started {} tunnel(s).", tunnels.len()),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_forward_stop(path: &Path, selector: &str) {
    match forward::stop_tunnel(path, selector) {
        Ok(true) => println!("Stopped tunnel for '{}'.", selector),
        Ok(false) => {
            eprintln!("No active tunnel for '{}'", selector);
            let state = forward::active(path);
            if !state.tunnels.is_empty() {
                eprintln!("Active tunnels:");
                for t in &state.tunnels {
                    eprintln!("  {}", t.host);
                }
            }
            std::process::exit(1);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_forward_stop_all(path: &Path) {
    match forward::stop_all(path) {
        Ok(0) => println!("No active tunnels."),
        Ok(n) => println!("Stopped {} tunnel(s).", n),
        Err(e) => eprintln!("Error: {}", e),
    }
}

// ── SSH CLI ────────────────────────────────────────────────

fn run_ssh(ssh: &SshCli, path: &Path, hosts_path: &Path, cli: &Cli) {
    let content = match read_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let mut config = SshConfig::parse(&content);

    match &ssh.command {
        SshCommand::List => cmd_ssh_list(&config),
        SshCommand::Test { selector } => {
            if resolve_selector(config.select(selector), &config, selector).is_none() {
                std::process::exit(1);
            }
            if let Err(error) = guajara::connection::test_command(path, selector) {
                eprintln!("Error: {error}");
                std::process::exit(1);
            }
            if cli.dry_run {
                println!(
                    "Would test SSH connection to '{selector}' using {}",
                    path.display()
                );
                return;
            }
            match guajara::connection::test(path, selector) {
                Ok(()) => {
                    println!("Successfully connected and authenticated to '{selector}'.");
                    if let Err(error) = forward::record_host_use(&forward::state_path(), selector) {
                        eprintln!(
                            "Warning: Connected, but could not save last-use history: {error}"
                        );
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    std::process::exit(1);
                }
            }
        }
        SshCommand::Show { selector } => cmd_ssh_show(&config, selector),
        SshCommand::Add {
            pattern,
            hostname,
            user,
            port,
            identity_file,
        } => cmd_ssh_add(
            &mut config,
            pattern,
            hostname.as_deref(),
            user.as_deref(),
            *port,
            identity_file.as_deref(),
            path,
            cli,
        ),
        SshCommand::Set {
            selector,
            key,
            value,
        } => cmd_ssh_set(&mut config, selector, key, value, path, cli),
        SshCommand::Unset { selector, key } => cmd_ssh_unset(&mut config, selector, key, path, cli),
        SshCommand::Remove { selector } => cmd_ssh_remove(&mut config, selector, path, cli),
        SshCommand::Edit { selector } => cmd_ssh_edit(selector, path, hosts_path, cli),
        SshCommand::Validate => cmd_ssh_validate(&config),
    }
}

fn cmd_ssh_list(config: &SshConfig) {
    let hosts = config.hosts();
    if hosts.is_empty() {
        println!("No host blocks found.");
        return;
    }

    let name_width = hosts
        .iter()
        .map(|h| h.patterns.join(" ").len())
        .max()
        .unwrap_or(8)
        .min(40);
    let hostname_width = hosts
        .iter()
        .flat_map(|h| {
            h.directives
                .iter()
                .filter(|d| d.key.eq_ignore_ascii_case("HostName"))
        })
        .map(|d| d.value.len())
        .max()
        .unwrap_or(8)
        .min(40);

    let hdr_p = pad_right("PATTERNS", name_width);
    let hdr_h = pad_right("HOSTNAME", hostname_width);
    println!("{}  {}  USER", hdr_p, hdr_h);
    println!(
        "{}  {}  -----",
        pad_right("", name_width).replace(' ', "-"),
        pad_right("", hostname_width).replace(' ', "-")
    );

    for host in &hosts {
        let p = pad_right(&host.patterns.join(" "), name_width);
        let h = pad_right(
            host.directives
                .iter()
                .find(|d| d.key.eq_ignore_ascii_case("HostName"))
                .map_or("-", |d| &d.value),
            hostname_width,
        );
        let u = host
            .directives
            .iter()
            .find(|d| d.key.eq_ignore_ascii_case("User"))
            .map_or("-", |d| &d.value);
        println!("{}  {}  {}", p, h, u);
    }
}

fn cmd_ssh_show(config: &SshConfig, selector: &str) {
    let idx = match resolve_selector(config.select(selector), config, selector) {
        Some(i) => i,
        None => return,
    };
    let host = &config.hosts()[idx];
    println!(
        "Block {} (lines {}-{})",
        idx + 1,
        host.start_idx + 1,
        host.end_idx
    );
    println!("     Patterns: {}", host.patterns.join(" "));
    println!("    Directives:");
    for d in &host.directives {
        println!("        {} = {}", d.key, d.value);
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_ssh_add(
    config: &mut SshConfig,
    patterns: &[String],
    hostname: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    identity_file: Option<&str>,
    path: &Path,
    cli: &Cli,
) {
    if patterns.is_empty() {
        eprintln!("Error: at least one pattern is required");
        std::process::exit(1);
    }
    let mut dirs: Vec<(String, String)> = Vec::new();
    if let Some(h) = hostname {
        dirs.push(("HostName".to_string(), h.to_string()));
    }
    if let Some(u) = user {
        dirs.push(("User".to_string(), u.to_string()));
    }
    if let Some(p) = port {
        dirs.push(("Port".to_string(), p.to_string()));
    }
    if let Some(i) = identity_file {
        dirs.push(("IdentityFile".to_string(), i.to_string()));
    }

    let old = config.to_string();
    config.add(patterns, &dirs);
    let new = config.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Apply?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved to {}", path.display()),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_ssh_set(
    config: &mut SshConfig,
    selector: &str,
    key: &str,
    value: &str,
    path: &Path,
    cli: &Cli,
) {
    let idx = match resolve_selector(config.select(selector), config, selector) {
        Some(i) => i,
        None => return,
    };
    let start = config.hosts()[idx].start_idx;
    let old = config.to_string();
    if let Err(e) = config.set(start, key, value) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    let new = config.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Apply?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_ssh_unset(config: &mut SshConfig, selector: &str, key: &str, path: &Path, cli: &Cli) {
    let idx = match resolve_selector(config.select(selector), config, selector) {
        Some(i) => i,
        None => return,
    };
    let start = config.hosts()[idx].start_idx;
    let old = config.to_string();
    if let Err(e) = config.unset(start, key) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    let new = config.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Apply?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_ssh_remove(config: &mut SshConfig, selector: &str, path: &Path, cli: &Cli) {
    let idx = match resolve_selector(config.select(selector), config, selector) {
        Some(i) => i,
        None => return,
    };
    let start = config.hosts()[idx].start_idx;
    let old = config.to_string();
    if let Err(e) = config.remove_block(start) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    let new = config.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Remove?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_ssh_edit(selector: &str, path: &Path, hosts_path: &Path, _cli: &Cli) {
    let content = read_file(path).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
    let config = SshConfig::parse(&content);
    let idx = match resolve_selector(config.select(selector), &config, selector) {
        Some(i) => i,
        None => std::process::exit(1),
    };
    run_tui(path, hosts_path, Some(InitScreen::SshEdit(idx)));
}

fn cmd_ssh_validate(config: &SshConfig) {
    let errors = config.validate();
    if errors.is_empty() {
        println!("Config is valid.");
    } else {
        for e in &errors {
            eprintln!("{}", e);
        }
        std::process::exit(1);
    }
}

// ── Hosts CLI ──────────────────────────────────────────────

fn run_hosts(h: &HostsCli, path: &Path, ssh_path: &Path, cli: &Cli) {
    let content = match read_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let mut hosts_file = HostsFile::parse(&content);

    match &h.command {
        HostsCommand::List => cmd_hosts_list(&hosts_file),
        HostsCommand::Add { ip, hostnames } => {
            cmd_hosts_add(&mut hosts_file, ip, hostnames, path, cli)
        }
        HostsCommand::SetIp { selector, ip } => {
            cmd_hosts_set_ip(&mut hosts_file, selector, ip, path, cli)
        }
        HostsCommand::Remove { selector } => cmd_hosts_remove(&mut hosts_file, selector, path, cli),
        HostsCommand::Edit { selector } => cmd_hosts_edit(selector, path, ssh_path, cli),
        HostsCommand::Validate => cmd_hosts_validate(&hosts_file),
    }
}

fn cmd_hosts_list(hosts_file: &HostsFile) {
    let records = hosts_file.records();
    if records.is_empty() {
        println!("No entries found.");
        return;
    }
    let iw = records
        .iter()
        .map(|r| r.ip.len())
        .max()
        .unwrap_or(15)
        .min(40);
    println!("{:<iw$}  HOSTNAMES", "IP", iw = iw);
    println!("{:-<iw$}  ------", "", iw = iw);
    for r in &records {
        let c = r
            .comment
            .as_ref()
            .map(|c| format!("  #{}", c))
            .unwrap_or_default();
        println!("{:<iw$}  {}{}", r.ip, r.hostnames.join(" "), c, iw = iw);
    }
}

fn cmd_hosts_add(
    hosts_file: &mut HostsFile,
    ip: &str,
    hostnames: &[String],
    path: &Path,
    cli: &Cli,
) {
    if hostnames.is_empty() {
        eprintln!("Error: at least one hostname required");
        std::process::exit(1);
    }
    let old = hosts_file.to_string();
    hosts_file.add(ip, hostnames);
    let new = hosts_file.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Apply?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_hosts_set_ip(hosts_file: &mut HostsFile, selector: &str, ip: &str, path: &Path, cli: &Cli) {
    let idx = match resolve_hosts_selector(&hosts_file.find(selector), hosts_file, selector) {
        Some(i) => i,
        None => return,
    };
    let old = hosts_file.to_string();
    if let Err(e) = hosts_file.set_ip(idx, ip) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    let new = hosts_file.to_string();
    println!("Proposed changes:");
    print!("{}", diff(&old, &new));
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Apply?") {
        return;
    }
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_hosts_remove(hosts_file: &mut HostsFile, selector: &str, path: &Path, cli: &Cli) {
    let idx = match resolve_hosts_selector(&hosts_file.find(selector), hosts_file, selector) {
        Some(i) => i,
        None => return,
    };
    let r = &hosts_file.records()[idx];
    println!("Removing: {} -> {}", r.ip, r.hostnames.join(" "));
    let new = {
        let mut h = hosts_file.clone();
        h.remove(idx).ok();
        h.to_string()
    };
    if cli.dry_run {
        println!("[dry-run]");
        return;
    }
    if !cli.yes && !confirm("Remove?") {
        return;
    }
    hosts_file.remove(idx).ok();
    match write_file(path, &new) {
        Ok(()) => println!("Saved"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn cmd_hosts_edit(selector: &str, path: &Path, ssh_path: &Path, _cli: &Cli) {
    let content = read_file(path).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
    let hosts_file = HostsFile::parse(&content);
    let idx = match resolve_hosts_selector(&hosts_file.find(selector), &hosts_file, selector) {
        Some(i) => i,
        None => std::process::exit(1),
    };
    run_tui(ssh_path, path, Some(InitScreen::HostsEdit(idx)));
}

fn cmd_hosts_validate(hosts_file: &HostsFile) {
    let errors = hosts_file.validate();
    if errors.is_empty() {
        println!("Hosts file is valid.");
    } else {
        for e in &errors {
            eprintln!("{}", e);
        }
        std::process::exit(1);
    }
}

fn confirm(msg: &str) -> bool {
    print!("{} [y/N] ", msg);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    input.trim().eq_ignore_ascii_case("y")
}

// ── Selector helpers ───────────────────────────────────────

fn resolve_selector(
    result: guajara::ssh::SelectResult,
    config: &SshConfig,
    selector: &str,
) -> Option<usize> {
    match result {
        guajara::ssh::SelectResult::Single(idx) => Some(idx),
        guajara::ssh::SelectResult::None => {
            eprintln!("No block found matching '{}'", selector);
            if !config.hosts().is_empty() {
                eprintln!("Available:");
                for h in &config.hosts() {
                    eprintln!("  {}", h.patterns.join(" "));
                }
            }
            None
        }
        guajara::ssh::SelectResult::Multiple(indices) => {
            eprintln!("Multiple blocks match '{}':", selector);
            for (i, &idx) in indices.iter().enumerate() {
                let h = &config.hosts()[idx];
                eprintln!(
                    "  {}. {} (lines {}-{})",
                    i + 1,
                    h.patterns.join(" "),
                    h.start_idx + 1,
                    h.end_idx
                );
            }
            eprintln!("Use a more specific selector.");
            None
        }
    }
}

fn resolve_hosts_selector(
    indices: &[usize],
    hosts_file: &HostsFile,
    selector: &str,
) -> Option<usize> {
    match indices.len() {
        0 => {
            eprintln!("No entry found matching '{}'", selector);
            None
        }
        1 => Some(indices[0]),
        _ => {
            eprintln!("Multiple entries match '{}':", selector);
            for (i, &idx) in indices.iter().enumerate() {
                let r = &hosts_file.records()[idx];
                eprintln!("  {}. {} -> {}", i + 1, r.ip, r.hostnames.join(" "));
            }
            None
        }
    }
}

// ── TUI (Ratatui) ──────────────────────────────────────────

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};
use std::io::stdout;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TuiScreen {
    MainMenu,
    SshList,
    SshDetail(usize),
    SshAddForm,
    SshEditForm(usize),
    SshDuplicateForm(usize),
    HostsList,
    HostsDetail(usize),
    HostsAddForm,
    HostsEditForm(usize),
    ForwardHostSelect,
    ForwardList,
    ForwardAddForm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SortMode {
    Name,
    LastUsed,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::Name => "name",
            SortMode::LastUsed => "last used",
        }
    }
}

enum PopupKind {
    Success,
    Error,
    Info,
}

struct Popup {
    kind: PopupKind,
    title: String,
    message: String,
    expires_at: Option<Instant>,
}

#[derive(Default)]
enum IdentityAction {
    #[default]
    Closed,
    Select {
        keys: Vec<PathBuf>,
        selected: usize,
    },
    Name {
        value: String,
    },
    Generate {
        name: String,
    },
}

struct TuiApp {
    screen: TuiScreen,
    nav_stack: Vec<(TuiScreen, usize)>,
    ssh_config: SshConfig,
    hosts_file: HostsFile,
    ssh_path: PathBuf,
    hosts_path: PathBuf,
    forward_state: ForwardState,
    forward_state_path: PathBuf,
    pending_rules: Vec<ForwardRule>,
    last_forward_check: Option<Instant>,
    sort_mode: SortMode,
    selected: usize,
    status: Option<String>,
    status_expires_at: Option<Instant>,
    form_fields: Vec<(String, String)>,
    form_focus: usize,
    form_edit_buffer: String,
    form_edit_active: bool,
    should_quit: bool,
    popup: Option<Popup>,
    identity_action: IdentityAction,
    identity_directory: PathBuf,
    pending_connection_test: Option<String>,
    pending_remote: Option<remote_ui::Launch>,
    marked_hosts: std::collections::BTreeSet<usize>,
}

impl TuiApp {
    fn new(ssh_path: &Path, hosts_path: &Path, init: Option<InitScreen>) -> Self {
        let ssh = read_file(ssh_path).unwrap_or_default();
        let hosts = read_file(hosts_path).unwrap_or_default();
        let forward_state_path = forward::state_path();
        let forward_state = forward::active(&forward_state_path);
        let mut app = TuiApp {
            screen: TuiScreen::MainMenu,
            nav_stack: Vec::new(),
            ssh_config: SshConfig::parse(&ssh),
            hosts_file: HostsFile::parse(&hosts),
            ssh_path: ssh_path.to_path_buf(),
            hosts_path: hosts_path.to_path_buf(),
            forward_state,
            forward_state_path,
            pending_rules: Vec::new(),
            last_forward_check: None,
            sort_mode: SortMode::Name,
            selected: 0,
            status: None,
            status_expires_at: None,
            form_fields: Vec::new(),
            form_focus: 0,
            form_edit_buffer: String::new(),
            form_edit_active: false,
            should_quit: false,
            popup: None,
            identity_action: IdentityAction::Closed,
            identity_directory: expand_path("~/.ssh"),
            pending_connection_test: None,
            pending_remote: None,
            marked_hosts: std::collections::BTreeSet::new(),
        };
        if let Some(init) = init {
            match init {
                InitScreen::SshEdit(idx) => {
                    app.nav_stack.push((TuiScreen::SshList, idx));
                    app.setup_ssh_edit_form(idx);
                    app.screen = TuiScreen::SshEditForm(idx);
                    app.selected = 0;
                }
                InitScreen::HostsEdit(idx) => {
                    app.nav_stack.push((TuiScreen::HostsList, idx));
                    app.setup_hosts_edit_form(idx);
                    app.screen = TuiScreen::HostsEditForm(idx);
                    app.selected = 0;
                }
            }
        }
        app
    }

    fn reload(&mut self) {
        self.marked_hosts.clear();
        let s = read_file(&self.ssh_path).unwrap_or_default();
        let h = read_file(&self.hosts_path).unwrap_or_default();
        self.ssh_config = SshConfig::parse(&s);
        self.hosts_file = HostsFile::parse(&h);
        self.forward_state = forward::active(&self.forward_state_path);
    }

    fn navigate_to(&mut self, screen: TuiScreen, selected: usize) {
        self.nav_stack.push((self.screen, self.selected));
        self.screen = screen;
        self.selected = selected;
    }

    fn go_back(&mut self) -> bool {
        if let Some((screen, selected)) = self.nav_stack.pop() {
            self.screen = screen;
            self.selected = selected;
            true
        } else {
            false
        }
    }

    fn set_status(&mut self, msg: String) {
        self.status = Some(msg);
        self.status_expires_at = Some(Instant::now() + Duration::from_secs(3));
    }

    fn show_popup(&mut self, kind: PopupKind, title: String, message: String) {
        let expires_at = match kind {
            PopupKind::Success => Some(Instant::now() + Duration::from_secs(3)),
            PopupKind::Error | PopupKind::Info => None,
        };
        self.popup = Some(Popup {
            kind,
            title,
            message,
            expires_at,
        });
        self.status = None;
        self.status_expires_at = None;
    }

    // ── SSH save ────────────────────────────────────────

    fn save_ssh(&mut self) -> Option<String> {
        match self.screen {
            TuiScreen::SshDuplicateForm(index) => {
                let patterns: Vec<String> = self.form_fields[0]
                    .1
                    .split_whitespace()
                    .map(String::from)
                    .collect();
                let mut updated = self.ssh_config.clone();
                if let Err(error) =
                    updated.duplicate_host(index, &patterns, &self.form_fields[1..5])
                {
                    return Some(error);
                }
                if let Err(error) = write_file(&self.ssh_path, &updated.to_string()) {
                    return Some(error);
                }
                self.reload();
                self.show_popup(
                    PopupKind::Success,
                    "Host duplicated".into(),
                    "New SSH host saved; the original and key files were not changed.".into(),
                );
                return None;
            }
            TuiScreen::SshAddForm => {
                let pat: Vec<String> = self.form_fields[0]
                    .1
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if pat.is_empty() {
                    return Some("Patterns cannot be empty".to_string());
                }
                let mut dirs = Vec::new();
                for (label, val) in &self.form_fields[1..5] {
                    if !val.is_empty() {
                        dirs.push((label.clone(), val.clone()));
                    }
                }
                self.ssh_config.add(&pat, &dirs);
            }
            TuiScreen::SshEditForm(idx) => {
                let hosts = self.ssh_config.hosts();
                if idx >= hosts.len() {
                    return Some("Host not found".to_string());
                }
                let start = hosts[idx].start_idx;
                let new_pat: Vec<&str> = self.form_fields[0].1.split_whitespace().collect();
                if new_pat.is_empty() {
                    return Some("Patterns cannot be empty".to_string());
                }
                // Replace the header line directly instead of remove+add patterns
                let indent: String = self.ssh_config.lines[start]
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect();
                let new_header = format!("{}Host {}", indent, new_pat.join(" "));
                self.ssh_config.lines[start] = new_header;
                for (label, val) in &self.form_fields[1..5] {
                    if val.is_empty() {
                        let _ = self.ssh_config.unset(start, label);
                    } else {
                        let _ = self.ssh_config.set(start, label, val);
                    }
                }
            }
            _ => {}
        }
        match write_file(&self.ssh_path, &self.ssh_config.to_string()) {
            Ok(()) => {
                self.reload();
                self.show_popup(
                    PopupKind::Success,
                    "Saved".into(),
                    "SSH config saved".into(),
                );
                None
            }
            Err(e) => Some(e),
        }
    }

    // ── Hosts save ──────────────────────────────────────

    fn save_hosts(&mut self) -> Option<String> {
        match self.screen {
            TuiScreen::HostsAddForm => {
                let ip = self.form_fields[0].1.clone();
                let h: Vec<String> = self.form_fields[1]
                    .1
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if ip.is_empty() || h.is_empty() {
                    return Some("IP and hostname required".to_string());
                }
                self.hosts_file.add(&ip, &h);
            }
            TuiScreen::HostsEditForm(idx) => {
                let records = self.hosts_file.records();
                if idx >= records.len() {
                    return Some("Entry not found".to_string());
                }
                let ip = self.form_fields[0].1.clone();
                let h: Vec<String> = self.form_fields[1]
                    .1
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if ip.is_empty() || h.is_empty() {
                    return Some("IP and hostname required".to_string());
                }
                let c = &self.form_fields[2].1;
                let record = &records[idx];
                // Preserve original indentation and comment style
                let indent: String = self.hosts_file.lines[record.line_idx]
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect();
                let comment_str = if c.is_empty() {
                    String::new()
                } else {
                    // Preserve the original comment marker style (with or without space after #)
                    if let Some(pos) = record.raw.find('#') {
                        let orig_marker = &record.raw[pos..];
                        format!(" {}", orig_marker)
                    } else {
                        format!(" #{}", c)
                    }
                };
                self.hosts_file.lines[record.line_idx] =
                    format!("{}{}\t{}{}", indent, ip, h.join(" "), comment_str);
            }
            _ => {}
        }
        match write_file(&self.hosts_path, &self.hosts_file.to_string()) {
            Ok(()) => {
                self.reload();
                self.show_popup(
                    PopupKind::Success,
                    "Saved".into(),
                    "Hosts file saved".into(),
                );
                None
            }
            Err(e) => Some(e),
        }
    }

    // ── Forwards ─────────────────────────────────────────

    fn setup_forward_add_form(&mut self) {
        self.form_fields = vec![
            ("Host".into(), String::new()),
            ("Local Port".into(), String::new()),
            ("Target Host".into(), String::new()),
            ("Target Port".into(), String::new()),
            ("Add Rule".into(), String::new()),
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ];
        self.pending_rules.clear();
        self.form_focus = 0;
        self.form_edit_active = false;
        self.form_edit_buffer = String::new();
    }

    fn forward_host_options(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .ssh_config
            .hosts()
            .iter()
            .flat_map(|host| host.patterns.iter())
            .filter(|pattern| !pattern.contains('*') && !pattern.contains('?'))
            .filter(|pattern| !pattern.starts_with('!'))
            .cloned()
            .collect();
        hosts.sort_by(|left, right| match self.sort_mode {
            SortMode::Name => left.cmp(right),
            SortMode::LastUsed => self
                .forward_state
                .last_used
                .get(right)
                .copied()
                .unwrap_or(0)
                .cmp(&self.forward_state.last_used.get(left).copied().unwrap_or(0))
                .then_with(|| left.cmp(right)),
        });
        hosts
    }

    fn ssh_display_indices(&self) -> Vec<usize> {
        let hosts = self.ssh_config.hosts();
        let mut indices: Vec<usize> = (0..hosts.len()).collect();
        indices.sort_by(|left, right| {
            let left_host = &hosts[*left];
            let right_host = &hosts[*right];
            match self.sort_mode {
                SortMode::Name => left_host
                    .patterns
                    .join(" ")
                    .cmp(&right_host.patterns.join(" ")),
                SortMode::LastUsed => self
                    .host_last_used(left_host)
                    .cmp(&self.host_last_used(right_host))
                    .reverse()
                    .then_with(|| {
                        left_host
                            .patterns
                            .join(" ")
                            .cmp(&right_host.patterns.join(" "))
                    }),
            }
        });
        indices
    }

    fn host_last_used(&self, host: &guajara::ssh::SshHost) -> u64 {
        host.patterns
            .iter()
            .filter_map(|pattern| self.forward_state.last_used.get(pattern).copied())
            .max()
            .unwrap_or(0)
    }

    fn forward_display_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.forward_state.tunnels.len()).collect();
        indices.sort_by(|left, right| {
            let left_tunnel = &self.forward_state.tunnels[*left];
            let right_tunnel = &self.forward_state.tunnels[*right];
            match self.sort_mode {
                SortMode::Name => left_tunnel.host.cmp(&right_tunnel.host),
                SortMode::LastUsed => right_tunnel
                    .started_at
                    .cmp(&left_tunnel.started_at)
                    .then_with(|| left_tunnel.host.cmp(&right_tunnel.host)),
            }
        });
        indices
    }

    fn toggle_sort_mode(&mut self) {
        let selected_ssh = self.ssh_display_indices().get(self.selected).copied();
        let selected_tunnel = self.forward_display_indices().get(self.selected).copied();
        let selected_alias = self.forward_host_options().get(self.selected).cloned();
        self.sort_mode = match self.sort_mode {
            SortMode::Name => SortMode::LastUsed,
            SortMode::LastUsed => SortMode::Name,
        };
        let selected = match self.screen {
            TuiScreen::SshList => self
                .ssh_display_indices()
                .iter()
                .position(|index| Some(*index) == selected_ssh),
            TuiScreen::ForwardList => self
                .forward_display_indices()
                .iter()
                .position(|index| Some(*index) == selected_tunnel),
            TuiScreen::ForwardHostSelect => self
                .forward_host_options()
                .iter()
                .position(|alias| Some(alias) == selected_alias.as_ref()),
            _ => None,
        };
        if let Some(selected) = selected {
            self.selected = selected;
        }
        if self.sort_mode == SortMode::LastUsed
            && self.forward_state.last_used.is_empty()
            && self.screen != TuiScreen::ForwardList
        {
            self.set_status("Sort: last used — no history yet; test SSH or start a tunnel".into());
        } else {
            self.set_status(format!("Sort: {}", self.sort_mode.label()));
        }
    }

    fn record_connection_use(&mut self, host: &str) -> Result<(), String> {
        forward::record_host_use(&self.forward_state_path, host)?;
        self.forward_state = forward::active(&self.forward_state_path);
        if self.sort_mode == SortMode::LastUsed && self.screen == TuiScreen::SshList {
            let hosts = self.ssh_config.hosts();
            if let Some(selected) = self
                .ssh_display_indices()
                .iter()
                .position(|index| hosts[*index].patterns.iter().any(|alias| alias == host))
            {
                self.selected = selected;
            }
        }
        Ok(())
    }

    fn setup_forward_form_for_host(&mut self, host: &str) {
        self.setup_forward_add_form();
        self.form_fields[0].1 = host.to_string();
    }

    fn add_pending_rule(&mut self) -> Option<String> {
        let host = self.form_fields[0].1.trim().to_string();
        let local_port: u16 = self.form_fields[1].1.trim().parse().unwrap_or(0);
        let target_host = self.form_fields[2].1.trim().to_string();
        let target_port: u16 = self.form_fields[3].1.trim().parse().unwrap_or(0);
        if host.is_empty() {
            return Some("Host field is required".to_string());
        }
        if local_port == 0 {
            return Some("Local port must be between 1 and 65535".to_string());
        }
        if target_host.is_empty() {
            return Some("Target host is required".to_string());
        }
        if target_port == 0 {
            return Some("Target port must be between 1 and 65535".to_string());
        }
        let mut all = self.pending_rules.clone();
        all.push(ForwardRule {
            host,
            local_port,
            target_host,
            target_port,
        });
        if let Err(e) = forward::validate_start(&self.forward_state_path, &all) {
            return Some(e);
        }
        self.pending_rules = all;
        self.form_fields[0].1.clear();
        self.form_fields[1].1.clear();
        self.form_fields[2].1.clear();
        self.form_fields[3].1.clear();
        self.set_status(format!(
            "1 rule queued — {} total",
            self.pending_rules.len()
        ));
        None
    }

    fn save_forwards(&mut self) -> Option<String> {
        if self.pending_rules.is_empty() {
            return Some("Add at least one rule before saving".to_string());
        }
        match forward::start_all(&self.forward_state_path, &self.pending_rules) {
            Ok(tunnels) => {
                let summary = tunnels
                    .iter()
                    .map(|t| {
                        let rules = t
                            .rules
                            .iter()
                            .map(|r| r.describe())
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("  {}: {}", t.host, rules)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                self.pending_rules.clear();
                self.forward_state = forward::active(&self.forward_state_path);
                self.show_popup(
                    PopupKind::Success,
                    "Tunnels started".into(),
                    format!("{} tunnel(s) up:\n{}", tunnels.len(), summary),
                );
                None
            }
            Err(e) => Some(e),
        }
    }

    fn stop_selected_tunnel(&mut self) {
        let Some(&index) = self.forward_display_indices().get(self.selected) else {
            return;
        };
        let Some(tunnel) = self.forward_state.tunnels.get(index).cloned() else {
            return;
        };
        match forward::stop_tunnel(&self.forward_state_path, &tunnel.host) {
            Ok(_) => {
                self.forward_state = forward::active(&self.forward_state_path);
                self.clamp_forward_sel();
                self.set_status(format!("Stopped tunnel for '{}'", tunnel.host));
            }
            Err(e) => self.show_popup(PopupKind::Error, "Error".into(), e),
        }
    }

    fn clamp_forward_sel(&mut self) {
        self.selected = self
            .selected
            .min(self.forward_state.tunnels.len().saturating_sub(1));
    }

    // ── Form setup ──────────────────────────────────────

    fn setup_ssh_add_form(&mut self) {
        self.form_fields = vec![
            ("Patterns".into(), String::new()),
            ("HostName".into(), String::new()),
            ("User".into(), String::new()),
            ("Port".into(), String::new()),
            ("IdentityFile".into(), String::new()),
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ];
        self.form_focus = 0;
        self.form_edit_active = false;
        self.form_edit_buffer = String::new();
    }

    fn setup_ssh_edit_form(&mut self, idx: usize) {
        let h = &self.ssh_config.hosts();
        let host = if idx < h.len() { &h[idx] } else { return };
        self.form_fields = vec![
            ("Patterns".into(), host.patterns.join(" ")),
            (
                "HostName".into(),
                host.directives
                    .iter()
                    .find(|d| d.key.eq_ignore_ascii_case("HostName"))
                    .map_or(String::new(), |d| d.value.clone()),
            ),
            (
                "User".into(),
                host.directives
                    .iter()
                    .find(|d| d.key.eq_ignore_ascii_case("User"))
                    .map_or(String::new(), |d| d.value.clone()),
            ),
            (
                "Port".into(),
                host.directives
                    .iter()
                    .find(|d| d.key.eq_ignore_ascii_case("Port"))
                    .map_or(String::new(), |d| d.value.clone()),
            ),
            (
                "IdentityFile".into(),
                host.directives
                    .iter()
                    .find(|d| d.key.eq_ignore_ascii_case("IdentityFile"))
                    .map_or(String::new(), |d| d.value.clone()),
            ),
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ];
        self.form_focus = 0;
        self.form_edit_active = false;
        self.form_edit_buffer = String::new();
    }

    fn setup_ssh_duplicate_form(&mut self, index: usize) {
        self.setup_ssh_edit_form(index);
        let hosts = self.ssh_config.hosts();
        let Some(host) = hosts.get(index) else {
            return;
        };
        let base = host
            .patterns
            .iter()
            .find(|pattern| guajara::connection::is_concrete_host(pattern))
            .map(String::as_str)
            .unwrap_or("host");
        let mut alias = format!("{base}-copy");
        let mut suffix = 2;
        while hosts.iter().any(|host| {
            host.patterns
                .iter()
                .any(|pattern| pattern.eq_ignore_ascii_case(&alias))
        }) {
            alias = format!("{base}-copy-{suffix}");
            suffix += 1;
        }
        self.form_fields[0].1 = alias;
    }

    fn setup_hosts_add_form(&mut self) {
        self.form_fields = vec![
            ("IP".into(), String::new()),
            ("Hostnames".into(), String::new()),
            ("Comment".into(), String::new()),
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ];
        self.form_focus = 0;
        self.form_edit_active = false;
        self.form_edit_buffer = String::new();
    }

    fn setup_hosts_edit_form(&mut self, idx: usize) {
        let r = &self.hosts_file.records();
        let rec = if idx < r.len() { &r[idx] } else { return };
        self.form_fields = vec![
            ("IP".into(), rec.ip.clone()),
            ("Hostnames".into(), rec.hostnames.join(" ")),
            (
                "Comment".into(),
                rec.comment.as_deref().unwrap_or("").to_string(),
            ),
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ];
        self.form_focus = 0;
        self.form_edit_active = false;
        self.form_edit_buffer = String::new();
    }

    fn clamp_ssh_sel(&mut self) {
        self.selected = self
            .selected
            .min(self.ssh_config.hosts().len().saturating_sub(1));
    }

    fn clamp_hosts_sel(&mut self) {
        self.selected = self
            .selected
            .min(self.hosts_file.records().len().saturating_sub(1));
    }
}

// ── TUI main loop ─────────────────────────────────────────

fn run_tui(ssh_path: &Path, hosts_path: &Path, init: Option<InitScreen>) {
    enable_raw_mode().ok();
    stdout().execute(EnterAlternateScreen).ok();
    let terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(stdout())).ok();
    if terminal.is_none() {
        eprintln!("TUI not available.");
        disable_raw_mode().ok();
        stdout().execute(LeaveAlternateScreen).ok();
        println!("Use: guajara ssh --help  or  guajara hosts --help\n");
        return;
    }
    let mut terminal = terminal.unwrap();
    let mut app = TuiApp::new(ssh_path, hosts_path, init);

    loop {
        if let Some(launch) = app.pending_remote.take() {
            remote_ui::run(&mut terminal, &app.ssh_path, &app.ssh_config, launch);
        }
        if let Some(host) = app.pending_connection_test.take() {
            let result = (|| {
                disable_raw_mode().map_err(|error| error.to_string())?;
                stdout()
                    .execute(LeaveAlternateScreen)
                    .map_err(|error| error.to_string())?;
                println!("Testing SSH connection to '{host}' (saved configuration)…");
                let result = guajara::connection::test(&app.ssh_path, &host);
                match &result {
                    Ok(()) => println!("SSH authentication succeeded."),
                    Err(error) => eprintln!("{error}"),
                }
                println!("Press Enter to return to Guajará.");
                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .map_err(|error| error.to_string())?;
                result
            })();
            stdout().execute(EnterAlternateScreen).ok();
            enable_raw_mode().ok();
            terminal.clear().ok();
            match result {
                Ok(()) => match app.record_connection_use(&host) {
                    Ok(()) => app.show_popup(
                        PopupKind::Success,
                        "SSH connection".into(),
                        format!("Successfully connected and authenticated to '{host}'."),
                    ),
                    Err(error) => app.show_popup(
                        PopupKind::Info,
                        "SSH connection".into(),
                        format!(
                            "Connected to '{host}', but could not save last-use history:\n{error}"
                        ),
                    ),
                },
                Err(error) => app.show_popup(PopupKind::Error, "SSH connection".into(), error),
            }
        }
        if matches!(app.identity_action, IdentityAction::Generate { .. })
            && let IdentityAction::Generate { name } = std::mem::take(&mut app.identity_action)
        {
            let result = (|| {
                disable_raw_mode().map_err(|error| error.to_string())?;
                stdout()
                    .execute(LeaveAlternateScreen)
                    .map_err(|error| error.to_string())?;
                guajara::identity::generate(&app.identity_directory, &name)
            })();
            stdout().execute(EnterAlternateScreen).ok();
            enable_raw_mode().ok();
            terminal.clear().ok();
            match result {
                Ok(path) => {
                    app.form_fields[4].1 = identity_config_path(&path);
                    app.show_popup(PopupKind::Info, "SSH key created".into(),
                        format!("Selected {}\nSave the host to apply it.\nInstall the .pub key on your server before connecting.\nThe key remains on disk if you cancel the host form.", path.display()));
                }
                Err(error) => app.show_popup(PopupKind::Error, "Key creation".into(), error),
            }
        }
        terminal.draw(|f| render_tui(f, &mut app)).ok();
        if event::poll(Duration::from_millis(200))
            .ok()
            .unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            handle_tui_key(&mut app, key);
        }
        if app.should_quit {
            break;
        }
    }
    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
}

// ── Key handling ──────────────────────────────────────────

fn handle_tui_key(app: &mut TuiApp, key: event::KeyEvent) {
    // Popup takes priority — Enter or Esc dismisses it
    if app.popup.is_some() {
        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            app.popup = None;
        }
        return;
    }

    if !matches!(app.identity_action, IdentityAction::Closed) {
        handle_identity_key(app, key);
        return;
    }

    // Delegate to form handler if in a form screen
    if matches!(
        app.screen,
        TuiScreen::SshAddForm
            | TuiScreen::SshEditForm(_)
            | TuiScreen::SshDuplicateForm(_)
            | TuiScreen::HostsAddForm
            | TuiScreen::HostsEditForm(_)
            | TuiScreen::ForwardAddForm
    ) {
        handle_form_key(app, key);
        return;
    }

    match key.code {
        KeyCode::Esc => {
            if !matches!(app.screen, TuiScreen::MainMenu) {
                app.go_back();
            }
        }
        KeyCode::Char('q') => {
            app.should_quit = true;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            let n = match app.screen {
                TuiScreen::MainMenu => 5,
                TuiScreen::SshList => app.ssh_config.hosts().len().max(1),
                TuiScreen::HostsList => app.hosts_file.records().len().max(1),
                TuiScreen::ForwardHostSelect => app.forward_host_options().len().max(1),
                TuiScreen::ForwardList => app.forward_state.tunnels.len().max(1),
                _ => 1,
            };
            app.selected = (app.selected + 1) % n;
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let n = match app.screen {
                TuiScreen::MainMenu => 5,
                TuiScreen::SshList => app.ssh_config.hosts().len().max(1),
                TuiScreen::HostsList => app.hosts_file.records().len().max(1),
                TuiScreen::ForwardHostSelect => app.forward_host_options().len().max(1),
                TuiScreen::ForwardList => app.forward_state.tunnels.len().max(1),
                _ => 1,
            };
            app.selected = if app.selected == 0 {
                n.saturating_sub(1)
            } else {
                app.selected - 1
            };
        }
        KeyCode::Enter => match app.screen {
            TuiScreen::MainMenu => match app.selected {
                0 => app.navigate_to(TuiScreen::SshList, 0),
                1 => app.navigate_to(TuiScreen::HostsList, 0),
                2 => {
                    let state = forward::active(&app.forward_state_path);
                    app.forward_state = state;
                    app.navigate_to(TuiScreen::ForwardList, 0);
                }
                3 => {
                    let mut parts = Vec::new();
                    let se = app.ssh_config.validate();
                    let he = app.hosts_file.validate();
                    parts.push(if se.is_empty() {
                        "✓ SSH config is valid".into()
                    } else {
                        format!("✗ SSH: {} error(s)", se.len())
                    });
                    parts.push(if he.is_empty() {
                        "✓ Hosts file is valid".into()
                    } else {
                        format!("✗ Hosts: {} error(s)", he.len())
                    });
                    let mut msg = parts.join("\n");
                    if !se.is_empty() {
                        msg.push_str("\n\nSSH errors:");
                        for e in &se {
                            msg.push_str(&format!("\n  {}", e));
                        }
                    }
                    if !he.is_empty() {
                        msg.push_str("\n\nHosts errors:");
                        for e in &he {
                            msg.push_str(&format!("\n  {}", e));
                        }
                    }
                    app.show_popup(PopupKind::Info, "Validation".into(), msg);
                }
                4 => app.should_quit = true,
                _ => {}
            },
            TuiScreen::SshList => {
                let indices = app.ssh_display_indices();
                if let Some(&idx) = indices.get(app.selected) {
                    app.navigate_to(TuiScreen::SshDetail(idx), 0);
                }
            }
            TuiScreen::HostsList => {
                let idx = app.selected;
                if idx < app.hosts_file.records().len() {
                    app.navigate_to(TuiScreen::HostsDetail(idx), 0);
                }
            }
            TuiScreen::ForwardHostSelect => {
                let hosts = app.forward_host_options();
                if let Some(host) = hosts.get(app.selected) {
                    let host = host.clone();
                    app.setup_forward_form_for_host(&host);
                    app.navigate_to(TuiScreen::ForwardAddForm, 0);
                }
            }
            _ => {}
        },
        KeyCode::Char('a') => match app.screen {
            TuiScreen::SshList => {
                let sel = app.selected;
                app.setup_ssh_add_form();
                app.navigate_to(TuiScreen::SshAddForm, sel);
            }
            TuiScreen::HostsList => {
                let sel = app.selected;
                app.setup_hosts_add_form();
                app.navigate_to(TuiScreen::HostsAddForm, sel);
            }
            TuiScreen::ForwardList => {
                let sel = app.selected;
                if app.forward_host_options().is_empty() {
                    app.show_popup(
                        PopupKind::Info,
                        "No SSH hosts".into(),
                        "Add a host in Manage SSH hosts first.".into(),
                    );
                } else {
                    app.navigate_to(TuiScreen::ForwardHostSelect, sel);
                }
            }
            _ => {}
        },
        KeyCode::Char('e') => match app.screen {
            TuiScreen::SshList if app.selected < app.ssh_config.hosts().len() => {
                if let Some(&idx) = app.ssh_display_indices().get(app.selected) {
                    app.setup_ssh_edit_form(idx);
                    app.navigate_to(TuiScreen::SshEditForm(idx), app.selected);
                }
            }
            TuiScreen::HostsList if app.selected < app.hosts_file.records().len() => {
                let idx = app.selected;
                app.setup_hosts_edit_form(idx);
                app.navigate_to(TuiScreen::HostsEditForm(idx), idx);
            }
            _ => {}
        },
        KeyCode::Char('u') => {
            let index = match app.screen {
                TuiScreen::SshList => app.ssh_display_indices().get(app.selected).copied(),
                TuiScreen::SshDetail(index) => Some(index),
                _ => None,
            };
            if let Some(index) = index
                && index < app.ssh_config.hosts().len()
            {
                app.setup_ssh_duplicate_form(index);
                app.navigate_to(TuiScreen::SshDuplicateForm(index), app.selected);
            }
        }
        KeyCode::Char(' ') if app.screen == TuiScreen::SshList => {
            if let Some(&index) = app.ssh_display_indices().get(app.selected)
                && !app.marked_hosts.remove(&index)
            {
                app.marked_hosts.insert(index);
            }
        }
        KeyCode::Char('c') if app.screen == TuiScreen::SshList => {
            let indices: Vec<usize> = if app.marked_hosts.is_empty() {
                app.ssh_display_indices()
                    .get(app.selected)
                    .copied()
                    .into_iter()
                    .collect()
            } else {
                app.marked_hosts.iter().copied().collect()
            };
            if !indices.is_empty() {
                app.pending_remote = Some(remote_ui::Launch::Copy(indices));
            }
        }
        KeyCode::Char('m') if app.screen == TuiScreen::SshList => {
            if let Some(&index) = app.ssh_display_indices().get(app.selected)
                && let Some(host) = app.ssh_config.hosts().get(index)
            {
                match host
                    .patterns
                    .iter()
                    .find(|alias| guajara::connection::is_concrete_host(alias))
                {
                    Some(alias) => {
                        app.pending_remote = Some(remote_ui::Launch::Manage(alias.clone()))
                    }
                    None => app.show_popup(
                        PopupKind::Error,
                        "Remote SSH".into(),
                        "Select a concrete destination alias, not a wildcard block.".into(),
                    ),
                }
            }
        }
        KeyCode::Char('t') => {
            let index = match app.screen {
                TuiScreen::SshList => app.ssh_display_indices().get(app.selected).copied(),
                TuiScreen::SshDetail(index) => Some(index),
                _ => None,
            };
            if let Some(index) = index
                && let Some(host) = app.ssh_config.hosts().get(index)
            {
                match host.patterns.iter().find(|pattern| guajara::connection::is_concrete_host(pattern)) {
                    Some(alias) => app.pending_connection_test = Some(alias.clone()),
                    None => app.show_popup(PopupKind::Error, "SSH connection".into(), "This block has no concrete host alias to test (only wildcard or negated patterns).".into()),
                }
            }
        }
        KeyCode::Char('d') => match app.screen {
            TuiScreen::SshList if app.selected < app.ssh_config.hosts().len() => {
                if let Some(&idx) = app.ssh_display_indices().get(app.selected) {
                    let p = app.ssh_config.hosts()[idx].patterns.join(" ");
                    let start = app.ssh_config.hosts()[idx].start_idx;
                    let _ = app.ssh_config.remove_block(start);
                    app.marked_hosts.clear();
                    app.set_status(format!("Removed '{}' — save with s", p));
                    app.clamp_ssh_sel();
                }
            }
            TuiScreen::HostsList if app.selected < app.hosts_file.records().len() => {
                let e = app.hosts_file.records()[app.selected].hostnames.join(" ");
                let _ = app.hosts_file.remove(app.selected);
                app.set_status(format!("Removed '{}' — save with s", e));
                app.clamp_hosts_sel();
            }
            _ => {}
        },
        KeyCode::Char('x') => {
            if app.screen == TuiScreen::ForwardList {
                app.stop_selected_tunnel();
            }
        }
        KeyCode::Char('o') => match app.screen {
            TuiScreen::SshList | TuiScreen::ForwardList | TuiScreen::ForwardHostSelect => {
                app.toggle_sort_mode()
            }
            _ => {}
        },
        KeyCode::Char('n') => {
            if app.screen == TuiScreen::ForwardHostSelect {
                app.navigate_to(TuiScreen::SshList, 0);
            }
        }
        KeyCode::Char('s') => match app.screen {
            TuiScreen::SshList => {
                if let Some(e) = app.save_ssh() {
                    app.show_popup(PopupKind::Error, "Error".into(), e);
                }
            }
            TuiScreen::HostsList => {
                if let Some(e) = app.save_hosts() {
                    app.show_popup(PopupKind::Error, "Error".into(), e);
                }
            }
            _ => {}
        },
        KeyCode::Char('r') => {
            app.reload();
            app.set_status("Reloaded".to_string());
        }
        _ => {}
    }
}

fn handle_form_key(app: &mut TuiApp, key: event::KeyEvent) {
    // Popup takes priority
    if app.popup.is_some() {
        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            app.popup = None;
        }
        return;
    }

    if app.form_edit_active {
        match key.code {
            KeyCode::Enter => {
                let val = std::mem::take(&mut app.form_edit_buffer);
                if app.form_focus < app.form_fields.len() {
                    app.form_fields[app.form_focus].1 = val;
                }
                app.form_edit_active = false;
            }
            KeyCode::Esc => {
                app.form_edit_active = false;
                app.form_edit_buffer = String::new();
            }
            KeyCode::Backspace => {
                app.form_edit_buffer.pop();
            }
            KeyCode::Char(c) => app.form_edit_buffer.push(c),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.go_back();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.form_focus = (app.form_focus + 1) % app.form_fields.len();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let n = app.form_fields.len();
            app.form_focus = if app.form_focus == 0 {
                n.saturating_sub(1)
            } else {
                app.form_focus - 1
            };
        }
        KeyCode::Enter => {
            let label = app.form_fields[app.form_focus].0.clone();
            match label.as_str() {
                "Save" => {
                    let err = match app.screen {
                        TuiScreen::SshAddForm
                        | TuiScreen::SshEditForm(_)
                        | TuiScreen::SshDuplicateForm(_) => app.save_ssh(),
                        TuiScreen::ForwardAddForm => app.save_forwards(),
                        _ => app.save_hosts(),
                    };
                    match err {
                        Some(e) => app.show_popup(PopupKind::Error, "Error".into(), e),
                        None if matches!(app.screen, TuiScreen::ForwardAddForm) => {
                            app.set_status("Tunnels started".to_string());
                            app.go_back();
                        }
                        None => {
                            app.set_status("Saved".to_string());
                            app.go_back();
                            app.reload();
                        }
                    }
                }
                "Cancel" => {
                    app.go_back();
                }
                "Add Rule" => {
                    if let Some(e) = app.add_pending_rule() {
                        app.show_popup(PopupKind::Error, "Error".into(), e);
                    }
                }
                "IdentityFile" => match guajara::identity::discover(&app.identity_directory) {
                    Ok(keys) => {
                        let current =
                            expand_path(app.form_fields[app.form_focus].1.trim_matches('"'));
                        let selected = keys.iter().position(|path| *path == current).unwrap_or(0);
                        app.identity_action = IdentityAction::Select { keys, selected };
                    }
                    Err(error) => app.show_popup(PopupKind::Error, "SSH keys".into(), error),
                },
                _ => {
                    app.form_edit_buffer = app.form_fields[app.form_focus].1.clone();
                    app.form_edit_active = true;
                }
            }
        }
        _ => {}
    }
}

// ── Rendering ──────────────────────────────────────────────

fn identity_config_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '"' | '\\'))
    {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.into_owned()
    }
}

fn handle_identity_key(app: &mut TuiApp, key: event::KeyEvent) {
    match &mut app.identity_action {
        IdentityAction::Select { keys, selected } => {
            let count = keys.len() + 3;
            match key.code {
                KeyCode::Esc => app.identity_action = IdentityAction::Closed,
                KeyCode::Down | KeyCode::Char('j') => *selected = (*selected + 1) % count,
                KeyCode::Up | KeyCode::Char('k') => *selected = (*selected + count - 1) % count,
                KeyCode::Enter => {
                    if *selected < keys.len() {
                        app.form_fields[4].1 = identity_config_path(&keys[*selected]);
                        app.identity_action = IdentityAction::Closed;
                    } else {
                        match *selected - keys.len() {
                            0 => {
                                app.identity_action = IdentityAction::Name {
                                    value: String::new(),
                                }
                            }
                            1 => {
                                app.form_edit_buffer = app.form_fields[4].1.clone();
                                app.form_edit_active = true;
                                app.identity_action = IdentityAction::Closed;
                            }
                            _ => {
                                app.form_fields[4].1.clear();
                                app.identity_action = IdentityAction::Closed;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        IdentityAction::Name { value } => match key.code {
            KeyCode::Esc => app.identity_action = IdentityAction::Closed,
            KeyCode::Backspace => {
                value.pop();
            }
            KeyCode::Char(character) => value.push(character),
            KeyCode::Enter => match guajara::identity::new_key_path(&app.identity_directory, value)
            {
                Ok(_) => {
                    app.identity_action = IdentityAction::Generate {
                        name: value.clone(),
                    }
                }
                Err(error) => app.show_popup(PopupKind::Error, "Invalid key name".into(), error),
            },
            _ => {}
        },
        IdentityAction::Closed | IdentityAction::Generate { .. } => {}
    }
}

fn render_identity_picker(frame: &mut Frame, app: &TuiApp) {
    let area = frame
        .area()
        .centered(Constraint::Percentage(85), Constraint::Percentage(75));
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" IdentityFile — Esc cancel ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    match &app.identity_action {
        IdentityAction::Select { keys, selected } => {
            let mut options: Vec<String> =
                keys.iter().map(|path| path.display().to_string()).collect();
            options.extend([
                "Create new SSH key…".into(),
                "Enter path manually…".into(),
                "Clear (use SSH defaults)".into(),
            ]);
            let items: Vec<ListItem> = options.into_iter().map(ListItem::new).collect();
            let mut state = ratatui::widgets::ListState::default().with_selected(Some(*selected));
            frame.render_stateful_widget(
                List::new(items).highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan)),
                inner,
                &mut state,
            );
        }
        IdentityAction::Name { value } => {
            frame.render_widget(Paragraph::new(format!("New Ed25519 key in {}\n\nFilename: {value}▏\n\nEnter: create and choose a passphrase in the terminal\nExisting keys are never replaced automatically.", app.identity_directory.display())).wrap(ratatui::widgets::Wrap { trim: false }), inner);
        }
        IdentityAction::Closed | IdentityAction::Generate { .. } => {}
    }
}

fn render_popup(frame: &mut Frame, area: Rect, popup: &Popup) {
    let (border_color, title_icon) = match popup.kind {
        PopupKind::Success => (Color::Green, " ✓ "),
        PopupKind::Error => (Color::Red, " ✗ "),
        PopupKind::Info => (Color::Cyan, " ℹ "),
    };

    let centered = area.centered(Constraint::Percentage(70), Constraint::Percentage(40));

    frame.render_widget(Clear, centered);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(format!("{}{}", title_icon, popup.title))
        .title_style(
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        );

    let inner = block.inner(centered);
    frame.render_widget(block, centered);

    let lines: Vec<Line> = popup
        .message
        .lines()
        .map(|l| Line::from(Span::raw(l.to_string())))
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);

    if popup.expires_at.is_none() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Press Enter or Esc to close",
                Style::default().fg(Color::DarkGray),
            ))),
            Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        );
    }
}

fn render_tui(frame: &mut Frame, app: &mut TuiApp) {
    // Clear expired status messages
    if let Some(expires) = app.status_expires_at
        && Instant::now() >= expires
    {
        app.status = None;
        app.status_expires_at = None;
    }

    // Periodically re-check tunnel liveness on the forwards screen
    if matches!(app.screen, TuiScreen::ForwardList) {
        let should_refresh = app
            .last_forward_check
            .map(|t| t.elapsed() >= Duration::from_secs(2))
            .unwrap_or(true);
        if should_refresh {
            app.forward_state = forward::active(&app.forward_state_path);
            app.clamp_forward_sel();
            app.last_forward_check = Some(Instant::now());
        }
    }

    // Auto-dismiss expired popups
    if let Some(ref popup) = app.popup
        && let Some(expires) = popup.expires_at
        && Instant::now() >= expires
    {
        app.popup = None;
    }

    let size = frame.area();
    if size.width < 30 || size.height < 10 {
        return;
    }

    let lo = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(size);

    let title = Line::from(vec![
        Span::styled(
            " Guajará ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" — "),
        Span::styled(
            match app.screen {
                TuiScreen::MainMenu => "Main Menu",
                TuiScreen::SshList => "SSH Hosts",
                TuiScreen::SshDetail(_) => "SSH Details",
                TuiScreen::SshAddForm => "Add SSH Host",
                TuiScreen::SshEditForm(_) => "Edit SSH Host",
                TuiScreen::SshDuplicateForm(_) => "Duplicate SSH Host",
                TuiScreen::HostsList => "Hosts Entries",
                TuiScreen::HostsDetail(_) => "Hosts Details",
                TuiScreen::HostsAddForm => "Add Hosts Entry",
                TuiScreen::HostsEditForm(_) => "Edit Hosts Entry",
                TuiScreen::ForwardHostSelect => "Select SSH Host",
                TuiScreen::ForwardList => "Port Forwards",
                TuiScreen::ForwardAddForm => "Add Port Forwards",
            },
            Style::default().fg(Color::Yellow),
        ),
    ]);
    frame.render_widget(Paragraph::new(title), lo[0]);

    match app.screen {
        TuiScreen::MainMenu => render_main_menu(frame, lo[1], app),
        TuiScreen::SshList => render_ssh_list(frame, lo[1], app),
        TuiScreen::SshDetail(idx) => render_ssh_detail(frame, lo[1], app, idx),
        TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) | TuiScreen::SshDuplicateForm(_) => {
            render_form(frame, lo[1], app)
        }
        TuiScreen::HostsList => render_hosts_list(frame, lo[1], app),
        TuiScreen::HostsDetail(idx) => render_hosts_detail(frame, lo[1], app, idx),
        TuiScreen::HostsAddForm | TuiScreen::HostsEditForm(_) => render_form(frame, lo[1], app),
        TuiScreen::ForwardHostSelect => render_forward_host_select(frame, lo[1], app),
        TuiScreen::ForwardList => render_forward_list(frame, lo[1], app),
        TuiScreen::ForwardAddForm => render_form(frame, lo[1], app),
    }

    let st = app.status.clone().unwrap_or_else(|| match app.screen {
        TuiScreen::MainMenu => "up/down nav  enter select  r reload  q quit".into(),
        TuiScreen::SshList => {
            format!(
                "o sort:{}  Enter view  u duplicate  t test  m remote  Space mark  c copy  a add  e edit  d delete  s save  r reload  Esc back",
                app.sort_mode.label()
            )
        }
        TuiScreen::HostsList => {
            "j/k nav  enter view  a add  e edit  d delete  s save  r reload  Esc back".into()
        }
        TuiScreen::ForwardList => {
            format!(
                "j/k nav  o sort:{}  a add forwards  x stop tunnel  r refresh  Esc back",
                app.sort_mode.label()
            )
        }
        TuiScreen::ForwardHostSelect => format!("j/k nav  o sort:{}  Enter select  n add SSH host  Esc back", app.sort_mode.label()),
        TuiScreen::SshDetail(_) => "u duplicate  t test SSH (saved config)  Esc back  r reload".into(),
        TuiScreen::HostsDetail(_) => "Esc back  r reload".into(),
        _ if app.form_edit_active => "Enter confirm  Esc cancel  typing".into(),
        _ => "up/down field  enter edit / save / cancel  Esc back".into(),
    });
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            st,
            Style::default().fg(Color::DarkGray),
        ))),
        lo[2],
    );

    if !matches!(app.identity_action, IdentityAction::Closed) {
        render_identity_picker(frame, app);
    }

    // Popup overlay
    if let Some(ref popup) = app.popup {
        render_popup(frame, frame.area(), popup);
    }
}

fn render_main_menu(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items = [
        "Manage SSH hosts",
        "Manage /etc/hosts entries",
        "Port forwards",
        "Validate both files",
        "Quit",
    ];
    let li: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let s = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(
                format!("{} {}", if i == app.selected { ">" } else { " " }, t),
                s,
            )))
        })
        .collect();
    frame.render_widget(
        List::new(li).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Guajará Dashboard "),
        ),
        area,
    );
}

fn render_ssh_list(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let hosts = app.ssh_config.hosts();
    if hosts.is_empty() {
        frame.render_widget(
            Paragraph::new("No SSH hosts.\n\nPress 'a' to add.")
                .block(Block::default().borders(Borders::ALL).title(" SSH Hosts ")),
            area,
        );
        return;
    }
    let li: Vec<ListItem> = app
        .ssh_display_indices()
        .into_iter()
        .enumerate()
        .map(|(i, index)| {
            let h = &hosts[index];
            let s = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let hn = h
                .directives
                .iter()
                .find(|d| d.key.eq_ignore_ascii_case("HostName"))
                .map_or("-", |d| &d.value);
            let u = h
                .directives
                .iter()
                .find(|d| d.key.eq_ignore_ascii_case("User"))
                .map_or("-", |d| &d.value);
            ListItem::new(Line::from(Span::styled(
                format!(
                    "{}{}{:<20} {:<30} {}",
                    if i == app.selected { "> " } else { "  " },
                    if app.marked_hosts.contains(&index) {
                        "[x] "
                    } else {
                        "[ ] "
                    },
                    h.patterns.join(" "),
                    hn,
                    u
                ),
                s,
            )))
        })
        .collect();
    frame.render_widget(
        List::new(li).block(Block::default().borders(Borders::ALL).title(" SSH Hosts ")),
        area,
    );
}

fn render_ssh_detail(frame: &mut Frame, area: Rect, app: &mut TuiApp, idx: usize) {
    let hosts = app.ssh_config.hosts();
    if idx >= hosts.len() {
        if !app.go_back() {
            app.screen = TuiScreen::SshList;
        }
        return;
    }
    let h = &hosts[idx];
    let mut lines = vec![
        Line::from(Span::styled(
            format!("  Patterns: {}", h.patterns.join(" ")),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("")),
    ];
    for d in &h.directives {
        lines.push(Line::from(Span::raw(format!(
            "    {} = {}",
            d.key, d.value
        ))));
    }
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "  u duplicate  t test SSH (saved config)  Esc back  r reload",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" SSH: {}", h.patterns.join(" "))),
        ),
        area,
    );
}

fn render_hosts_list(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let records = app.hosts_file.records();
    if records.is_empty() {
        frame.render_widget(
            Paragraph::new("No hosts entries.\n\nPress 'a' to add.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Hosts Entries "),
            ),
            area,
        );
        return;
    }
    let li: Vec<ListItem> = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let s = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let c = r
                .comment
                .as_ref()
                .map(|c| format!(" #{}", c))
                .unwrap_or_default();
            ListItem::new(Line::from(Span::styled(
                format!(
                    "{}{:<20} {}{}",
                    if i == app.selected { "> " } else { "  " },
                    r.ip,
                    r.hostnames.join(" "),
                    c
                ),
                s,
            )))
        })
        .collect();
    frame.render_widget(
        List::new(li).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Hosts Entries "),
        ),
        area,
    );
}

fn render_hosts_detail(frame: &mut Frame, area: Rect, app: &mut TuiApp, idx: usize) {
    let records = app.hosts_file.records();
    if idx >= records.len() {
        if !app.go_back() {
            app.screen = TuiScreen::HostsList;
        }
        return;
    }
    let r = &records[idx];
    let mut lines = vec![
        Line::from(Span::styled(
            format!("  IP: {}", r.ip),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw(format!("  Hostnames: {}", r.hostnames.join(" ")))),
    ];
    if let Some(c) = &r.comment {
        lines.push(Line::from(Span::raw(format!("  Comment: {}", c))));
    }
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "  Esc back  r reload",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Hosts: {}", r.hostnames[0])),
        ),
        area,
    );
}

fn render_forward_list(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let tunnels = &app.forward_state.tunnels;
    if tunnels.is_empty() {
        frame.render_widget(
            Paragraph::new("No active tunnels.\n\nPress 'a' to add port forwards.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Port Forwards "),
            ),
            area,
        );
        return;
    }
    let li: Vec<ListItem> = app
        .forward_display_indices()
        .into_iter()
        .enumerate()
        .map(|(i, index)| {
            let t = &tunnels[index];
            let s = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Green)
            } else {
                Style::default()
            };
            let rules = t
                .rules
                .iter()
                .map(|r| r.describe())
                .collect::<Vec<_>>()
                .join(", ");
            Line::from(vec![
                Span::styled(
                    format!(
                        "{}{:<16} pid:{:<8}",
                        if i == app.selected { "> " } else { "  " },
                        t.host,
                        t.pid
                    ),
                    s,
                ),
                Span::styled("UP ", Style::default().fg(Color::Green)),
                Span::styled(rules, s),
            ])
            .into()
        })
        .collect();
    frame.render_widget(
        List::new(li).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Port Forwards "),
        ),
        area,
    );
}

fn render_forward_host_select(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let hosts = app.forward_host_options();
    if hosts.is_empty() {
        frame.render_widget(
            Paragraph::new("No SSH hosts configured.\n\nPress 'n' to add one.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Select SSH Host "),
            ),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let style = if index == app.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(
                format!(
                    "{}{}",
                    if index == app.selected { "> " } else { "  " },
                    host
                ),
                style,
            )))
        })
        .collect();
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Select SSH Host "),
        ),
        area,
    );
}

fn render_form(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let title = match app.screen {
        TuiScreen::SshAddForm => " Add SSH Host ",
        TuiScreen::SshEditForm(_) => " Edit SSH Host ",
        TuiScreen::SshDuplicateForm(_) => {
            " Duplicate SSH Host — change alias and HostName, then Save "
        }
        TuiScreen::HostsAddForm => " Add Hosts Entry ",
        TuiScreen::HostsEditForm(_) => " Edit Hosts Entry ",
        TuiScreen::ForwardAddForm => " Add Port Forwards ",
        _ => " Form ",
    };

    let mut lines = Vec::new();
    for (i, (label, val)) in app.form_fields.iter().enumerate() {
        let focused = i == app.form_focus;
        let action = label == "Save" || label == "Cancel" || label == "Add Rule";
        let display = if action {
            format!("  [ {} ]{}", label, if focused { " <" } else { "" })
        } else if focused && app.form_edit_active {
            format!("  {}: {}_", label, app.form_edit_buffer)
        } else {
            format!("  {}: {}", label, val)
        };
        let st = if focused && !app.form_edit_active {
            if action {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Black).bg(Color::DarkGray)
            }
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(display, st)));
    }

    if matches!(
        app.screen,
        TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) | TuiScreen::SshDuplicateForm(_)
    ) {
        lines.push(Line::from(
            "  IdentityFile: Enter to select / create a key or enter a path",
        ));
    }

    if matches!(app.screen, TuiScreen::ForwardAddForm) {
        if app.pending_rules.is_empty() {
            lines.push(Line::from(Span::styled(
                "  No rules queued — fill the fields above and press Enter on Add Rule",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "  Pending rules:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for r in &app.pending_rules {
                lines.push(Line::from(Span::raw(format!(
                    "    [{}] {}",
                    r.host,
                    r.describe()
                ))));
            }
        }
    }

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;
    use guajara::forward::Tunnel;

    fn test_app() -> TuiApp {
        let mut app = TuiApp::new(
            Path::new("/nonexistent/__guajara_test_ssh"),
            Path::new("/nonexistent/__guajara_test_hosts"),
            None,
        );
        app.forward_state = ForwardState::default();
        app.forward_state_path = PathBuf::from("/nonexistent/__guajara_test_forwards");
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        code.into()
    }

    #[test]
    fn should_select_identity_without_changing_other_form_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample-key");
        std::fs::write(&path, "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture").unwrap();
        let mut app = test_app();
        app.identity_directory = directory.path().to_path_buf();
        app.setup_ssh_add_form();
        app.screen = TuiScreen::SshAddForm;
        app.form_fields[0].1 = "server".into();
        app.form_focus = 4;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.identity_action, IdentityAction::Select { .. }));
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.form_fields[4].1, identity_config_path(&path));
        assert_eq!(app.form_fields[0].1, "server");
        assert!(matches!(app.identity_action, IdentityAction::Closed));
    }

    #[test]
    fn should_offer_creation_manual_path_and_clear_without_existing_keys() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = test_app();
        app.identity_directory = directory.path().to_path_buf();
        app.setup_ssh_add_form();
        app.screen = TuiScreen::SshAddForm;
        app.form_focus = 4;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.identity_action, IdentityAction::Name { .. }));
        for character in "id_example".chars() {
            handle_tui_key(&mut app, key(KeyCode::Char(character)));
        }
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(
            matches!(&app.identity_action, IdentityAction::Generate { name } if name == "id_example")
        );
        assert!(app.form_fields[4].1.is_empty());
        app.identity_action = IdentityAction::Closed;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Down));
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(app.form_edit_active);
        for character in "/custom/key".chars() {
            handle_tui_key(&mut app, key(KeyCode::Char(character)));
        }
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.form_fields[4].1, "/custom/key");
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Up));
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(app.form_fields[4].1.is_empty());
    }

    #[test]
    fn should_cancel_identity_picker_and_reject_existing_key_name() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("existing.pub"), "fixture").unwrap();
        let mut app = test_app();
        app.identity_directory = directory.path().to_path_buf();
        app.setup_ssh_add_form();
        app.screen = TuiScreen::SshEditForm(0);
        app.form_focus = 4;
        app.form_fields[4].1 = "original".into();
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshEditForm(0));
        assert_eq!(app.form_fields[4].1, "original");
        app.identity_action = IdentityAction::Name {
            value: "existing".into(),
        };
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(app.popup.is_some());
        assert!(matches!(app.identity_action, IdentityAction::Name { .. }));
        assert_eq!(app.form_fields[4].1, "original");
    }

    #[test]
    fn should_render_identity_picker_with_scrolling_and_name_prompt() {
        let mut app = test_app();
        app.identity_action = IdentityAction::Select {
            keys: (0..40)
                .map(|index| PathBuf::from(format!("/keys/key-{index}")))
                .collect(),
            selected: 40,
        };
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_tui(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
        assert!(text.contains("Create new SSH key"));
        app.identity_action = IdentityAction::Name {
            value: "new-key".into(),
        };
        terminal.draw(|frame| render_tui(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Filename: new-key"));
    }

    #[test]
    fn should_queue_connection_test_for_sorted_selected_host_and_detail() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert_eq!(app.pending_connection_test.take().as_deref(), Some("alpha"));
        app.screen = TuiScreen::SshDetail(0);
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert_eq!(app.pending_connection_test.take().as_deref(), Some("zebra"));
        assert_eq!(app.screen, TuiScreen::SshDetail(0));
    }

    #[test]
    fn should_open_duplicate_form_for_sorted_selection_and_suggest_unique_alias() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse(
            "Host zebra\nHost alpha secondary\n    HostName 203.0.113.10\n    User alice\n    IdentityFile ~/.ssh/existing-key\nHost alpha-copy\nHost alpha-copy-2\n",
        );
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('u')));
        assert_eq!(app.screen, TuiScreen::SshDuplicateForm(1));
        assert_eq!(app.form_fields[0].1, "alpha-copy-3");
        assert_eq!(app.form_fields[1].1, "203.0.113.10");
        assert_eq!(app.form_fields[2].1, "alice");
        assert_eq!(app.form_fields[4].1, "~/.ssh/existing-key");
        assert_eq!(app.ssh_config.hosts().len(), 4);
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.ssh_config.hosts().len(), 4);
    }

    #[test]
    fn should_duplicate_from_details_save_to_disk_and_preserve_original() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config");
        let original = "Host server\n    HostName 203.0.113.10\n    User alice\n    Port 2222\n    IdentityFile ~/.ssh/existing-key\n    ServerAliveInterval 30\n";
        std::fs::write(&path, original).unwrap();
        let mut app = test_app();
        app.ssh_path = path.clone();
        app.ssh_config = SshConfig::parse(original);
        app.screen = TuiScreen::SshDetail(0);
        handle_tui_key(&mut app, key(KeyCode::Char('u')));
        app.form_fields[0].1 = "server-tailscale".into();
        app.form_fields[1].1 = "100.64.0.10".into();
        app.form_focus = 5;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::SshDetail(0));
        let saved = std::fs::read_to_string(path).unwrap();
        assert!(saved.starts_with(original));
        assert!(saved.contains("Host server-tailscale"));
        assert!(saved.contains("HostName 100.64.0.10"));
        assert_eq!(saved.matches("IdentityFile ~/.ssh/existing-key").count(), 2);
        assert_eq!(saved.matches("ServerAliveInterval 30").count(), 2);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn should_cancel_duplicate_without_writing_and_leave_source_unchanged_on_save_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config");
        let original = "Host server\n    HostName 203.0.113.10\n";
        std::fs::write(&path, original).unwrap();
        let mut app = test_app();
        app.ssh_path = path.clone();
        app.ssh_config = SshConfig::parse(original);
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('u')));
        app.form_focus = 6;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
        handle_tui_key(&mut app, key(KeyCode::Char('u')));
        app.form_fields[0].1 = "server".into();
        assert!(app.save_ssh().unwrap().contains("already exists"));
        assert_eq!(app.ssh_config.to_string(), original);
        app.form_fields[0].1 = "server-tailscale".into();
        app.ssh_path = directory.path().join("missing-parent/config");
        assert!(app.save_ssh().is_some());
        assert_eq!(app.ssh_config.to_string(), original);
        assert_eq!(app.screen, TuiScreen::SshDuplicateForm(0));
    }

    #[test]
    fn should_mark_multiple_sorted_hosts_and_queue_batch_copy_without_connecting() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\nHost destination\n");
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char(' ')));
        handle_tui_key(&mut app, key(KeyCode::Down));
        handle_tui_key(&mut app, key(KeyCode::Down));
        handle_tui_key(&mut app, key(KeyCode::Char(' ')));
        handle_tui_key(&mut app, key(KeyCode::Char('c')));
        let Some(remote_ui::Launch::Copy(indices)) = &app.pending_remote else {
            panic!("Expected batch copy launch");
        };
        assert_eq!(indices, &vec![0, 1]);
        assert_eq!(app.ssh_config.hosts().len(), 3);
        handle_tui_key(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(
            app.marked_hosts.iter().copied().collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn should_queue_remote_management_for_selected_alias_and_reject_wildcards() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host destination\nHost *\n");
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('m')));
        assert!(app.pending_remote.is_none());
        assert!(app.popup.is_some());
        handle_tui_key(&mut app, key(KeyCode::Esc));
        handle_tui_key(&mut app, key(KeyCode::Down));
        handle_tui_key(&mut app, key(KeyCode::Char('m')));
        assert!(
            matches!(&app.pending_remote, Some(remote_ui::Launch::Manage(alias)) if alias == "destination")
        );
    }

    #[test]
    fn should_reject_pattern_only_block_and_skip_negated_aliases() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host * !excluded\nHost !excluded production backup\n");
        app.screen = TuiScreen::SshDetail(0);
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert!(app.popup.is_some());
        assert!(app.pending_connection_test.is_none());
        handle_tui_key(&mut app, key(KeyCode::Esc));
        app.screen = TuiScreen::SshDetail(1);
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert_eq!(app.pending_connection_test.as_deref(), Some("production"));
    }

    #[test]
    fn should_not_test_missing_host_or_intercept_form_typing() {
        let mut app = test_app();
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert!(app.pending_connection_test.is_none());
        app.setup_ssh_add_form();
        app.screen = TuiScreen::SshAddForm;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Char('t')));
        assert_eq!(app.form_edit_buffer, "t");
        assert!(app.pending_connection_test.is_none());
    }

    #[test]
    fn should_quote_identity_paths_with_spaces_and_escape_quotes() {
        assert_eq!(
            identity_config_path(Path::new("/keys/my key")),
            "\"/keys/my key\""
        );
        assert_eq!(
            identity_config_path(Path::new("/keys/a\"b")),
            "\"/keys/a\\\"b\""
        );
        assert_eq!(
            identity_config_path(Path::new("/keys/simple")),
            "/keys/simple"
        );
    }

    /// Returns a reference to the nav_stack publicly for assertions.
    /// In tests we can also access `app.nav_stack` directly since this is
    /// an inner module, but having a helper keeps things explicit.
    fn stack_len(app: &TuiApp) -> usize {
        app.nav_stack.len()
    }

    // ── Stack unit tests ───────────────────────────────────

    #[test]
    fn test_navigate_to_pushes_and_sets_screen() {
        let mut app = test_app();
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 0);

        app.navigate_to(TuiScreen::SshList, 0);
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 1);
        assert_eq!(app.nav_stack[0], (TuiScreen::MainMenu, 0));
    }

    #[test]
    fn test_go_back_pops_and_restores() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.navigate_to(TuiScreen::SshDetail(3), 0);
        assert_eq!(stack_len(&app), 2);
        assert_eq!(app.screen, TuiScreen::SshDetail(3));

        let popped = app.go_back();
        assert!(popped);
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 1);

        let popped = app.go_back();
        assert!(popped);
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 0);
    }

    #[test]
    fn test_go_back_empty_stack_returns_false() {
        let mut app = test_app();
        assert!(!app.go_back());
        assert_eq!(app.screen, TuiScreen::MainMenu);
    }

    #[test]
    fn test_deep_stack_multiple_back() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.navigate_to(TuiScreen::SshDetail(1), 0);
        app.navigate_to(TuiScreen::SshDetail(2), 0); // unrealistic but tests deep
        assert_eq!(stack_len(&app), 3);

        app.go_back();
        assert_eq!(app.screen, TuiScreen::SshDetail(1));
        app.go_back();
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 0);
        app.go_back();
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert!(!app.go_back());
    }

    #[test]
    fn test_go_back_restores_selection_exactly() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 42);
        assert_eq!(stack_len(&app), 1);

        app.go_back();
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 0);
    }

    // ── Esc key tests ──────────────────────────────────────

    #[test]
    fn test_esc_on_main_menu_does_nothing() {
        let mut app = test_app();
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(stack_len(&app), 0);
    }

    #[test]
    fn test_esc_on_list_goes_back_to_menu() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        assert_eq!(stack_len(&app), 1);

        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 0);
    }

    #[test]
    fn test_esc_on_detail_goes_back_to_list() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 2);
        app.navigate_to(TuiScreen::SshDetail(2), 0);
        assert_eq!(stack_len(&app), 2);

        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 2);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_esc_on_hosts_detail_goes_back_to_hosts_list() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::HostsList, 1);
        app.navigate_to(TuiScreen::HostsDetail(1), 0);

        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::HostsList);
        assert_eq!(app.selected, 1);
    }

    // ── Popup priority ─────────────────────────────────────

    #[test]
    fn test_esc_dismisses_popup_without_affecting_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.navigate_to(TuiScreen::SshDetail(0), 0);
        app.show_popup(PopupKind::Info, "title".into(), "msg".into());
        assert!(app.popup.is_some());
        assert_eq!(stack_len(&app), 2);

        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert!(app.popup.is_none());
        assert_eq!(app.screen, TuiScreen::SshDetail(0));
        assert_eq!(stack_len(&app), 2);
    }

    #[test]
    fn test_enter_dismisses_popup_without_affecting_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.show_popup(PopupKind::Info, "title".into(), "msg".into());
        assert!(app.popup.is_some());

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert!(app.popup.is_none());
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(stack_len(&app), 1);
    }

    // ── Form field edit priority ───────────────────────────

    #[test]
    fn test_esc_in_form_edit_cancels_edit_without_affecting_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshAddForm, 0);
        app.form_edit_active = true;
        app.form_edit_buffer = "typing".into();
        assert_eq!(stack_len(&app), 1);

        handle_form_key(&mut app, key(KeyCode::Esc));
        assert!(!app.form_edit_active);
        assert_eq!(app.form_edit_buffer, "");
        assert_eq!(app.screen, TuiScreen::SshAddForm);
        assert_eq!(stack_len(&app), 1);
    }

    // ── Form Esc / Save / Cancel ───────────────────────────

    #[test]
    fn test_form_esc_uses_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 3);
        app.navigate_to(TuiScreen::SshAddForm, 3);
        assert_eq!(stack_len(&app), 2);

        // handle_form_key is called by handle_tui_key for form screens
        handle_form_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 3);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_form_cancel_uses_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::HostsList, 1);
        app.navigate_to(TuiScreen::HostsAddForm, 1);
        app.form_fields = vec![
            ("Patterns".into(), "".into()),
            ("HostName".into(), "".into()),
            ("User".into(), "".into()),
            ("Port".into(), "".into()),
            ("IdentityFile".into(), "".into()),
            ("Save".into(), "".into()),
            ("Cancel".into(), "".into()),
        ];
        app.form_focus = 6; // Cancel button

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::HostsList);
        assert_eq!(app.selected, 1);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_form_save_uses_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.navigate_to(TuiScreen::SshAddForm, 0);
        app.form_fields = vec![
            ("Patterns".into(), "test".into()),
            ("HostName".into(), "".into()),
            ("User".into(), "".into()),
            ("Port".into(), "".into()),
            ("IdentityFile".into(), "".into()),
            ("Save".into(), "".into()),
            ("Cancel".into(), "".into()),
        ];
        app.form_focus = 5; // Save button

        handle_form_key(&mut app, key(KeyCode::Enter));
        // Save may succeed or show popup on error; either way stack should be consumed
        assert!(app.screen == TuiScreen::SshList || app.popup.is_some());
    }

    // ── Enter on MainMenu ──────────────────────────────────

    #[test]
    fn test_enter_on_main_menu_ssh_navigates() {
        let mut app = test_app();
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 0);

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_enter_on_main_menu_hosts_navigates() {
        let mut app = test_app();
        app.selected = 1;

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::HostsList);
        assert_eq!(app.selected, 0);
    }

    // ── Enter on unknown screen is no-op ───────────────────

    #[test]
    fn test_enter_on_detail_does_nothing() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshDetail(0), 0);

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::SshDetail(0));
        assert_eq!(stack_len(&app), 1);
    }

    // ── CLI init ───────────────────────────────────────────

    #[test]
    fn test_cli_init_ssh_edit_has_parent_stack() {
        let app = TuiApp::new(
            Path::new("/nonexistent/__guajara_test_ssh"),
            Path::new("/nonexistent/__guajara_test_hosts"),
            Some(InitScreen::SshEdit(5)),
        );
        assert_eq!(app.screen, TuiScreen::SshEditForm(5));
        assert_eq!(stack_len(&app), 1);
        assert_eq!(app.nav_stack[0], (TuiScreen::SshList, 5));
    }

    #[test]
    fn test_cli_init_hosts_edit_has_parent_stack() {
        let app = TuiApp::new(
            Path::new("/nonexistent/__guajara_test_ssh"),
            Path::new("/nonexistent/__guajara_test_hosts"),
            Some(InitScreen::HostsEdit(3)),
        );
        assert_eq!(app.screen, TuiScreen::HostsEditForm(3));
        assert_eq!(stack_len(&app), 1);
        assert_eq!(app.nav_stack[0], (TuiScreen::HostsList, 3));
    }

    #[test]
    fn test_cli_init_ssh_edit_esc_returns_to_list() {
        let mut app = TuiApp::new(
            Path::new("/nonexistent/__guajara_test_ssh"),
            Path::new("/nonexistent/__guajara_test_hosts"),
            Some(InitScreen::SshEdit(5)),
        );
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 5);
        assert_eq!(stack_len(&app), 0);
    }

    // ── Render guard fallback ──────────────────────────────

    #[test]
    fn test_render_ssh_detail_out_of_bounds_goes_back() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::SshList, 0);
        app.navigate_to(TuiScreen::SshDetail(42), 0);
        // Simulate what render_ssh_detail does
        let hosts = app.ssh_config.hosts();
        if 42 >= hosts.len() && !app.go_back() {
            app.screen = TuiScreen::SshList;
        }
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(stack_len(&app), 1);
        // Now go back to MainMenu
        app.go_back();
        assert_eq!(app.screen, TuiScreen::MainMenu);
    }

    #[test]
    fn test_render_hosts_detail_out_of_bounds_fallback() {
        let mut app = test_app();
        // Set up without stack entry (shouldn't happen but tests fallback)
        app.screen = TuiScreen::HostsDetail(99);
        let records = app.hosts_file.records();
        if 99 >= records.len() && !app.go_back() {
            app.screen = TuiScreen::HostsList;
        }
        assert_eq!(app.screen, TuiScreen::HostsList);
    }

    // ── Forward TUI ────────────────────────────────────────

    fn fake_tunnel(host: &str, pid: u32, local_port: u16) -> Tunnel {
        Tunnel {
            host: host.to_string(),
            pid,
            started_at: 0,
            rules: vec![ForwardRule {
                host: host.to_string(),
                local_port,
                target_host: "db.internal".to_string(),
                target_port: local_port,
            }],
            managed: true,
        }
    }

    #[test]
    fn test_enter_on_main_menu_forwards_navigates() {
        let mut app = test_app();
        app.selected = 2;

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::ForwardList);
        assert_eq!(app.selected, 0);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_forward_add_opens_registered_host_selector() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse(
            "Host production staging\n    HostName example.internal\n\nHost *.internal\n",
        );
        app.selected = 2;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Char('a')));
        assert_eq!(app.screen, TuiScreen::ForwardHostSelect);
        assert_eq!(app.forward_host_options(), vec!["production", "staging"]);
    }

    #[test]
    fn test_forward_host_selector_copies_selected_alias_to_form() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host production\n    HostName example.internal\n");
        app.navigate_to(TuiScreen::ForwardHostSelect, 0);

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::ForwardAddForm);
        assert_eq!(
            app.form_fields[0],
            ("Host".to_string(), "production".to_string())
        );
    }

    #[test]
    fn test_forward_host_selector_can_open_ssh_host_manager() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host production\n    HostName example.internal\n");
        app.navigate_to(TuiScreen::ForwardHostSelect, 0);

        handle_tui_key(&mut app, key(KeyCode::Char('n')));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(stack_len(&app), 2);
    }

    #[test]
    fn test_ssh_hosts_are_sorted_by_name_by_default() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse(
            "Host zebra\n    HostName zebra.internal\n\nHost alpha\n    HostName alpha.internal\n",
        );

        let indices = app.ssh_display_indices();
        let hosts = app.ssh_config.hosts();
        assert_eq!(hosts[indices[0]].patterns[0], "alpha");
        assert_eq!(hosts[indices[1]].patterns[0], "zebra");
    }

    #[test]
    fn should_apply_last_used_sort_in_forward_host_selection() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.forward_state.last_used.insert("zebra".into(), 20);
        app.forward_state.last_used.insert("alpha".into(), 10);
        app.screen = TuiScreen::ForwardHostSelect;
        assert_eq!(app.forward_host_options(), vec!["alpha", "zebra"]);
        handle_tui_key(&mut app, key(KeyCode::Char('o')));
        assert_eq!(app.sort_mode, SortMode::LastUsed);
        assert_eq!(app.forward_host_options(), vec!["zebra", "alpha"]);
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn should_preserve_selected_ssh_host_when_sort_changes() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.forward_state.last_used.insert("zebra".into(), 20);
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('o')));
        assert_eq!(app.ssh_display_indices(), vec![0, 1]);
        assert_eq!(app.selected, 1);
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::SshDetail(1));
    }

    #[test]
    fn should_persist_successful_connection_usage_and_reorder_after_reload() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = test_app();
        app.forward_state_path = directory.path().join("forwards.json");
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.screen = TuiScreen::SshList;
        app.sort_mode = SortMode::LastUsed;
        assert_eq!(app.ssh_display_indices(), vec![1, 0]);
        app.record_connection_use("zebra").unwrap();
        assert_eq!(app.ssh_display_indices(), vec![0, 1]);
        assert_eq!(app.selected, 0);
        let saved = forward::load(&app.forward_state_path);
        assert!(saved.last_used["zebra"] > 0);
        let mut reopened = test_app();
        reopened.ssh_config = app.ssh_config.clone();
        reopened.forward_state = saved;
        reopened.sort_mode = SortMode::LastUsed;
        assert_eq!(reopened.forward_host_options(), vec!["zebra", "alpha"]);
        assert_eq!(reopened.ssh_display_indices(), vec![0, 1]);
    }

    #[test]
    fn should_explain_empty_usage_history_and_keep_alphabetical_fallback() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.screen = TuiScreen::SshList;
        handle_tui_key(&mut app, key(KeyCode::Char('o')));
        assert!(app.status.as_deref().unwrap().contains("no history yet"));
        assert_eq!(app.ssh_display_indices(), vec![1, 0]);
    }

    #[test]
    fn should_render_last_used_host_order_in_both_lists() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse("Host zebra\nHost alpha\n");
        app.forward_state.last_used.insert("zebra".into(), 20);
        app.sort_mode = SortMode::LastUsed;
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        for screen in [TuiScreen::SshList, TuiScreen::ForwardHostSelect] {
            app.screen = screen;
            terminal.draw(|frame| render_tui(frame, &mut app)).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(text.find("zebra").unwrap() < text.find("alpha").unwrap());
        }
    }

    #[test]
    fn test_ssh_hosts_can_be_sorted_by_last_used_forward() {
        let mut app = test_app();
        app.ssh_config = SshConfig::parse(
            "Host zebra\n    HostName zebra.internal\n\nHost alpha\n    HostName alpha.internal\n",
        );
        app.forward_state.last_used.insert("zebra".into(), 10);
        app.forward_state.last_used.insert("alpha".into(), 20);
        app.toggle_sort_mode();

        let indices = app.ssh_display_indices();
        let hosts = app.ssh_config.hosts();
        assert_eq!(hosts[indices[0]].patterns[0], "alpha");
        assert_eq!(hosts[indices[1]].patterns[0], "zebra");
        assert_eq!(app.sort_mode, SortMode::LastUsed);
    }

    #[test]
    fn test_forward_tunnels_are_sorted_by_name_by_default() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![
            fake_tunnel("zebra", std::process::id(), 5432),
            fake_tunnel("alpha", std::process::id(), 5433),
        ];

        let indices = app.forward_display_indices();
        assert_eq!(app.forward_state.tunnels[indices[0]].host, "alpha");
        assert_eq!(app.forward_state.tunnels[indices[1]].host, "zebra");
    }

    #[test]
    fn test_forward_tunnels_can_be_sorted_by_last_used() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![
            Tunnel {
                host: "zebra".into(),
                pid: std::process::id(),
                started_at: 10,
                rules: vec![],
                managed: true,
            },
            Tunnel {
                host: "alpha".into(),
                pid: std::process::id(),
                started_at: 20,
                rules: vec![],
                managed: true,
            },
        ];
        app.toggle_sort_mode();

        let indices = app.forward_display_indices();
        assert_eq!(app.forward_state.tunnels[indices[0]].host, "alpha");
        assert_eq!(app.forward_state.tunnels[indices[1]].host, "zebra");
    }

    #[test]
    fn test_main_menu_has_five_items_and_wraps() {
        let mut app = test_app();
        for _ in 0..5 {
            handle_tui_key(&mut app, key(KeyCode::Down));
        }
        assert_eq!(app.selected, 0);
        handle_tui_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.selected, 4);
    }

    #[test]
    fn test_esc_on_forward_list_goes_back_to_menu() {
        let mut app = test_app();
        app.selected = 2;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 2);
        assert_eq!(stack_len(&app), 0);
    }

    #[test]
    fn test_forward_list_nav_cycles_over_tunnels() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![
            fake_tunnel("a", std::process::id(), 5432),
            fake_tunnel("b", std::process::id(), 5433),
            fake_tunnel("c", std::process::id(), 5434),
        ];
        app.navigate_to(TuiScreen::ForwardList, 0);

        handle_tui_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected, 1);
        handle_tui_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected, 2);
        handle_tui_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected, 0);
        handle_tui_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn test_forward_add_rule_queues_pending_rule() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::ForwardList, 0);
        app.setup_forward_add_form();
        app.navigate_to(TuiScreen::ForwardAddForm, 0);
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "5432".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4; // Add Rule

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.pending_rules.len(), 1);
        assert_eq!(app.pending_rules[0].host, "web1");
        assert_eq!(app.pending_rules[0].local_port, 5432);
        // Fields cleared after queuing
        assert_eq!(app.form_fields[0].1, "");
        assert_eq!(app.form_fields[1].1, "");
        assert_eq!(app.form_fields[2].1, "");
        assert_eq!(app.form_fields[3].1, "");
        assert!(app.popup.is_none());
    }

    #[test]
    fn test_forward_add_rule_rejects_invalid_port() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "not-a-number".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.pending_rules.is_empty());
        assert!(app.popup.is_some());
    }

    #[test]
    fn test_forward_add_rule_rejects_zero_port() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "0".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.pending_rules.is_empty());
        assert!(app.popup.is_some());
    }

    #[test]
    fn test_forward_add_rule_rejects_duplicate_port_across_hosts() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "5432".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;
        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.pending_rules.len(), 1);

        app.form_fields[0].1 = "web2".into();
        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.popup.is_some());
        assert_eq!(app.pending_rules.len(), 1);
    }

    #[test]
    fn test_forward_add_rule_allows_second_rule_same_host_different_port() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "5432".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;
        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.pending_rules.len(), 1);

        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "8080".into();
        app.form_fields[2].1 = "web".into();
        app.form_fields[3].1 = "80".into();
        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.popup.is_none());
        assert_eq!(app.pending_rules.len(), 2);
    }

    #[test]
    fn test_form_forward_save_with_no_rules_shows_error() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::ForwardList, 0);
        app.setup_forward_add_form();
        app.navigate_to(TuiScreen::ForwardAddForm, 0);
        app.form_focus = 5; // Save

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.popup.is_some());
        assert_eq!(app.screen, TuiScreen::ForwardAddForm);
        assert_eq!(stack_len(&app), 2);
    }

    #[test]
    fn test_forward_add_form_cancel_uses_stack() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::ForwardList, 1);
        app.setup_forward_add_form();
        app.navigate_to(TuiScreen::ForwardAddForm, 1);
        app.form_focus = 6; // Cancel

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::ForwardList);
        assert_eq!(app.selected, 1);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_stop_selected_tunnel_with_dead_pid_prunes_state() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![fake_tunnel("ghost", 4_000_000_000, 5432)];
        app.navigate_to(TuiScreen::ForwardList, 0);

        handle_tui_key(&mut app, key(KeyCode::Char('x')));
        assert!(app.forward_state.tunnels.is_empty());
        assert!(app.status.is_some());
    }

    #[test]
    fn test_stop_selected_tunnel_clamps_selection() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![
            fake_tunnel("a", 4_000_000_000, 5432),
            fake_tunnel("b", 4_000_000_001, 5433),
        ];
        app.navigate_to(TuiScreen::ForwardList, 1);

        handle_tui_key(&mut app, key(KeyCode::Char('x')));
        assert!(app.forward_state.tunnels.is_empty());
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_popup_on_forward_list_dismisses_without_nav() {
        let mut app = test_app();
        app.navigate_to(TuiScreen::ForwardList, 0);
        app.show_popup(PopupKind::Info, "t".into(), "m".into());

        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert!(app.popup.is_none());
        assert_eq!(app.screen, TuiScreen::ForwardList);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_enter_on_forward_list_is_noop() {
        let mut app = test_app();
        app.forward_state.tunnels = vec![fake_tunnel("a", std::process::id(), 5432)];
        app.navigate_to(TuiScreen::ForwardList, 0);

        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::ForwardList);
        assert_eq!(stack_len(&app), 1);
    }

    #[test]
    fn test_forward_add_rule_trims_input() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "  web1  ".into();
        app.form_fields[1].1 = " 5432 ".into();
        app.form_fields[2].1 = " db.internal ".into();
        app.form_fields[3].1 = " 5432 ".into();
        app.form_focus = 4;

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.pending_rules.len(), 1);
        assert_eq!(app.pending_rules[0].host, "web1");
        assert_eq!(app.pending_rules[0].target_host, "db.internal");
        assert_eq!(app.pending_rules[0].local_port, 5432);
    }

    #[test]
    fn test_forward_add_rule_rejects_port_above_65535() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "web1".into();
        app.form_fields[1].1 = "99999".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.pending_rules.is_empty());
        assert!(app.popup.is_some());
    }

    #[test]
    fn test_forward_add_rule_rejects_whitespace_only_host() {
        let mut app = test_app();
        app.setup_forward_add_form();
        app.form_fields[0].1 = "   ".into();
        app.form_fields[1].1 = "5432".into();
        app.form_fields[2].1 = "db.internal".into();
        app.form_fields[3].1 = "5432".into();
        app.form_focus = 4;

        handle_form_key(&mut app, key(KeyCode::Enter));
        assert!(app.pending_rules.is_empty());
        assert!(app.popup.is_some());
    }

    #[test]
    fn test_forward_form_focus_cycles_over_fields() {
        let mut app = test_app();
        app.setup_forward_add_form();
        assert_eq!(app.form_fields.len(), 7);

        for _ in 0..7 {
            handle_form_key(&mut app, key(KeyCode::Down));
        }
        assert_eq!(app.form_focus, 0);

        handle_form_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.form_focus, 6);
    }

    // ── Integration: full SSH flow ─────────────────────────

    #[test]
    fn test_full_ssh_back_navigation() {
        let mut app = test_app();
        assert_eq!(stack_len(&app), 0);

        // MainMenu → SshList
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(stack_len(&app), 1);

        // Simulate selecting item 2 on the list, then navigating to detail
        app.selected = 2;
        app.navigate_to(TuiScreen::SshDetail(2), 0);
        assert_eq!(stack_len(&app), 2);

        // detail → list (selected restored)
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::SshList);
        assert_eq!(app.selected, 2);
        assert_eq!(stack_len(&app), 1);

        // list → menu
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(stack_len(&app), 0);

        // menu Esc is no-op
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(stack_len(&app), 0);
    }

    #[test]
    fn test_full_hosts_back_navigation() {
        let mut app = test_app();

        // MainMenu → HostsList (item 1 selected on menu)
        app.selected = 1;
        handle_tui_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.screen, TuiScreen::HostsList);
        assert_eq!(stack_len(&app), 1);

        // Simulate selecting item 1 on the list, then navigating to detail
        app.selected = 1;
        app.navigate_to(TuiScreen::HostsDetail(1), 0);
        assert_eq!(stack_len(&app), 2);

        // detail → list (selected restored)
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::HostsList);
        assert_eq!(app.selected, 1);
        assert_eq!(stack_len(&app), 1);

        // list → menu (menu selection restored)
        handle_tui_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.screen, TuiScreen::MainMenu);
        assert_eq!(app.selected, 1);
        assert_eq!(stack_len(&app), 0);
    }
}

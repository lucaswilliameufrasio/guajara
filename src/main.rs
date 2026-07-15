use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::{Path, PathBuf};

use guajara::{
    HOSTS_PATH, SSH_PATH, diff, expand_path, hosts::HostsFile, read_file, ssh::SshConfig,
    write_file,
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
}

#[derive(clap::Args)]
struct SshCli {
    #[command(subcommand)]
    command: SshCommand,
}

#[derive(Subcommand)]
enum SshCommand {
    List,
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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};
use std::io::stdout;

enum TuiScreen {
    MainMenu,
    SshList,
    SshDetail(usize),
    SshAddForm,
    SshEditForm(usize),
    HostsList,
    HostsDetail(usize),
    HostsAddForm,
    HostsEditForm(usize),
}

struct TuiApp {
    screen: TuiScreen,
    ssh_config: SshConfig,
    hosts_file: HostsFile,
    ssh_path: PathBuf,
    hosts_path: PathBuf,
    selected: usize,
    status: Option<String>,
    form_fields: Vec<(String, String)>,
    form_focus: usize,
    form_edit_buffer: String,
    form_edit_active: bool,
}

impl TuiApp {
    fn new(ssh_path: &Path, hosts_path: &Path, init: Option<InitScreen>) -> Self {
        let ssh = read_file(ssh_path).unwrap_or_default();
        let hosts = read_file(hosts_path).unwrap_or_default();
        let mut app = TuiApp {
            screen: TuiScreen::MainMenu,
            ssh_config: SshConfig::parse(&ssh),
            hosts_file: HostsFile::parse(&hosts),
            ssh_path: ssh_path.to_path_buf(),
            hosts_path: hosts_path.to_path_buf(),
            selected: 0,
            status: None,
            form_fields: Vec::new(),
            form_focus: 0,
            form_edit_buffer: String::new(),
            form_edit_active: false,
        };
        if let Some(init) = init {
            match init {
                InitScreen::SshEdit(idx) => {
                    app.setup_ssh_edit_form(idx);
                    app.screen = TuiScreen::SshEditForm(idx);
                }
                InitScreen::HostsEdit(idx) => {
                    app.setup_hosts_edit_form(idx);
                    app.screen = TuiScreen::HostsEditForm(idx);
                }
            }
        }
        app
    }

    fn reload(&mut self) {
        let s = read_file(&self.ssh_path).unwrap_or_default();
        let h = read_file(&self.hosts_path).unwrap_or_default();
        self.ssh_config = SshConfig::parse(&s);
        self.hosts_file = HostsFile::parse(&h);
    }

    // ── SSH save ────────────────────────────────────────

    fn save_ssh(&mut self) -> Option<String> {
        let old = self.ssh_config.to_string();
        match self.screen {
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
                for p in &hosts[idx].patterns {
                    let _ = self.ssh_config.remove_pattern(start, p);
                }
                for p in &new_pat {
                    let _ = self.ssh_config.add_pattern(start, p);
                }
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
        let new = self.ssh_config.to_string();
        eprintln!("{}", diff(&old, &new));
        match write_file(&self.ssh_path, &new) {
            Ok(()) => {
                self.reload();
                self.status = Some("SSH config saved".to_string());
                None
            }
            Err(e) => Some(e),
        }
    }

    // ── Hosts save ──────────────────────────────────────

    fn save_hosts(&mut self) -> Option<String> {
        let old = self.hosts_file.to_string();
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
                let cs = if c.is_empty() {
                    String::new()
                } else {
                    format!("\t#{}", c)
                };
                self.hosts_file.lines[records[idx].line_idx] =
                    format!("{}\t{}{}", ip, h.join(" "), cs);
            }
            _ => {}
        }
        let new = self.hosts_file.to_string();
        eprintln!("{}", diff(&old, &new));
        match write_file(&self.hosts_path, &new) {
            Ok(()) => {
                self.reload();
                self.status = Some("Hosts file saved".to_string());
                None
            }
            Err(e) => Some(e),
        }
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
        terminal.draw(|f| render_tui(f, &mut app)).ok();
        if let Event::Key(key) = event::read()
            .ok()
            .unwrap_or(Event::Key(KeyCode::Esc.into()))
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            handle_tui_key(&mut app, key);
            if matches!(app.screen, TuiScreen::MainMenu) && key.code == KeyCode::Char('q') {
                break;
            }
        }
    }
    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
}

// ── Key handling ──────────────────────────────────────────

fn handle_tui_key(app: &mut TuiApp, key: event::KeyEvent) {
    // Delegate to form handler if in a form screen
    if matches!(
        app.screen,
        TuiScreen::SshAddForm
            | TuiScreen::SshEditForm(_)
            | TuiScreen::HostsAddForm
            | TuiScreen::HostsEditForm(_)
    ) {
        handle_form_key(app, key);
        return;
    }

    match key.code {
        KeyCode::Esc => match app.screen {
            TuiScreen::MainMenu => {}
            _ => {
                app.screen = TuiScreen::MainMenu;
                app.selected = 0;
            }
        },
        KeyCode::Char('j') | KeyCode::Down => {
            let n = match app.screen {
                TuiScreen::MainMenu => 4,
                TuiScreen::SshList => app.ssh_config.hosts().len().max(1),
                TuiScreen::HostsList => app.hosts_file.records().len().max(1),
                _ => 1,
            };
            app.selected = (app.selected + 1) % n;
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let n = match app.screen {
                TuiScreen::MainMenu => 4,
                TuiScreen::SshList => app.ssh_config.hosts().len().max(1),
                TuiScreen::HostsList => app.hosts_file.records().len().max(1),
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
                0 => {
                    app.screen = TuiScreen::SshList;
                    app.selected = 0;
                }
                1 => {
                    app.screen = TuiScreen::HostsList;
                    app.selected = 0;
                }
                2 => {
                    let mut m = Vec::new();
                    let se = app.ssh_config.validate();
                    let he = app.hosts_file.validate();
                    m.push(if se.is_empty() {
                        "SSH: valid".into()
                    } else {
                        format!("SSH: {} error(s)", se.len())
                    });
                    m.push(if he.is_empty() {
                        "Hosts: valid".into()
                    } else {
                        format!("Hosts: {} error(s)", he.len())
                    });
                    app.status = Some(m.join(" | "));
                }
                3 => {}
                _ => {}
            },
            TuiScreen::SshList => {
                let h = app.ssh_config.hosts();
                if app.selected < h.len() {
                    app.screen = TuiScreen::SshDetail(app.selected);
                    app.selected = 0;
                }
            }
            TuiScreen::HostsList => {
                let r = app.hosts_file.records();
                if app.selected < r.len() {
                    app.screen = TuiScreen::HostsDetail(app.selected);
                    app.selected = 0;
                }
            }
            _ => {
                app.screen = TuiScreen::MainMenu;
                app.selected = 0;
            }
        },
        KeyCode::Char('a') => match app.screen {
            TuiScreen::SshList => {
                app.setup_ssh_add_form();
                app.screen = TuiScreen::SshAddForm;
            }
            TuiScreen::HostsList => {
                app.setup_hosts_add_form();
                app.screen = TuiScreen::HostsAddForm;
            }
            _ => {}
        },
        KeyCode::Char('e') => match app.screen {
            TuiScreen::SshList if app.selected < app.ssh_config.hosts().len() => {
                app.setup_ssh_edit_form(app.selected);
                app.screen = TuiScreen::SshEditForm(app.selected);
            }
            TuiScreen::HostsList if app.selected < app.hosts_file.records().len() => {
                app.setup_hosts_edit_form(app.selected);
                app.screen = TuiScreen::HostsEditForm(app.selected);
            }
            _ => {}
        },
        KeyCode::Char('d') => match app.screen {
            TuiScreen::SshList if app.selected < app.ssh_config.hosts().len() => {
                let p = app.ssh_config.hosts()[app.selected].patterns.join(" ");
                let _ = app
                    .ssh_config
                    .remove_block(app.ssh_config.hosts()[app.selected].start_idx);
                app.status = Some(format!("Removed '{}' — save with s", p));
                app.clamp_ssh_sel();
            }
            TuiScreen::HostsList if app.selected < app.hosts_file.records().len() => {
                let e = app.hosts_file.records()[app.selected].hostnames.join(" ");
                let _ = app.hosts_file.remove(app.selected);
                app.status = Some(format!("Removed '{}' — save with s", e));
                app.clamp_hosts_sel();
            }
            _ => {}
        },
        KeyCode::Char('s') => match app.screen {
            TuiScreen::SshList => {
                if let Some(e) = app.save_ssh() {
                    app.status = Some(e);
                }
            }
            TuiScreen::HostsList => {
                if let Some(e) = app.save_hosts() {
                    app.status = Some(e);
                }
            }
            _ => {}
        },
        KeyCode::Char('r') => {
            app.reload();
            app.status = Some("Reloaded".to_string());
        }
        _ => {}
    }
}

fn handle_form_key(app: &mut TuiApp, key: event::KeyEvent) {
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
            app.screen = match app.screen {
                TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) => TuiScreen::SshList,
                _ => TuiScreen::HostsList,
            };
            app.selected = 0;
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
            let label = &app.form_fields[app.form_focus].0;
            if label == "Save" {
                let err = match app.screen {
                    TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) => app.save_ssh(),
                    _ => app.save_hosts(),
                };
                if let Some(e) = err {
                    app.status = Some(e);
                } else {
                    app.status = Some("Saved".to_string());
                    app.screen = match app.screen {
                        TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) => TuiScreen::SshList,
                        _ => TuiScreen::HostsList,
                    };
                    app.selected = 0;
                    app.reload();
                }
            } else if label == "Cancel" {
                app.screen = match app.screen {
                    TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) => TuiScreen::SshList,
                    _ => TuiScreen::HostsList,
                };
                app.selected = 0;
            } else {
                app.form_edit_buffer = app.form_fields[app.form_focus].1.clone();
                app.form_edit_active = true;
            }
        }
        _ => {}
    }
}

// ── Rendering ──────────────────────────────────────────────

fn render_tui(frame: &mut Frame, app: &mut TuiApp) {
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
                TuiScreen::HostsList => "Hosts Entries",
                TuiScreen::HostsDetail(_) => "Hosts Details",
                TuiScreen::HostsAddForm => "Add Hosts Entry",
                TuiScreen::HostsEditForm(_) => "Edit Hosts Entry",
            },
            Style::default().fg(Color::Yellow),
        ),
    ]);
    frame.render_widget(Paragraph::new(title), lo[0]);

    match app.screen {
        TuiScreen::MainMenu => render_main_menu(frame, lo[1], app),
        TuiScreen::SshList => render_ssh_list(frame, lo[1], app),
        TuiScreen::SshDetail(idx) => render_ssh_detail(frame, lo[1], app, idx),
        TuiScreen::SshAddForm | TuiScreen::SshEditForm(_) => render_form(frame, lo[1], app),
        TuiScreen::HostsList => render_hosts_list(frame, lo[1], app),
        TuiScreen::HostsDetail(idx) => render_hosts_detail(frame, lo[1], app, idx),
        TuiScreen::HostsAddForm | TuiScreen::HostsEditForm(_) => render_form(frame, lo[1], app),
    }

    let st = app.status.clone().unwrap_or_else(|| match app.screen {
        TuiScreen::MainMenu => "up/down nav  enter select  r reload  q quit".into(),
        TuiScreen::SshList => {
            "j/k nav  enter view  a add  e edit  d delete  s save  r reload  Esc back".into()
        }
        TuiScreen::HostsList => {
            "j/k nav  enter view  a add  e edit  d delete  s save  r reload  Esc back".into()
        }
        TuiScreen::SshDetail(_) | TuiScreen::HostsDetail(_) => "Esc back  r reload".into(),
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
}

fn render_main_menu(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items = [
        "Manage SSH hosts",
        "Manage /etc/hosts entries",
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
    let li: Vec<ListItem> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| {
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
                    "{}{:<20} {:<30} {}",
                    if i == app.selected { "> " } else { "  " },
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
        app.screen = TuiScreen::SshList;
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
        "  Esc back  r reload",
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
        app.screen = TuiScreen::HostsList;
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

fn render_form(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let title = match app.screen {
        TuiScreen::SshAddForm => " Add SSH Host ",
        TuiScreen::SshEditForm(_) => " Edit SSH Host ",
        TuiScreen::HostsAddForm => " Add Hosts Entry ",
        TuiScreen::HostsEditForm(_) => " Edit Hosts Entry ",
        _ => " Form ",
    };

    let mut lines = Vec::new();
    for (i, (label, val)) in app.form_fields.iter().enumerate() {
        let focused = i == app.form_focus;
        let action = label == "Save" || label == "Cancel";
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

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

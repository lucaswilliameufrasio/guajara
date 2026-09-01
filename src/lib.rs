pub mod forward;
pub mod hosts;
pub mod ssh;

pub use forward::{ForwardRule, ForwardState, Tunnel};
pub use hosts::HostsFile;
pub use ssh::SshConfig;

pub const SSH_PATH: &str = "~/.ssh/config";
pub const HOSTS_PATH: &str = "/etc/hosts";

pub fn expand_path(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home).join(rest)
    } else {
        std::path::PathBuf::from(path)
    }
}

pub fn read_file(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))
}

pub fn write_file(path: &std::path::Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("guajara-tmp");
    std::fs::write(&tmp, content).map_err(|e| format!("Cannot write {}: {}", tmp.display(), e))?;
    // Preserve original file permissions if the file exists
    if let Ok(meta) = std::fs::metadata(path) {
        let perms = meta.permissions();
        if let Err(e) = std::fs::set_permissions(&tmp, perms) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("Cannot set permissions: {}", e));
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("Cannot rename {}: {}", path.display(), e))?;
    Ok(())
}

pub fn diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut result = String::new();
    let mut i = 0;
    let mut j = 0;
    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            result.push_str(&format!("  {}\n", old_lines[i]));
            i += 1;
            j += 1;
        } else if j < new_lines.len() && (i >= old_lines.len() || new_lines[j] != old_lines[i]) {
            result.push_str(&format!("+ {}\n", new_lines[j]));
            j += 1;
        } else if i < old_lines.len() {
            result.push_str(&format!("- {}\n", old_lines[i]));
            i += 1;
        }
    }
    result
}

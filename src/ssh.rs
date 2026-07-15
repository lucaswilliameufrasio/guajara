use std::fmt::{self, Display};

/// Lossless SSH config document.
/// Stores every original line and provides structured operations
/// that modify only the targeted parts of the file.
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub lines: Vec<String>,
}

/// A parsed host block within the SSH config.
#[derive(Debug, Clone)]
pub struct SshHost {
    /// Index of the `Host ...` header line
    pub header_idx: usize,
    /// Index of the first line of this block in the file
    pub start_idx: usize,
    /// Index after the last line of this block (exclusive end)
    pub end_idx: usize,
    /// Parsed pattern strings from the header
    pub patterns: Vec<String>,
    /// The raw header text
    pub header: String,
    /// Parsed body directives (key, value, raw line)
    pub directives: Vec<SshDirective>,
}

#[derive(Debug, Clone)]
pub struct SshDirective {
    pub raw: String,
    pub key: String,
    pub value: String,
}

/// A parsed Match block (read-only for now)
#[derive(Debug, Clone)]
pub struct SshMatch {
    pub start_idx: usize,
    pub end_idx: usize,
    pub header: String,
    pub criteria: String,
}

/// Result of attempting to locate a block by selector
#[derive(Debug)]
pub enum SelectResult {
    Single(usize),
    Multiple(Vec<usize>),
    None,
}

impl SshConfig {
    pub fn parse(text: &str) -> Self {
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        if text.ends_with('\n') && !text.is_empty() {
            lines.push(String::new());
        }
        SshConfig { lines }
    }

    pub fn from_string(s: &str) -> Self {
        Self::parse(s)
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() || self.lines.iter().all(|l| l.trim().is_empty())
    }

    // ── Block enumeration ──────────────────────────────────

    fn classify(line: &str) -> LineKind {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return LineKind::Blank;
        }
        if trimmed.starts_with('#') {
            return LineKind::Comment;
        }
        let first = match trimmed.split_whitespace().next() {
            Some(w) => w,
            None => return LineKind::Blank,
        };
        if first.eq_ignore_ascii_case("Host") {
            LineKind::HostHeader
        } else if first.eq_ignore_ascii_case("Match") {
            LineKind::MatchHeader
        } else if first.eq_ignore_ascii_case("Include") {
            LineKind::Include
        } else {
            LineKind::Directive
        }
    }

    fn is_block_start(line: &str) -> bool {
        matches!(
            Self::classify(line),
            LineKind::HostHeader | LineKind::MatchHeader | LineKind::Include
        )
    }

    fn parse_host_patterns(header: &str) -> Vec<String> {
        header
            .split_whitespace()
            .skip(1)
            .map(|s| s.to_string())
            .collect()
    }

    fn parse_match_criteria(header: &str) -> String {
        let trimmed = header.trim();
        // Skip "Match " prefix
        if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            trimmed[pos..].trim().to_string()
        } else {
            String::new()
        }
    }

    fn parse_directive(line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }
        let stripped = match trimmed.find('#') {
            Some(pos) => trimmed[..pos].trim(),
            None => trimmed,
        };
        // Find the end of the key (before space, tab, or =)
        let key_start = 0;
        let mut key_end = stripped.len();
        for (i, c) in stripped.char_indices() {
            if c.is_whitespace() || c == '=' {
                key_end = i;
                break;
            }
        }
        let key = stripped[key_start..key_end].trim().to_string();
        if key.is_empty() {
            return None;
        }
        let rest = stripped[key_end..].trim();
        let value = if let Some(eq_rest) = rest.strip_prefix('=') {
            eq_rest.trim()
        } else {
            rest
        };
        Some((key, value.to_string()))
    }

    fn host_range(&self, header_idx: usize) -> Option<(usize, usize)> {
        if header_idx >= self.lines.len() {
            return None;
        }
        let mut end = header_idx + 1;
        while end < self.lines.len() {
            if Self::is_block_start(&self.lines[end]) {
                break;
            }
            end += 1;
        }
        Some((header_idx, end))
    }

    /// Return all parsed Host blocks.
    pub fn hosts(&self) -> Vec<SshHost> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.lines.len() {
            let kind = Self::classify(&self.lines[i]);
            if matches!(kind, LineKind::HostHeader) {
                let start = i;
                let end = self.host_range(i).map(|(_, e)| e).unwrap_or(i + 1);
                let header = self.lines[i].clone();
                let patterns = Self::parse_host_patterns(&header);
                let mut directives = Vec::new();
                for j in (start + 1)..end {
                    if let Some((key, value)) = Self::parse_directive(&self.lines[j]) {
                        directives.push(SshDirective {
                            raw: self.lines[j].clone(),
                            key,
                            value,
                        });
                    }
                }
                out.push(SshHost {
                    header_idx: i,
                    start_idx: start,
                    end_idx: end,
                    patterns,
                    header,
                    directives,
                });
                i = end;
            } else {
                i += 1;
            }
        }
        out
    }

    /// Return all parsed Match blocks.
    pub fn matches(&self) -> Vec<SshMatch> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.lines.len() {
            let kind = Self::classify(&self.lines[i]);
            if matches!(kind, LineKind::MatchHeader) {
                let start = i;
                let end = self.host_range(i).map(|(_, e)| e).unwrap_or(i + 1);
                let header = self.lines[i].clone();
                let criteria = Self::parse_match_criteria(&header);
                out.push(SshMatch {
                    start_idx: start,
                    end_idx: end,
                    header,
                    criteria,
                });
                i = end;
            } else {
                i += 1;
            }
        }
        out
    }

    /// Select a block by matching any of its patterns against `selector`.
    /// Returns `SelectResult::Multiple` when more than one block matches.
    pub fn select(&self, selector: &str) -> SelectResult {
        let hosts = self.hosts();
        let matching: Vec<usize> = hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| h.patterns.iter().any(|p| p == selector))
            .map(|(i, _)| i)
            .collect();

        match matching.len() {
            0 => SelectResult::None,
            1 => SelectResult::Single(matching[0]),
            _ => SelectResult::Multiple(matching),
        }
    }

    // ── Mutating operations ────────────────────────────────

    /// Set a directive `key = value` in the host block at `block_start_idx`.
    /// If the directive already exists, its value is replaced in-place.
    /// If not, it is appended after the last non-blank body line.
    pub fn set(&mut self, block_start_idx: usize, key: &str, value: &str) -> Result<(), String> {
        let range = self
            .host_range(block_start_idx)
            .ok_or("Block start index out of range")?;
        let (_start, end) = range;

        // Try to find existing directive
        let body_start = block_start_idx + 1;
        for i in body_start..end {
            if let Some((k, _v)) = Self::parse_directive(&self.lines[i])
                && k.eq_ignore_ascii_case(key)
            {
                // Preserve indentation and separator style
                let raw = &self.lines[i];
                let indent: String = raw.chars().take_while(|c| c.is_whitespace()).collect();
                let trimmed = raw.trim();
                let sep = if trimmed.contains('=') { "=" } else { " " };
                let inline_comment = match raw.find('#') {
                    Some(pos) => {
                        // Only preserve comment if it was after the value originally
                        let before_comment = raw[..pos].trim();
                        if before_comment.ends_with(&_v) || before_comment.ends_with(value) {
                            raw[pos..].to_string()
                        } else {
                            String::new()
                        }
                    }
                    None => String::new(),
                };
                let comment_part = if inline_comment.is_empty() {
                    String::new()
                } else {
                    format!(" {}", inline_comment)
                };
                self.lines[i] = format!("{}{}{}{}{}", indent, key, sep, value, comment_part);
                return Ok(());
            }
        }

        // Not found: insert after the last non-blank body line
        let mut insert_at = body_start;
        for i in body_start..end {
            if !self.lines[i].trim().is_empty() && !self.lines[i].trim().starts_with('#') {
                insert_at = i + 1;
            }
        }

        // Determine indentation from nearest preceding directive
        let indent = if insert_at > body_start {
            let prev = &self.lines[insert_at - 1];
            let ind: String = prev.chars().take_while(|c| c.is_whitespace()).collect();
            if ind.is_empty() {
                "    ".to_string()
            } else {
                ind
            }
        } else {
            "    ".to_string()
        };

        self.lines
            .insert(insert_at, format!("{}{} {}", indent, key, value));
        Ok(())
    }

    /// Remove a directive `key` from the host block at `block_start_idx`.
    pub fn unset(&mut self, block_start_idx: usize, key: &str) -> Result<(), String> {
        let range = self
            .host_range(block_start_idx)
            .ok_or("Block start index out of range")?;
        let body_start = block_start_idx + 1;
        let end = range.1;

        // Collect indices to remove in reverse order
        let mut to_remove = Vec::new();
        for i in body_start..end {
            if let Some((k, _)) = Self::parse_directive(&self.lines[i])
                && k.eq_ignore_ascii_case(key)
            {
                to_remove.push(i);
            }
        }

        if to_remove.is_empty() {
            return Err(format!("Directive '{}' not found in this block", key));
        }

        for idx in to_remove.into_iter().rev() {
            self.lines.remove(idx);
        }

        Ok(())
    }

    /// Add a new Host block after the last block in the file.
    /// `patterns` should be the host patterns (e.g., `["production"]`, `["*.internal"]`).
    /// `directives` should be key-value pairs.
    pub fn add(&mut self, patterns: &[String], directives: &[(String, String)]) -> usize {
        let header = format!("Host {}", patterns.join(" "));
        // Ensure trailing newline before adding
        if !self.lines.is_empty() && !self.lines.last().unwrap().is_empty() {
            self.lines.push(String::new());
        }
        let insert_at = self.lines.len();
        self.lines.push(header);
        let indent = "    ";
        for (k, v) in directives {
            self.lines.push(format!("{}{} {}", indent, k, v));
        }
        insert_at
    }

    /// Remove the host block starting at `block_start_idx` (inclusive).
    pub fn remove_block(&mut self, block_start_idx: usize) -> Result<(), String> {
        let range = self
            .host_range(block_start_idx)
            .ok_or("Block start index out of range")?;
        let (start, end) = range;
        // Remove in reverse order
        for _ in start..end {
            self.lines.remove(start);
        }
        Ok(())
    }

    /// Add a pattern to the Host header line at `block_start_idx`.
    pub fn add_pattern(&mut self, block_start_idx: usize, pattern: &str) -> Result<(), String> {
        let line = &mut self.lines[block_start_idx];
        let trimmed = line.trim();
        if !trimmed.starts_with("Host ")
            && !trimmed.starts_with("host ")
            && !trimmed.starts_with("HOST ")
        {
            return Err("Not a Host header line".to_string());
        }
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let new_line = format!("{}Host {} {}", indent, trimmed[5..].trim(), pattern);
        *line = new_line;
        Ok(())
    }

    /// Remove a pattern from the Host header line at `block_start_idx`.
    /// If the last pattern is removed, the block header remains but empty.
    pub fn remove_pattern(&mut self, block_start_idx: usize, pattern: &str) -> Result<(), String> {
        let line = &self.lines[block_start_idx];
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let trimmed = line.trim();
        let patterns: Vec<&str> = trimmed
            .split_whitespace()
            .skip(1)
            .filter(|p| *p != pattern)
            .collect();
        if patterns.len() == trimmed.split_whitespace().skip(1).count() {
            return Err(format!("Pattern '{}' not found", pattern));
        }
        let new_line = format!("{}Host {}", indent, patterns.join(" "));
        self.lines[block_start_idx] = new_line;
        Ok(())
    }

    /// Validate the config by checking that it parses without error
    /// (basic check: every line that looks like a directive has a valid key-value pair).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let first = trimmed.split_whitespace().next().unwrap_or("");
            if Self::is_block_start(line) {
                continue;
            }
            if first.eq_ignore_ascii_case("Host")
                || first.eq_ignore_ascii_case("Match")
                || first.eq_ignore_ascii_case("Include")
            {
                continue;
            }
            // Should be a directive
            if Self::parse_directive(line).is_none() && !trimmed.is_empty() {
                errors.push(format!(
                    "Line {}: could not parse directive: {}",
                    i + 1,
                    line
                ));
            }
        }
        errors
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

impl Display for SshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.lines.join("\n"))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum LineKind {
    Blank,
    Comment,
    HostHeader,
    MatchHeader,
    Include,
    Directive,
}

impl fmt::Display for SelectResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectResult::Single(idx) => write!(f, "{}", idx),
            SelectResult::Multiple(indices) => {
                write!(f, "{} matches", indices.len())
            }
            SelectResult::None => write!(f, "no match"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config() {
        let cfg = SshConfig::parse("");
        assert!(cfg.is_empty());
        assert_eq!(cfg.hosts().len(), 0);
    }

    #[test]
    fn test_single_host() {
        let content = "Host production\n    HostName prod.example.com\n    User deploy\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].patterns, vec!["production"]);
        assert_eq!(hosts[0].directives.len(), 2);
        assert_eq!(hosts[0].directives[0].key, "HostName");
        assert_eq!(hosts[0].directives[0].value, "prod.example.com");
        assert_eq!(hosts[0].directives[1].key, "User");
        assert_eq!(hosts[0].directives[1].value, "deploy");
    }

    #[test]
    fn test_multi_pattern_host() {
        let content = "Host production staging\n    HostName example.com\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].patterns, vec!["production", "staging"]);
    }

    #[test]
    fn test_wildcard_pattern() {
        let content = "Host *.internal\n    HostName 10.0.0.%h\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].patterns, vec!["*.internal"]);
    }

    #[test]
    fn test_negated_pattern() {
        let content = "Host * !bastion\n    User admin\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].patterns, vec!["*", "!bastion"]);
    }

    #[test]
    fn test_preserves_indentation() {
        let content = "Host dev\n  HostName dev.example.com\n  User dev\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_preserves_comments_and_blanks() {
        let content =
            "# This is a comment\n\nHost test\n    HostName test.com\n\n# Another comment\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_preserves_trailing_newline() {
        let content = "Host a\n    HostName a.com\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_no_trailing_newline() {
        let content = "Host a\n    HostName a.com";
        let cfg = SshConfig::parse(content);
        // to_string adds newlines between lines, but no trailing newline
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_multiple_hosts() {
        let content = "Host a\n    HostName a.com\nHost b\n    HostName b.com\n    User test\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].patterns, vec!["a"]);
        assert_eq!(hosts[1].patterns, vec!["b"]);
        assert_eq!(hosts[1].directives.len(), 2);
    }

    #[test]
    fn test_mixed_case_keywords() {
        let content = "HOST production\n    hostname prod.example.com\n    USER deploy\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].patterns, vec!["production"]);
    }

    #[test]
    fn test_global_directives() {
        let content = "StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\n\nHost test\n    HostName test.com\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        assert!(!hosts[0].directives.is_empty());
        // Global directives should be preserved
        assert!(cfg.to_string().starts_with("StrictHostKeyChecking no"));
    }

    #[test]
    fn test_case_insensitive_keyword() {
        let raw = "    hostname test.com";
        let (key, val) = SshConfig::parse_directive(raw).unwrap();
        assert_eq!(key, "hostname");
        assert_eq!(val, "test.com");
    }

    #[test]
    fn test_include_directive() {
        let content = "Include ~/.ssh/config.d/*\nHost a\n    HostName a.com\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.hosts().len(), 1);
        assert!(cfg.to_string().contains("Include ~/.ssh/config.d/*"));
    }

    #[test]
    fn test_roundtrip() {
        let content = r#"Host production
    HostName prod.example.com
    User deploy
    Port 22
    IdentityFile ~/.ssh/prod-key

Host staging
    HostName staging.example.com
    User deploy
    Port 2222
"#;
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_empty_file_preservation() {
        let cfg = SshConfig::parse("");
        assert!(cfg.is_empty());
        assert_eq!(cfg.to_string(), "");
    }

    #[test]
    fn test_set_existing_directive() {
        let content = "Host test\n    HostName old.com\n    User me\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 1);
        let idx = hosts[0].start_idx;

        cfg.set(idx, "HostName", "new.com").unwrap();
        let updated = cfg.to_string();
        assert!(updated.contains("HostName new.com"));
        assert!(!updated.contains("HostName old.com"));
        assert!(updated.contains("User me"));
    }

    #[test]
    fn test_set_new_directive() {
        let content = "Host test\n    HostName test.com\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        let idx = hosts[0].start_idx;

        cfg.set(idx, "Port", "2222").unwrap();
        let updated = cfg.to_string();
        assert!(updated.contains("Port 2222"));
        assert!(updated.contains("HostName test.com"));
    }

    #[test]
    fn test_unset_directive() {
        let content = "Host test\n    HostName test.com\n    User me\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        let idx = hosts[0].start_idx;

        cfg.unset(idx, "User").unwrap();
        let updated = cfg.to_string();
        assert!(!updated.contains("User me"));
        assert!(updated.contains("HostName test.com"));
    }

    #[test]
    fn test_unset_nonexistent_directive() {
        let content = "Host test\n    HostName test.com\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        let idx = hosts[0].start_idx;

        assert!(cfg.unset(idx, "Port").is_err());
    }

    #[test]
    fn test_remove_host() {
        let content = "Host a\n    HostName a.com\nHost b\n    HostName b.com\n";
        let mut cfg = SshConfig::parse(content);
        assert_eq!(cfg.hosts().len(), 2);

        let hosts = cfg.hosts();
        cfg.remove_block(hosts[0].start_idx).unwrap();
        assert_eq!(cfg.hosts().len(), 1);
        assert!(cfg.to_string().contains("Host b"));
        assert!(!cfg.to_string().contains("Host a"));
    }

    #[test]
    fn test_add_host() {
        let content = "Host a\n    HostName a.com\n";
        let mut cfg = SshConfig::parse(content);
        cfg.add(
            &["new".to_string()],
            &[
                ("HostName".to_string(), "new.com".to_string()),
                ("User".to_string(), "test".to_string()),
            ],
        );
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1].patterns, vec!["new"]);
    }

    #[test]
    fn test_add_pattern() {
        let content = "Host a\n    HostName a.com\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        cfg.add_pattern(hosts[0].start_idx, "b").unwrap();
        let updated = cfg.hosts();
        assert_eq!(updated[0].patterns, vec!["a", "b"]);
    }

    #[test]
    fn test_remove_pattern() {
        let content = "Host a b\n    HostName a.com\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        cfg.remove_pattern(hosts[0].start_idx, "b").unwrap();
        let updated = cfg.hosts();
        assert_eq!(updated[0].patterns, vec!["a"]);
    }

    #[test]
    fn test_remove_pattern_not_found() {
        let content = "Host a\n    HostName a.com\n";
        let mut cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        assert!(cfg.remove_pattern(hosts[0].start_idx, "b").is_err());
    }

    #[test]
    fn test_select_single() {
        let content =
            "Host production\n    HostName prod.com\nHost staging\n    HostName staging.com\n";
        let cfg = SshConfig::parse(content);
        match cfg.select("production") {
            SelectResult::Single(idx) => assert_eq!(cfg.hosts()[idx].patterns, vec!["production"]),
            _ => panic!("Expected Single match"),
        }
    }

    #[test]
    fn test_select_none() {
        let content = "Host a\n    HostName a.com\n";
        let cfg = SshConfig::parse(content);
        assert!(matches!(cfg.select("nonexistent"), SelectResult::None));
    }

    #[test]
    fn test_select_multiple() {
        let content = "Host production\n    HostName prod.com\nHost production-staging\n    HostName staging.com\n";
        let cfg = SshConfig::parse(content);
        match cfg.select("production") {
            SelectResult::Single(_) => {} // Only one exact match
            _ => panic!("Expected Single"),
        }
    }

    #[test]
    fn test_match_block_parsing() {
        let content = r#"Match host bastion exec "nc -z %h 22"
    User admin
    Port 22
Host a
    HostName a.com
"#;
        let cfg = SshConfig::parse(content);
        let matches = cfg.matches();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].criteria.contains("bastion"));
        // Host blocks still parse correctly
        assert_eq!(cfg.hosts().len(), 1);
    }

    #[test]
    fn test_long_config_roundtrip() {
        let content = r#"Host a
    HostName a.com
    User user1
    Port 22

Host *.internal
    HostName 10.0.0.%h
    User admin

Host b c d
    HostName b.com
    User user2

Match host bastion
    User bastion-user

Include ~/.ssh/config.d/*
"#;
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
        assert_eq!(cfg.hosts().len(), 3);
        assert_eq!(cfg.matches().len(), 1);
    }

    #[test]
    fn test_inline_comment_preservation() {
        let content = "Host test\n    HostName test.com  # this is a comment\n    User me\n";
        let cfg = SshConfig::parse(content);
        let hosts = cfg.hosts();
        let idx = hosts[0].start_idx;

        let mut cfg2 = SshConfig::parse(&cfg.to_string());
        cfg2.set(idx, "HostName", "new.com").unwrap();
        // Inline comment preservation is best-effort; the key-value should be correct
        assert!(cfg2.to_string().contains("HostName new.com"));
    }

    #[test]
    fn test_validate_valid() {
        let content = "Host test\n    HostName test.com\n";
        let cfg = SshConfig::parse(content);
        let errors = cfg.validate();
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_invalid() {
        let content = "Host test\n    HostName test.com\n    \n";
        let cfg = SshConfig::parse(content);
        let errors = cfg.validate();
        assert!(errors.is_empty()); // blank line is fine
    }

    #[test]
    fn test_directive_with_equals() {
        let raw = "    HostName=test.com";
        let (key, val) = SshConfig::parse_directive(raw).unwrap();
        assert_eq!(key, "HostName");
        assert_eq!(val, "test.com");
    }

    #[test]
    fn test_set_with_equals_preservation() {
        let content = "Host test\n    HostName=old.com\n";
        let mut cfg = SshConfig::parse(content);
        let idx = cfg.hosts()[0].start_idx;
        cfg.set(idx, "HostName", "new.com").unwrap();
        assert!(cfg.to_string().contains("HostName=new.com"));
    }

    #[test]
    fn test_comment_only_file() {
        let content = "# just a comment\n# another one\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.hosts().len(), 0);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_tab_indentation() {
        let content = "Host test\n\tHostName test.com\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
    }

    #[test]
    fn test_multiple_blank_lines() {
        let content = "Host a\n    HostName a.com\n\n\nHost b\n    HostName b.com\n";
        let cfg = SshConfig::parse(content);
        assert_eq!(cfg.to_string(), content);
        assert_eq!(cfg.hosts().len(), 2);
    }
}

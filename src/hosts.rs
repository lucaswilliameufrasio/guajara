use std::fmt::{self, Display};

/// Lossless hosts file document.
/// Stores every original line and provides structured operations
/// that modify only the targeted entries.
#[derive(Debug, Clone)]
pub struct HostsFile {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HostsRecord {
    /// Line index of this record
    pub line_idx: usize,
    /// The full raw line
    pub raw: String,
    /// Parsed IP address
    pub ip: String,
    /// Parsed hostnames (first is the canonical name)
    pub hostnames: Vec<String>,
    /// Inline comment (without # prefix)
    pub comment: Option<String>,
}

impl HostsFile {
    pub fn parse(text: &str) -> Self {
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        if text.ends_with('\n') && !text.is_empty() {
            lines.push(String::new());
        }
        HostsFile { lines }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() || self.lines.iter().all(|l| l.trim().is_empty())
    }

    /// Parse a single hosts line into its components.
    fn parse_record(line: &str) -> Option<(String, Vec<String>, Option<String>)> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // Split off inline comment
        let (data, comment) = match trimmed.find('#') {
            Some(pos) => (&trimmed[..pos], Some(trimmed[pos + 1..].trim().to_string())),
            None => (trimmed, None),
        };

        let data = data.trim();
        if data.is_empty() {
            return None;
        }

        let mut parts = data.split_whitespace();
        let ip = match parts.next() {
            Some(ip) => ip.to_string(),
            None => return None,
        };
        let hostnames: Vec<String> = parts.map(|s| s.to_string()).collect();
        if hostnames.is_empty() {
            return None;
        }

        Some((ip, hostnames, comment))
    }

    /// Return all parsed records.
    pub fn records(&self) -> Vec<HostsRecord> {
        let mut out = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            if let Some((ip, hostnames, comment)) = Self::parse_record(line) {
                out.push(HostsRecord {
                    line_idx: i,
                    raw: line.clone(),
                    ip,
                    hostnames,
                    comment,
                });
            }
        }
        out
    }

    /// Find records where any hostname matches `name` exactly or as a suffix.
    /// Returns all matching record indices.
    pub fn find(&self, name: &str) -> Vec<usize> {
        let records = self.records();
        records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.hostnames.iter().any(|h| h == name))
            .map(|(i, _)| i)
            .collect()
    }

    /// Add a new hosts entry. Appends at the end of the file.
    /// Returns the line index where the record was inserted.
    pub fn add(&mut self, ip: &str, hostnames: &[String]) -> usize {
        if !self.lines.is_empty() && !self.lines.last().unwrap().is_empty() {
            self.lines.push(String::new());
        }
        let line = format!("{}\t{}", ip, hostnames.join(" "));
        self.lines.push(line);
        self.lines.len() - 1
    }

    /// Update the IP of the record at `record_idx` (index from `records()`).
    pub fn set_ip(&mut self, record_idx: usize, new_ip: &str) -> Result<(), String> {
        let records = self.records();
        let record = records
            .get(record_idx)
            .ok_or_else(|| format!("Record index {} out of range", record_idx))?;

        let line_idx = record.line_idx;
        let indent: String = self.lines[line_idx]
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
        let hostnames_str = record.hostnames.join(" ");
        let comment_str = record
            .comment
            .as_ref()
            .map(|c| format!(" #{}", c))
            .unwrap_or_default();
        self.lines[line_idx] = format!("{}{}\t{}{}", indent, new_ip, hostnames_str, comment_str);
        Ok(())
    }

    /// Add a hostname to an existing record.
    pub fn add_hostname(&mut self, record_idx: usize, hostname: &str) -> Result<(), String> {
        let records = self.records();
        let record = records
            .get(record_idx)
            .ok_or_else(|| format!("Record index {} out of range", record_idx))?;

        let line_idx = record.line_idx;
        let indent: String = self.lines[line_idx]
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
        let mut all_hostnames = record.hostnames.clone();
        if !all_hostnames.contains(&hostname.to_string()) {
            all_hostnames.push(hostname.to_string());
        }
        let hostnames_str = all_hostnames.join(" ");
        let comment_str = record
            .comment
            .as_ref()
            .map(|c| format!(" #{}", c))
            .unwrap_or_default();
        self.lines[line_idx] = format!("{}{}\t{}{}", indent, record.ip, hostnames_str, comment_str);
        Ok(())
    }

    /// Remove a hostname from a record. If it's the last hostname, remove the entire record.
    pub fn remove_hostname(&mut self, record_idx: usize, hostname: &str) -> Result<(), String> {
        let records = self.records();
        let record = records
            .get(record_idx)
            .ok_or_else(|| format!("Record index {} out of range", record_idx))?;

        if record.hostnames.len() <= 1 {
            // Remove the entire record
            self.lines.remove(record.line_idx);
            return Ok(());
        }

        let line_idx = record.line_idx;
        let indent: String = self.lines[line_idx]
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
        let remaining: Vec<&str> = record
            .hostnames
            .iter()
            .filter(|h| *h != hostname)
            .map(|s| s.as_str())
            .collect();
        if remaining.len() == record.hostnames.len() {
            return Err(format!("Hostname '{}' not found", hostname));
        }
        let hostnames_str = remaining.join(" ");
        let comment_str = record
            .comment
            .as_ref()
            .map(|c| format!(" #{}", c))
            .unwrap_or_default();
        self.lines[line_idx] = format!("{}{}\t{}{}", indent, record.ip, hostnames_str, comment_str);
        Ok(())
    }

    /// Remove the record at `record_idx` (index from `records()`).
    pub fn remove(&mut self, record_idx: usize) -> Result<(), String> {
        let records = self.records();
        let record = records
            .get(record_idx)
            .ok_or_else(|| format!("Record index {} out of range", record_idx))?;
        self.lines.remove(record.line_idx);
        Ok(())
    }

    /// Validate the hosts file.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if Self::parse_record(line).is_none() {
                errors.push(format!("Line {}: could not parse: {}", i + 1, line));
            }
        }
        errors
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

impl Display for HostsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_file() {
        let hf = HostsFile::parse("");
        assert!(hf.is_empty());
        assert_eq!(hf.records().len(), 0);
    }

    #[test]
    fn test_single_entry() {
        let content = "127.0.0.1\tlocalhost\n";
        let hf = HostsFile::parse(content);
        let records = hf.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, "127.0.0.1");
        assert_eq!(records[0].hostnames, vec!["localhost"]);
    }

    #[test]
    fn test_multiple_hostnames() {
        let content = "192.168.1.1\tnas home-server\n";
        let hf = HostsFile::parse(content);
        let records = hf.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, "192.168.1.1");
        assert_eq!(records[0].hostnames, vec!["nas", "home-server"]);
    }

    #[test]
    fn test_comment_line() {
        let content = "# this is a comment\n127.0.0.1\tlocalhost\n";
        let hf = HostsFile::parse(content);
        assert_eq!(hf.records().len(), 1);
    }

    #[test]
    fn test_inline_comment() {
        let content = "192.168.1.1\tnas  # My NAS\n";
        let hf = HostsFile::parse(content);
        let records = hf.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].comment.as_deref(), Some("My NAS"));
    }

    #[test]
    fn test_find_by_hostname() {
        let content = "127.0.0.1\tlocalhost\n192.168.1.1\tnas\n";
        let hf = HostsFile::parse(content);
        let indices = hf.find("nas");
        assert_eq!(indices.len(), 1);
        assert_eq!(hf.records()[indices[0]].ip, "192.168.1.1");
    }

    #[test]
    fn test_find_not_found() {
        let content = "127.0.0.1\tlocalhost\n";
        let hf = HostsFile::parse(content);
        assert!(hf.find("nonexistent").is_empty());
    }

    #[test]
    fn test_add_record() {
        let mut hf = HostsFile::parse("127.0.0.1\tlocalhost\n");
        hf.add(
            "192.168.1.1",
            &["nas".to_string(), "home-server".to_string()],
        );
        let records = hf.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].ip, "192.168.1.1");
        assert_eq!(records[1].hostnames, vec!["nas", "home-server"]);
    }

    #[test]
    fn test_remove_record() {
        let mut hf = HostsFile::parse("127.0.0.1\tlocalhost\n192.168.1.1\tnas\n");
        hf.remove(1).unwrap();
        assert_eq!(hf.records().len(), 1);
        assert_eq!(hf.records()[0].ip, "127.0.0.1");
    }

    #[test]
    fn test_set_ip() {
        let mut hf = HostsFile::parse("127.0.0.1\tlocalhost\n");
        hf.set_ip(0, "127.0.1.1").unwrap();
        assert_eq!(hf.records()[0].ip, "127.0.1.1");
    }

    #[test]
    fn test_add_hostname() {
        let mut hf = HostsFile::parse("127.0.0.1\tlocalhost\n");
        hf.add_hostname(0, "myhost").unwrap();
        let records = hf.records();
        assert!(records[0].hostnames.contains(&"myhost".to_string()));
    }

    #[test]
    fn test_remove_hostname_keeps_record() {
        let mut hf = HostsFile::parse("192.168.1.1\tnas home-server\n");
        hf.remove_hostname(0, "home-server").unwrap();
        let records = hf.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].hostnames, vec!["nas"]);
    }

    #[test]
    fn test_remove_last_hostname_removes_record() {
        let mut hf = HostsFile::parse("192.168.1.1\tnas\n");
        hf.remove_hostname(0, "nas").unwrap();
        assert!(hf.records().is_empty());
    }

    #[test]
    fn test_validate_valid() {
        let content = "127.0.0.1\tlocalhost\n192.168.1.1\tnas\n";
        let hf = HostsFile::parse(content);
        assert!(hf.validate().is_empty());
    }

    #[test]
    fn test_validate_invalid() {
        let content = "127.0.0.1\tlocalhost\ninvalid_line_without_ip\n";
        let hf = HostsFile::parse(content);
        let errors = hf.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_trailing_newline_preservation() {
        let content = "127.0.0.1\tlocalhost\n";
        let hf = HostsFile::parse(content);
        assert_eq!(hf.to_string(), content);
    }

    #[test]
    fn test_no_trailing_newline() {
        let content = "127.0.0.1\tlocalhost";
        let hf = HostsFile::parse(content);
        assert_eq!(hf.to_string(), content);
    }

    #[test]
    fn test_blank_lines_preserved() {
        let content = "127.0.0.1\tlocalhost\n\n192.168.1.1\tnas\n";
        let hf = HostsFile::parse(content);
        assert_eq!(hf.to_string(), content);
    }

    #[test]
    fn test_ipv6() {
        let content = "::1\tlocalhost ip6-localhost\n";
        let hf = HostsFile::parse(content);
        let records = hf.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, "::1");
    }

    #[test]
    fn test_multiple_blank_lines_between() {
        let content = "127.0.0.1\tlocalhost\n\n\n192.168.1.1\tnas\n";
        let hf = HostsFile::parse(content);
        assert_eq!(hf.records().len(), 2);
        assert_eq!(hf.to_string(), content);
    }

    #[test]
    fn test_empty_hosts_file_with_comments() {
        let content = "#\n# Hosts file\n#\n";
        let hf = HostsFile::parse(content);
        assert!(hf.records().is_empty());
        assert_eq!(hf.to_string(), content);
    }

    #[test]
    fn test_tab_separator_preserved() {
        let content = "127.0.0.1\tlocalhost\n";
        let mut hf = HostsFile::parse(content);
        hf.set_ip(0, "127.0.0.2").unwrap();
        // The tab separator should be preserved
        assert!(hf.to_string().contains("127.0.0.2\tlocalhost"));
    }

    #[test]
    fn test_add_does_not_duplicate() {
        let mut hf = HostsFile::parse("127.0.0.1\tlocalhost\n");
        hf.add_hostname(0, "localhost").unwrap(); // already exists
        let records = hf.records();
        assert_eq!(records[0].hostnames, vec!["localhost"]);
    }
}

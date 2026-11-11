use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSection {
    Questions,
    Answers,
    Any,
}

impl Default for RuleSection {
    fn default() -> Self {
        RuleSection::Any
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum StringOrList {
    String(String),
    List(Vec<String>),
}

impl Default for StringOrList {
    fn default() -> Self {
        StringOrList::String("*".to_string())
    }
}

impl StringOrList {
    pub fn normalized(&self) -> Self {
        match self {
            StringOrList::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() || trimmed == "*" {
                    StringOrList::String("*".to_string())
                } else {
                    StringOrList::String(trimmed.to_string())
                }
            }
            StringOrList::List(list) => {
                let mut cleaned = Vec::new();
                for item in list {
                    let trimmed = item.trim();
                    if trimmed == "*" {
                        return StringOrList::String("*".to_string());
                    }
                    if !trimmed.is_empty() && !cleaned.iter().any(|x: &String| x == trimmed) {
                        cleaned.push(trimmed.to_string());
                    }
                }
                if cleaned.is_empty() {
                    StringOrList::String("*".to_string())
                } else if cleaned.len() == 1 {
                    StringOrList::String(cleaned.into_iter().next().unwrap())
                } else {
                    StringOrList::List(cleaned)
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FilterRuleConfig {
    pub action: String, // "forward" or "drop"
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub src: StringOrList,
    #[serde(default)]
    pub dst: StringOrList,
    #[serde(default)]
    pub section: RuleSection,
}

#[derive(Debug, Clone)]
pub struct FilterRule {
    pub action: bool,
    pub services: Vec<Regex>,
    pub hosts: Vec<Regex>,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub src_any: bool,
    pub dst_any: bool,
    pub section: RuleSection,
}

fn fnmatch_to_regex(pattern: &str) -> Regex {
    let mut regex_pattern = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => regex_pattern.push_str(".*"),
            '?' => regex_pattern.push('.'),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '[' | ']' | '{' | '}' | '\\' => {
                regex_pattern.push('\\');
                regex_pattern.push(c);
            }
            _ => regex_pattern.push(c),
        }
    }
    regex_pattern.push('$');
    Regex::new(&regex_pattern).unwrap()
}

impl FilterRule {
    pub fn from_config(cfg: &FilterRuleConfig) -> Self {
        let services = cfg.services.iter()
            .map(|s| s.trim_end_matches('.').to_lowercase())
            .map(|s| fnmatch_to_regex(&s))
            .collect();
            
        let hosts = cfg.hosts.iter()
            .map(|s| s.trim_end_matches('.').to_lowercase())
            .map(|s| fnmatch_to_regex(&s))
            .collect();

        let (src, src_any) = match &cfg.src {
            StringOrList::String(s) => {
                if s == "*" {
                    (vec![], true)
                } else {
                    (vec![s.clone()], false)
                }
            }
            StringOrList::List(l) => {
                let mut v = Vec::new();
                let mut any = false;
                for s in l {
                    if s == "*" {
                        any = true;
                    } else {
                        v.push(s.clone());
                    }
                }
                (v, any)
            }
        };

        let (dst, dst_any) = match &cfg.dst {
            StringOrList::String(s) => {
                if s == "*" {
                    (vec![], true)
                } else {
                    (vec![s.clone()], false)
                }
            }
            StringOrList::List(l) => {
                let mut v = Vec::new();
                let mut any = false;
                for s in l {
                    if s == "*" {
                        any = true;
                    } else {
                        v.push(s.clone());
                    }
                }
                (v, any)
            }
        };

        Self {
            action: cfg.action == "forward",
            services,
            hosts,
            src,
            dst,
            src_any,
            dst_any,
            section: cfg.section,
        }
    }

    pub fn applies_to(&self, src_interface: &str, dst_interface: &str) -> bool {
        let src_match = self.src_any || self.src.iter().any(|s| s == src_interface);
        let dst_match = self.dst_any || self.dst.iter().any(|s| s == dst_interface);
        src_match && dst_match
    }

    pub fn matches_packet(&self, question_names: &HashSet<String>, answer_names: &HashSet<String>) -> bool {
        let target_names = match self.section {
            RuleSection::Questions => question_names,
            RuleSection::Answers => answer_names,
            RuleSection::Any => return self.matches_packet_iter(question_names.iter().chain(answer_names.iter())),
        };
        self.matches_packet_iter(target_names.iter())
    }

    fn matches_packet_iter<'a>(&self, iter: impl Iterator<Item = &'a String>) -> bool {
        if self.services.is_empty() && self.hosts.is_empty() {
            let mut has_items = false;
            for _ in iter {
                has_items = true;
                break;
            }
            return has_items;
        }

        for name in iter {
            let clean_name = name.trim_end_matches('.').to_lowercase();
            
            for pat in &self.services {
                if pat.is_match(&clean_name) {
                    return true;
                }
            }
            
            for pat in &self.hosts {
                if pat.is_match(&clean_name) {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TrackingConfig {
    pub enabled: bool,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_db_path")]
    pub db_path: String,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_seconds: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_retention_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_history_records: Option<usize>,
}

impl TrackingConfig {
    pub fn effective_retention_days(&self) -> u32 {
        self.history_retention_days.unwrap_or(self.retention_days)
    }

    pub fn effective_max_records(&self) -> usize {
        self.max_history_records.unwrap_or(self.max_records)
    }
}

fn default_db_path() -> String { "/var/lib/mdns-sieve/responses.db".to_string() }
fn default_flush_interval() -> u64 { 3600 }
fn default_retention_days() -> u32 { 7 }
fn default_max_records() -> usize { 50000 }

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SystemInterfaceInfo {
    pub name: String,
    pub operstate: String,
}

pub fn discover_system_interfaces() -> Vec<SystemInterfaceInfo> {
    discover_system_interfaces_from_dir(Path::new("/sys/class/net"))
}

pub fn discover_system_interfaces_from_dir(net_dir: &Path) -> Vec<SystemInterfaceInfo> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(net_dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" || name.starts_with('.') {
            continue;
        }
        let operstate_path = entry.path().join("operstate");
        let operstate = fs::read_to_string(operstate_path)
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_else(|_| "unknown".to_string());
        results.push(SystemInterfaceInfo { name, operstate });
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    results
}

fn is_valid_interface_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return false;
    }
    !trimmed.chars().any(|c| c.is_whitespace() || c == '/' || c == '\\' || c == '\0')
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AppConfigData {
    #[serde(default)]
    pub interfaces: Vec<String>,
    pub default_action: String,
    #[serde(default)]
    pub rewrite_mixed_packets: bool,
    #[serde(default)]
    pub forward_known_answers: bool,
    pub web_server: Option<WebServerConfig>,
    pub tracking: Option<TrackingConfig>,
    #[serde(default)]
    pub rules: Vec<FilterRuleConfig>,
}

impl AppConfigData {
    pub fn from_yaml_str(content: &str) -> Result<Self, String> {
        let mut data: AppConfigData = serde_yaml::from_str(content)
            .map_err(|e| format!("Invalid YAML configuration: {}", e))?;
        data.normalize();
        data.validate()?;
        Ok(data)
    }

    pub fn normalize(&mut self) {
        self.default_action = self.default_action.trim().to_lowercase();

        let mut clean_ifaces = Vec::new();
        for iface in &self.interfaces {
            let trimmed = iface.trim();
            if !trimmed.is_empty() && !clean_ifaces.iter().any(|x: &String| x == trimmed) {
                clean_ifaces.push(trimmed.to_string());
            }
        }
        self.interfaces = clean_ifaces;

        if let Some(ref mut ws) = self.web_server {
            ws.host = ws.host.trim().to_string();
        }

        if let Some(ref mut tc) = self.tracking {
            tc.db_path = tc.db_path.trim().to_string();
            if tc.db_path.is_empty() {
                tc.db_path = default_db_path();
            }
            if let Some(days) = tc.history_retention_days.take() {
                tc.retention_days = days;
            }
            if let Some(max_rec) = tc.max_history_records.take() {
                tc.max_records = max_rec;
            }
        }

        for rule in &mut self.rules {
            rule.action = rule.action.trim().to_lowercase();
            rule.src = rule.src.normalized();
            rule.dst = rule.dst.normalized();
            rule.services = rule.services.iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            rule.hosts = rule.hosts.iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.default_action != "forward" && self.default_action != "drop" {
            return Err(format!(
                "default_action must be 'forward' or 'drop', got '{}'",
                self.default_action
            ));
        }

        for iface in &self.interfaces {
            if !is_valid_interface_name(iface) {
                return Err(format!("Invalid network interface name: '{}'", iface));
            }
        }

        if let Some(ref ws) = self.web_server {
            if ws.host.trim().is_empty() {
                return Err("web_server.host cannot be empty".to_string());
            }
            if ws.port == 0 {
                return Err("web_server.port must be between 1 and 65535".to_string());
            }
        }

        if let Some(ref tc) = self.tracking {
            if tc.db_path.trim().is_empty() {
                return Err("tracking.db_path cannot be empty".to_string());
            }
            if tc.flush_interval_seconds == 0 {
                return Err("tracking.flush_interval_seconds must be at least 1".to_string());
            }
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            let rule_num = idx + 1;
            if rule.action != "forward" && rule.action != "drop" {
                return Err(format!(
                    "Rule #{}: action must be 'forward' or 'drop', got '{}'",
                    rule_num, rule.action
                ));
            }
            let validate_target = |target: &StringOrList, label: &str| -> Result<(), String> {
                match target {
                    StringOrList::String(s) => {
                        if s != "*" && !is_valid_interface_name(s) {
                            return Err(format!("Rule #{}: invalid {} interface '{}'", rule_num, label, s));
                        }
                    }
                    StringOrList::List(list) => {
                        if list.is_empty() {
                            return Err(format!("Rule #{}: {} interface list cannot be empty", rule_num, label));
                        }
                        for s in list {
                            if s != "*" && !is_valid_interface_name(s) {
                                return Err(format!("Rule #{}: invalid {} interface '{}'", rule_num, label, s));
                            }
                        }
                    }
                }
                Ok(())
            };
            validate_target(&rule.src, "src")?;
            validate_target(&rule.dst, "dst")?;
        }

        Ok(())
    }

    pub fn to_commented_yaml(&self) -> Result<String, String> {
        let mut normalized = self.clone();
        normalized.normalize();
        normalized.validate()?;

        let mut out = String::new();
        out.push_str("# mdns-sieve Configuration File\n");
        out.push_str("# This file defines how mDNS packets are filtered and routed between interfaces.\n\n");

        out.push_str("# List of physical or virtual network interfaces available on the system.\n");
        let ifaces_yaml = serde_yaml::to_string(&serde_json::json!({ "interfaces": normalized.interfaces }))
            .map_err(|e| e.to_string())?;
        out.push_str(&ifaces_yaml);
        out.push('\n');

        out.push_str("# The default action to take if no rules match a packet (\"forward\" or \"drop\").\n");
        let default_action_yaml = serde_yaml::to_string(&serde_json::json!({ "default_action": normalized.default_action }))
            .map_err(|e| e.to_string())?;
        out.push_str(&default_action_yaml);
        out.push('\n');

        out.push_str("# Whether to rewrite packets that contain both questions and answers (default: false).\n");
        let rewrite_yaml = serde_yaml::to_string(&serde_json::json!({ "rewrite_mixed_packets": normalized.rewrite_mixed_packets }))
            .map_err(|e| e.to_string())?;
        out.push_str(&rewrite_yaml);
        out.push('\n');

        out.push_str("# Whether to forward known-answers in query packets.\n");
        let known_ans_yaml = serde_yaml::to_string(&serde_json::json!({ "forward_known_answers": normalized.forward_known_answers }))
            .map_err(|e| e.to_string())?;
        out.push_str(&known_ans_yaml);
        out.push('\n');

        if let Some(ref ws) = normalized.web_server {
            out.push_str("# Configuration for the internal HTTP API and Web Dashboard server.\n");
            let ws_yaml = serde_yaml::to_string(&serde_json::json!({ "web_server": ws }))
                .map_err(|e| e.to_string())?;
            out.push_str(&ws_yaml);
            out.push('\n');
        }

        if let Some(ref tc) = normalized.tracking {
            out.push_str("# Configuration for tracking mDNS message history in a local SQLite database.\n");
            let tc_yaml = serde_yaml::to_string(&serde_json::json!({ "tracking": tc }))
                .map_err(|e| e.to_string())?;
            out.push_str(&tc_yaml);
            out.push('\n');
        }

        out.push_str("# Filtering rules are processed in order; the first matching rule wins.\n");
        let rules_yaml = serde_yaml::to_string(&serde_json::json!({ "rules": normalized.rules }))
            .map_err(|e| e.to_string())?;
        out.push_str(&rules_yaml);

        Ok(out)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<String, String> {
        let path_ref = path.as_ref();
        let yaml_content = self.to_commented_yaml()?;

        // Verify the generated YAML parses cleanly back into AppConfigData
        let _: AppConfigData = serde_yaml::from_str(&yaml_content)
            .map_err(|e| format!("Failed round-trip validation of generated YAML: {}", e))?;

        if let Some(parent) = path_ref.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create config directory {}: {}", parent.display(), e))?;
            }
        }

        // Create backup (.bak) if original file exists
        if path_ref.exists() {
            let bak_path = path_ref.with_extension(
                path_ref
                    .extension()
                    .map(|ext| format!("{}.bak", ext.to_string_lossy()))
                    .unwrap_or_else(|| "bak".to_string()),
            );
            fs::copy(path_ref, &bak_path).map_err(|e| {
                format!(
                    "Failed to create backup file {}: {}",
                    bak_path.display(),
                    e
                )
            })?;
        }

        let tmp_path = path_ref.with_extension(
            path_ref
                .extension()
                .map(|ext| format!("{}.tmp", ext.to_string_lossy()))
                .unwrap_or_else(|| "tmp".to_string()),
        );

        fs::write(&tmp_path, &yaml_content).map_err(|e| {
            format!(
                "Failed to write temporary config file {}: {}",
                tmp_path.display(),
                e
            )
        })?;

        if let Err(e) = fs::rename(&tmp_path, path_ref) {
            // Fallback if rename fails across mount points
            fs::copy(&tmp_path, path_ref).map_err(|copy_err| {
                format!(
                    "Failed to atomically replace config file {} ({}): {}",
                    path_ref.display(),
                    e,
                    copy_err
                )
            })?;
            let _ = fs::remove_file(&tmp_path);
        }

        Ok(yaml_content)
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub interfaces: Vec<String>,
    pub default_action_is_forward: bool,
    pub rewrite_mixed_packets: bool,
    pub forward_known_answers: bool,
    pub web_server: Option<WebServerConfig>,
    pub tracking: Option<TrackingConfig>,
    pub rules: Vec<FilterRule>,
}

impl AppConfig {
    pub fn from_data(cfg_data: &AppConfigData) -> Self {
        let rules = cfg_data.rules.iter().map(FilterRule::from_config).collect();

        Self {
            interfaces: cfg_data.interfaces.clone(),
            default_action_is_forward: cfg_data.default_action == "forward",
            rewrite_mixed_packets: cfg_data.rewrite_mixed_packets,
            forward_known_answers: cfg_data.forward_known_answers,
            web_server: cfg_data.web_server.clone(),
            tracking: cfg_data.tracking.clone(),
            rules,
        }
    }

    pub fn load_from_file_with_data<P: AsRef<Path>>(path: P) -> Result<(Self, AppConfigData), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut cfg_data: AppConfigData = serde_yaml::from_str(&content)?;
        cfg_data.normalize();
        let app_cfg = Self::from_data(&cfg_data);
        Ok((app_cfg, cfg_data))
    }

    #[allow(dead_code)]
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let (app_cfg, _) = Self::load_from_file_with_data(path)?;
        Ok(app_cfg)
    }

    pub fn should_forward(
        &self,
        src_interface: &str,
        dst_interface: &str,
        question_names: &HashSet<String>,
        answer_names: Option<&HashSet<String>>,
    ) -> bool {
        let ans_names = answer_names.unwrap_or(question_names);

        for rule in &self.rules {
            if rule.applies_to(src_interface, dst_interface) {
                if rule.matches_packet(question_names, ans_names) {
                    return rule.action;
                }
            }
        }

        self.default_action_is_forward
    }

    pub fn should_forward_question(&self, src_interface: &str, dst_interface: &str, name: &str) -> bool {
        let mut q_names = HashSet::new();
        q_names.insert(name.to_string());
        let a_names = HashSet::new();

        for rule in &self.rules {
            if rule.applies_to(src_interface, dst_interface) && rule.matches_packet(&q_names, &a_names) {
                return rule.action;
            }
        }
        self.default_action_is_forward
    }

    pub fn should_forward_record(
        &self,
        src_interface: &str,
        dst_interface: &str,
        name: &str,
        target_name: Option<&str>,
        is_response: bool,
    ) -> bool {
        let mut names = HashSet::new();
        names.insert(name.to_string());
        if let Some(t) = target_name {
            names.insert(t.to_string());
        }

        if !is_response {
            if self.forward_known_answers {
                return true;
            }
            
            let empty_set = HashSet::new();
            for rule in &self.rules {
                if rule.applies_to(dst_interface, src_interface) && 
                   (rule.section == RuleSection::Answers || rule.section == RuleSection::Any) &&
                   rule.matches_packet(&empty_set, &names) {
                    return rule.action;
                }
                
                if rule.applies_to(src_interface, dst_interface) && 
                   (rule.section == RuleSection::Answers || rule.section == RuleSection::Any) &&
                   rule.matches_packet(&empty_set, &names) {
                    return rule.action;
                }
            }
            
            return false; // Drop if no rules match known answers
        }

        let empty_set = HashSet::new();
        for rule in &self.rules {
            if rule.applies_to(src_interface, dst_interface) && rule.matches_packet(&empty_set, &names) {
                return rule.action;
            }
        }

        self.default_action_is_forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_config_data() -> AppConfigData {
        AppConfigData {
            interfaces: vec!["eth0".to_string(), "wlan0".to_string()],
            default_action: "forward".to_string(),
            rewrite_mixed_packets: true,
            forward_known_answers: false,
            web_server: Some(WebServerConfig {
                enabled: true,
                host: "0.0.0.0".to_string(),
                port: 8080,
            }),
            tracking: Some(TrackingConfig {
                enabled: true,
                max_records: 50000,
                db_path: "/var/lib/mdns-sieve/responses.db".to_string(),
                flush_interval_seconds: 3600,
                retention_days: 7,
                history_retention_days: None,
                max_history_records: None,
            }),
            rules: vec![FilterRuleConfig {
                action: "drop".to_string(),
                services: vec!["_googlecast._tcp.local".to_string()],
                hosts: vec!["printer.local".to_string()],
                src: StringOrList::String("wlan0".to_string()),
                dst: StringOrList::String("*".to_string()),
                section: RuleSection::Answers,
            }],
        }
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = sample_config_data();
        assert!(cfg.validate().is_ok());

        cfg.default_action = "invalid".to_string();
        assert!(cfg.validate().is_err());

        cfg.default_action = "drop".to_string();
        cfg.rules[0].action = "allow".to_string();
        assert!(cfg.validate().is_err());

        cfg.rules[0].action = "forward".to_string();
        cfg.interfaces.push("bad/iface".to_string());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_atomic_save_and_backup() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("mdns_sieve_cfg_{}.yaml", nanos));
        let bak_path = path.with_extension("yaml.bak");

        let mut cfg = sample_config_data();
        let yaml1 = cfg.save_to_file(&path).expect("First save should succeed");
        assert!(path.exists());
        assert!(!bak_path.exists());
        assert!(yaml1.contains("# mdns-sieve Configuration File"));

        // Modify and save again -> .bak should be created with previous contents
        cfg.default_action = "drop".to_string();
        cfg.rules.push(FilterRuleConfig {
            action: "forward".to_string(),
            services: vec!["*.local".to_string()],
            hosts: vec![],
            src: StringOrList::List(vec!["eth0".to_string(), "wlan0".to_string()]),
            dst: StringOrList::String("*".to_string()),
            section: RuleSection::Questions,
        });
        let _yaml2 = cfg.save_to_file(&path).expect("Second save should succeed");
        assert!(bak_path.exists());
        let bak_content = fs::read_to_string(&bak_path).unwrap();
        assert_eq!(bak_content, yaml1);

        let (_, loaded_data) = AppConfig::load_from_file_with_data(&path).expect("Should reload cleanly");
        assert_eq!(loaded_data, cfg);
        let loaded_app_cfg = AppConfig::load_from_file(&path).expect("load_from_file should succeed");
        assert_eq!(loaded_app_cfg.rules.len(), 2);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak_path);
    }

    #[test]
    fn test_discover_system_interfaces_from_dir() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("mdns_sieve_net_{}", nanos));
        fs::create_dir_all(dir.join("lo")).unwrap();
        fs::create_dir_all(dir.join("eth0")).unwrap();
        fs::create_dir_all(dir.join("wlan0")).unwrap();
        fs::write(dir.join("eth0").join("operstate"), "up\n").unwrap();
        fs::write(dir.join("wlan0").join("operstate"), "down\n").unwrap();

        let discovered = discover_system_interfaces_from_dir(&dir);
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].name, "eth0");
        assert_eq!(discovered[0].operstate, "up");
        assert_eq!(discovered[1].name, "wlan0");
        assert_eq!(discovered[1].operstate, "down");

        let _ = fs::remove_dir_all(&dir);
    }
}

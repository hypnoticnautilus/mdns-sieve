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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrackingConfig {
    pub enabled: bool,
    pub max_records: usize,
    #[serde(default = "default_db_path")]
    pub db_path: String,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_seconds: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_db_path() -> String { "/var/lib/mdns-sieve/responses.db".to_string() }
fn default_flush_interval() -> u64 { 3600 }
fn default_retention_days() -> u32 { 7 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfigData {
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
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let cfg_data: AppConfigData = serde_yaml::from_str(&content)?;
        
        let rules = cfg_data.rules.iter().map(FilterRule::from_config).collect();
        
        Ok(Self {
            interfaces: cfg_data.interfaces,
            default_action_is_forward: cfg_data.default_action == "forward",
            rewrite_mixed_packets: cfg_data.rewrite_mixed_packets,
            forward_known_answers: cfg_data.forward_known_answers,
            web_server: cfg_data.web_server,
            tracking: cfg_data.tracking,
            rules,
        })
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

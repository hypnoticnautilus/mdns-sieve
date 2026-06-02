"""
Configuration Engine

Loads, validates, and manages YAML-based filtering configurations and
matches incoming packet metadata against defined interface routing and wildcard rules.
"""

from dataclasses import dataclass, field
from enum import Enum
import fnmatch
from typing import Any, Dict, List, Optional, Set
import yaml


class RuleSection(str, Enum):
    """Enumeration of packet sections that filtering rules can target."""

    QUESTIONS = "questions"
    ANSWERS = "answers"
    ANY = "any"


class ConfigurationError(ValueError):
    """Raised when the configuration is invalid or missing required values."""


@dataclass
class FilterRule:
    """Represents a specific filtering and routing rule."""

    action: bool  # True to allow/forward matching packets, False to deny/block
    services: List[str] = field(
        default_factory=list
    )  # List of service type wildcard patterns to match
    hosts: List[str] = field(default_factory=list)  # List of hostname wildcard patterns to match
    src: str = "*"  # Source physical interface name or "*" to match any source interface
    dst: str = "*"  # Destination physical interface name or "*" to match any destination interface
    section: RuleSection = RuleSection.ANY  # Targets questions, answers, or any packet section

    def __post_init__(self) -> None:
        """Cleans and canonicalizes match patterns ahead of time for high performance."""
        self.services = [s.rstrip(".").lower() for s in self.services]
        self.hosts = [h.rstrip(".").lower() for h in self.hosts]

    def applies_to(self, src_interface: str, dst_interface: str) -> bool:
        """Checks if this rule matches the source and destination routing path."""
        src_match = self.src in ("*", src_interface)
        dst_match = self.dst in ("*", dst_interface)
        return src_match and dst_match

    def matches_packet(self, question_names: Set[str], answer_names: Set[str]) -> bool:
        """
        Checks if this rule matches any service types or hostnames in the packet
        based on the rule's target section.
        """
        if self.section == RuleSection.QUESTIONS:
            target_names = question_names
        elif self.section == RuleSection.ANSWERS:
            target_names = answer_names
        else:  # RuleSection.ANY
            target_names = question_names | answer_names

        if not self.services and not self.hosts:
            return bool(target_names)

        for name in target_names:
            # Canonicalize name by stripping trailing dots and checking case-insensitively
            clean_name = name.rstrip(".").lower()

            if self.services:
                for clean_pattern in self.services:
                    if fnmatch.fnmatchcase(clean_name, clean_pattern):
                        return True

            if self.hosts:
                for clean_pattern in self.hosts:
                    if fnmatch.fnmatchcase(clean_name, clean_pattern):
                        return True

        return False


@dataclass
class AppConfig:
    """Represents the global application configuration."""

    interfaces: List[str]
    default_action: str  # "allow" or "deny"
    rules: List[FilterRule] = field(default_factory=list)

    def should_forward(
        self,
        src_interface: str,
        dst_interface: str,
        question_names: Set[str],
        answer_names: Optional[Set[str]] = None,
    ) -> bool:
        """
        Evaluates the rules list in order (first match wins) to determine
        if a packet should be forwarded from src_interface to dst_interface.
        Falls back to default_action if no rules match. Supports backward compatibility
        if only a single set of names is passed.
        """
        if answer_names is None:
            q_names = question_names
            a_names = question_names
        else:
            q_names = question_names
            a_names = answer_names

        for rule in self.rules:
            if rule.applies_to(src_interface, dst_interface):
                if rule.matches_packet(q_names, a_names):
                    return rule.action

        return self.default_action == "allow"


def _parse_rule(idx: int, r: Dict[str, Any], interfaces: List[str]) -> FilterRule:
    """
    Parses and validates a single filtering rule dictionary.
    Raises ConfigurationError if the rule structure is invalid.
    """
    if not isinstance(r, dict):
        raise ConfigurationError(f"Rule at index {idx} must be a dictionary")

    action = r.get("action")
    if action not in ("allow", "deny"):
        raise ConfigurationError(
            f"Rule {idx} missing or invalid 'action' (must be 'allow' or 'deny')"
        )

    src = r.get("src", "*")
    dst = r.get("dst", "*")

    # Typos in interfaces check
    if src != "*" and src not in interfaces:
        raise ConfigurationError(
            f"Rule {idx} source interface '{src}' not listed in global interfaces"
        )
    if dst != "*" and dst not in interfaces:
        raise ConfigurationError(
            f"Rule {idx} destination interface '{dst}' not listed in global interfaces"
        )

    services = r.get("services", [])
    if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
        raise ConfigurationError(f"Rule {idx} 'services' must be a list of strings")

    hosts = r.get("hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        raise ConfigurationError(f"Rule {idx} 'hosts' must be a list of strings")

    section_str = r.get("section", "any")
    try:
        section = RuleSection(section_str)
    except ValueError as e:
        raise ConfigurationError(
            f"Rule {idx} invalid 'section' '{section_str}' "
            "(must be 'questions', 'answers', or 'any')"
        ) from e

    is_allow = action == "allow"
    return FilterRule(
        action=is_allow,
        services=services,
        hosts=hosts,
        src=src,
        dst=dst,
        section=section,
    )


def load_config(config_path: str) -> AppConfig:
    """
    Parses and thoroughly validates a yaml configuration file.
    Raises ConfigurationError if the syntax or structure is incorrect.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found: {config_path}") from e
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML parsing failed: {str(e)}") from e

    if not isinstance(raw_data, dict):
        raise ConfigurationError("Configuration root must be a YAML dictionary")

    # Validate interfaces
    interfaces = raw_data.get("interfaces")
    if not interfaces:
        raise ConfigurationError("Missing or empty 'interfaces' list in configuration")
    if not isinstance(interfaces, list) or not all(isinstance(i, str) for i in interfaces):
        raise ConfigurationError("'interfaces' must be a list of strings")

    # Validate default action
    default_action = raw_data.get("default_action")
    if default_action not in ("allow", "deny"):
        raise ConfigurationError("'default_action' must be either 'allow' or 'deny'")

    # Validate and parse rules
    raw_rules = raw_data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ConfigurationError("'rules' must be a list of rule mappings")

    rules: List[FilterRule] = []
    for idx, r in enumerate(raw_rules):
        rules.append(_parse_rule(idx, r, interfaces))

    return AppConfig(interfaces=interfaces, default_action=default_action, rules=rules)

"""
Configuration Engine

Loads, validates, and manages YAML-based filtering configurations and
matches incoming packet metadata against defined interface routing and wildcard rules.
"""

from dataclasses import dataclass, field
from enum import Enum
import fnmatch
from typing import Any, Dict, List, Optional, Set, Union
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

    action: bool  # True to forward matching packets, False to drop/block
    services: List[str] = field(
        default_factory=list
    )  # List of service type wildcard patterns to match
    hosts: List[str] = field(default_factory=list)  # List of hostname wildcard patterns to match
    src: Union[str, List[str]] = "*"  # Source physical interface name, list, or "*"
    dst: Union[str, List[str]] = "*"  # Destination physical interface name, list, or "*"
    section: RuleSection = RuleSection.ANY  # Targets questions, answers, or any packet section

    def __post_init__(self) -> None:
        """Cleans and canonicalizes match patterns ahead of time for high performance."""
        self.services = [s.rstrip(".").lower() for s in self.services]
        self.hosts = [h.rstrip(".").lower() for h in self.hosts]

    def applies_to(self, src_interface: str, dst_interface: str) -> bool:
        """Checks if this rule matches the source and destination routing path."""
        if isinstance(self.src, str):
            src_match = self.src in ("*", src_interface)
        elif isinstance(self.src, (list, set)):
            src_match = "*" in self.src or src_interface in self.src
        else:
            src_match = False

        if isinstance(self.dst, str):
            dst_match = self.dst in ("*", dst_interface)
        elif isinstance(self.dst, (list, set)):
            dst_match = "*" in self.dst or dst_interface in self.dst
        else:
            dst_match = False

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
class CommandServerConfig:
    """Represents the configuration for the TCP command/statistics server."""

    enabled: bool
    host: str
    port: int


@dataclass
class TrackingConfig:
    """Represents the configuration for tracking host-specific history."""

    enabled: bool
    max_records: int
    db_path: str = "/var/lib/mdns-sieve/responses.db"
    flush_interval_seconds: int = 3600
    retention_days: int = 7


@dataclass
class AppConfig:
    """Represents the global application configuration."""

    interfaces: List[str]
    default_action: str  # "forward" or "drop"
    rewrite_mixed_packets: bool = False
    command_server: Optional[CommandServerConfig] = None
    tracking: Optional[TrackingConfig] = None
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

        return self.default_action == "forward"

    def should_forward_question(self, src_interface: str, dst_interface: str, name: str) -> bool:
        """Determines if a single question name should be forwarded."""
        for rule in self.rules:
            if rule.applies_to(src_interface, dst_interface):
                if rule.matches_packet({name}, set()):
                    return rule.action
        return self.default_action == "forward"

    def should_forward_record(
        self,
        src_interface: str,
        dst_interface: str,
        rr: Any,  # Avoid circular import issues or keep it generic
    ) -> bool:
        """Determines if a single resource record should be forwarded."""
        names = {rr.name}
        if rr.target_name:
            names.add(rr.target_name)

        for rule in self.rules:
            if rule.applies_to(src_interface, dst_interface):
                if rule.matches_packet(set(), names):
                    return rule.action
        return self.default_action == "forward"


# pylint: disable=too-many-locals,too-many-branches
def _parse_rule(idx: int, r: Dict[str, Any], interfaces: List[str]) -> FilterRule:
    """
    Parses and validates a single filtering rule dictionary.
    Raises ConfigurationError if the rule structure is invalid.
    """
    if not isinstance(r, dict):
        raise ConfigurationError(f"Rule at index {idx} must be a dictionary")

    action = r.get("action")
    if action not in ("forward", "drop"):
        raise ConfigurationError(
            f"Rule {idx} missing or invalid 'action' (must be 'forward' or 'drop')"
        )

    src = r.get("src", "*")
    if isinstance(src, str):
        src_list = [src]
    elif isinstance(src, list) and all(isinstance(s, str) for s in src):
        src_list = src
    else:
        raise ConfigurationError(f"Rule {idx} 'src' must be a string or a list of strings")

    for s in src_list:
        if s != "*" and s not in interfaces:
            raise ConfigurationError(
                f"Rule {idx} source interface '{s}' not listed in global interfaces"
            )

    dst = r.get("dst", "*")
    if isinstance(dst, str):
        dst_list = [dst]
    elif isinstance(dst, list) and all(isinstance(d, str) for d in dst):
        dst_list = dst
    else:
        raise ConfigurationError(f"Rule {idx} 'dst' must be a string or a list of strings")

    for d in dst_list:
        if d != "*" and d not in interfaces:
            raise ConfigurationError(
                f"Rule {idx} destination interface '{d}' not listed in global interfaces"
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

    is_forward = action == "forward"
    return FilterRule(
        action=is_forward,
        services=services,
        hosts=hosts,
        src=src,
        dst=dst,
        section=section,
    )


# pylint: disable=too-many-statements
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
    if default_action not in ("forward", "drop"):
        raise ConfigurationError("'default_action' must be either 'forward' or 'drop'")

    # Validate rewrite_mixed_packets
    rewrite_mixed_packets = raw_data.get("rewrite_mixed_packets", False)
    if not isinstance(rewrite_mixed_packets, bool):
        raise ConfigurationError("'rewrite_mixed_packets' must be a boolean")

    # Validate command_server
    command_server = None
    raw_server = raw_data.get("command_server")
    if raw_server is not None:
        if not isinstance(raw_server, dict):
            raise ConfigurationError("'command_server' must be a dictionary")
        enabled = raw_server.get("enabled")
        if not isinstance(enabled, bool):
            raise ConfigurationError("'command_server.enabled' must be a boolean")
        host = raw_server.get("host")
        if not isinstance(host, str):
            raise ConfigurationError("'command_server.host' must be a string")
        port = raw_server.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ConfigurationError("'command_server.port' must be an integer between 1 and 65535")
        command_server = CommandServerConfig(enabled=enabled, host=host, port=port)

    # Validate tracking
    tracking = None
    raw_tracking = raw_data.get("tracking")
    if raw_tracking is not None:
        if not isinstance(raw_tracking, dict):
            raise ConfigurationError("'tracking' must be a dictionary")
        enabled = raw_tracking.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ConfigurationError("'tracking.enabled' must be a boolean")
        max_records = raw_tracking.get("max_records", 500)
        if not isinstance(max_records, int) or max_records <= 0:
            raise ConfigurationError("'tracking.max_records' must be a positive integer")
        db_path = raw_tracking.get("db_path", "/var/lib/mdns-sieve/responses.db")
        if not isinstance(db_path, str):
            raise ConfigurationError("'tracking.db_path' must be a string")
        flush_interval_seconds = raw_tracking.get("flush_interval_seconds", 3600)
        if not isinstance(flush_interval_seconds, int) or flush_interval_seconds <= 0:
            raise ConfigurationError("'tracking.flush_interval_seconds' must be a positive integer")
        retention_days = raw_tracking.get("retention_days", 7)
        if not isinstance(retention_days, int) or retention_days <= 0:
            raise ConfigurationError("'tracking.retention_days' must be a positive integer")
        tracking = TrackingConfig(
            enabled=enabled,
            max_records=max_records,
            db_path=db_path,
            flush_interval_seconds=flush_interval_seconds,
            retention_days=retention_days,
        )

    # Validate and parse rules
    raw_rules = raw_data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ConfigurationError("'rules' must be a list of rule mappings")

    rules: List[FilterRule] = []
    for idx, r in enumerate(raw_rules):
        rules.append(_parse_rule(idx, r, interfaces))

    return AppConfig(
        interfaces=interfaces,
        default_action=default_action,
        rewrite_mixed_packets=rewrite_mixed_packets,
        command_server=command_server,
        tracking=tracking,
        rules=rules,
    )

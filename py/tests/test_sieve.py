"""
mdns-sieve Test Suite

Verifies configuration loading, fine-grained matching, robust mDNS binary parsing
with recursion protection, and mock-based network socket reflection behavior.
"""

import io
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from mdns_sieve.config import load_config, ConfigurationError, AppConfig, FilterRule, RuleSection
from mdns_sieve.mdns_parser import (
    parse_mdns_packet,
    MdnsParsingError,
    DNSPacket,
    DNSQuestion,
    DNSResourceRecord,
    write_name,
)
from mdns_sieve.reflector import MdnsReflector


class TestConfigEngine(unittest.TestCase):
    """Verifies YAML parsing, validation, and rules routing logic."""

    def test_basic_yaml_loading(self) -> None:
        """Verifies that valid configurations parse successfully."""
        yaml_content = """
interfaces:
  - eth0
  - eth1
  - wlan0
default_action: drop
rules:
  - action: forward
    services:
      - "_googlecast._tcp.local"
    src: "*"
    dst: "*"
  - action: drop
    hosts:
      - "spotted-tv.local"
    src: eth0
    dst: wlan0
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            config = load_config("mock_config.yaml")

        self.assertEqual(config.interfaces, ["eth0", "eth1", "wlan0"])
        self.assertEqual(config.default_action, "drop")
        self.assertEqual(len(config.rules), 2)

        self.assertTrue(config.rules[0].action)
        self.assertEqual(config.rules[0].services, ["_googlecast._tcp.local"])
        self.assertEqual(config.rules[0].src, "*")
        self.assertEqual(config.rules[0].dst, "*")

        self.assertFalse(config.rules[1].action)
        self.assertEqual(config.rules[1].hosts, ["spotted-tv.local"])
        self.assertEqual(config.rules[1].src, "eth0")
        self.assertEqual(config.rules[1].dst, "wlan0")

    def test_validation_errors(self) -> None:
        """Verifies that malformed or incomplete YAML raises ConfigurationError."""
        # Missing interfaces
        with patch("builtins.open", return_value=io.StringIO("default_action: forward")):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")

        # Invalid default_action
        yaml_bad_action = "interfaces: [eth0]\ndefault_action: maybe"
        with patch("builtins.open", return_value=io.StringIO(yaml_bad_action)):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")

        # Typo in rule interface name
        yaml_bad_iface = """
interfaces:
  - eth0
default_action: drop
rules:
  - action: forward
    src: invalid_interface_name
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_bad_iface)):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")

    def test_routing_logic(self) -> None:
        """Verifies rules are evaluated in order and match names correctly."""
        rules = [
            # Drop Spotify from eth1 to wlan0
            FilterRule(
                action=False,
                services=["_spotify-connect._tcp.local"],
                src="eth1",
                dst="wlan0",
            ),
            # Forward general Google Cast everywhere
            FilterRule(action=True, services=["_googlecast._tcp.local"], src="*", dst="*"),
            # Forward specific local apple tv host
            FilterRule(action=True, hosts=["*.local"], src="eth0", dst="eth1"),
        ]
        config = AppConfig(interfaces=["eth0", "eth1", "wlan0"], default_action="drop", rules=rules)

        # 1. Drop rule matches Spotify from eth1 -> wlan0
        self.assertFalse(config.should_forward("eth1", "wlan0", {"_spotify-connect._tcp.local"}))

        # 2. Spotify from eth1 -> eth0 is not blocked by that specific rule, falls back to default
        #    drop
        self.assertFalse(config.should_forward("eth1", "eth0", {"_spotify-connect._tcp.local"}))

        # 3. Google Cast from eth1 -> wlan0 is forwarded (action=True)
        self.assertTrue(config.should_forward("eth1", "wlan0", {"_googlecast._tcp.local"}))

        # 4. Host match wildcard *.local from eth0 -> eth1 is forwarded (action=True)
        self.assertTrue(config.should_forward("eth0", "eth1", {"my-device.local"}))

        # 5. Casing and trailing dot canonicalization checks
        self.assertTrue(config.should_forward("eth0", "eth1", {"My-Device.Local."}))

    def test_routing_with_lists(self) -> None:
        """Verifies routing logic handles list values for src and dst correctly."""
        rules = [
            FilterRule(
                action=True,
                services=["_googlecast._tcp.local"],
                src=["eth0", "eth1"],
                dst=["eth2"],
            )
        ]
        config = AppConfig(
            interfaces=["eth0", "eth1", "eth2"],
            default_action="drop",
            rules=rules,
        )

        # Forwarded because source is in list and dest is in list
        self.assertTrue(config.should_forward("eth0", "eth2", {"_googlecast._tcp.local"}))
        self.assertTrue(config.should_forward("eth1", "eth2", {"_googlecast._tcp.local"}))

        # Dropped because source interface is not in src list
        self.assertFalse(config.should_forward("eth2", "eth0", {"_googlecast._tcp.local"}))

    def test_config_src_dst_list_parsing(self) -> None:
        """Verifies parsing of configurations with list src and dst fields."""
        yaml_content = """
interfaces:
  - eth0
  - eth1
  - eth2
default_action: drop
rules:
  - action: forward
    src: [eth0, eth1]
    dst: eth2
    services: [_googlecast._tcp.local]
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            config = load_config("mock_config.yaml")

        self.assertEqual(config.rules[0].src, ["eth0", "eth1"])
        self.assertEqual(config.rules[0].dst, "eth2")

    def test_config_src_dst_invalid_list(self) -> None:
        """Verifies config loading raises error for invalid types in src/dst lists."""
        yaml_bad_src = """
interfaces: [eth0, eth1]
default_action: drop
rules:
  - action: forward
    src: 12345
    dst: eth1
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_bad_src)):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")

        yaml_bad_dst = """
interfaces: [eth0, eth1]
default_action: drop
rules:
  - action: forward
    src: eth0
    dst: [eth1, 999]
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_bad_dst)):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")


class TestMdnsParser(unittest.TestCase):
    """Verifies raw binary decoding and robust security boundaries."""

    def test_empty_or_short_payload(self) -> None:
        """Verifies that truncated payloads are rejected."""
        with self.assertRaises(MdnsParsingError):
            parse_mdns_packet(b"too_short")

    def test_parse_simple_question(self) -> None:
        """Decodes a constructed, valid binary query packet."""
        # Construct header: ID=0, Flags=0, QD=1, AN=0, NS=0, AR=0
        header = struct.pack("!HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        # Construct question name: \x05local\x00
        name = b"\x05local\x00"
        # Question details: QTYPE=12 (PTR), QCLASS=1 (IN)
        qdetails = struct.pack("!HH", 12, 1)

        packet = parse_mdns_packet(header + name + qdetails)
        self.assertEqual(packet.transaction_id, 0x1234)
        self.assertEqual(len(packet.questions), 1)
        self.assertEqual(packet.questions[0].name, "local")
        self.assertEqual(packet.questions[0].qtype, 12)
        self.assertEqual(packet.questions[0].qclass, 1)

    def test_pointer_loops_protection(self) -> None:
        """Ensures infinite compression pointer loops are caught and rejected."""
        # Header: QD=1, others 0
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        # Pointer at offset 12 pointing back to offset 12: 0b11000000 0b00001100 -> 0xc0 0x0c
        bad_name = b"\xc0\x0c"
        qdetails = struct.pack("!HH", 12, 1)

        with self.assertRaises(MdnsParsingError) as ctx:
            parse_mdns_packet(header + bad_name + qdetails)
        self.assertIn("recursion loop", str(ctx.exception))

    def test_excessive_pointer_depth(self) -> None:
        """Ensures that deep/chained pointers are rejected even if they don't loop."""
        # We can construct a series of names referencing each other
        # offset 12: pointer to 14
        # offset 14: pointer to 16, etc.
        data = bytearray(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0))
        # Chain of 25 pointers
        for i in range(25):
            next_offset = 12 + (i + 1) * 2
            data.extend(struct.pack("!H", 0xC000 | next_offset))
        # Terminate last pointer with empty name
        data.extend(b"\x00")
        data.extend(struct.pack("!HH", 12, 1))

        with self.assertRaises(MdnsParsingError) as ctx:
            parse_mdns_packet(bytes(data))
        self.assertIn("redirection depth", str(ctx.exception))

    def test_extract_names_helper(self) -> None:
        """Verifies extraction of service types and targets in RRs."""
        # Mock a packet
        packet = DNSPacket(
            transaction_id=0,
            flags=0,
            questions=[DNSQuestion(name="_googlecast._tcp.local", qtype=12, qclass=1)],
            answers=[
                DNSResourceRecord(
                    name="_googlecast._tcp.local",
                    rtype=12,
                    rclass=1,
                    ttl=120,
                    rdata=b"",
                    target_name="chromecast-1.local",
                )
            ],
        )
        names = packet.extract_names()
        self.assertIn("_googlecast._tcp.local", names)
        self.assertIn("chromecast-1.local", names)


class TestReflectorEngine(unittest.TestCase):
    """Verifies select-loop socket coordination and packet forwarding policies."""

    @patch("socket.socket")
    @patch("mdns_sieve.reflector.MdnsReflector.get_interface_ip")
    def test_setup_socket_options(self, mock_get_ip: MagicMock, mock_socket: MagicMock) -> None:
        """Verifies socket initialization binds correctly and configures multicast."""
        mock_get_ip.return_value = "192.168.1.1"
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        config = AppConfig(interfaces=["eth0"], default_action="drop")
        reflector = MdnsReflector(config)
        sock = reflector.setup_socket("eth0")

        self.assertEqual(sock, mock_sock)
        # Check standard bindings and option configurations
        mock_sock.bind.assert_called_with(("", 5353))
        # IP_ADD_MEMBERSHIP, IP_MULTICAST_IF, IP_MULTICAST_TTL, IP_MULTICAST_LOOP
        mock_sock.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    @patch("select.select")
    def test_forwarding_loop_exclusion(self, mock_select: MagicMock) -> None:  # pylint: disable=unused-argument
        """Verifies packets are forwarded based on rules, and never reflected back to source."""
        config = AppConfig(interfaces=["eth0", "eth1"], default_action="forward")
        reflector = MdnsReflector(config)

        # Mock the two interface sockets
        mock_sock_eth0 = MagicMock()
        mock_sock_eth1 = MagicMock()
        reflector.sockets = {"eth0": mock_sock_eth0, "eth1": mock_sock_eth1}
        reflector.interface_ips = {"eth0": "192.168.1.1", "eth1": "192.168.2.1"}

        # Simulate a packet arrived on eth0: QD=1, Name=device.local
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        name = b"\x06device\x05local\x00"
        qdetails = struct.pack("!HH", 1, 1)
        packet_data = header + name + qdetails

        # Trigger packet handler manually
        reflector.handle_packet("eth0", packet_data)

        # Should NOT send packet back out on eth0
        mock_sock_eth0.sendto.assert_not_called()
        # Should forward packet out on eth1
        mock_sock_eth1.sendto.assert_called_once_with(packet_data, ("224.0.0.251", 5353))


class TestQAFiltering(unittest.TestCase):
    """Verifies Question vs. Answer rule segmentation and unidirectional matching."""

    def test_config_section_validation(self) -> None:
        """Verifies parsing of the 'section' field in rules YAML."""
        yaml_content = """
interfaces: [eth0, eth1]
default_action: drop
rules:
  - action: forward
    section: questions
    services: [_googlecast._tcp.local]
  - action: drop
    section: answers
    hosts: [badhost.local]
  - action: forward
    section: invalid_section_name
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            with self.assertRaises(ConfigurationError) as ctx:
                load_config("mock.yaml")
        self.assertIn("invalid 'section'", str(ctx.exception))

    def test_rule_matching_by_section(self) -> None:
        """Verifies FilterRule.matches_packet targets only specified packet components."""
        # 1. Questions rule should match question names, ignore answers
        q_rule = FilterRule(
            action=True, services=["_googlecast._tcp.local"], section=RuleSection.QUESTIONS
        )
        self.assertTrue(
            q_rule.matches_packet({"_googlecast._tcp.local"}, {"_spotify-connect._tcp.local"})
        )
        self.assertFalse(
            q_rule.matches_packet({"_spotify-connect._tcp.local"}, {"_googlecast._tcp.local"})
        )

        # 2. Answers rule should match answer names, ignore questions
        a_rule = FilterRule(
            action=True, services=["_googlecast._tcp.local"], section=RuleSection.ANSWERS
        )
        self.assertFalse(
            a_rule.matches_packet({"_googlecast._tcp.local"}, {"_spotify-connect._tcp.local"})
        )
        self.assertTrue(
            a_rule.matches_packet({"_spotify-connect._tcp.local"}, {"_googlecast._tcp.local"})
        )

        # 3. 'Any' rule matches either
        any_rule = FilterRule(
            action=True, services=["_googlecast._tcp.local"], section=RuleSection.ANY
        )
        self.assertTrue(
            any_rule.matches_packet({"_googlecast._tcp.local"}, {"_spotify-connect._tcp.local"})
        )
        self.assertTrue(
            any_rule.matches_packet({"_spotify-connect._tcp.local"}, {"_googlecast._tcp.local"})
        )

    @patch("select.select")
    def test_unidirectional_forwarding(self, _mock_select: MagicMock) -> None:
        """Verifies end-to-end unidirectional discovery between Trusted and IoT VLANs."""
        # Rules:
        # - Forward Questions: eth0 (Trusted) -> eth1 (IoT)
        # - Drop Questions: eth1 (IoT) -> eth0 (Trusted)
        # - Forward Answers: eth1 (IoT) -> eth0 (Trusted)
        # - Drop Answers: eth0 (Trusted) -> eth1 (IoT)
        rules = [
            FilterRule(
                action=True, services=["*"], src="eth0", dst="eth1", section=RuleSection.QUESTIONS
            ),
            FilterRule(
                action=False, services=["*"], src="eth1", dst="eth0", section=RuleSection.QUESTIONS
            ),
            FilterRule(
                action=True, services=["*"], src="eth1", dst="eth0", section=RuleSection.ANSWERS
            ),
            FilterRule(
                action=False, services=["*"], src="eth0", dst="eth1", section=RuleSection.ANSWERS
            ),
        ]
        config = AppConfig(interfaces=["eth0", "eth1"], default_action="drop", rules=rules)
        reflector = MdnsReflector(config)

        mock_sock_eth0 = MagicMock()
        mock_sock_eth1 = MagicMock()
        reflector.sockets = {"eth0": mock_sock_eth0, "eth1": mock_sock_eth1}
        reflector.interface_ips = {"eth0": "192.168.1.1", "eth1": "192.168.2.1"}

        # Construct a mock query packet (1 Question, 0 Answers)
        q_packet = (
            struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x05local\x00" + struct.pack("!HH", 12, 1)
        )

        # Construct a mock answer packet (0 Questions, 1 Answer)
        a_packet = (
            struct.pack("!HHHHHH", 0, 0, 0, 1, 0, 0)
            + b"\x05local\x00"
            + struct.pack("!HHIH", 12, 1, 120, 0)
        )

        # A. Trusted asks IoT (Question eth0 -> eth1): FORWARDED
        mock_sock_eth1.sendto.reset_mock()
        reflector.handle_packet("eth0", q_packet)
        mock_sock_eth1.sendto.assert_called_once_with(q_packet, ("224.0.0.251", 5353))

        # B. IoT responds to Trusted (Answer eth1 -> eth0): FORWARDED
        mock_sock_eth0.sendto.reset_mock()
        reflector.handle_packet("eth1", a_packet)
        mock_sock_eth0.sendto.assert_called_once_with(a_packet, ("224.0.0.251", 5353))

        # C. IoT asks Trusted (Question eth1 -> eth0): DROPPED
        mock_sock_eth0.reset_mock()
        reflector.handle_packet("eth1", q_packet)
        mock_sock_eth0.sendto.assert_not_called()

        # D. Trusted responds to IoT (Answer eth0 -> eth1): DROPPED
        mock_sock_eth1.reset_mock()
        reflector.handle_packet("eth0", a_packet)
        mock_sock_eth1.sendto.assert_not_called()

    @patch("select.select")
    @patch("mdns_sieve.reflector.logger")
    def test_logging_indicates_section(
        self, mock_logger: MagicMock, _mock_select: MagicMock
    ) -> None:
        """Verifies that forwarded and dropped packet logs include the section categorization."""
        rules = [
            FilterRule(
                action=True, services=["*"], src="eth0", dst="eth1", section=RuleSection.QUESTIONS
            ),
        ]
        config = AppConfig(interfaces=["eth0", "eth1"], default_action="drop", rules=rules)
        reflector = MdnsReflector(config)

        mock_sock_eth0 = MagicMock()
        mock_sock_eth1 = MagicMock()
        reflector.sockets = {"eth0": mock_sock_eth0, "eth1": mock_sock_eth1}
        reflector.interface_ips = {"eth0": "192.168.1.1", "eth1": "192.168.2.1"}

        # Construct a mock query packet (1 Question, 0 Answers)
        q_packet = (
            struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x05local\x00" + struct.pack("!HH", 12, 1)
        )

        # 1. Forwarded packet logging (verbosity >= 2)
        reflector.handle_packet("eth0", q_packet)
        called_debug_messages = [
            call[0][0] % call[0][1:] for call in mock_logger.debug.call_args_list
        ]
        any_forward_log = any(
            "Forwarding" in msg and "questions: ['local'], answers: []" in msg
            for msg in called_debug_messages
        )
        self.assertTrue(any_forward_log, f"Log was not found: {called_debug_messages}")

        # 2. Dropped packet logging (verbosity >= 2)
        mock_logger.reset_mock()
        reflector.handle_packet("eth1", q_packet)
        called_debug_messages = [
            call[0][0] % call[0][1:] for call in mock_logger.debug.call_args_list
        ]
        any_drop_log = any(
            "Dropped" in msg and "questions: ['local'], answers: []" in msg
            for msg in called_debug_messages
        )
        self.assertTrue(any_drop_log, f"Log was not found: {called_debug_messages}")

    @patch("select.select")
    @patch("mdns_sieve.reflector.logger")
    def test_logging_warning_mixed_records(
        self, mock_logger: MagicMock, _mock_select: MagicMock
    ) -> None:
        """
        Verifies that dropping a packet with mixed forwarded/dropped Q/A records
        logs an info message (representing the first verbose level).
        """
        rules = [
            FilterRule(
                action=False, services=["*"], src="eth0", dst="eth1", section=RuleSection.ANSWERS
            ),
            FilterRule(
                action=True, services=["*"], src="eth0", dst="eth1", section=RuleSection.QUESTIONS
            ),
        ]
        config = AppConfig(interfaces=["eth0", "eth1"], default_action="drop", rules=rules)
        reflector = MdnsReflector(config)

        mock_sock_eth0 = MagicMock()
        mock_sock_eth1 = MagicMock()
        reflector.sockets = {"eth0": mock_sock_eth0, "eth1": mock_sock_eth1}
        reflector.interface_ips = {"eth0": "192.168.1.1", "eth1": "192.168.2.1"}

        # Construct a packet with 1 Question and 1 Answer
        header = struct.pack("!HHHHHH", 0, 0, 1, 1, 0, 0)
        question = b"\x05local\x00" + struct.pack("!HH", 12, 1)
        answer = b"\x05local\x00" + struct.pack("!HHIH", 12, 1, 120, 0)
        mixed_packet = header + question + answer

        # Process packet
        reflector.handle_packet("eth0", mixed_packet)

        # It should be blocked (not sent on eth1)
        mock_sock_eth1.sendto.assert_not_called()

        # Warning/Info logger should be called with info level (first verbose level)
        called_info_messages = [
            call[0][0] % call[0][1:] for call in mock_logger.info.call_args_list
        ]
        any_warning = any(
            "Dropped mDNS packet" in msg and "mixture of forwarded/dropped" in msg
            for msg in called_info_messages
        )
        self.assertTrue(any_warning, f"Info log not found: {called_info_messages}")


class TestPacketRewriting(unittest.TestCase):
    """Verifies config, serialization, and end-to-end routing with packet rewriting/filtering."""

    def test_config_rewriting_flag(self) -> None:
        """Verifies parsing of the 'rewrite_mixed_packets' configuration option."""
        # 1. Parsing when enabled
        yaml_enabled = """
interfaces: [eth0, eth1]
default_action: drop
rewrite_mixed_packets: true
rules: []
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_enabled)):
            config = load_config("dummy.yaml")
            self.assertTrue(config.rewrite_mixed_packets)

        # 2. Parsing when disabled/omitted
        yaml_disabled = """
interfaces: [eth0, eth1]
default_action: drop
rules: []
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_disabled)):
            config = load_config("dummy.yaml")
            self.assertFalse(config.rewrite_mixed_packets)

        # 3. Validation error on non-boolean
        yaml_invalid = """
interfaces: [eth0, eth1]
default_action: drop
rewrite_mixed_packets: "not-a-boolean"
rules: []
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_invalid)):
            with self.assertRaises(ConfigurationError):
                load_config("dummy.yaml")

    def test_write_name(self) -> None:
        """Verifies DNS name serialization and full-name compression."""
        compression_dict: dict[str, int] = {}

        # Write first name at offset 12
        name1 = "googlecast.local"
        b1 = write_name(name1, compression_dict, 12)
        # Expected encoding: \x0a googlecast \x05 local \x00
        expected1 = b"\x0agooglecast\x05local\x00"
        self.assertEqual(b1, expected1)
        self.assertEqual(compression_dict["googlecast.local"], 12)

        # Write same name again, should return 2-byte pointer 0xC00C (0xC000 | 12)
        b2 = write_name(name1, compression_dict, len(b1) + 12)
        self.assertEqual(b2, b"\xc0\x0c")

        # Write empty name
        self.assertEqual(write_name("", compression_dict, 0), b"\x00")

    def test_packet_serialization(self) -> None:
        """Verifies DNSPacket.serialize matches the original decoded packet structure."""
        # Let's construct a binary packet with Questions, Answers, PTR, SRV
        # Header: transaction_id=1, flags=0, qd=1, an=2, ns=0, ar=0
        header = struct.pack("!HHHHHH", 1, 0, 1, 2, 0, 0)
        # Question: _services._dns-sd._udp.local (PTR query)
        qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        question = qname + struct.pack("!HH", 12, 1)

        # Answer 1: PTR type 12 targetting appletv.local (uncompressed target name)
        # Name: _services._dns-sd._udp.local (compresses to question name pointer: 12)
        rr1_name = b"\xc0\x0c"
        rr1_meta = struct.pack("!HHIH", 12, 1, 120, 15)  # rdlen = 15
        rr1_rdata = b"\x07appletv\x05local\x00"

        # Answer 2: SRV type 33 targetting target.local
        rr2_name = b"\x07appletv\x05local\x00"
        # SRV RDATA: priority=1, weight=2, port=5000, target=target.local (14 bytes)
        rr2_rdata = struct.pack("!HHH", 1, 2, 5000) + b"\x06target\x05local\x00"
        rr2_meta = struct.pack("!HHIH", 33, 1, 120, len(rr2_rdata))

        packet_bytes = (
            header + question + rr1_name + rr1_meta + rr1_rdata + rr2_name + rr2_meta + rr2_rdata
        )

        # Parse it
        parsed = parse_mdns_packet(packet_bytes)
        self.assertEqual(parsed.transaction_id, 1)
        self.assertEqual(len(parsed.questions), 1)
        self.assertEqual(len(parsed.answers), 2)

        # Re-serialize it
        serialized = parsed.serialize()

        # Re-parse the serialized bytes to make sure it matches identically
        re_parsed = parse_mdns_packet(serialized)
        self.assertEqual(re_parsed.transaction_id, parsed.transaction_id)
        self.assertEqual(re_parsed.flags, parsed.flags)
        self.assertEqual(len(re_parsed.questions), len(parsed.questions))
        self.assertEqual(re_parsed.questions[0].name, parsed.questions[0].name)
        self.assertEqual(len(re_parsed.answers), len(parsed.answers))
        self.assertEqual(re_parsed.answers[0].name, parsed.answers[0].name)
        self.assertEqual(re_parsed.answers[0].target_name, parsed.answers[0].target_name)
        self.assertEqual(re_parsed.answers[1].name, parsed.answers[1].name)
        self.assertEqual(re_parsed.answers[1].target_name, parsed.answers[1].target_name)

    @patch("select.select")
    @patch("mdns_sieve.reflector.logger")
    def test_filtered_forwarding_rewriting(
        self, mock_logger: MagicMock, _mock_select: MagicMock
    ) -> None:
        """Verifies that mixed packets are rewritten and forwarded with dropped records stripped."""
        # Rules:
        # - Forward Questions: eth0 -> eth1
        # - Drop Answers: eth0 -> eth1 (default action or explicit drop)
        rules = [
            FilterRule(
                action=True,
                services=["*"],
                src="eth0",
                dst="eth1",
                section=RuleSection.QUESTIONS,
            ),
            FilterRule(
                action=False, services=["*"], src="eth0", dst="eth1", section=RuleSection.ANSWERS
            ),
        ]
        config = AppConfig(
            interfaces=["eth0", "eth1"],
            default_action="drop",
            rewrite_mixed_packets=True,
            rules=rules,
        )
        reflector = MdnsReflector(config)

        mock_sock_eth1 = MagicMock()
        reflector.sockets = {"eth0": MagicMock(), "eth1": mock_sock_eth1}
        reflector.interface_ips = {"eth0": "192.168.1.1", "eth1": "192.168.2.1"}

        # Construct a packet with 1 Question (allowed) and 1 Answer (dropped)
        mixed_packet = (
            struct.pack("!HHHHHH", 42, 0, 1, 1, 0, 0)
            + b"\x05local\x00"
            + struct.pack("!HH", 12, 1)
            + b"\x05local\x00"
            + struct.pack("!HHIH", 12, 1, 120, 0)
        )

        # Process packet
        reflector.handle_packet("eth0", mixed_packet)

        # Re-serialized packet is transmitted on eth1
        mock_sock_eth1.sendto.assert_called_once()
        self.assertEqual(mock_sock_eth1.sendto.call_args[0][1], ("224.0.0.251", 5353))

        # The sent packet should only have 1 question and 0 answers
        sent_packet = parse_mdns_packet(mock_sock_eth1.sendto.call_args[0][0])
        self.assertEqual(sent_packet.transaction_id, 42)
        self.assertEqual(len(sent_packet.questions), 1)
        self.assertEqual(len(sent_packet.answers), 0)
        self.assertEqual(sent_packet.questions[0].name, "local")

        # Verify it logs at debug level
        called_debug_messages = [
            call[0][0] % call[0][1:] for call in mock_logger.debug.call_args_list
        ]
        any_rewrite_log = any(
            "Forwarding rewritten mDNS packet" in msg
            and "Kept 1 Qs, 0 RRs; stripped 0 Qs, 1 RRs." in msg
            for msg in called_debug_messages
        )
        self.assertTrue(any_rewrite_log, f"Debug log not found: {called_debug_messages}")


if __name__ == "__main__":
    unittest.main()

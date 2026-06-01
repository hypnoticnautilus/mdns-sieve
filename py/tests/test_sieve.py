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

from mdns_sieve.config import load_config, ConfigurationError, AppConfig, FilterRule
from mdns_sieve.mdns_parser import (
    parse_mdns_packet,
    MdnsParsingError,
    DNSPacket,
    DNSQuestion,
    DNSResourceRecord,
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
default_action: deny
rules:
  - action: allow
    services:
      - "_googlecast._tcp.local"
    src: "*"
    dst: "*"
  - action: deny
    hosts:
      - "spotted-tv.local"
    src: eth0
    dst: wlan0
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            config = load_config("mock_config.yaml")

        self.assertEqual(config.interfaces, ["eth0", "eth1", "wlan0"])
        self.assertEqual(config.default_action, "deny")
        self.assertEqual(len(config.rules), 2)

        self.assertEqual(config.rules[0].action, "allow")
        self.assertEqual(config.rules[0].services, ["_googlecast._tcp.local"])
        self.assertEqual(config.rules[0].src, "*")
        self.assertEqual(config.rules[0].dst, "*")

        self.assertEqual(config.rules[1].action, "deny")
        self.assertEqual(config.rules[1].hosts, ["spotted-tv.local"])
        self.assertEqual(config.rules[1].src, "eth0")
        self.assertEqual(config.rules[1].dst, "wlan0")

    def test_validation_errors(self) -> None:
        """Verifies that malformed or incomplete YAML raises ConfigurationError."""
        # Missing interfaces
        with patch("builtins.open", return_value=io.StringIO("default_action: allow")):
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
default_action: deny
rules:
  - action: allow
    src: invalid_interface_name
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_bad_iface)):
            with self.assertRaises(ConfigurationError):
                load_config("mock.yaml")

    def test_routing_logic(self) -> None:
        """Verifies rules are evaluated in order and match names correctly."""
        rules = [
            # Block Spotify from eth1 to wlan0
            FilterRule(
                action="deny",
                services=["_spotify-connect._tcp.local"],
                src="eth1",
                dst="wlan0",
            ),
            # Allow general Google Cast everywhere
            FilterRule(action="allow", services=["_googlecast._tcp.local"], src="*", dst="*"),
            # Allow specific local apple tv host
            FilterRule(action="allow", hosts=["*.local"], src="eth0", dst="eth1"),
        ]
        config = AppConfig(interfaces=["eth0", "eth1", "wlan0"], default_action="deny", rules=rules)

        # 1. Deny rule matches Spotify from eth1 -> wlan0
        self.assertFalse(config.should_forward("eth1", "wlan0", {"_spotify-connect._tcp.local"}))

        # 2. Spotify from eth1 -> eth0 is not blocked by that specific rule, falls back to default
        #    deny
        self.assertFalse(config.should_forward("eth1", "eth0", {"_spotify-connect._tcp.local"}))

        # 3. Google Cast from eth1 -> wlan0 is allowed
        self.assertTrue(config.should_forward("eth1", "wlan0", {"_googlecast._tcp.local"}))

        # 4. Host match wildcard *.local from eth0 -> eth1 is allowed
        self.assertTrue(config.should_forward("eth0", "eth1", {"my-device.local"}))

        # 5. Casing and trailing dot canonicalization checks
        self.assertTrue(config.should_forward("eth0", "eth1", {"My-Device.Local."}))


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

        config = AppConfig(interfaces=["eth0"], default_action="deny")
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
        config = AppConfig(interfaces=["eth0", "eth1"], default_action="allow")
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


if __name__ == "__main__":
    unittest.main()

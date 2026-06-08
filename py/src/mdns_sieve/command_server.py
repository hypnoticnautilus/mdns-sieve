"""
TCP Command & Statistics Server for mDNS Sieve

Manages client TCP connections, accepts and processes JSON-formatted commands,
tracks packet forwarding statistics, and sends null-byte delimited responses.
"""

import errno
import json
import logging
import socket
from typing import Dict, Any, Optional, Set

logger = logging.getLogger("mdns_sieve.command_server")


# pylint: disable=too-many-instance-attributes
class CommandServerManager:
    """Manages the TCP Command Server socket, client connections, stats, and commands."""

    def __init__(self, config_server: Any) -> None:
        self.config_server = config_server
        self.tcp_listener: Optional[socket.socket] = None
        self.tcp_clients: Dict[socket.socket, bytearray] = {}

        # Statistics trackers
        self.stats_total: int = 0
        self.stats_forwarded: int = 0
        self.stats_dropped: int = 0
        self.stats_rewritten: int = 0
        self.stats_hosts: Dict[str, Dict[str, Any]] = {}
        self.stats_names_forwarded_queries: Dict[str, Dict[str, int]] = {}
        self.stats_names_forwarded_responses: Dict[str, Dict[str, int]] = {}
        self.stats_names_dropped_queries: Dict[str, Dict[str, int]] = {}
        self.stats_names_dropped_responses: Dict[str, Dict[str, int]] = {}

    def collect_stats(
        self,
        src_interface: str,
        src_ip: str,
        action: str,
        allowed_names: Set[str],
        disallowed_names: Set[str],
        timestamp: float,
        is_response: bool = False,
    ) -> None:
        # pylint: disable=too-many-branches
        """Collects routing and name statistics."""
        if not self.config_server or not self.config_server.enabled:
            return

        self.stats_total += 1
        if action == "forwarded":
            self.stats_forwarded += 1
        elif action == "dropped":
            self.stats_dropped += 1
        elif action == "rewritten":
            self.stats_rewritten += 1

        if src_ip not in self.stats_hosts:
            self.stats_hosts[src_ip] = {
                "packets_sent": 0,
                "last_interface": src_interface,
                "last_seen_time": 0.0,
            }
        host_info = self.stats_hosts[src_ip]
        host_info["packets_sent"] += 1
        host_info["last_interface"] = src_interface
        host_info["last_seen_time"] = timestamp

        if is_response:
            for name in allowed_names:
                if name not in self.stats_names_forwarded_responses:
                    self.stats_names_forwarded_responses[name] = {}
                self.stats_names_forwarded_responses[name][src_ip] = (
                    self.stats_names_forwarded_responses[name].get(src_ip, 0) + 1
                )
            for name in disallowed_names:
                if name not in self.stats_names_dropped_responses:
                    self.stats_names_dropped_responses[name] = {}
                self.stats_names_dropped_responses[name][src_ip] = (
                    self.stats_names_dropped_responses[name].get(src_ip, 0) + 1
                )
        else:
            for name in allowed_names:
                if name not in self.stats_names_forwarded_queries:
                    self.stats_names_forwarded_queries[name] = {}
                self.stats_names_forwarded_queries[name][src_ip] = (
                    self.stats_names_forwarded_queries[name].get(src_ip, 0) + 1
                )
            for name in disallowed_names:
                if name not in self.stats_names_dropped_queries:
                    self.stats_names_dropped_queries[name] = {}
                self.stats_names_dropped_queries[name][src_ip] = (
                    self.stats_names_dropped_queries[name].get(src_ip, 0) + 1
                )

    def try_initialize(self) -> None:
        """Initializes the TCP command/statistics listener socket if enabled."""
        if not self.config_server or not self.config_server.enabled:
            return

        if self.tcp_listener is not None:
            return

        try:
            # Create a non-blocking TCP server socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config_server.host, self.config_server.port))
            sock.listen(5)
            sock.setblocking(False)
            self.tcp_listener = sock
            logger.info(
                "TCP Command Server listening on %s:%d",
                self.config_server.host,
                self.config_server.port,
            )
        except OSError as e:
            logger.error(
                "Failed to bind TCP Command Server to %s:%d: %s. "
                "Continuing core mDNS reflector service.",
                self.config_server.host,
                self.config_server.port,
                str(e),
            )

    def handle_client_data(self, client_sock: socket.socket) -> None:
        """Reads data from a client TCP socket, parses commands, and sends responses."""
        buffer = self.tcp_clients.get(client_sock)
        if buffer is None:
            return

        try:
            data = client_sock.recv(4096)
        except OSError as e:
            if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                self.disconnect_client(client_sock)
            return

        if not data:
            self.disconnect_client(client_sock)
            return

        buffer.extend(data)

        # Enforce buffer limit of 4096 bytes
        if len(buffer) > 4096:
            logger.warning("TCP client buffer limit exceeded (4096 bytes). Disconnecting client.")
            self.disconnect_client(client_sock)
            return

        while b"\x00" in buffer:
            idx = buffer.index(b"\x00")
            cmd_bytes = bytes(buffer[:idx])
            del buffer[: idx + 1]

            # Process command
            response_dict = self.process_command(cmd_bytes)
            try:
                response_json = json.dumps(response_dict)
                client_sock.sendall(response_json.encode("utf-8") + b"\x00")
            except OSError:
                self.disconnect_client(client_sock)
                return

    def disconnect_client(self, client_sock: socket.socket) -> None:
        """Closes a client socket and removes it from tracking."""
        self.tcp_clients.pop(client_sock, None)
        try:
            client_sock.close()
        except OSError:
            pass

    def process_command(self, cmd_bytes: bytes) -> Dict[str, Any]:
        """Parses and executes a command payload, returning the JSON dict response."""
        try:
            cmd_str = cmd_bytes.decode("utf-8")
            payload = json.loads(cmd_str)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"status": "error", "error": "Invalid JSON"}

        if not isinstance(payload, dict):
            return {"status": "error", "error": "Malformed command object"}

        cmd = payload.get("command")
        if not cmd:
            return {"status": "error", "error": "Missing 'command' key"}

        return self._dispatch_command(cmd)

    def _dispatch_command(self, cmd: str) -> Dict[str, Any]:
        """Executes the specific command routine."""
        if cmd == "stats":
            return {
                "status": "ok",
                "data": {
                    "total": self.stats_total,
                    "forwarded": self.stats_forwarded,
                    "dropped": self.stats_dropped,
                    "rewritten": self.stats_rewritten,
                },
            }
        if cmd == "hosts":
            return {
                "status": "ok",
                "data": self.stats_hosts,
            }
        if cmd == "names":
            return {
                "status": "ok",
                "data": {
                    "forwarded_queries": self.stats_names_forwarded_queries,
                    "forwarded_responses": self.stats_names_forwarded_responses,
                    "dropped_queries": self.stats_names_dropped_queries,
                    "dropped_responses": self.stats_names_dropped_responses,
                },
            }
        if cmd == "clear":
            self.stats_total = 0
            self.stats_forwarded = 0
            self.stats_dropped = 0
            self.stats_rewritten = 0
            self.stats_hosts.clear()
            self.stats_names_forwarded_queries.clear()
            self.stats_names_forwarded_responses.clear()
            self.stats_names_dropped_queries.clear()
            self.stats_names_dropped_responses.clear()
            return {"status": "ok"}

        return {"status": "error", "error": "Unknown command"}

    def stop(self) -> None:
        """Stops the command server and releases sockets."""
        if self.tcp_listener:
            try:
                self.tcp_listener.close()
            except OSError:
                pass
            self.tcp_listener = None

        for sock in list(self.tcp_clients.keys()):
            try:
                sock.close()
            except OSError:
                pass
        self.tcp_clients.clear()

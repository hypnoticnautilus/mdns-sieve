"""
TCP Command & Statistics Server for mDNS Sieve

Manages client TCP connections, accepts and processes JSON-formatted commands,
tracks packet forwarding statistics, and sends null-byte delimited responses.
"""

import errno
import json
import logging
import socket
import time
from typing import Dict, Any, Optional, Set, List, Tuple

from mdns_sieve.database import DatabaseManager

logger = logging.getLogger("mdns_sieve.command_server")


# pylint: disable=too-many-instance-attributes
class CommandServerManager:
    """Manages the TCP Command Server socket, client connections, stats, and commands."""

    def __init__(self, config_server: Any, tracking_config: Any = None) -> None:
        self.config_server = config_server
        self.tracking_config = tracking_config
        self.tcp_listener: Optional[socket.socket] = None
        self.tcp_clients: Dict[socket.socket, bytearray] = {}

        # Statistics trackers
        self.stats_total: int = 0
        self.stats_forwarded: int = 0
        self.stats_dropped: int = 0
        self.stats_rewritten: int = 0

        # Database tracking
        self.db_manager: Optional[DatabaseManager] = None
        self.db_buffer_responses: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.db_buffer_queries: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.last_flush_time = time.time()
        if self.tracking_config and self.tracking_config.enabled:
            self.db_manager = DatabaseManager(self.tracking_config.db_path)
            self.stats_total, self.stats_forwarded, self.stats_dropped, self.stats_rewritten = (
                self.db_manager.load_global_stats()
            )

    def collect_stats(
        self,
        src_interface: str,
        src_ip: str,
        action: str,
        allowed_names: Set[str],
        disallowed_names: Set[str],
        timestamp: float,
        is_response: bool = False,
        forwarded_interfaces: Optional[List[str]] = None,
        dropped_interfaces: Optional[List[str]] = None,
    ) -> None:
        # pylint: disable=too-many-branches,too-many-arguments,too-many-locals,too-many-statements
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

        if self.db_manager:
            forwarded_str = ",".join(sorted(forwarded_interfaces)) if forwarded_interfaces else ""
            dropped_str = ",".join(sorted(dropped_interfaces)) if dropped_interfaces else ""
            buffer = self.db_buffer_responses if is_response else self.db_buffer_queries
            all_names = allowed_names | disallowed_names
            for name in all_names:
                parts = name.split(".")
                service_type = name
                for i, part in enumerate(parts):
                    if part.startswith("_"):
                        service_type = ".".join(parts[i:])
                        break
                key = (src_ip, service_type, src_interface)
                if key not in buffer:
                    buffer[key] = {
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "packet_count": 1,
                        "last_forwarded_interfaces": forwarded_str,
                        "last_dropped_interfaces": dropped_str,
                    }
                else:
                    entry = buffer[key]
                    entry["last_seen"] = timestamp
                    entry["packet_count"] += 1
                    entry["last_forwarded_interfaces"] = forwarded_str
                    entry["last_dropped_interfaces"] = dropped_str

    def flush_stats(self, force: bool = False) -> None:
        """Flushes the database memory buffers and prunes old records."""
        if not self.db_manager or not self.tracking_config:
            return

        now = time.time()
        if not force and now - self.last_flush_time < self.tracking_config.flush_interval_seconds:
            return

        self.last_flush_time = now

        if self.db_buffer_responses:
            records = [
                (
                    key[0],
                    key[1],
                    key[2],
                    val["first_seen"],
                    val["last_seen"],
                    val["packet_count"],
                    val["last_forwarded_interfaces"],
                    val["last_dropped_interfaces"],
                )
                for key, val in self.db_buffer_responses.items()
            ]
            self.db_manager.batch_upsert("responses", records)
            self.db_buffer_responses.clear()

        if self.db_buffer_queries:
            records = [
                (
                    key[0],
                    key[1],
                    key[2],
                    val["first_seen"],
                    val["last_seen"],
                    val["packet_count"],
                    val["last_forwarded_interfaces"],
                    val["last_dropped_interfaces"],
                )
                for key, val in self.db_buffer_queries.items()
            ]
            self.db_manager.batch_upsert("queries", records)
            self.db_buffer_queries.clear()

        self.db_manager.save_global_stats(
            self.stats_total, self.stats_forwarded, self.stats_dropped, self.stats_rewritten
        )
        self.db_manager.prune_old_records(self.tracking_config.retention_days)

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

        return self._dispatch_command(cmd, payload)

    # pylint: disable=too-many-return-statements
    def _dispatch_command(self, cmd: str, _payload: Dict[str, Any]) -> Dict[str, Any]:
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

        if cmd in ("hosts", "names", "host_details"):
            if not self.db_manager:
                return {"status": "error", "error": "Database tracking is disabled"}

            # Fetch all DB records
            db_responses = self.db_manager.fetch_records("responses")
            db_queries = self.db_manager.fetch_records("queries")

            def merge_data(
                db_rows: List[Tuple[Any, ...]], buffer: Dict[Tuple[str, str, str], Dict[str, Any]]
            ) -> List[Dict[str, Any]]:
                merged_dict = {}
                for row in db_rows:
                    key = (row[0], row[1], row[2])
                    merged_dict[key] = {
                        "src_ip": row[0],
                        "service_type": row[1],
                        "src_interface": row[2],
                        "first_seen": row[3],
                        "last_seen": row[4],
                        "packet_count": row[5],
                        "last_forwarded_interfaces": row[6],
                        "last_dropped_interfaces": row[7],
                    }
                for bkey, bval in buffer.items():
                    if bkey in merged_dict:
                        entry = merged_dict[bkey]
                        entry["first_seen"] = min(entry["first_seen"], bval["first_seen"])
                        entry["last_seen"] = max(entry["last_seen"], bval["last_seen"])
                        entry["packet_count"] += bval["packet_count"]
                        entry["last_forwarded_interfaces"] = bval["last_forwarded_interfaces"]
                        entry["last_dropped_interfaces"] = bval["last_dropped_interfaces"]
                    else:
                        merged_dict[bkey] = {
                            "src_ip": bkey[0],
                            "service_type": bkey[1],
                            "src_interface": bkey[2],
                            "first_seen": bval["first_seen"],
                            "last_seen": bval["last_seen"],
                            "packet_count": bval["packet_count"],
                            "last_forwarded_interfaces": bval["last_forwarded_interfaces"],
                            "last_dropped_interfaces": bval["last_dropped_interfaces"],
                        }
                return list(merged_dict.values())

            return {
                "status": "ok",
                "data": {
                    "responses": merge_data(db_responses, self.db_buffer_responses),
                    "queries": merge_data(db_queries, self.db_buffer_queries),
                },
            }

        if cmd == "clear":
            self.stats_total = 0
            self.stats_forwarded = 0
            self.stats_dropped = 0
            self.stats_rewritten = 0
            if self.db_manager:
                self.db_manager.save_global_stats(0, 0, 0, 0)
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

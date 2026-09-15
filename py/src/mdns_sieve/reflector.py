"""
mDNS Multicast Reflector Engine

Manages physical interface UDP sockets, configures socket options for multicast,
runs the select-based event loop, and handles dynamic interface failures and recovery.
"""

import errno
import logging
import select
import socket
import struct
import time
from typing import Dict, Set, Any, Optional

# Only import fcntl on UNIX platforms to keep static tools/type checkers happy
try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

from mdns_sieve.config import AppConfig
from mdns_sieve.mdns_parser import parse_mdns_packet, MdnsParsingError, DNSPacket
from mdns_sieve.command_server import CommandServerManager

logger = logging.getLogger("mdns_sieve.reflector")


# pylint: disable=too-many-instance-attributes,too-many-public-methods
class MdnsReflector:
    """Core daemon service running the mDNS reflection and filtering event loop."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.sockets: Dict[str, socket.socket] = {}
        self.interface_ips: Dict[str, str] = {}
        self.offline_interfaces: Set[str] = set(config.interfaces)
        self.last_retry_time: float = 0.0
        self.retry_interval: float = 10.0  # Seconds between reconnection retries
        self.running: bool = False

        self.command_server = CommandServerManager(
            config.command_server,
            tracking_config=config.tracking,
        )

    @property
    def stats_total(self) -> int:
        """Gets the total packets stats counter."""
        return self.command_server.stats_total

    @stats_total.setter
    def stats_total(self, val: int) -> None:
        """Sets the total packets stats counter."""
        self.command_server.stats_total = val

    @property
    def stats_forwarded(self) -> int:
        """Gets the forwarded packets stats counter."""
        return self.command_server.stats_forwarded

    @stats_forwarded.setter
    def stats_forwarded(self, val: int) -> None:
        """Sets the forwarded packets stats counter."""
        self.command_server.stats_forwarded = val

    @property
    def stats_dropped(self) -> int:
        """Gets the dropped packets stats counter."""
        return self.command_server.stats_dropped

    @stats_dropped.setter
    def stats_dropped(self, val: int) -> None:
        """Sets the dropped packets stats counter."""
        self.command_server.stats_dropped = val

    @property
    def stats_rewritten(self) -> int:
        """Gets the rewritten packets stats counter."""
        return self.command_server.stats_rewritten

    @stats_rewritten.setter
    def stats_rewritten(self, val: int) -> None:
        """Sets the rewritten packets stats counter."""
        self.command_server.stats_rewritten = val

    @property
    def tcp_listener(self) -> Optional[socket.socket]:
        """Gets the TCP command server listener socket."""
        return self.command_server.tcp_listener

    @tcp_listener.setter
    def tcp_listener(self, val: Optional[socket.socket]) -> None:
        """Sets the TCP command server listener socket."""
        self.command_server.tcp_listener = val

    @property
    def tcp_clients(self) -> Dict[socket.socket, bytearray]:
        """Gets the dictionary mapping active client sockets to their receive buffers."""
        return self.command_server.tcp_clients

    @tcp_clients.setter
    def tcp_clients(self, val: Dict[socket.socket, bytearray]) -> None:
        """Sets the dictionary mapping active client sockets to their receive buffers."""
        self.command_server.tcp_clients = val

    def get_interface_ip(self, ifname: str) -> str:
        """
        Uses Linux ioctl (SIOCGIFADDR) to fetch the IPv4 address of an interface by name.
        Raises OSError if the interface is down or lacks an IP.
        """
        if not fcntl:
            # Fallback for non-UNIX testing environments
            raise OSError("fcntl not supported on this platform")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # struct ifreq: 16 bytes interface name, 16 bytes sockaddr
            packed_ifname = struct.pack("32s", ifname[:15].encode("utf-8"))
            # ioctl SIOCGIFADDR = 0x8915
            info = fcntl.ioctl(s.fileno(), 0x8915, packed_ifname)
            # IPv4 address is in bytes 20-24 of the returned ifreq structure
            return socket.inet_ntoa(info[20:24])
        except OSError as e:
            raise OSError(f"Failed to resolve IP for interface {ifname}: {str(e)}") from e
        finally:
            s.close()

    def setup_socket(self, ifname: str) -> socket.socket:
        """
        Creates and configures a UDP multicast socket isolated to a specific interface.
        """
        ip = self.get_interface_ip(ifname)
        self.interface_ips[ifname] = ip

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            # Enable port and address sharing
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass  # SO_REUSEPORT not supported on this kernel/OS

            # Bind to wildcard address to receive multicast traffic
            sock.bind(("", 5353))

            # Bind strictly to the physical device to prevent interface crosstalk (Linux specific)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8"))
            except OSError as e:
                logger.warning(
                    "SO_BINDTODEVICE failed for %s: %s. Relying on membership isolation.",
                    ifname,
                    str(e),
                )

            # Join multicast group 224.0.0.251 on this interface
            mcast_group = socket.inet_aton("224.0.0.251")
            interface_ip = socket.inet_aton(ip)
            mreq = struct.pack("4s4s", mcast_group, interface_ip)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # Route outgoing multicast packets to this interface specifically
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_ip)

            # Set TTL to 255 (RFC 6762 requirement)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

            # Disable loopback to prevent echoing our own packets back to ourselves
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

            sock.setblocking(False)
            logger.info(
                "Successfully bound and joined multicast on interface %s (%s)",
                ifname,
                ip,
            )
            return sock

        except OSError as e:
            sock.close()
            raise OSError(f"Socket setup failed for {ifname}: {str(e)}") from e

    def try_initialize_interfaces(self) -> None:
        """Attempts to setup sockets for all currently offline interfaces."""
        if not self.offline_interfaces:
            return

        still_offline: Set[str] = set()
        for ifname in self.offline_interfaces:
            try:
                sock = self.setup_socket(ifname)
                self.sockets[ifname] = sock
            except OSError as e:
                logger.warning("Interface %s is unavailable: %s. Will retry.", ifname, str(e))
                still_offline.add(ifname)

        self.offline_interfaces = still_offline
        self.last_retry_time = time.time()

    def mark_interface_offline(self, ifname: str) -> None:
        """Closes a faulty socket and schedules the interface for automatic retry."""
        sock = self.sockets.pop(ifname, None)
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        self.interface_ips.pop(ifname, None)
        self.offline_interfaces.add(ifname)
        logger.error("Interface %s marked OFFLINE. Reconnection scheduled.", ifname)

    # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    def handle_packet(self, src_interface: str, data: bytes, src_ip: str = "0.0.0.0") -> None:
        """Parses a packet, evaluates filtering rules, and replicates to forwarded interfaces."""
        try:
            packet = parse_mdns_packet(data)
        except MdnsParsingError as e:
            logger.debug("Parsing failed for packet received on %s: %s", src_interface, str(e))
            return

        q_names = packet.extract_question_names()
        a_names = packet.extract_answer_names()
        if not q_names and not a_names:
            return

        names_desc = f"questions: {sorted(q_names)}, answers: {sorted(a_names)}"

        is_forwarded_any = False
        is_rewritten_any = False
        dest_count = 0
        kept_q = 0
        kept_a = 0
        stripped_q = 0
        stripped_a = 0

        all_pkt_names = q_names | a_names
        allowed_names_packet: Dict[str, Set[str]] = {}
        disallowed_names_packet: Dict[str, Set[str]] = {}

        for dst_interface, sock in list(self.sockets.items()):
            if dst_interface == src_interface:
                continue
            dest_count += 1

            if self.config.rewrite_mixed_packets:
                filtered_questions = [
                    q
                    for q in packet.questions
                    if self.config.should_forward_question(src_interface, dst_interface, q.name)
                ]
                filtered_answers = [
                    rr
                    for rr in packet.answers
                    if self.config.should_forward_record(
                        src_interface, dst_interface, rr, packet.is_response
                    )
                ]
                filtered_authorities = [
                    rr
                    for rr in packet.authorities
                    if self.config.should_forward_record(
                        src_interface, dst_interface, rr, packet.is_response
                    )
                ]
                filtered_additionals = [
                    rr
                    for rr in packet.additionals
                    if self.config.should_forward_record(
                        src_interface, dst_interface, rr, packet.is_response
                    )
                ]

                kq = len(filtered_questions)
                ka = len(filtered_answers) + len(filtered_authorities) + len(filtered_additionals)
                total_orig_q = len(packet.questions)
                total_orig_a = (
                    len(packet.answers) + len(packet.authorities) + len(packet.additionals)
                )

                sq = total_orig_q - kq
                sa = total_orig_a - ka

                kept_q = max(kept_q, kq)
                kept_a = max(kept_a, ka)
                stripped_q = max(stripped_q, sq)
                stripped_a = max(stripped_a, sa)

                if kq == 0 and ka == 0:
                    for name in all_pkt_names:
                        disallowed_names_packet.setdefault(name, set()).add(dst_interface)
                    logger.debug(
                        "Dropped mDNS packet from %s -> %s for names: %s",
                        src_interface,
                        dst_interface,
                        names_desc,
                    )
                elif sq == 0 and sa == 0:
                    for name in all_pkt_names:
                        allowed_names_packet.setdefault(name, set()).add(dst_interface)
                    is_forwarded_any = True
                    logger.debug(
                        "Forwarding mDNS packet (%d bytes) from %s -> %s for names: %s",
                        len(data),
                        src_interface,
                        dst_interface,
                        names_desc,
                    )
                    try:
                        sock.sendto(data, ("224.0.0.251", 5353))
                    except OSError as e:
                        logger.error("Transmit failed on %s: %s", dst_interface, str(e))
                        if e.errno in (errno.EBADF, errno.ENETDOWN, errno.ENETUNREACH):
                            self.mark_interface_offline(dst_interface)
                else:
                    kept_names = {q.name for q in filtered_questions}
                    for rr in filtered_answers + filtered_authorities + filtered_additionals:
                        kept_names.add(rr.name)
                        if rr.target_name:
                            kept_names.add(rr.target_name)
                    stripped_names = all_pkt_names - kept_names
                    for name in kept_names:
                        allowed_names_packet.setdefault(name, set()).add(dst_interface)
                    for name in stripped_names:
                        disallowed_names_packet.setdefault(name, set()).add(dst_interface)
                    is_rewritten_any = True

                    rewritten_packet = DNSPacket(
                        transaction_id=packet.transaction_id,
                        flags=packet.flags,
                        questions=filtered_questions,
                        answers=filtered_answers,
                        authorities=filtered_authorities,
                        additionals=filtered_additionals,
                    )
                    try:
                        serialized_data = rewritten_packet.serialize()
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logger.error(
                            "Failed to serialize rewritten packet from %s -> %s: %s",
                            src_interface,
                            dst_interface,
                            str(e),
                        )
                        continue

                    logger.debug(
                        "Forwarding rewritten mDNS packet (%d B, orig %d B) from %s -> %s. "
                        "Kept %d Qs, %d RRs; stripped %d Qs, %d RRs.",
                        len(serialized_data),
                        len(data),
                        src_interface,
                        dst_interface,
                        kq,
                        ka,
                        sq,
                        sa,
                    )
                    try:
                        sock.sendto(serialized_data, ("224.0.0.251", 5353))
                    except OSError as e:
                        logger.error("Transmit failed on %s: %s", dst_interface, str(e))
                        if e.errno in (errno.EBADF, errno.ENETDOWN, errno.ENETUNREACH):
                            self.mark_interface_offline(dst_interface)
            else:
                if self.config.should_forward(src_interface, dst_interface, q_names, a_names):
                    for name in all_pkt_names:
                        allowed_names_packet.setdefault(name, set()).add(dst_interface)
                    is_forwarded_any = True
                    logger.debug(
                        "Forwarding mDNS packet (%d bytes) from %s -> %s for names: %s",
                        len(data),
                        src_interface,
                        dst_interface,
                        names_desc,
                    )
                    try:
                        sock.sendto(data, ("224.0.0.251", 5353))
                    except OSError as e:
                        logger.error("Transmit failed on %s: %s", dst_interface, str(e))
                        if e.errno in (errno.EBADF, errno.ENETDOWN, errno.ENETUNREACH):
                            self.mark_interface_offline(dst_interface)
                else:
                    for name in all_pkt_names:
                        disallowed_names_packet.setdefault(name, set()).add(dst_interface)
                    is_mixed = False
                    if q_names and a_names:
                        q_forward = self.config.should_forward(
                            src_interface, dst_interface, q_names, set()
                        )
                        a_forward = self.config.should_forward(
                            src_interface, dst_interface, set(), a_names
                        )
                        if q_forward != a_forward:
                            is_mixed = True

                    if is_mixed:
                        logger.info(
                            "Dropped mDNS packet from %s -> %s containing a mixture "
                            "of forwarded/dropped questions and answers. Names: %s",
                            src_interface,
                            dst_interface,
                            names_desc,
                        )
                    else:
                        logger.debug(
                            "Dropped mDNS packet from %s -> %s for names: %s",
                            src_interface,
                            dst_interface,
                            names_desc,
                        )

        if dest_count == 0:
            for name in all_pkt_names:
                disallowed_names_packet.setdefault(name, set())

        if is_rewritten_any:
            action = "rewritten"
        elif is_forwarded_any:
            action = "forwarded"
        else:
            action = "dropped"

        self._collect_stats(
            src_interface,
            src_ip,
            action,
            allowed_names_packet,
            disallowed_names_packet,
            packet.is_response,
            kept_q,
            kept_a,
            stripped_q,
            stripped_a,
        )

    def _collect_stats(
        self,
        src_interface: str,
        src_ip: str,
        action: str,
        allowed_names: Dict[str, Set[str]],
        disallowed_names: Dict[str, Set[str]],
        is_response: bool = False,
        kept_q: int = 0,
        kept_a: int = 0,
        stripped_q: int = 0,
        stripped_a: int = 0,
    ) -> None:
        """Helper to collect routing and name statistics for the command server."""
        allowed_converted = {name: list(ifaces) for name, ifaces in allowed_names.items()}
        disallowed_converted = {name: list(ifaces) for name, ifaces in disallowed_names.items()}
        self.command_server.collect_stats(
            src_interface,
            src_ip,
            action,
            allowed_converted,
            disallowed_converted,
            time.time(),
            is_response,
            kept_q,
            kept_a,
            stripped_q,
            stripped_a,
        )

    def try_initialize_command_server(self) -> None:
        """Initializes the TCP command/statistics listener socket if enabled."""
        self.command_server.try_initialize()

    def _handle_client_data(self, client_sock: socket.socket) -> None:
        """Reads data from a client TCP socket, parses commands, and sends responses."""
        self.command_server.handle_client_data(client_sock)

    def _process_command(self, cmd_bytes: bytes) -> Dict[str, Any]:
        """Parses and executes a command payload, returning the JSON dict response."""
        return self.command_server.process_command(cmd_bytes)

    # pylint: disable=too-many-branches
    def run(self) -> None:
        """Starts the main select-based routing event loop."""
        self.running = True
        self.try_initialize_command_server()
        self.try_initialize_interfaces()

        logger.info("mDNS Sieve Reflector is active.")
        while self.running:
            now = time.time()
            self.command_server.flush_stats()
            if now - self.last_retry_time >= self.retry_interval:
                self.try_initialize_command_server()
                self.try_initialize_interfaces()

            # Build socket poll dictionary mapping fd -> (sock, interface)
            active_sockets = {sock: ifname for ifname, sock in self.sockets.items()}
            if not active_sockets and self.tcp_listener is None and not self.tcp_clients:
                logger.debug("No active interfaces or clients. Waiting for recovery...")
                time.sleep(1.0)
                continue

            # Build select read list
            read_sockets = list(active_sockets.keys())
            if self.tcp_listener is not None:
                read_sockets.append(self.tcp_listener)
            read_sockets.extend(self.tcp_clients.keys())

            try:
                readable, _, errored = select.select(
                    read_sockets,
                    [],
                    list(active_sockets.keys()),
                    1.0,  # Timeout of 1s to allow periodic interface retry checks
                )
            except OSError as e:
                # Interrupted system calls (EINTR) are expected when signals arrive
                if getattr(e, "errno", None) == errno.EINTR:
                    continue
                # General bad file descriptor/socket select error (EBADF)
                if getattr(e, "errno", None) == errno.EBADF:
                    logger.error("General select error: %s", str(e))
                    # Clean up any bad file descriptors in our socket map
                    for ifname, sock in list(self.sockets.items()):
                        try:
                            select.select([sock], [], [], 0.0)
                        except OSError:
                            logger.error("Detected bad socket on %s", ifname)
                            self.mark_interface_offline(ifname)
                    continue

                logger.error("Select exception: %s", str(e))
                time.sleep(0.5)
                continue

            # Handle socket errors reported by select
            for sock in errored:
                ifname = active_sockets[sock]
                self.mark_interface_offline(ifname)

            # Process readable sockets
            for sock in readable:
                if sock == self.tcp_listener:
                    try:
                        client_sock, client_addr = self.tcp_listener.accept()
                        client_sock.setblocking(False)
                        self.tcp_clients[client_sock] = bytearray()
                        logger.debug("Accepted TCP connection from %s", str(client_addr))
                    except OSError as e:
                        logger.error("Failed to accept TCP connection: %s", str(e))
                elif sock in self.tcp_clients:
                    self._handle_client_data(sock)
                else:
                    ifname = active_sockets[sock]

                    try:
                        data, addr = sock.recvfrom(4096)
                    except OSError as e:
                        if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                            self.mark_interface_offline(ifname)
                        continue

                    # Ignore packets echoed from our own host IP address
                    if addr[0] == self.interface_ips.get(ifname):
                        continue

                    self.handle_packet(ifname, data, addr[0])

    def stop(self) -> None:
        """Stops the event loop and cleans up open sockets."""
        self.running = False
        logger.info("Stopping reflector and releasing sockets...")

        # Force a database flush on shutdown to avoid data loss
        self.command_server.flush_stats(force=True)

        # Clean up TCP listener & clients
        self.command_server.stop()

        # Clean up UDP sockets
        for sock in list(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()
        self.interface_ips.clear()

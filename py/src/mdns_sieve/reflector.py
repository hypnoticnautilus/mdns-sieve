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
from typing import Dict, Set

# Only import fcntl on UNIX platforms to keep static tools/type checkers happy
try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

from mdns_sieve.config import AppConfig
from mdns_sieve.mdns_parser import parse_mdns_packet, MdnsParsingError

logger = logging.getLogger("mdns_sieve.reflector")


# pylint: disable=too-many-instance-attributes
class MdnsReflector:
    """Core daemon service running the mDNS reflection and filtering event loop."""

    def __init__(self, config: AppConfig, verbosity: int = 0) -> None:
        self.config = config
        self.verbosity = verbosity
        self.sockets: Dict[str, socket.socket] = {}
        self.interface_ips: Dict[str, str] = {}
        self.offline_interfaces: Set[str] = set(config.interfaces)
        self.last_retry_time: float = 0.0
        self.retry_interval: float = 10.0  # Seconds between reconnection retries
        self.running: bool = False

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

    def handle_packet(self, src_interface: str, data: bytes) -> None:
        """Parses a packet, evaluates filtering rules, and replicates to allowed interfaces."""
        try:
            packet = parse_mdns_packet(data)
        except MdnsParsingError as e:
            logger.debug("Parsing failed for packet received on %s: %s", src_interface, str(e))
            return

        names = packet.extract_names()
        if not names:
            return

        for dst_interface, sock in list(self.sockets.items()):
            if dst_interface == src_interface:
                continue

            if self.config.should_forward(src_interface, dst_interface, names):
                if self.verbosity >= 2:
                    logger.debug(
                        "Forwarding mDNS packet (%d bytes) from %s -> %s for names: %s",
                        len(data),
                        src_interface,
                        dst_interface,
                        names,
                    )
                try:
                    sock.sendto(data, ("224.0.0.251", 5353))
                except OSError as e:
                    # Log failure. If it is a bad socket descriptor, mark interface offline.
                    logger.error("Transmit failed on %s: %s", dst_interface, str(e))
                    if e.errno in (errno.EBADF, errno.ENETDOWN, errno.ENETUNREACH):
                        self.mark_interface_offline(dst_interface)
            else:
                if self.verbosity >= 1:
                    logger.debug(
                        "Denied mDNS packet from %s -> %s for names: %s",
                        src_interface,
                        dst_interface,
                        names,
                    )

    # pylint: disable=too-many-branches
    def run(self) -> None:
        """Starts the main select-based routing event loop."""
        self.running = True
        self.try_initialize_interfaces()

        logger.info("mDNS Sieve Reflector is active.")
        while self.running:
            now = time.time()
            if now - self.last_retry_time >= self.retry_interval:
                self.try_initialize_interfaces()

            # Build socket poll dictionary mapping fd -> (sock, interface)
            active_sockets = {sock: ifname for ifname, sock in self.sockets.items()}
            if not active_sockets:
                logger.debug("No active interfaces. Waiting for recovery...")
                time.sleep(1.0)
                continue

            try:
                readable, _, errored = select.select(
                    list(active_sockets.keys()),
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

                self.handle_packet(ifname, data)

    def stop(self) -> None:
        """Stops the event loop and cleans up open sockets."""
        self.running = False
        logger.info("Stopping reflector and releasing sockets...")
        for sock in list(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()
        self.interface_ips.clear()

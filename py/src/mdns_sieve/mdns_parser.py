"""
mDNS Packet Parser

Provides high-performance, dependency-free binary parsing of DNS/mDNS packets
with support for label compression traversal and strict bounds checks.
"""

from dataclasses import dataclass, field
import struct
from typing import Set, Tuple, List, Optional


class MdnsParsingError(ValueError):
    """Raised when mDNS payload parsing fails due to truncation or malformation."""


@dataclass
class DNSQuestion:
    """Represents a DNS Question entry."""

    name: str
    qtype: int
    qclass: int


@dataclass
class DNSResourceRecord:
    """Represents a DNS Resource Record (Answer, Authority, or Additional)."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    target_name: Optional[str] = None  # Populated for PTR or SRV targets


@dataclass
class DNSPacket:
    """Represents a decoded DNS/mDNS packet."""

    transaction_id: int
    flags: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSResourceRecord] = field(default_factory=list)
    authorities: List[DNSResourceRecord] = field(default_factory=list)
    additionals: List[DNSResourceRecord] = field(default_factory=list)

    def extract_names(self) -> Set[str]:
        """
        Extracts all names and service types from the packet.
        This includes question names, resource record names, and any target names
        found inside PTR or SRV resource data.
        """
        names: Set[str] = set()
        for q in self.questions:
            names.add(q.name)
        for rr in self.answers + self.authorities + self.additionals:
            names.add(rr.name)
            if rr.target_name:
                names.add(rr.target_name)
        return names


# pylint: disable=too-many-branches
def parse_name(
    data: bytes, offset: int, visited: Optional[Set[int]] = None
) -> Tuple[str, int]:
    """
    Parses a DNS domain name from the binary data starting at offset.
    Traverses compression pointers safely and guards against pointer loop exploits.

    Returns:
        Tuple of (uncompressed_name_string, next_offset)
    """
    if visited is None:
        visited = set()

    labels: List[str] = []
    stepped_over_pointer = False
    next_offset = offset

    while True:
        if offset >= len(data):
            raise MdnsParsingError("Offset out of packet bounds while parsing name")

        len_byte = data[offset]

        # Check if the length byte represents a compression pointer (0b11xxxxxx)
        if (len_byte & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise MdnsParsingError("Compression pointer truncated")

            ptr_offset = ((len_byte & 0x3F) << 8) | data[offset + 1]

            if ptr_offset in visited:
                raise MdnsParsingError(
                    "Infinite recursion loop in compression pointers"
                )
            if len(visited) > 20:
                raise MdnsParsingError(
                    "Exceeded maximum compression pointer redirection depth (20)"
                )

            visited.add(ptr_offset)

            # Advance next_offset past this pointer only if we haven't already branched
            if not stepped_over_pointer:
                next_offset = offset + 2
                stepped_over_pointer = True

            # Recursively resolve the pointer's name target
            sub_name, _ = parse_name(data, ptr_offset, visited)
            if sub_name:
                labels.append(sub_name)
            break

        # Check for other invalid/reserved upper-bit configurations
        if (len_byte & 0xC0) != 0:
            raise MdnsParsingError(f"Unsupported label prefix byte 0x{len_byte:02x}")

        # Standard end-of-name indicator (0x00)
        if len_byte == 0:
            offset += 1
            if not stepped_over_pointer:
                next_offset = offset
            break

        # Standard label sequence
        offset += 1
        if offset + len_byte > len(data):
            raise MdnsParsingError("Label length exceeds packet boundary")

        label_bytes = data[offset : offset + len_byte]
        # Decode using UTF-8 or fallback to latin-1 to keep parser crash-free
        try:
            label = label_bytes.decode("utf-8")
        except UnicodeDecodeError:
            label = label_bytes.decode("latin-1")

        labels.append(label)
        offset += len_byte

    return ".".join(labels), next_offset


# pylint: disable=too-many-branches,too-many-locals
def parse_mdns_packet(data: bytes) -> DNSPacket:
    """
    Decodes a binary mDNS packet payload into a structured DNSPacket object.
    Protects the caller by safely capturing parsing issues and throwing MdnsParsingError.
    """
    if len(data) < 12:
        raise MdnsParsingError("Packet too short to contain a DNS header")

    try:
        # Header layout: ID (2B), Flags (2B), QDCOUNT (2B), ANCOUNT (2B), NSCOUNT (2B), ARCOUNT (2B)
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", data[:12]
        )

        offset = 12
        questions: List[DNSQuestion] = []
        answers: List[DNSResourceRecord] = []
        authorities: List[DNSResourceRecord] = []
        additionals: List[DNSResourceRecord] = []

        # Parser helper for Resource Records
        def parse_rr(curr_offset: int) -> Tuple[DNSResourceRecord, int]:
            name, curr_offset = parse_name(data, curr_offset)
            if curr_offset + 10 > len(data):
                raise MdnsParsingError(
                    f"Resource Record metadata truncated for name: {name}"
                )

            rtype, rclass, ttl, rdlen = struct.unpack(
                "!HHIH", data[curr_offset : curr_offset + 10]
            )
            curr_offset += 10

            if curr_offset + rdlen > len(data):
                raise MdnsParsingError(
                    f"Resource Record data truncated for name: {name}"
                )

            rdata = data[curr_offset : curr_offset + rdlen]
            curr_offset += rdlen

            # Extract targets of name-carrying resource records (PTR, SRV) for filtering
            target_name: Optional[str] = None
            try:
                if rtype == 12:  # PTR (Domain Name pointer)
                    target_name, _ = parse_name(data, curr_offset - rdlen)
                elif rtype == 33:
                    # SRV: Priority, Weight, Port, Target Name
                    if rdlen > 6:
                        target_name, _ = parse_name(data, curr_offset - rdlen + 6)
            except Exception:  # pylint: disable=broad-exception-caught
                # Safe fallback if name extraction within RDATA fails
                pass

            return DNSResourceRecord(
                name=name,
                rtype=rtype,
                rclass=rclass,
                ttl=ttl,
                rdata=rdata,
                target_name=target_name,
            ), curr_offset

        # Parse Questions Section
        for _ in range(qdcount):
            name, offset = parse_name(data, offset)
            if offset + 4 > len(data):
                raise MdnsParsingError(f"Question metadata truncated for name: {name}")
            qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

        # Parse Answers Section
        for _ in range(ancount):
            rr, offset = parse_rr(offset)
            answers.append(rr)

        # Parse Authorities Section
        for _ in range(nscount):
            rr, offset = parse_rr(offset)
            authorities.append(rr)

        # Parse Additionals Section
        for _ in range(arcount):
            rr, offset = parse_rr(offset)
            additionals.append(rr)

        return DNSPacket(
            transaction_id=tx_id,
            flags=flags,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    except Exception as e:
        if not isinstance(e, MdnsParsingError):
            raise MdnsParsingError(f"Binary parse error: {str(e)}") from e
        raise

"""
mDNS Packet Parser

Provides high-performance, dependency-free binary parsing of DNS/mDNS packets
with support for label compression traversal and strict bounds checks.
"""

from dataclasses import dataclass, field
import struct
from typing import Set, Tuple, List, Optional, Dict


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


# pylint: disable=too-many-instance-attributes
@dataclass
class DNSPacket:
    """Represents a decoded DNS/mDNS packet."""

    transaction_id: int
    flags: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSResourceRecord] = field(default_factory=list)
    authorities: List[DNSResourceRecord] = field(default_factory=list)
    additionals: List[DNSResourceRecord] = field(default_factory=list)
    _extracted_names: Optional[Set[str]] = field(default=None, init=False, repr=False)
    _extracted_question_names: Optional[Set[str]] = field(default=None, init=False, repr=False)
    _extracted_answer_names: Optional[Set[str]] = field(default=None, init=False, repr=False)

    def extract_names(self) -> Set[str]:
        """
        Extracts all names and service types from the packet.
        This includes question names, resource record names, and any target names
        found inside PTR or SRV resource data. Caches results on first evaluation.
        """
        if self._extracted_names is None:
            self._extracted_names = self.extract_question_names() | self.extract_answer_names()
        return self._extracted_names

    def extract_question_names(self) -> Set[str]:
        """Extracts and returns all names present in the Questions section."""
        if self._extracted_question_names is None:
            names: Set[str] = set()
            for q in self.questions:
                names.add(q.name)
            self._extracted_question_names = names
        return self._extracted_question_names

    def extract_answer_names(self) -> Set[str]:
        """Extracts and returns all names present in Answers, Authority, and Additionals."""
        if self._extracted_answer_names is None:
            names: Set[str] = set()
            for rr in self.answers + self.authorities + self.additionals:
                names.add(rr.name)
                if rr.target_name:
                    names.add(rr.target_name)
            self._extracted_answer_names = names
        return self._extracted_answer_names

    @property
    def is_response(self) -> bool:
        """Returns True if this is a response packet, False if it is a query packet."""
        return (self.flags & 0x8000) != 0

    def serialize(self) -> bytes:
        """
        Serializes the DNSPacket back into a binary DNS/mDNS payload.
        Implements full-name compression for all questions and resource records.
        """
        qdcount = len(self.questions)
        ancount = len(self.answers)
        nscount = len(self.authorities)
        arcount = len(self.additionals)

        buffer = bytearray(
            struct.pack(
                "!HHHHHH",
                self.transaction_id,
                self.flags,
                qdcount,
                ancount,
                nscount,
                arcount,
            )
        )
        compression_dict: Dict[str, int] = {}

        # 1. Questions
        for q in self.questions:
            qname_bytes = write_name(q.name, compression_dict, len(buffer))
            buffer.extend(qname_bytes)
            buffer.extend(struct.pack("!HH", q.qtype, q.qclass))

        # Helper to serialize a list of resource records
        def serialize_rr_list(rrs: List[DNSResourceRecord]) -> None:
            for rr in rrs:
                # Name
                name_bytes = write_name(rr.name, compression_dict, len(buffer))
                buffer.extend(name_bytes)
                # Type, Class, TTL
                buffer.extend(struct.pack("!HHI", rr.rtype, rr.rclass, rr.ttl))

                # Reserve 2 bytes for RDlen, then append serialized data, then patch
                rdlen_offset = len(buffer)
                buffer.extend(b"\x00\x00")

                start_rdata = len(buffer)

                if rr.rtype == 12 and rr.target_name:  # PTR
                    target_bytes = write_name(rr.target_name, compression_dict, len(buffer))
                    buffer.extend(target_bytes)
                elif rr.rtype == 33 and rr.target_name:  # SRV
                    priority = 0
                    weight = 0
                    port = 0
                    if len(rr.rdata) >= 6:
                        priority, weight, port = struct.unpack("!HHH", rr.rdata[:6])

                    buffer.extend(struct.pack("!HHH", priority, weight, port))
                    target_bytes = write_name(rr.target_name, compression_dict, len(buffer))
                    buffer.extend(target_bytes)
                else:
                    buffer.extend(rr.rdata)

                # Patch the RDlen field
                rdlen = len(buffer) - start_rdata
                struct.pack_into("!H", buffer, rdlen_offset, rdlen)

        # 2. Answers
        serialize_rr_list(self.answers)
        # 3. Authorities
        serialize_rr_list(self.authorities)
        # 4. Additionals
        serialize_rr_list(self.additionals)

        return bytes(buffer)


def write_name(name: str, compression_dict: Dict[str, int], current_offset: int) -> bytes:
    """
    Serializes a domain name string into DNS label format.
    Implements full-name compression by referencing compression_dict.
    """
    canon_name = name.rstrip(".").lower()
    if not canon_name:
        return b"\x00"

    if canon_name in compression_dict:
        offset = compression_dict[canon_name]
        return struct.pack("!H", 0xC000 | offset)

    compression_dict[canon_name] = current_offset

    parts = name.rstrip(".").split(".")
    out = bytearray()
    for part in parts:
        part_bytes = part.encode("utf-8")
        if len(part_bytes) > 63:
            raise ValueError("DNS label too long")
        out.append(len(part_bytes))
        out.extend(part_bytes)
    out.append(0)
    return bytes(out)


def _resolve_pointer(data: bytes, offset: int, len_byte: int, visited: Set[int]) -> str:
    """Recursively resolves a DNS compression pointer target."""
    if offset + 1 >= len(data):
        raise MdnsParsingError("Compression pointer truncated")

    ptr_offset = ((len_byte & 0x3F) << 8) | data[offset + 1]

    if ptr_offset in visited:
        raise MdnsParsingError("Infinite recursion loop in compression pointers")
    if len(visited) > 20:
        raise MdnsParsingError("Exceeded maximum compression pointer redirection depth (20)")

    visited.add(ptr_offset)
    sub_name, _ = parse_name(data, ptr_offset, visited)
    return sub_name


def _decode_label(label_bytes: bytes) -> str:
    """Decodes label bytes using UTF-8, falling back to latin-1 to keep parser crash-free."""
    try:
        return label_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return label_bytes.decode("latin-1")


def parse_name(data: bytes, offset: int, visited: Optional[Set[int]] = None) -> Tuple[str, int]:
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
            sub_name = _resolve_pointer(data, offset, len_byte, visited)
            if not stepped_over_pointer:
                next_offset = offset + 2
                stepped_over_pointer = True
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

        label = _decode_label(data[offset : offset + len_byte])
        labels.append(label)
        offset += len_byte

    return ".".join(labels), next_offset


def _parse_rr(data: bytes, curr_offset: int) -> Tuple[DNSResourceRecord, int]:
    """
    Parses a single DNS Resource Record from the binary data at the given offset.
    Extracts name, metadata, and handles specific target name parsing for PTR/SRV.
    """
    name, curr_offset = parse_name(data, curr_offset)
    if curr_offset + 10 > len(data):
        raise MdnsParsingError(f"Resource Record metadata truncated for name: {name}")

    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[curr_offset : curr_offset + 10])
    curr_offset += 10

    if curr_offset + rdlen > len(data):
        raise MdnsParsingError(f"Resource Record data truncated for name: {name}")

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


def parse_mdns_packet(data: bytes) -> DNSPacket:
    """
    Decodes a binary mDNS packet payload into a structured DNSPacket object.
    Protects the caller by safely capturing parsing issues and throwing MdnsParsingError.
    """
    if len(data) < 12:
        raise MdnsParsingError("Packet too short to contain a DNS header")

    try:
        # Header layout: ID (2B), Flags (2B), QDCOUNT (2B), ANCOUNT (2B), NSCOUNT (2B), ARCOUNT (2B)
        header = struct.unpack("!HHHHHH", data[:12])

        offset = 12
        questions: List[DNSQuestion] = []
        answers: List[DNSResourceRecord] = []
        authorities: List[DNSResourceRecord] = []
        additionals: List[DNSResourceRecord] = []

        # Parse Questions Section
        for _ in range(header[2]):  # qdcount
            name, offset = parse_name(data, offset)
            if offset + 4 > len(data):
                raise MdnsParsingError(f"Question metadata truncated for name: {name}")
            qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

        # Parse Answers Section
        for _ in range(header[3]):  # ancount
            rr, offset = _parse_rr(data, offset)
            answers.append(rr)

        # Parse Authorities Section
        for _ in range(header[4]):  # nscount
            rr, offset = _parse_rr(data, offset)
            authorities.append(rr)

        # Parse Additionals Section
        for _ in range(header[5]):  # arcount
            rr, offset = _parse_rr(data, offset)
            additionals.append(rr)

        return DNSPacket(
            transaction_id=header[0],
            flags=header[1],
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    except Exception as e:
        if not isinstance(e, MdnsParsingError):
            raise MdnsParsingError(f"Binary parse error: {str(e)}") from e
        raise

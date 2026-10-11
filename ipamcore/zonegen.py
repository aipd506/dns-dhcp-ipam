"""RFC 1035 Standard DNS Master Zone File Generator.

Supports SOA, NS, A, AAAA, CNAME, PTR, MX, TXT, SRV with RFC 1035 §3.3.14 TXT chunking.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Sequence


class RecordType(str, Enum):
    SOA = "SOA"
    NS = "NS"
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    PTR = "PTR"
    MX = "MX"
    TXT = "TXT"
    SRV = "SRV"


class DNSSyntaxError(Exception):
    """Raised when DNS record syntax or configuration is invalid."""
    pass


@dataclass
class DNSRecord:
    name: str
    record_type: RecordType
    rdata: str
    ttl: int | None = None
    priority: int | None = None  # Used for MX and SRV

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "record_type": self.record_type.value,
            "rdata": self.rdata,
            "ttl": self.ttl,
            "priority": self.priority,
        }


def chunk_txt_record(txt: str) -> str:
    """Chunks TXT records exceeding 255 bytes into quoted character-strings per RFC 1035 §3.3.14."""
    # Escape existing backslashes and double quotes
    escaped = txt.replace("\\", "\\\\").replace('"', '\\"')

    if len(escaped) <= 255:
        return f'"{escaped}"'

    chunks: list[str] = []
    # Chunk by character length <= 255, ensuring escape sequences aren't broken
    idx = 0
    while idx < len(escaped):
        chunk_len = 255
        # Don't end on an odd number of trailing backslashes
        chunk = escaped[idx : idx + chunk_len]
        if chunk.endswith("\\") and not chunk.endswith("\\\\"):
            chunk_len -= 1
            chunk = escaped[idx : idx + chunk_len]
        chunks.append(f'"{chunk}"')
        idx += chunk_len

    return " ".join(chunks)


def _ipv4_to_arpa(ip_str: str) -> str:
    octets = ip_str.strip().split(".")
    if len(octets) != 4:
        raise DNSSyntaxError(f"Invalid IPv4 address for reverse lookup: {ip_str}")
    return ".".join(reversed(octets)) + ".in-addr.arpa."


def _ipv6_to_arpa(ip_str: str) -> str:
    addr = ipaddress.IPv6Address(ip_str.strip())
    # 32 hex nibbles separated by dots reversed
    hex_str = addr.exploded.replace(":", "")
    reversed_nibbles = list(reversed(hex_str))
    return ".".join(reversed_nibbles) + ".ip6.arpa."


def _default_serial() -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return int(now.strftime("%Y%m%d01"))


def generate_forward_zone(
    origin: str,
    records: Sequence[dict[str, Any] | DNSRecord],
    default_ttl: int = 3600,
    ns: Sequence[str] | None = None,
    serial: int | None = None,
    mname: str = "ns1.example.com.",
    rname: str = "hostmaster.example.com.",
) -> str:
    """Generates an RFC 1035 compliant forward zone file."""
    norm_origin = origin.strip()
    if not norm_origin.endswith("."):
        norm_origin += "."

    if not mname.endswith("."):
        mname += "."
    if not rname.endswith("."):
        rname += "."

    soa_serial = serial if serial is not None else _default_serial()
    ns_list = list(ns) if ns else ["ns1." + norm_origin]

    lines: list[str] = [
        f"; Zone file for {norm_origin}",
        f"$ORIGIN {norm_origin}",
        f"$TTL {default_ttl}",
        "; SOA Record",
        f"@       IN  SOA     {mname} {rname} (",
        f"                    {soa_serial:<12} ; Serial",
        "                    7200         ; Refresh (2 hours)",
        "                    3600         ; Retry (1 hour)",
        "                    1209600      ; Expire (2 weeks)",
        "                    3600 )       ; Minimum TTL (1 hour)",
        "",
        "; Name Servers",
    ]

    for nameserver in ns_list:
        ns_target = nameserver.strip()
        if not ns_target.endswith("."):
            ns_target += "."
        lines.append(f"@       IN  NS      {ns_target}")

    lines.append("")
    lines.append("; Resource Records")

    for raw in records:
        if isinstance(raw, DNSRecord):
            rec = raw
        else:
            rtype = RecordType(raw["record_type"].upper())
            rec = DNSRecord(
                name=raw["name"],
                record_type=rtype,
                rdata=raw["rdata"],
                ttl=raw.get("ttl"),
                priority=raw.get("priority"),
            )

        ttl_str = f"{rec.ttl:<7}" if rec.ttl else "       "
        name_str = f"{rec.name:<15}"

        if rec.record_type == RecordType.TXT:
            formatted_rdata = chunk_txt_record(rec.rdata)
            lines.append(f"{name_str} {ttl_str} IN  TXT     {formatted_rdata}")
        elif rec.record_type == RecordType.MX:
            prio = rec.priority if rec.priority is not None else 10
            target = rec.rdata if rec.rdata.endswith(".") else f"{rec.rdata}."
            lines.append(f"{name_str} {ttl_str} IN  MX      {prio:<3} {target}")
        elif rec.record_type == RecordType.SRV:
            prio = rec.priority if rec.priority is not None else 10
            lines.append(f"{name_str} {ttl_str} IN  SRV     {prio} {rec.rdata}")
        elif rec.record_type == RecordType.CNAME:
            target = rec.rdata if rec.rdata.endswith(".") else f"{rec.rdata}."
            lines.append(f"{name_str} {ttl_str} IN  CNAME   {target}")
        else:
            lines.append(f"{name_str} {ttl_str} IN  {rec.record_type.value:<7} {rec.rdata}")

    lines.append("")
    return "\n".join(lines)


def generate_reverse_zone(
    network: str,
    records: Sequence[dict[str, Any] | tuple[str, str]],
    default_ttl: int = 3600,
    ns: Sequence[str] | None = None,
    origin: str | None = None,
    serial: int | None = None,
    mname: str = "ns1.example.com.",
    rname: str = "hostmaster.example.com.",
) -> str:
    """Generates an RFC 1035 compliant reverse zone file (in-addr.arpa or ip6.arpa)."""
    net = ipaddress.ip_network(network.strip(), strict=False)

    if origin:
        rev_origin = origin.strip()
        if not rev_origin.endswith("."):
            rev_origin += "."
    else:
        if net.version == 4:
            octets = str(net.network_address).split(".")
            # Determine prefix octet boundaries
            if net.prefixlen <= 8:
                rev_origin = f"{octets[0]}.in-addr.arpa."
            elif net.prefixlen <= 16:
                rev_origin = f"{octets[1]}.{octets[0]}.in-addr.arpa."
            elif net.prefixlen <= 24:
                rev_origin = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
            else:
                rev_origin = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
        else:
            # IPv6 prefix nibbles
            addr = net.network_address
            hex_str = addr.exploded.replace(":", "")
            nibbles_count = net.prefixlen // 4
            selected_nibbles = hex_str[:nibbles_count]
            rev_origin = ".".join(reversed(selected_nibbles)) + ".ip6.arpa."

    soa_serial = serial if serial is not None else _default_serial()
    ns_list = list(ns) if ns else ["ns1.example.com."]

    if not mname.endswith("."):
        mname += "."
    if not rname.endswith("."):
        rname += "."

    lines: list[str] = [
        f"; Reverse Zone for {net}",
        f"$ORIGIN {rev_origin}",
        f"$TTL {default_ttl}",
        "; SOA Record",
        f"@       IN  SOA     {mname} {rname} (",
        f"                    {soa_serial:<12} ; Serial",
        "                    7200         ; Refresh (2 hours)",
        "                    3600         ; Retry (1 hour)",
        "                    1209600      ; Expire (2 weeks)",
        "                    3600 )       ; Minimum TTL (1 hour)",
        "",
        "; Name Servers",
    ]

    for nameserver in ns_list:
        ns_target = nameserver.strip()
        if not ns_target.endswith("."):
            ns_target += "."
        lines.append(f"@       IN  NS      {ns_target}")

    lines.append("")
    lines.append("; PTR Records")

    for entry in records:
        if isinstance(entry, tuple):
            ip_val, hostname = entry
        elif isinstance(entry, dict):
            ip_val = entry.get("ip") or entry.get("name")
            hostname = entry.get("hostname") or entry.get("rdata")
        else:
            continue

        ip_obj = ipaddress.ip_address(str(ip_val).strip())
        target = hostname.strip()
        if not target.endswith("."):
            target += "."

        if net.version == 4:
            # Host part relative to zone origin or full reverse
            octets = str(ip_obj).split(".")
            # Relative last octet for standard /24
            last_part = octets[3]
            lines.append(f"{last_part:<15} IN  PTR     {target}")
        else:
            # Full reverse IPv6 PTR
            arpa_name = _ipv6_to_arpa(str(ip_obj))
            lines.append(f"{arpa_name:<64} IN  PTR     {target}")

    lines.append("")
    return "\n".join(lines)

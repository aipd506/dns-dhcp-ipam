"""IPv4/IPv6 CIDR Subnet Calculator, Splitter, Summarizer, and Allocation Engine.

Pure Python standard library implementation using ipaddress.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


class PoolExhaustedError(Exception):
    """Raised when no usable IP addresses remain in the specified subnet pool."""
    pass


@dataclass(frozen=True)
class SubnetInfo:
    network_address: str
    broadcast_address: str | None
    netmask: str
    hostmask: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_usable_ip: str | None
    last_usable_ip: str | None
    ip_version: int
    is_private: bool
    is_global: bool
    is_loopback: bool
    is_multicast: bool

    def to_dict(self) -> dict:
        return asdict(self)


def get_subnet_info(cidr: str) -> SubnetInfo:
    """Calculates detailed subnet information for IPv4 or IPv6 CIDR."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    version = net.version
    total = net.num_addresses
    prefix = net.prefixlen

    if version == 4:
        if prefix == 32:
            broadcast = None
            usable = 1
            first_usable = str(net.network_address)
            last_usable = str(net.network_address)
        elif prefix == 31:
            # RFC 3021: Point-to-Point links with 31-bit prefixes
            broadcast = None
            usable = 2
            first_usable = str(net.network_address)
            last_usable = str(net.network_address + 1)
        else:
            broadcast = str(net.broadcast_address)
            usable = max(0, total - 2)
            first_usable = str(net.network_address + 1) if usable > 0 else None
            last_usable = str(net.broadcast_address - 1) if usable > 0 else None
    else:  # IPv6
        broadcast = None
        if prefix == 128:
            usable = 1
            first_usable = str(net.network_address)
            last_usable = str(net.network_address)
        elif prefix == 127:
            # RFC 6164: Inter-router links with 127-bit prefixes
            usable = 2
            first_usable = str(net.network_address)
            last_usable = str(net.network_address + 1)
        else:
            # Exclude subnet router anycast address (::0)
            usable = total - 1
            first_usable = str(net.network_address + 1)
            last_ip = net.network_address + (total - 1)
            last_usable = str(last_ip)

    return SubnetInfo(
        network_address=str(net.network_address),
        broadcast_address=broadcast,
        netmask=str(net.netmask),
        hostmask=str(net.hostmask),
        prefix_length=prefix,
        total_addresses=total,
        usable_hosts=usable,
        first_usable_ip=first_usable,
        last_usable_ip=last_usable,
        ip_version=version,
        is_private=net.is_private,
        is_global=net.is_global,
        is_loopback=net.is_loopback,
        is_multicast=net.is_multicast,
    )


def split_subnet(
    cidr: str,
    new_prefix: int | None = None,
    count: int | None = None,
) -> list[str]:
    """Divides an IPv4/IPv6 CIDR into sub-prefixes or target subnet count."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    max_prefix = 32 if net.version == 4 else 128

    if new_prefix is not None:
        if new_prefix > max_prefix:
            raise ValueError(
                f"Prefix length {new_prefix} invalid for IPv{net.version} (maximum is {max_prefix})."
            )
        if new_prefix < net.prefixlen:
            raise ValueError(
                f"New prefix length ({new_prefix}) must be greater than or equal to base prefix length ({net.prefixlen})."
            )
        if new_prefix == net.prefixlen:
            return [str(net)]
        return [str(sub) for sub in net.subnets(new_prefix=new_prefix)]

    if count is not None:
        if count <= 0:
            raise ValueError("Count must be a positive integer.")
        if count == 1:
            return [str(net)]
        bits_needed = math.ceil(math.log2(count))
        target_prefix = net.prefixlen + bits_needed
        if target_prefix > max_prefix:
            raise ValueError(
                f"Cannot split /{net.prefixlen} into {count} subnets: prefix would be /{target_prefix} (maximum is /{max_prefix})."
            )
        subnets = [str(sub) for sub in net.subnets(new_prefix=target_prefix)]
        return subnets[:count]

    raise ValueError("Must specify either new_prefix or count.")


def summarize_subnets(cidrs: Sequence[str]) -> list[str]:
    """Merges adjacent and enclosed CIDR subnets into minimal supernet set."""
    if not cidrs:
        return []
    nets = [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs if c.strip()]
    collapsed = ipaddress.collapse_addresses(nets)
    return [str(c) for c in sorted(collapsed, key=lambda n: (n.version, n.network_address, n.prefixlen))]


def next_available_ip(cidr: str, allocated: Iterable[str]) -> str:
    """Finds the lowest unassigned usable IP address in a subnet given allocated IPs."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    allocated_set = {
        ipaddress.ip_address(str(ip).strip())
        for ip in allocated
        if str(ip).strip()
    }

    if net.version == 4:
        if net.prefixlen == 32:
            usable_iter = [net.network_address]
        elif net.prefixlen == 31:
            usable_iter = [net.network_address, net.network_address + 1]
        else:
            usable_iter = net.hosts()
    else:  # IPv6
        if net.prefixlen == 128:
            usable_iter = [net.network_address]
        elif net.prefixlen == 127:
            usable_iter = [net.network_address, net.network_address + 1]
        else:
            # Generator for IPv6 starting after ::0
            def _v6_hosts():
                curr = int(net.network_address) + 1
                end = int(net.network_address) + net.num_addresses - 1
                while curr <= end:
                    yield ipaddress.IPv6Address(curr)
                    curr += 1
            usable_iter = _v6_hosts()

    for candidate in usable_iter:
        if candidate not in allocated_set:
            return str(candidate)

    raise PoolExhaustedError(
        f"Subnet {cidr} is exhausted: all usable IP addresses are already allocated."
    )

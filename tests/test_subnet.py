"""Tests for subnet calculator, splitter, summarizer, and allocation engine."""

import pytest
from ipamcore.subnet import (
    PoolExhaustedError,
    get_subnet_info,
    next_available_ip,
    split_subnet,
    summarize_subnets,
)


def test_ipv4_standard_subnet_info():
    info = get_subnet_info("192.168.1.0/24")
    assert info.network_address == "192.168.1.0"
    assert info.broadcast_address == "192.168.1.255"
    assert info.netmask == "255.255.255.0"
    assert info.hostmask == "0.0.0.255"
    assert info.prefix_length == 24
    assert info.total_addresses == 256
    assert info.usable_hosts == 254
    assert info.first_usable_ip == "192.168.1.1"
    assert info.last_usable_ip == "192.168.1.254"
    assert info.ip_version == 4
    assert info.is_private is True
    assert info.is_loopback is False


def test_ipv4_point_to_point_rfc3021():
    """IPv4 /31 per RFC 3021 has 2 usable addresses and no broadcast."""
    info = get_subnet_info("10.0.0.0/31")
    assert info.total_addresses == 2
    assert info.usable_hosts == 2
    assert info.broadcast_address is None
    assert info.first_usable_ip == "10.0.0.0"
    assert info.last_usable_ip == "10.0.0.1"


def test_ipv4_host_route_32():
    info = get_subnet_info("10.0.0.5/32")
    assert info.total_addresses == 1
    assert info.usable_hosts == 1
    assert info.broadcast_address is None
    assert info.first_usable_ip == "10.0.0.5"
    assert info.last_usable_ip == "10.0.0.5"


def test_ipv6_subnet_info():
    info = get_subnet_info("2001:db8::/64")
    assert info.ip_version == 6
    assert info.network_address == "2001:db8::"
    assert info.broadcast_address is None
    assert info.first_usable_ip == "2001:db8::1"
    assert info.usable_hosts == (2**64) - 1


def test_ipv6_inter_router_rfc6164():
    """IPv6 /127 per RFC 6164 has 2 usable addresses."""
    info = get_subnet_info("2001:db8::/127")
    assert info.total_addresses == 2
    assert info.usable_hosts == 2
    assert info.broadcast_address is None
    assert info.first_usable_ip == "2001:db8::"
    assert info.last_usable_ip == "2001:db8::1"


def test_split_subnet_by_prefix():
    subs = split_subnet("192.168.1.0/24", new_prefix=26)
    assert len(subs) == 4
    assert subs[0] == "192.168.1.0/26"
    assert subs[1] == "192.168.1.64/26"
    assert subs[2] == "192.168.1.128/26"
    assert subs[3] == "192.168.1.192/26"


def test_split_subnet_by_count():
    subs = split_subnet("10.0.0.0/16", count=4)
    assert len(subs) == 4
    assert subs[0] == "10.0.0.0/18"
    assert subs[1] == "10.0.64.0/18"


def test_split_subnet_edge_cases():
    # Same prefix returns original
    assert split_subnet("192.168.1.0/24", new_prefix=24) == ["192.168.1.0/24"]

    # Shorter prefix raises ValueError
    with pytest.raises(ValueError):
        split_subnet("192.168.1.0/24", new_prefix=23)

    # Prefix > 32 for IPv4 raises ValueError
    with pytest.raises(ValueError):
        split_subnet("192.168.1.0/32", new_prefix=33)


def test_summarize_subnets():
    # Contiguous subnets merge
    cidrs = ["10.0.0.0/24", "10.0.1.0/24"]
    summarized = summarize_subnets(cidrs)
    assert summarized == ["10.0.0.0/23"]

    # Discontiguous subnets remain separate
    discontiguous = ["10.0.0.0/24", "10.0.2.0/24"]
    assert summarize_subnets(discontiguous) == ["10.0.0.0/24", "10.0.2.0/24"]

    # Enclosed subnet collapsed
    enclosed = ["10.0.0.0/16", "10.0.5.0/24"]
    assert summarize_subnets(enclosed) == ["10.0.0.0/16"]


def test_next_available_ip():
    allocated = ["192.168.1.1", "192.168.1.2"]
    next_ip = next_available_ip("192.168.1.0/24", allocated)
    assert next_ip == "192.168.1.3"

    # Next ip for /31
    next_31 = next_available_ip("10.0.0.0/31", ["10.0.0.0"])
    assert next_31 == "10.0.0.1"


def test_next_available_ip_pool_exhausted():
    # /30 has 2 usable IPs: .1 and .2
    with pytest.raises(PoolExhaustedError):
        next_available_ip("192.168.1.0/30", ["192.168.1.1", "192.168.1.2"])

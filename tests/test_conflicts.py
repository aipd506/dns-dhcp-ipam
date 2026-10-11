"""Tests for subnet and IP allocation conflict detector."""

from ipamcore.conflicts import ConflictType, detect_conflicts


def test_detect_no_conflicts():
    cidrs = ["10.0.0.0/24", "10.0.1.0/24", "192.168.1.0/24"]
    conflicts = detect_conflicts(cidrs)
    assert len(conflicts) == 0


def test_detect_exact_match():
    cidrs = ["172.16.0.0/16", "172.16.0.0/16"]
    conflicts = detect_conflicts(cidrs)
    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == ConflictType.EXACT_MATCH
    assert "identical" in conflicts[0].description


def test_detect_containment():
    cidrs = ["10.0.0.0/8", "10.50.0.0/16"]
    conflicts = detect_conflicts(cidrs)
    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == ConflictType.CONTAINMENT
    assert "enclosed within" in conflicts[0].description


def test_detect_multiple_conflicts():
    cidrs = [
        "192.168.0.0/16",
        "192.168.1.0/24",
        "192.168.1.0/24",  # duplicate of above
        "10.0.0.0/24",
    ]
    conflicts = detect_conflicts(cidrs)
    # 192.168.0.0/16 contains 192.168.1.0/24 (first)
    # 192.168.0.0/16 contains 192.168.1.0/24 (second)
    # 192.168.1.0/24 exact match 192.168.1.0/24
    assert len(conflicts) == 3


def test_ipv4_and_ipv6_isolation():
    # IPv4 and IPv6 subnets do not conflict
    cidrs = ["10.0.0.0/24", "2001:db8::/64"]
    conflicts = detect_conflicts(cidrs)
    assert len(conflicts) == 0

"""Tests for DHCP lease lifecycle tracking and MAC normalization."""

import pytest
from ipamcore.dhcp import (
    DHCPTracker,
    InvalidMACAddressError,
    LeaseConflictError,
    LeaseExpiredError,
    LeaseNotFoundError,
    LeaseState,
    normalize_mac,
)


def test_mac_normalization():
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"


def test_invalid_mac_addresses():
    with pytest.raises(InvalidMACAddressError):
        normalize_mac("ZZ:11:22:33:44:55")
    with pytest.raises(InvalidMACAddressError):
        normalize_mac("11:22:33")
    with pytest.raises(InvalidMACAddressError):
        normalize_mac("")


def test_dhcp_allocation_and_retrieval():
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    lease = tracker.allocate(
        mac="aa:bb:cc:dd:ee:01",
        subnet="192.168.1.0/24",
        hostname="web-1",
        duration=3600,
        now=now,
    )
    assert lease.mac_address == "AA:BB:CC:DD:EE:01"
    assert lease.ip_address == "192.168.1.1"
    assert lease.state == LeaseState.BOUND
    assert lease.lease_end == 4600.0

    leases = tracker.list_leases(now=now)
    assert len(leases) == 1
    assert leases[0].mac_address == "AA:BB:CC:DD:EE:01"


def test_dhcp_multiple_allocations_in_subnet():
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    l1 = tracker.allocate(mac="aa:bb:cc:dd:ee:01", subnet="192.168.1.0/24", now=now)
    l2 = tracker.allocate(mac="aa:bb:cc:dd:ee:02", subnet="192.168.1.0/24", now=now)
    assert l1.ip_address == "192.168.1.1"
    assert l2.ip_address == "192.168.1.2"


def test_dhcp_requested_ip_conflict():
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    tracker.allocate(
        mac="aa:bb:cc:dd:ee:01",
        subnet="192.168.1.0/24",
        requested_ip="192.168.1.50",
        now=now,
    )
    # Another MAC requesting the same active IP raises LeaseConflictError
    with pytest.raises(LeaseConflictError):
        tracker.allocate(
            mac="aa:bb:cc:dd:ee:02",
            subnet="192.168.1.0/24",
            requested_ip="192.168.1.50",
            now=now,
        )


def test_dhcp_renew_active_lease():
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    tracker.allocate(
        mac="aa:bb:cc:dd:ee:01",
        subnet="192.168.1.0/24",
        duration=3600,
        now=now,
    )
    # Renew at now = 2000
    renewed = tracker.renew(
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.1",
        duration=3600,
        now=2000.0,
    )
    assert renewed.lease_end == 5600.0


def test_dhcp_renew_expired_refused():
    """Edge Case #12: Renewing a lease that has transitioned to EXPIRED must be refused."""
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    tracker.allocate(
        mac="aa:bb:cc:dd:ee:01",
        subnet="192.168.1.0/24",
        duration=3600,
        now=now,
    )
    # Try renewing at now = 5000 (after lease_end = 4600)
    with pytest.raises(LeaseExpiredError):
        tracker.renew(
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.1",
            now=5000.0,
        )


def test_dhcp_release_and_reclaim():
    tracker = DHCPTracker(":memory:")
    now = 1000.0
    tracker.allocate(mac="aa:bb:cc:dd:ee:01", subnet="192.168.1.0/30", now=now)
    # Release lease
    tracker.release(mac="aa:bb:cc:dd:ee:01", now=now)
    leases = tracker.list_leases(now=now)
    assert leases[0].state == LeaseState.RELEASED

    # Re-allocation can reclaim the released IP
    l2 = tracker.allocate(mac="aa:bb:cc:dd:ee:02", subnet="192.168.1.0/30", now=now)
    assert l2.ip_address == "192.168.1.1"


def test_dhcp_prune():
    tracker = DHCPTracker(":memory:")
    tracker.allocate(mac="aa:bb:cc:dd:ee:01", subnet="10.0.0.0/24", duration=100, now=1000.0)
    # Advance time to 2000.0
    pruned = tracker.prune(expired_only=True, retention=0, now=2000.0)
    assert pruned == 1
    assert len(tracker.list_leases(now=2000.0)) == 0

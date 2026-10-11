"""ipamcore: Enterprise IPAM, Subnetting, DHCP Lease Tracking, and DNS Zone Generation.

Zero-dependency standard library implementation.
"""

__version__ = "0.1.0"

from ipamcore.subnet import SubnetInfo, get_subnet_info, split_subnet, summarize_subnets, next_available_ip, PoolExhaustedError
from ipamcore.conflicts import SubnetConflict, ConflictType, detect_conflicts
from ipamcore.dhcp import DHCPLease, LeaseState, DHCPTracker, normalize_mac, InvalidMACAddressError, LeaseConflictError, LeaseNotFoundError
from ipamcore.zonegen import RecordType, DNSRecord, generate_forward_zone, generate_reverse_zone, chunk_txt_record

__all__ = [
    "SubnetInfo",
    "get_subnet_info",
    "split_subnet",
    "summarize_subnets",
    "next_available_ip",
    "PoolExhaustedError",
    "SubnetConflict",
    "ConflictType",
    "detect_conflicts",
    "DHCPLease",
    "LeaseState",
    "DHCPTracker",
    "normalize_mac",
    "InvalidMACAddressError",
    "LeaseConflictError",
    "LeaseNotFoundError",
    "RecordType",
    "DNSRecord",
    "generate_forward_zone",
    "generate_reverse_zone",
    "chunk_txt_record",
]

"""Overlapping Subnet and IP Allocation Conflict Detector.

Detects EXACT_MATCH, CONTAINMENT, and PARTIAL_OVERLAP across IPv4/IPv6 networks.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Sequence


class ConflictType(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    CONTAINMENT = "CONTAINMENT"
    PARTIAL_OVERLAP = "PARTIAL_OVERLAP"


@dataclass(frozen=True)
class SubnetConflict:
    subnet_a: str
    subnet_b: str
    conflict_type: ConflictType
    description: str

    def to_dict(self) -> dict:
        return {
            "subnet_a": self.subnet_a,
            "subnet_b": self.subnet_b,
            "conflict_type": self.conflict_type.value,
            "description": self.description,
        }


def detect_conflicts(cidrs: Sequence[str]) -> list[SubnetConflict]:
    """Scans a list of CIDR strings for overlap and containment conflicts."""
    parsed_nets: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for raw in cidrs:
        clean = raw.strip()
        if not clean:
            continue
        net = ipaddress.ip_network(clean, strict=False)
        parsed_nets.append((clean, net))

    conflicts: list[SubnetConflict] = []
    n = len(parsed_nets)

    for i in range(n):
        orig_a, net_a = parsed_nets[i]
        for j in range(i + 1, n):
            orig_b, net_b = parsed_nets[j]

            # Different IP versions cannot conflict
            if net_a.version != net_b.version:
                continue

            if net_a == net_b:
                conflicts.append(
                    SubnetConflict(
                        subnet_a=orig_a,
                        subnet_b=orig_b,
                        conflict_type=ConflictType.EXACT_MATCH,
                        description=f"Exact duplicate network allocation: {orig_a} is identical to {orig_b}",
                    )
                )
            elif net_a.overlaps(net_b):
                if net_a.subnet_of(net_b):
                    conflicts.append(
                        SubnetConflict(
                            subnet_a=orig_a,
                            subnet_b=orig_b,
                            conflict_type=ConflictType.CONTAINMENT,
                            description=f"Containment conflict: {orig_a} is enclosed within parent {orig_b}",
                        )
                    )
                elif net_b.subnet_of(net_a):
                    conflicts.append(
                        SubnetConflict(
                            subnet_a=orig_a,
                            subnet_b=orig_b,
                            conflict_type=ConflictType.CONTAINMENT,
                            description=f"Containment conflict: {orig_b} is enclosed within parent {orig_a}",
                        )
                    )
                else:
                    conflicts.append(
                        SubnetConflict(
                            subnet_a=orig_a,
                            subnet_b=orig_b,
                            conflict_type=ConflictType.PARTIAL_OVERLAP,
                            description=f"Partial overlap conflict between {orig_a} and {orig_b}",
                        )
                    )

    return conflicts

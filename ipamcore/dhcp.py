"""Stateful DHCP Lease Lifecycle Coordinator.

Manages lease lifecycle (OFFERED, BOUND, EXPIRED, RELEASED, DECLINED) backed by SQLite.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ipamcore.subnet import PoolExhaustedError, next_available_ip


class LeaseState(str, Enum):
    OFFERED = "OFFERED"
    BOUND = "BOUND"
    EXPIRED = "EXPIRED"
    RELEASED = "RELEASED"
    DECLINED = "DECLINED"


class InvalidMACAddressError(Exception):
    """Raised when a MAC address format is invalid."""
    pass


class LeaseConflictError(Exception):
    """Raised when an IP or MAC is already bound in conflict."""
    pass


class LeaseNotFoundError(Exception):
    """Raised when a specified lease cannot be found or is not active."""
    pass


class LeaseExpiredError(Exception):
    """Raised when attempting to renew an expired lease."""
    pass


def normalize_mac(mac: str) -> str:
    """Normalizes MAC address into standard uppercase colon-separated format (AA:BB:CC:DD:EE:FF)."""
    if not mac:
        raise InvalidMACAddressError("MAC address string cannot be empty.")
    
    # Strip delimiters
    cleaned = re.sub(r"[\s:\.-]", "", mac.strip())
    if len(cleaned) != 12:
        raise InvalidMACAddressError(f"Invalid MAC address '{mac}': expected 12 hexadecimal digits, got {len(cleaned)}.")
    
    if not re.fullmatch(r"[0-9a-fA-F]{12}", cleaned):
        raise InvalidMACAddressError(f"Invalid MAC address '{mac}': contains non-hexadecimal characters.")

    upper = cleaned.upper()
    return ":".join(upper[i : i + 2] for i in range(0, 12, 2))


@dataclass
class DHCPLease:
    mac_address: str
    ip_address: str
    subnet: str
    hostname: str | None
    state: LeaseState
    lease_start: float
    lease_duration: int
    lease_end: float
    client_id: str | None = None
    options: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "subnet": self.subnet,
            "hostname": self.hostname,
            "state": self.state.value if isinstance(self.state, LeaseState) else str(self.state),
            "lease_start": self.lease_start,
            "lease_duration": self.lease_duration,
            "lease_end": self.lease_end,
            "client_id": self.client_id,
            "options": self.options,
        }


class DHCPTracker:
    """SQLite-backed persistent DHCP lease state tracker."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dhcp_leases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    subnet TEXT NOT NULL,
                    hostname TEXT,
                    state TEXT NOT NULL,
                    lease_start REAL NOT NULL,
                    lease_duration INTEGER NOT NULL,
                    lease_end REAL NOT NULL,
                    client_id TEXT,
                    options_json TEXT NOT NULL
                )
                """
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_mac ON dhcp_leases(mac_address)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON dhcp_leases(ip_address)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_state ON dhcp_leases(state)")

    def close(self) -> None:
        self.conn.close()

    def _sync_expired(self, current_time: float) -> None:
        with self.conn:
            self.conn.execute(
                """
                UPDATE dhcp_leases
                SET state = 'EXPIRED'
                WHERE state = 'BOUND' AND lease_end <= ?
                """,
                (current_time,),
            )

    def allocate(
        self,
        mac: str,
        subnet: str,
        requested_ip: str | None = None,
        hostname: str | None = None,
        duration: int = 86400,
        client_id: str | None = None,
        options: dict[str, str] | None = None,
        now: float | None = None,
    ) -> DHCPLease:
        """Allocates or updates a DHCP lease for a normalized MAC address."""
        current_time = time.time() if now is None else float(now)
        norm_mac = normalize_mac(mac)
        net = ipaddress.ip_network(subnet.strip(), strict=False)
        opts = options or {}

        self._sync_expired(current_time)

        # Check if MAC already has an active BOUND lease in this subnet
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM dhcp_leases
            WHERE mac_address = ? AND subnet = ? AND state = 'BOUND' AND lease_end > ?
            ORDER BY id DESC LIMIT 1
            """,
            (norm_mac, str(net), current_time),
        )
        existing = cur.fetchone()

        if requested_ip:
            target_ip_obj = ipaddress.ip_address(requested_ip.strip())
            if target_ip_obj not in net:
                raise ValueError(f"Requested IP {requested_ip} does not belong to subnet {subnet}")
            target_ip_str = str(target_ip_obj)

            # Check if target IP is bound to someone else
            cur.execute(
                """
                SELECT * FROM dhcp_leases
                WHERE ip_address = ? AND state = 'BOUND' AND lease_end > ? AND mac_address != ?
                LIMIT 1
                """,
                (target_ip_str, current_time, norm_mac),
            )
            conflict = cur.fetchone()
            if conflict:
                raise LeaseConflictError(
                    f"Requested IP {target_ip_str} is currently bound to another MAC ({conflict['mac_address']})"
                )
            assigned_ip = target_ip_str
        elif existing:
            # Re-use already bound IP for this MAC
            assigned_ip = existing["ip_address"]
        else:
            # Find active BOUND IPs in this subnet
            cur.execute(
                """
                SELECT ip_address FROM dhcp_leases
                WHERE subnet = ? AND state = 'BOUND' AND lease_end > ?
                """,
                (str(net), current_time),
            )
            active_ips = {row["ip_address"] for row in cur.fetchall()}
            assigned_ip = next_available_ip(str(net), active_ips)

        lease_end = current_time + duration
        with self.conn:
            # Retire any previous leases for this mac or ip
            self.conn.execute(
                """
                UPDATE dhcp_leases
                SET state = 'RELEASED'
                WHERE (mac_address = ? OR ip_address = ?) AND state = 'BOUND'
                """,
                (norm_mac, assigned_ip),
            )
            self.conn.execute(
                """
                INSERT INTO dhcp_leases (
                    mac_address, ip_address, subnet, hostname, state,
                    lease_start, lease_duration, lease_end, client_id, options_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    norm_mac,
                    assigned_ip,
                    str(net),
                    hostname,
                    LeaseState.BOUND.value,
                    current_time,
                    duration,
                    lease_end,
                    client_id,
                    json.dumps(opts),
                ),
            )

        return DHCPLease(
            mac_address=norm_mac,
            ip_address=assigned_ip,
            subnet=str(net),
            hostname=hostname,
            state=LeaseState.BOUND,
            lease_start=current_time,
            lease_duration=duration,
            lease_end=lease_end,
            client_id=client_id,
            options=opts,
        )

    def renew(
        self,
        mac: str,
        ip: str,
        duration: int = 86400,
        now: float | None = None,
    ) -> DHCPLease:
        """Renews an active DHCP lease. Refuses renewal if already expired."""
        current_time = time.time() if now is None else float(now)
        norm_mac = normalize_mac(mac)
        target_ip = str(ipaddress.ip_address(ip.strip()))

        self._sync_expired(current_time)

        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM dhcp_leases
            WHERE mac_address = ? AND ip_address = ?
            ORDER BY id DESC LIMIT 1
            """,
            (norm_mac, target_ip),
        )
        row = cur.fetchone()

        if not row:
            raise LeaseNotFoundError(f"No lease found for MAC {norm_mac} and IP {target_ip}.")

        if row["state"] != LeaseState.BOUND.value or row["lease_end"] <= current_time:
            raise LeaseExpiredError(
                f"Lease for MAC {norm_mac} and IP {target_ip} is {row['state']}. Cannot renew expired lease; fresh allocation required."
            )

        new_end = current_time + duration
        with self.conn:
            self.conn.execute(
                """
                UPDATE dhcp_leases
                SET lease_duration = ?, lease_end = ?
                WHERE id = ?
                """,
                (duration, new_end, row["id"]),
            )

        return DHCPLease(
            mac_address=norm_mac,
            ip_address=target_ip,
            subnet=row["subnet"],
            hostname=row["hostname"],
            state=LeaseState.BOUND,
            lease_start=row["lease_start"],
            lease_duration=duration,
            lease_end=new_end,
            client_id=row["client_id"],
            options=json.loads(row["options_json"]),
        )

    def release(
        self,
        mac: str | None = None,
        ip: str | None = None,
        now: float | None = None,
    ) -> bool:
        """Relinquishes an active lease immediately, setting state to RELEASED."""
        current_time = time.time() if now is None else float(now)
        self._sync_expired(current_time)

        if not mac and not ip:
            raise ValueError("Must provide either mac or ip to release lease.")

        clauses = []
        params = []
        if mac:
            clauses.append("mac_address = ?")
            params.append(normalize_mac(mac))
        if ip:
            clauses.append("ip_address = ?")
            params.append(str(ipaddress.ip_address(ip.strip())))

        where_clause = " AND ".join(clauses)
        params.extend([current_time])

        cur = self.conn.cursor()
        cur.execute(
            f"""
            SELECT id FROM dhcp_leases
            WHERE {where_clause} AND state = 'BOUND' AND lease_end > ?
            ORDER BY id DESC LIMIT 1
            """,
            params,
        )
        row = cur.fetchone()
        if not row:
            raise LeaseNotFoundError("No active BOUND lease found matching criteria.")

        with self.conn:
            self.conn.execute(
                "UPDATE dhcp_leases SET state = 'RELEASED' WHERE id = ?",
                (row["id"],),
            )
        return True

    def list_leases(
        self,
        state: LeaseState | str | None = None,
        subnet: str | None = None,
        now: float | None = None,
    ) -> list[DHCPLease]:
        """Lists leases matching optional state and subnet filters."""
        current_time = time.time() if now is None else float(now)
        self._sync_expired(current_time)

        query = "SELECT * FROM dhcp_leases WHERE 1=1"
        params: list[Any] = []

        if state:
            st_val = state.value if isinstance(state, LeaseState) else str(state)
            query += " AND state = ?"
            params.append(st_val)

        if subnet:
            net = ipaddress.ip_network(subnet.strip(), strict=False)
            query += " AND subnet = ?"
            params.append(str(net))

        query += " ORDER BY id ASC"

        cur = self.conn.cursor()
        cur.execute(query, params)
        leases: list[DHCPLease] = []
        for row in cur.fetchall():
            leases.append(
                DHCPLease(
                    mac_address=row["mac_address"],
                    ip_address=row["ip_address"],
                    subnet=row["subnet"],
                    hostname=row["hostname"],
                    state=LeaseState(row["state"]),
                    lease_start=row["lease_start"],
                    lease_duration=row["lease_duration"],
                    lease_end=row["lease_end"],
                    client_id=row["client_id"],
                    options=json.loads(row["options_json"]),
                )
            )
        return leases

    def prune(
        self,
        expired_only: bool = True,
        retention: int = 0,
        now: float | None = None,
    ) -> int:
        """Removes expired (and optionally released) lease records older than retention seconds."""
        current_time = time.time() if now is None else float(now)
        self._sync_expired(current_time)

        threshold = current_time - retention
        if expired_only:
            query = "DELETE FROM dhcp_leases WHERE state = 'EXPIRED' AND lease_end <= ?"
        else:
            query = "DELETE FROM dhcp_leases WHERE state IN ('EXPIRED', 'RELEASED') AND lease_end <= ?"

        with self.conn:
            res = self.conn.execute(query, (threshold,))
            return res.rowcount

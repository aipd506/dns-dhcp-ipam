"""CLI Entry Point for ipamcore.

Subcommands: subnet, conflicts, dhcp, zonegen.
Exit codes: 0 = Success, 1 = Validation/Operational error, 2 = CLI argument error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ipamcore.conflicts import detect_conflicts
from ipamcore.dhcp import (
    DHCPTracker,
    InvalidMACAddressError,
    LeaseConflictError,
    LeaseExpiredError,
    LeaseNotFoundError,
)
from ipamcore.subnet import (
    PoolExhaustedError,
    get_subnet_info,
    next_available_ip,
    split_subnet,
    summarize_subnets,
)
from ipamcore.zonegen import generate_forward_zone, generate_reverse_zone


def _print_output(data: Any, as_json: bool = False, text_fallback: str | None = None) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    elif text_fallback is not None:
        print(text_fallback)
    elif isinstance(data, dict):
        for k, v in data.items():
            print(f"{k}: {v}")
    elif isinstance(data, list):
        for item in data:
            print(item)
    else:
        print(str(data))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipamcore",
        description="Enterprise IPAM, Subnetting, DHCP Lease Tracking, and RFC 1035 Zone Generation",
    )
    parser.add_argument("--version", action="version", version="ipamcore 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. Subnet
    subnet_parser = subparsers.add_parser("subnet", help="Subnetting calculations and allocations")
    subnet_sub = subnet_parser.add_subparsers(dest="subnet_action", required=True)

    # subnet info
    info_p = subnet_sub.add_parser("info", help="Display subnet metrics")
    info_p.add_argument("cidr", help="CIDR network notation (e.g., 10.0.0.0/24 or 2001:db8::/64)")
    info_p.add_argument("--json", action="store_true", help="Output as JSON")

    # subnet split
    split_p = subnet_sub.add_parser("split", help="Divide subnet into smaller prefixes or count")
    split_p.add_argument("cidr", help="Base CIDR network")
    split_group = split_p.add_mutually_exclusive_group(required=True)
    split_group.add_argument("--prefix", type=int, help="Target subnet prefix length")
    split_group.add_argument("--count", type=int, help="Number of subnets to create")
    split_p.add_argument("--json", action="store_true", help="Output as JSON")

    # subnet summarize
    summ_p = subnet_sub.add_parser("summarize", help="Merge adjacent subnets into supernets")
    summ_p.add_argument("cidrs", nargs="*", help="List of CIDR strings")
    summ_p.add_argument("--file", help="Path to file containing CIDR lines")
    summ_p.add_argument("--json", action="store_true", help="Output as JSON")

    # subnet next-ip
    next_p = subnet_sub.add_parser("next-ip", help="Find next available unassigned IP")
    next_p.add_argument("cidr", help="Subnet CIDR")
    next_p.add_argument("--allocated", help="Comma-separated list of allocated IPs")
    next_p.add_argument("--allocated-file", help="Path to file containing allocated IP lines")
    next_p.add_argument("--json", action="store_true", help="Output as JSON")

    # 2. Conflicts
    conflict_parser = subparsers.add_parser("conflicts", help="Conflict and overlap detection")
    conflict_parser.add_argument("cidrs", nargs="*", help="List of CIDRs to check (optional subaction 'check')")
    conflict_parser.add_argument("--subnets", nargs="*", help="List of CIDRs to check")
    conflict_parser.add_argument("--file", help="Path to file containing CIDRs")
    conflict_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # 3. DHCP
    dhcp_parser = subparsers.add_parser("dhcp", help="DHCP lease lifecycle manager")
    dhcp_sub = dhcp_parser.add_subparsers(dest="dhcp_action", required=True)

    # dhcp allocate
    alloc_p = dhcp_sub.add_parser("allocate", help="Allocate or bind lease")
    alloc_p.add_argument("--mac", required=True, help="Client MAC address")
    alloc_p.add_argument("--subnet", required=True, help="Subnet CIDR")
    alloc_p.add_argument("--ip", help="Requested static IP address")
    alloc_p.add_argument("--hostname", help="Client hostname")
    alloc_p.add_argument("--duration", type=int, default=86400, help="Lease duration in seconds")
    alloc_p.add_argument("--db", default=":memory:", help="SQLite database path")
    alloc_p.add_argument("--json", action="store_true", help="Output as JSON")

    # dhcp renew
    renew_p = dhcp_sub.add_parser("renew", help="Renew existing lease")
    renew_p.add_argument("--mac", required=True, help="Client MAC address")
    renew_p.add_argument("--ip", required=True, help="Bound IP address")
    renew_p.add_argument("--duration", type=int, default=86400, help="Lease duration in seconds")
    renew_p.add_argument("--db", default=":memory:", help="SQLite database path")
    renew_p.add_argument("--json", action="store_true", help="Output as JSON")

    # dhcp release
    rel_p = dhcp_sub.add_parser("release", help="Release active lease")
    rel_p.add_argument("--mac", help="Client MAC address")
    rel_p.add_argument("--ip", help="Bound IP address")
    rel_p.add_argument("--db", default=":memory:", help="SQLite database path")
    rel_p.add_argument("--json", action="store_true", help="Output as JSON")

    # dhcp list
    list_p = dhcp_sub.add_parser("list", help="List current leases")
    list_p.add_argument("--state", help="Filter by lease state (BOUND, EXPIRED, RELEASED)")
    list_p.add_argument("--subnet", help="Filter by subnet")
    list_p.add_argument("--db", default=":memory:", help="SQLite database path")
    list_p.add_argument("--json", action="store_true", help="Output as JSON")

    # dhcp prune
    prune_p = dhcp_sub.add_parser("prune", help="Prune expired leases")
    prune_p.add_argument("--expired-only", action="store_true", default=True, help="Prune only expired leases")
    prune_p.add_argument("--retention", type=int, default=0, help="Retention period in seconds")
    prune_p.add_argument("--db", default=":memory:", help="SQLite database path")
    prune_p.add_argument("--json", action="store_true", help="Output as JSON")

    # 4. Zonegen
    zone_parser = subparsers.add_parser("zonegen", help="RFC 1035 DNS zone file generator")
    zone_sub = zone_parser.add_subparsers(dest="zone_action", required=True)

    # zonegen forward
    fwd_p = zone_sub.add_parser("forward", help="Generate forward DNS master zone")
    fwd_p.add_argument("--origin", required=True, help="Domain origin (e.g. example.com.)")
    fwd_p.add_argument("--records", required=True, help="JSON file containing DNS records")
    fwd_p.add_argument("--ns", help="Comma-separated list of nameservers")
    fwd_p.add_argument("--ttl", type=int, default=3600, help="Default TTL in seconds")
    fwd_p.add_argument("--output", help="Output file path (default stdout)")

    # zonegen reverse
    rev_p = zone_sub.add_parser("reverse", help="Generate reverse DNS zone")
    rev_p.add_argument("--network", required=True, help="Network CIDR")
    rev_p.add_argument("--records", required=True, help="JSON file containing PTR mappings")
    rev_p.add_argument("--origin", help="Reverse domain origin override")
    rev_p.add_argument("--ns", help="Comma-separated list of nameservers")
    rev_p.add_argument("--ttl", type=int, default=3600, help="Default TTL in seconds")
    rev_p.add_argument("--output", help="Output file path (default stdout)")

    return parser


def handle_subnet(args: argparse.Namespace) -> int:
    try:
        if args.subnet_action == "info":
            info = get_subnet_info(args.cidr)
            _print_output(info.to_dict(), as_json=args.json)
            return 0
        elif args.subnet_action == "split":
            res = split_subnet(args.cidr, new_prefix=args.prefix, count=args.count)
            _print_output({"base_cidr": args.cidr, "subnets": res}, as_json=args.json, text_fallback="\n".join(res))
            return 0
        elif args.subnet_action == "summarize":
            cidrs = list(args.cidrs or [])
            if args.file:
                content = Path(args.file).read_text(encoding="utf-8")
                cidrs.extend([line.strip() for line in content.splitlines() if line.strip()])
            res = summarize_subnets(cidrs)
            _print_output({"summarized": res}, as_json=args.json, text_fallback="\n".join(res))
            return 0
        elif args.subnet_action == "next-ip":
            allocated = []
            if args.allocated:
                allocated.extend([ip.strip() for ip in args.allocated.split(",") if ip.strip()])
            if args.allocated_file:
                content = Path(args.allocated_file).read_text(encoding="utf-8")
                allocated.extend([line.strip() for line in content.splitlines() if line.strip()])
            ip = next_available_ip(args.cidr, allocated)
            _print_output({"next_ip": ip, "subnet": args.cidr}, as_json=args.json, text_fallback=ip)
            return 0
    except (ValueError, PoolExhaustedError) as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1
    return 0


def handle_conflicts(args: argparse.Namespace) -> int:
    cidrs = list(args.cidrs or [])
    if cidrs and cidrs[0].lower() == "check":
        cidrs = cidrs[1:]

    if getattr(args, "subnets", None):
        cidrs.extend(args.subnets)

    if hasattr(args, "file") and args.file:
        content = Path(args.file).read_text(encoding="utf-8")
        cidrs.extend([line.strip() for line in content.splitlines() if line.strip()])

    if not cidrs:
        sys.stderr.write("Error: No CIDRs provided to check for conflicts.\n")
        return 2

    try:
        conflicts = detect_conflicts(cidrs)
        conf_dicts = [c.to_dict() for c in conflicts]
        if conflicts:
            _print_output(
                {"conflicts_found": len(conflicts), "conflicts": conf_dicts},
                as_json=args.json,
                text_fallback="\n".join(f"[{c.conflict_type.value}] {c.description}" for c in conflicts),
            )
            return 1
        else:
            _print_output(
                {"conflicts_found": 0, "conflicts": []},
                as_json=args.json,
                text_fallback="Clean: No subnet conflicts detected.",
            )
            return 0
    except ValueError as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1


def handle_dhcp(args: argparse.Namespace) -> int:
    tracker = DHCPTracker(db_path=args.db)
    try:
        if args.dhcp_action == "allocate":
            lease = tracker.allocate(
                mac=args.mac,
                subnet=args.subnet,
                requested_ip=args.ip,
                hostname=args.hostname,
                duration=args.duration,
            )
            _print_output(lease.to_dict(), as_json=args.json)
            return 0
        elif args.dhcp_action == "renew":
            lease = tracker.renew(mac=args.mac, ip=args.ip, duration=args.duration)
            _print_output(lease.to_dict(), as_json=args.json)
            return 0
        elif args.dhcp_action == "release":
            tracker.release(mac=args.mac, ip=args.ip)
            _print_output({"status": "released", "mac": args.mac, "ip": args.ip}, as_json=args.json, text_fallback="Lease released successfully.")
            return 0
        elif args.dhcp_action == "list":
            leases = tracker.list_leases(state=args.state, subnet=args.subnet)
            lease_dicts = [l.to_dict() for l in leases]
            _print_output(lease_dicts, as_json=args.json)
            return 0
        elif args.dhcp_action == "prune":
            count = tracker.prune(expired_only=args.expired_only, retention=args.retention)
            _print_output({"pruned_count": count}, as_json=args.json, text_fallback=f"Pruned {count} lease records.")
            return 0
    except (InvalidMACAddressError, LeaseConflictError, LeaseExpiredError, LeaseNotFoundError, ValueError, PoolExhaustedError) as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1
    finally:
        tracker.close()
    return 0


def handle_zonegen(args: argparse.Namespace) -> int:
    try:
        records_path = Path(args.records)
        if not records_path.exists():
            sys.stderr.write(f"Error: Records file not found: {args.records}\n")
            return 1
        records_data = json.loads(records_path.read_text(encoding="utf-8"))

        ns_list = [n.strip() for n in args.ns.split(",")] if args.ns else None

        if args.zone_action == "forward":
            output_text = generate_forward_zone(
                origin=args.origin,
                records=records_data,
                default_ttl=args.ttl,
                ns=ns_list,
            )
        else:
            output_text = generate_reverse_zone(
                network=args.network,
                records=records_data,
                default_ttl=args.ttl,
                origin=args.origin,
                ns=ns_list,
            )

        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
        else:
            print(output_text)
        return 0
    except Exception as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code

    if parsed.subcommand == "subnet":
        return handle_subnet(parsed)
    elif parsed.subcommand == "conflicts":
        return handle_conflicts(parsed)
    elif parsed.subcommand == "dhcp":
        return handle_dhcp(parsed)
    elif parsed.subcommand == "zonegen":
        return handle_zonegen(parsed)

    return 2


if __name__ == "__main__":
    sys.exit(main())

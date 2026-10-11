# dns-dhcp-ipam (`ipamcore`)

Enterprise IPv4/IPv6 CIDR Subnetting Calculator, Conflict Detector, Stateful DHCP Lease Tracker, and RFC 1035 DNS Zone File Generator. Built with zero external runtime dependencies on the Python standard library.

## Features

- **Subnet Engine**: Full IPv4 and IPv6 CIDR calculation, splitting, merging, summarization, and next-available IP allocation. Compliant with RFC 791, RFC 4632, RFC 4291, RFC 3021 (/31 point-to-point), and RFC 6164 (/127 inter-router links).
- **Conflict Detection**: Automated identification of subnet allocation overlaps: exact duplicates (`EXACT_MATCH`), parent-child enclosures (`CONTAINMENT`), and overlapping ranges (`PARTIAL_OVERLAP`).
- **DHCP Lease Lifecycle**: SQLite-backed state machine tracking leases across `OFFERED`, `BOUND`, `EXPIRED`, `RELEASED`, and `DECLINED` states. Automatic MAC normalization and lease pruning.
- **RFC 1035 Zone Generation**: Master zone compiler for forward and reverse DNS zones with SOA, NS, A, AAAA, CNAME, PTR, MX, and TXT records. Automatic RFC 1035 §3.3.14 255-byte chunking for large TXT records.

## Installation

```bash
pip install -e .
```

## CLI Usage

### Subnet Operations
```bash
# Calculate metrics for IPv4 or IPv6
ipamcore subnet info 10.0.0.0/24
ipamcore subnet info 2001:db8::/64 --json

# Split into smaller subnets
ipamcore subnet split 192.168.0.0/24 --prefix 26
ipamcore subnet split 10.0.0.0/16 --count 4

# Summarize subnets
ipamcore subnet summarize 10.0.0.0/24 10.0.1.0/24

# Allocate next available IP
ipamcore subnet next-ip 192.168.1.0/24 --allocated 192.168.1.1,192.168.1.2
```

### Overlap & Conflict Detection
```bash
ipamcore conflicts check 10.0.0.0/16 10.0.1.0/24 192.168.1.0/24
```

### DHCP Lease Management
```bash
# Allocate dynamic lease
ipamcore dhcp allocate --mac 00:11:22:33:44:55 --subnet 192.168.1.0/24 --hostname node-1

# Renew lease
ipamcore dhcp renew --mac 00:11:22:33:44:55 --ip 192.168.1.1

# Release lease
ipamcore dhcp release --mac 00:11:22:33:44:55
```

### RFC 1035 Zone Generation
```bash
# Forward zone
ipamcore zonegen forward --origin corp.internal. --records records.json --output /etc/bind/corp.zone

# Reverse zone
ipamcore zonegen reverse --network 192.168.1.0/24 --records ptr.json --output /etc/bind/rev.zone
```

## License

MIT License. Copyright (c) 2026 aipd506.

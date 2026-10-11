"""Tests for RFC 1035 zone file generator and TXT record chunking."""

from ipamcore.zonegen import (
    RecordType,
    chunk_txt_record,
    generate_forward_zone,
    generate_reverse_zone,
)


def test_chunk_txt_record_short():
    short_txt = "v=spf1 include:_spf.example.com ~all"
    res = chunk_txt_record(short_txt)
    assert res == f'"{short_txt}"'


def test_chunk_txt_record_exceeding_255_bytes():
    """RFC 1035 §3.3.14: TXT strings longer than 255 bytes must be segmented into quoted chunks."""
    long_txt = "A" * 600
    res = chunk_txt_record(long_txt)
    # Should contain multiple quoted segments separated by spaces
    parts = res.split(" ")
    assert len(parts) == 3
    for p in parts:
        assert p.startswith('"') and p.endswith('"')
        inner = p[1:-1]
        assert len(inner) <= 255
    # Combined length matches 600
    combined = "".join(p[1:-1] for p in parts)
    assert combined == long_txt


def test_chunk_txt_record_escaping():
    txt_with_quotes = 'He said "Hello World" and \\backslash'
    res = chunk_txt_record(txt_with_quotes)
    assert '\\"' in res
    assert "\\\\" in res


def test_generate_forward_zone():
    records = [
        {"name": "@", "record_type": "A", "rdata": "192.0.2.1"},
        {"name": "www", "record_type": "CNAME", "rdata": "example.com."},
        {"name": "@", "record_type": "MX", "priority": 10, "rdata": "mail.example.com."},
        {"name": "mail", "record_type": "A", "rdata": "192.0.2.10"},
        {"name": "@", "record_type": "TXT", "rdata": "v=spf1 -all"},
    ]
    zone_text = generate_forward_zone(
        origin="example.com.",
        records=records,
        default_ttl=3600,
        ns=["ns1.example.com.", "ns2.example.com."],
        serial=2026101101,
    )
    assert "$ORIGIN example.com." in zone_text
    assert "$TTL 3600" in zone_text
    assert "2026101101" in zone_text
    assert "IN  SOA" in zone_text
    assert "IN  NS      ns1.example.com." in zone_text
    assert "IN  NS      ns2.example.com." in zone_text
    assert "IN  A       192.0.2.1" in zone_text
    assert "IN  CNAME   example.com." in zone_text
    assert "IN  MX      10  mail.example.com." in zone_text


def test_generate_reverse_zone_ipv4():
    records = [
        {"ip": "192.0.2.1", "hostname": "gw.example.com."},
        {"ip": "192.0.2.42", "hostname": "node42.example.com."},
    ]
    zone_text = generate_reverse_zone(
        network="192.0.2.0/24",
        records=records,
        default_ttl=3600,
        serial=2026101101,
    )
    assert "$ORIGIN 2.0.192.in-addr.arpa." in zone_text
    assert "1               IN  PTR     gw.example.com." in zone_text
    assert "42              IN  PTR     node42.example.com." in zone_text


def test_generate_reverse_zone_ipv6():
    """Edge Case #14: IPv6 PTR expansion into reversed 32-nibbles format."""
    records = [
        {"ip": "2001:db8::1", "hostname": "router.example.com."},
    ]
    zone_text = generate_reverse_zone(
        network="2001:db8::/64",
        records=records,
        serial=2026101101,
    )
    # Check that ip6.arpa PTR record is present
    assert "ip6.arpa." in zone_text
    assert "router.example.com." in zone_text
    # 2001:0db8:... reversed ends with 8.b.d.0.1.0.0.2.ip6.arpa.
    assert "8.b.d.0.1.0.0.2.ip6.arpa." in zone_text

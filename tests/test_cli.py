"""Tests for ipamcore CLI interface and exit codes."""

import json
from pathlib import Path
from ipamcore.cli import main


def test_cli_help(capsys):
    try:
        rc = main(["--help"])
    except SystemExit as exc:
        rc = exc.code
    assert rc == 0


def test_cli_invalid_subcommand():
    rc = main(["nonexistent"])
    assert rc == 2


def test_cli_subnet_info(capsys):
    rc = main(["subnet", "info", "192.168.1.0/24", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["network_address"] == "192.168.1.0"
    assert data["usable_hosts"] == 254


def test_cli_subnet_split(capsys):
    rc = main(["subnet", "split", "10.0.0.0/24", "--prefix", "26", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["subnets"]) == 4


def test_cli_subnet_split_invalid(capsys):
    rc = main(["subnet", "split", "10.0.0.0/24", "--prefix", "22"])
    assert rc == 1


def test_cli_subnet_summarize(capsys):
    rc = main(["subnet", "summarize", "10.0.0.0/24", "10.0.1.0/24", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["summarized"] == ["10.0.0.0/23"]


def test_cli_subnet_next_ip(capsys):
    rc = main(["subnet", "next-ip", "10.0.0.0/24", "--allocated", "10.0.0.1,10.0.0.2", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["next_ip"] == "10.0.0.3"


def test_cli_conflicts_clean(capsys):
    rc = main(["conflicts", "check", "10.0.0.0/24", "10.0.1.0/24"])
    assert rc == 0


def test_cli_conflicts_detected(capsys):
    rc = main(["conflicts", "check", "10.0.0.0/16", "10.0.1.0/24", "--json"])
    assert rc == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["conflicts_found"] == 1


def test_cli_dhcp_workflow(tmp_path, capsys):
    db_file = str(tmp_path / "dhcp.db")
    # 1. Allocate
    rc = main([
        "dhcp", "allocate",
        "--mac", "00:11:22:33:44:55",
        "--subnet", "192.168.1.0/24",
        "--db", db_file,
        "--json",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    lease = json.loads(captured.out)
    assert lease["ip_address"] == "192.168.1.1"

    # 2. List
    rc = main(["dhcp", "list", "--db", db_file, "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    leases = json.loads(captured.out)
    assert len(leases) == 1

    # 3. Renew
    rc = main([
        "dhcp", "renew",
        "--mac", "00:11:22:33:44:55",
        "--ip", "192.168.1.1",
        "--db", db_file,
        "--json",
    ])
    assert rc == 0

    # 4. Release
    rc = main([
        "dhcp", "release",
        "--mac", "00:11:22:33:44:55",
        "--db", db_file,
    ])
    assert rc == 0


def test_cli_dhcp_invalid_mac(capsys):
    rc = main([
        "dhcp", "allocate",
        "--mac", "NOT-A-MAC",
        "--subnet", "192.168.1.0/24",
    ])
    assert rc == 1


def test_cli_zonegen_forward(tmp_path, capsys):
    records_file = tmp_path / "records.json"
    records_file.write_text(json.dumps([
        {"name": "@", "record_type": "A", "rdata": "192.0.2.1"},
        {"name": "www", "record_type": "CNAME", "rdata": "example.com."},
    ]))

    out_file = tmp_path / "example.zone"
    rc = main([
        "zonegen", "forward",
        "--origin", "example.com.",
        "--records", str(records_file),
        "--output", str(out_file),
    ])
    assert rc == 0
    content = out_file.read_text()
    assert "$ORIGIN example.com." in content
    assert "IN  A       192.0.2.1" in content

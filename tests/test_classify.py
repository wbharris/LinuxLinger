from pathlib import Path

from linux_linger.classify import classify
from linux_linger.models import Snapshot
from linux_linger.scan import scan

DATA = Path(__file__).parent / "data"


def test_critical_join_and_high_ghost():
    report = scan(fixture=DATA / "critical.json")
    by_id = {f.id: f for f in report.findings}
    assert by_id["join:4242"].severity == "critical"
    assert by_id["join:4242"].remote == "203.0.113.9:443"
    assert by_id["ghost:4242"].severity == "high"
    assert by_id["ghost:99"].severity == "info"
    assert by_id["persist:system:evil.service"].severity == "high"
    assert by_id["linger:alice"].severity == "medium"
    assert by_id["open:4242:3"].severity == "medium"
    assert by_id["open:summary"].severity == "info"
    assert report.problems()
    assert any(f.check == "channel" and f.severity == "high" for f in report.findings)
    summary = [f for f in report.findings if f.id == "channel:summary"]
    assert summary


def test_clean_fixture_has_no_problems():
    report = scan(fixture=DATA / "clean.json")
    assert report.problems() == []
    assert any(f.id == "channel:summary" for f in report.findings)


def test_chrome_tmp_unlinked_is_info():
    snap = Snapshot.from_dict(
        {
            "hostname": "box",
            "os": "Debian",
            "kernel": "1",
            "scanned_at": "2026-10-14T00:00:00Z",
            "unlinked": [
                {
                    "pid": 15034,
                    "command": "chrome",
                    "fd": "29",
                    "nlink": 0,
                    "size": 0,
                    "name": "/tmp/.com.google.Chrome.p7slPH (deleted)",
                    "type": "REG",
                }
            ],
        }
    )
    report = classify(snap, checks=["open"])
    assert report.findings[0].severity == "info"
    assert report.problems() == []


def test_memfd_unlinked_is_info():
    snap = Snapshot.from_dict(
        {
            "hostname": "box",
            "os": "Debian",
            "kernel": "1",
            "scanned_at": "2026-10-14T00:00:00Z",
            "unlinked": [
                {
                    "pid": 1145,
                    "command": "Xorg",
                    "fd": "77",
                    "nlink": 0,
                    "size": 4,
                    "name": "/memfd:xshmfence (deleted)",
                    "type": "REG",
                }
            ],
        }
    )
    report = classify(snap, checks=["open"])
    assert report.findings[0].severity == "info"
    assert report.problems() == []


def test_channel_only_prints_each_socket():
    snap = Snapshot.from_dict(
        {
            "hostname": "box",
            "os": "Debian",
            "kernel": "1",
            "scanned_at": "2026-10-14T00:00:00Z",
            "sockets": [
                {
                    "pid": 1,
                    "proto": "tcp",
                    "state": "ESTAB",
                    "local": "10.0.0.5:22",
                    "remote": "198.51.100.8:9",
                    "name": "sshd",
                }
            ],
        }
    )
    report = classify(snap, checks=["channel"])
    assert any(f.id.startswith("channel:1:") for f in report.findings)
    assert not any(f.id == "channel:summary" for f in report.findings)

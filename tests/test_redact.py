import json
from pathlib import Path

from linux_linger.cli import main
from linux_linger.models import Finding, Report
from linux_linger.redact import redact_report
from linux_linger.scan import scan

DATA = Path(__file__).parent / "data"


def test_redact_masks_cmdline_home_and_linger():
    report = scan(fixture=DATA / "critical.json")
    redact_report(report)
    details = " ".join(f.detail for f in report.findings)
    names = " ".join(f.name for f in report.findings)
    assert "--daemon" not in details
    assert "/tmp/.x ***" in details or "cmdline /tmp/.x ***" in details
    assert "linger:<user>" in names
    assert "linger:alice" not in names
    assert "for alice" not in details
    assert any("redacted command-line" in n for n in report.notes)


def test_redact_cmdline_ignores_remotes_in_arguments():
    cmdline = "/tmp/.x remotes SECRET --token=leak"
    report = Report(
        hostname="box",
        os="Linux",
        kernel="1",
        scanned_at="2026-01-01T00:00:00Z",
        findings=[
            Finding(
                id="ghost:1",
                check="ghost",
                severity="high",
                name=".x",
                detail=(
                    "deleted binary under a writable path. pid 1 exe /tmp/.x (deleted)"
                    f" cmdline {cmdline} remotes 203.0.113.9:443"
                ),
                cmdline=cmdline,
                remote="203.0.113.9:443",
            )
        ],
    )
    redact_report(report)
    finding = report.findings[0]
    assert finding.cmdline == "/tmp/.x ***"
    assert "SECRET" not in finding.detail
    assert "--token=leak" not in finding.detail
    assert "203.0.113.9:443" in finding.detail


def test_cli_redact_json_masks_home_in_argv0(tmp_path, capsys):
    dest = tmp_path / "home-argv0.json"
    dest.write_text(
        json.dumps(
            {
                "hostname": "box",
                "os": "Debian",
                "kernel": "1",
                "scanned_at": "2026-10-14T00:00:00Z",
                "ghosts": [
                    {
                        "pid": 7,
                        "exe": "/home/alice/private-tool (deleted)",
                        "cmdline": "/home/alice/private-tool --token=leak",
                        "comm": "private-tool",
                        "uid": 1000,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(["--fixture", str(dest), "--json", "--redact"])
    assert code == 1
    out = capsys.readouterr().out
    assert "/home/alice" not in out
    assert "alice" not in out
    assert "/home/<user>/private-tool" in out
    assert "--token=leak" not in out
    payload = json.loads(out)
    ghost_cmd = payload["snapshot"]["ghosts"][0]["cmdline"]
    finding_cmd = next(f["cmdline"] for f in payload["findings"] if f["id"] == "ghost:7")
    assert ghost_cmd == "/home/<user>/private-tool ***"
    assert finding_cmd == "/home/<user>/private-tool ***"


def test_cli_redact_json(capsys):
    code = main(["--fixture", str(DATA / "critical.json"), "--json", "--redact"])
    assert code == 1
    out = capsys.readouterr().out
    assert "--daemon" not in out
    assert "linger:alice" not in out
    assert "linger:<user>" in out

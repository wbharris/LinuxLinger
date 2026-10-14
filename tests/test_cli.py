from pathlib import Path

from linux_linger.cli import main
from linux_linger.guide import guide_text
from linux_linger.report import render_html, render_json, render_markdown, render_text
from linux_linger.scan import scan

DATA = Path(__file__).parent / "data"


def test_help_and_version(capsys):
    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    out = capsys.readouterr().out
    assert "ghost" in out.lower()
    assert "schedule" in out.lower()
    assert "doctor" in out.lower()
    try:
        main(["scan", "--help"])
    except SystemExit as e:
        assert e.code == 0
    scan_help = capsys.readouterr().out
    assert "join" in scan_help.lower()


def test_scan_fixture_json(capsys):
    code = main(["scan", "--fixture", str(DATA / "critical.json"), "--json", "--problems-only"])
    assert code == 1
    out = capsys.readouterr().out
    assert "join:4242" in out
    assert "critical" in out


def test_ghost_subcommand_filters(capsys):
    code = main(["ghost", "--fixture", str(DATA / "critical.json"), "--json"])
    assert code == 1
    out = capsys.readouterr().out
    assert "ghost:4242" in out
    assert "linger:alice" not in out


def test_clean_fixture_exit_zero(capsys):
    code = main(["scan", "--fixture", str(DATA / "clean.json")])
    assert code == 0
    out = capsys.readouterr().out
    assert "LinuxLinger" in out


def test_recent_days_must_be_positive(capsys):
    try:
        code = main(["scan", "--recent-days", "0"])
    except SystemExit as e:
        assert e.code == 2
    else:
        assert code == 2
    err = capsys.readouterr().err
    assert ">= 1" in err or "invalid" in err.lower()


def test_renderers_and_guide():
    report = scan(fixture=DATA / "critical.json")
    text = render_text(report, problems_only=True)
    assert "LinuxLinger" in text
    assert ".x" in text
    html = render_html(report)
    assert "<h1>LinuxLinger</h1>" in html
    assert "join" in html
    md = render_markdown(report)
    assert "# LinuxLinger" in md
    js = render_json(report)
    assert '"problem_count"' in js
    guide = guide_text(report)
    assert "cp /proc/4242/exe" in guide
    assert "read-only" in guide.lower()


def test_doctor_runs(capsys):
    code = main(["doctor"])
    assert code == 0
    out = capsys.readouterr().out
    assert "LinuxLinger doctor" in out
    assert "/proc" in out

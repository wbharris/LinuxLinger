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
    assert "linux-linger doctor" in out
    assert "linux-linger schedule" in out
    assert "linux-linger unschedule" in out
    assert "--check" not in out
    assert "--redact" in out
    assert "unschedule" in out


def test_scan_fixture_json(capsys):
    code = main(["--fixture", str(DATA / "critical.json"), "--json"])
    assert code == 1
    out = capsys.readouterr().out
    assert "join:4242" in out
    assert "critical" in out
    assert "open:summary" not in out


def test_all_includes_info(capsys):
    code = main(["--fixture", str(DATA / "critical.json"), "--json", "--all"])
    assert code == 1
    out = capsys.readouterr().out
    assert "open:summary" in out


def test_html_output_extension(tmp_path, capsys):
    dest = tmp_path / "case.html"
    code = main(["--fixture", str(DATA / "critical.json"), "-o", str(dest)])
    assert code == 1
    html = dest.read_text(encoding="utf-8")
    assert "<h1>LinuxLinger</h1>" in html
    assert "join" in html
    assert dest.stat().st_mode & 0o777 == 0o600
    out = capsys.readouterr().out
    assert "LinuxLinger" in out
    assert "<h1>" not in out


def test_html_output_replaces_symlink_without_following(tmp_path, capsys):
    decoy = tmp_path / "decoy.html"
    decoy.write_text("keep", encoding="utf-8")
    dest = tmp_path / "case.html"
    dest.symlink_to(decoy)
    code = main(["--fixture", str(DATA / "critical.json"), "-o", str(dest)])
    assert code == 1
    assert dest.is_file()
    assert not dest.is_symlink()
    assert "LinuxLinger" in dest.read_text(encoding="utf-8")
    assert decoy.read_text(encoding="utf-8") == "keep"
    capsys.readouterr()


def test_clean_fixture_exit_zero(capsys):
    code = main(["--fixture", str(DATA / "clean.json")])
    assert code == 0
    out = capsys.readouterr().out
    assert "LinuxLinger" in out
    assert "No matching findings." in out


def test_schedule_nonzero_when_reload_fails(monkeypatch, capsys):
    monkeypatch.setattr(
        "linux_linger.cli.schedule_install",
        lambda **_kwargs: "wrote /tmp/linux-linger.timer; daemon-reload failed: Failed to reload",
    )
    code = main(["schedule"])
    assert code == 1
    assert "daemon-reload failed:" in capsys.readouterr().out


def test_unschedule_nonzero_when_stop_fails(monkeypatch, capsys):
    monkeypatch.setattr(
        "linux_linger.cli.schedule_remove",
        lambda: "stop failed: Failed to connect to bus; left units in place",
    )
    code = main(["unschedule"])
    assert code == 1
    assert "stop failed:" in capsys.readouterr().out


def test_unknown_job_args(capsys):
    code = main(["doctor", "--json"])
    assert code == 2
    err = capsys.readouterr().err
    assert "no extra arguments" in err


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

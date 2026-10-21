from pathlib import Path

from linux_linger.collect import exec_argv_tokens, parse_exec_start, parse_lsof, parse_ss
from linux_linger.classify import is_loopback

DATA = Path(__file__).parent / "data"


def test_parse_ss_keeps_pid_and_remote():
    rows = parse_ss((DATA / "ss.txt").read_text(encoding="utf-8"))
    ghosts = [r for r in rows if r.pid == 4242]
    assert len(ghosts) == 1
    assert ghosts[0].remote == "203.0.113.9:443"
    assert ghosts[0].name == ".x"
    sshd = [r for r in rows if r.pid == 1204 and r.remote.startswith("198.51")]
    assert sshd


def test_parse_ss_loopback_present_for_filter():
    rows = parse_ss((DATA / "ss.txt").read_text(encoding="utf-8"))
    loop = [r for r in rows if r.remote.startswith("127.0.0.1")]
    assert loop
    assert is_loopback(loop[0].remote)


def test_parse_ss_bracketed_ipv6_loopback():
    rows = parse_ss((DATA / "ss.txt").read_text(encoding="utf-8"))
    loop = [r for r in rows if r.remote.startswith("[::1]")]
    assert loop
    assert is_loopback(loop[0].remote)


def test_parse_exec_start_quoted_continued_and_multiple():
    text = """
[Service]
ExecStart=/usr/bin/safe
ExecStart="/tmp/quoted pwn" --flag
ExecStartPre=/bin/true
ExecStart=/bin/echo \\
    /var/tmp/continued
"""
    parsed = parse_exec_start(text)
    tokens = exec_argv_tokens(parsed)
    assert "/usr/bin/safe" in tokens
    assert "/tmp/quoted pwn" in tokens
    assert "--flag" in tokens
    assert "/bin/true" in tokens
    assert "/bin/echo" in tokens
    assert "/var/tmp/continued" in tokens


def test_exec_argv_tokens_escapes():
    assert exec_argv_tokens(r'/bin/sh -c "/tmp/pwn"') == ["/bin/sh", "-c", "/tmp/pwn"]
    assert exec_argv_tokens("'/home/user/my bin'") == ["/home/user/my bin"]


def test_parse_lsof_nlink_zero_only():
    rows = parse_lsof((DATA / "lsof.txt").read_text(encoding="utf-8"))
    names = {r.name for r in rows}
    assert "/var/log/syslog (deleted)" in names
    assert "/tmp/.x.dat (deleted)" in names
    assert all(r.nlink == 0 for r in rows)
    assert not any("sshd_config" in r.name for r in rows)

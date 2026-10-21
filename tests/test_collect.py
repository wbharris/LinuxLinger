from pathlib import Path

from linux_linger.classify import is_loopback
from linux_linger.collect import (
    _keep_socket,
    exec_argv_tokens,
    parse_exec_start,
    parse_lsof,
    parse_ss,
)
from linux_linger.models import SocketRow

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


def test_parse_lsof_keeps_spaces_in_name():
    rows = parse_lsof((DATA / "lsof-spaces.txt").read_text(encoding="utf-8"))
    names = {r.name for r in rows}
    assert "/tmp/my file.dat (deleted)" in names
    assert "/home/alice/app data/cache.bin (deleted)" in names
    assert not any("sshd_config" in r.name for r in rows)


def test_parse_ss_variations_and_keep_socket():
    rows = parse_ss((DATA / "ss-variations.txt").read_text(encoding="utf-8"))
    by_pid = {r.pid: r for r in rows if r.pid is not None}
    assert by_pid[4242].remote == "203.0.113.9:443"
    assert by_pid[9].name == "web app"
    mapped = [r for r in rows if "ffff" in r.local]
    assert mapped
    assert is_loopback(mapped[0].remote)
    kept = [r for r in rows if _keep_socket(r)]
    states = {r.state.upper() for r in kept}
    assert "LISTEN" not in states
    assert "TIME-WAIT" not in states
    assert any(r.pid == 4242 for r in kept)


def test_keep_socket_tcp_udp():
    tcp = SocketRow(pid=1, proto="tcp", state="ESTAB", local="1:1", remote="203.0.113.9:443")
    listen = SocketRow(pid=1, proto="tcp", state="LISTEN", local="0.0.0.0:22", remote="0.0.0.0:*")
    udp_open = SocketRow(pid=1, proto="udp", state="UNCONN", local="1:53", remote="203.0.113.9:53")
    udp_star = SocketRow(pid=1, proto="udp", state="UNCONN", local="0.0.0.0:68", remote="0.0.0.0:*")
    assert _keep_socket(tcp)
    assert not _keep_socket(listen)
    assert _keep_socket(udp_open)
    assert not _keep_socket(udp_star)


def test_parse_exec_start_oneshot_fixture():
    text = (DATA / "unit-oneshot.service").read_text(encoding="utf-8")
    parsed = parse_exec_start(text)
    tokens = exec_argv_tokens(parsed)
    assert "/usr/bin/true" in tokens
    assert "/tmp/quoted pwn" in tokens
    assert "/bin/true" in tokens

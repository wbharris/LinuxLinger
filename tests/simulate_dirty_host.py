#!/usr/bin/env python3
"""Plant live leftovers on this host, run LinuxLinger, then tear them down.

Artifacts (all tagged linux-linger-sim / llinger-):
  1. ghost   — copy of this Python, exec'd from /tmp, then unlinked
  2. channel — that process holds an ESTAB TCP session to this host's LAN IP
  3. open    — that process holds an unlinked regular file under /tmp
  4. persist — user unit linux-linger-sim.service with ExecStart=/tmp/...
  5. join    — ghost PID ∩ non-loopback remote (critical)

The listener and ghost never leave this machine. Nothing is enabled in systemd.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from linux_linger.report import render_html, render_json, render_text
from linux_linger.scan import scan

UNIT_NAME = "linux-linger-sim.service"
HELD_PREFIX = "llinger-held-"
GHOST_PREFIX = "llinger-ghost-"
PAYLOAD = r"""
import os, socket, sys, time
held, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
fh = open(held, "wb")
fh.write(b"linux-linger-sim-held\n")
fh.flush()
os.unlink(held)
sock = socket.create_connection((host, port), 10)
sock.sendall(b"linux-linger-sim\n")
while True:
    time.sleep(1)
"""


def _non_loopback_ipv4() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        sock.close()
    if not ip or ip.startswith("127."):
        return None
    return ip


def _listen(bind_ip: str) -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, 0))
    srv.listen(1)
    srv.settimeout(15)
    return srv, int(srv.getsockname()[1])


def _unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / UNIT_NAME


def plant() -> dict:
    peer = _non_loopback_ipv4()
    if peer is None:
        raise RuntimeError("no non-loopback IPv4; join cannot be simulated on this host")

    tmp = Path("/tmp")
    ghost_bin = tmp / f"{GHOST_PREFIX}{os.getpid()}"
    held = tmp / f"{HELD_PREFIX}{os.getpid()}"
    shutil.copy2(Path(sys.executable).resolve(), ghost_bin)
    ghost_bin.chmod(0o755)

    srv, port = _listen(peer)
    ghost = subprocess.Popen(
        [str(ghost_bin), "-c", PAYLOAD, str(held), peer, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        conn, _addr = srv.accept()
    except TimeoutError as exc:
        err = (ghost.stderr.read() if ghost.stderr else b"").decode("utf-8", "replace")
        ghost.kill()
        srv.close()
        ghost_bin.unlink(missing_ok=True)
        raise RuntimeError(f"ghost did not connect: {err}") from exc

    time.sleep(0.2)
    ghost_bin.unlink(missing_ok=True)

    exe = Path(f"/proc/{ghost.pid}/exe")
    try:
        target = os.readlink(exe)
    except OSError as exc:
        conn.close()
        srv.close()
        ghost.kill()
        raise RuntimeError(f"cannot read {exe}: {exc}") from exc
    if "(deleted)" not in target:
        time.sleep(0.3)
        try:
            target = os.readlink(exe)
        except OSError:
            target = ""
        if "(deleted)" not in target:
            conn.close()
            srv.close()
            ghost.kill()
            raise RuntimeError(f"expected deleted exe, got {target!r}")

    unit = _unit_path()
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(
        "[Unit]\nDescription=LinuxLinger simulation leftover (safe to delete)\n\n"
        "[Service]\nType=oneshot\nExecStart=/tmp/llinger-sim-pwn\n",
        encoding="utf-8",
    )

    return {
        "pid": ghost.pid,
        "peer": peer,
        "port": port,
        "held": str(held),
        "exe": target,
        "ghost": ghost,
        "conn": conn,
        "srv": srv,
        "unit": unit,
    }


def cleanup(state: dict | None) -> None:
    if not state:
        return
    ghost = state.get("ghost")
    if ghost and ghost.poll() is None:
        ghost.terminate()
        try:
            ghost.wait(timeout=3)
        except subprocess.TimeoutExpired:
            ghost.kill()
    for key in ("conn", "srv"):
        sock = state.get(key)
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    unit = state.get("unit")
    if isinstance(unit, Path):
        unit.unlink(missing_ok=True)
    pid = state.get("pid")
    if pid:
        Path(f"/tmp/{GHOST_PREFIX}{os.getpid()}").unlink(missing_ok=True)
        Path(f"/tmp/{HELD_PREFIX}{pid}").unlink(missing_ok=True)
        Path(f"/tmp/{GHOST_PREFIX}{pid}").unlink(missing_ok=True)


def expect(report, state: dict) -> list[str]:
    pid = state["pid"]
    misses: list[str] = []
    by_check = {}
    for f in report.findings:
        by_check.setdefault(f.check, []).append(f)

    ghosts = [f for f in by_check.get("ghost", []) if f.pid == pid]
    if not ghosts:
        misses.append(f"ghost pid {pid} missing")
    elif ghosts[0].severity != "high":
        misses.append(f"ghost severity {ghosts[0].severity} (want high)")

    joins = [f for f in by_check.get("join", []) if f.pid == pid]
    if not joins:
        misses.append(f"join pid {pid} missing (critical ghost+channel)")
    elif joins[0].severity != "critical":
        misses.append(f"join severity {joins[0].severity} (want critical)")

    opened = [
        f
        for f in by_check.get("open", [])
        if f.pid == pid and f.path and HELD_PREFIX in f.path
    ]
    if not opened:
        misses.append(f"open unlinked {HELD_PREFIX}* on pid {pid} missing")
    elif opened[0].severity != "medium":
        misses.append(f"open severity {opened[0].severity} (want medium)")

    persist = [f for f in by_check.get("persist", []) if f.unit == UNIT_NAME]
    if not persist:
        misses.append(f"persist unit {UNIT_NAME} missing")
    elif persist[0].severity != "high":
        misses.append(f"persist severity {persist[0].severity} (want high)")

    channels = [f for f in by_check.get("channel", []) if f.pid == pid]
    if not channels:
        misses.append(f"channel pid {pid} missing")
    return misses


def main() -> int:
    state = None
    print("LinuxLinger dirty-host simulation", flush=True)
    try:
        state = plant()
        print(
            f"planted ghost pid={state['pid']} exe={state['exe']} "
            f"peer={state['peer']}:{state['port']} unit={state['unit']}",
            flush=True,
        )
        time.sleep(0.4)
        report = scan()
        body = render_text(report, problems_only=True)
        out_dir = Path(__file__).parent
        (out_dir / "last-results.txt").write_text(body, encoding="utf-8")
        (out_dir / "last-results.json").write_text(
            render_json(report, problems_only=True), encoding="utf-8"
        )
        (out_dir / "last-results.html").write_text(
            render_html(report, problems_only=True), encoding="utf-8"
        )
        print(body, end="")
        misses = expect(report, state)
        if misses:
            print("FAIL:", file=sys.stderr)
            for m in misses:
                print(f"  - {m}", file=sys.stderr)
            planted = {
                "pid": state["pid"],
                "exe": state["exe"],
                "peer": f"{state['peer']}:{state['port']}",
            }
            print("planted:", json.dumps(planted), file=sys.stderr)
            return 1
        print(
            f"PASS  join=critical ghost=high open=medium persist=high  pid={state['pid']}"
        )
        return 0
    finally:
        cleanup(state)


if __name__ == "__main__":
    raise SystemExit(main())

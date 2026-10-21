from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Iterable

from linux_linger.collect import exec_argv_tokens
from linux_linger.models import (
    CHECKS,
    Check,
    Finding,
    GhostProc,
    Report,
    Snapshot,
    SocketRow,
    UnlinkedFile,
    UnitFile,
)
from linux_linger.util import endpoint_host

SUSPICIOUS_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/root/",
    "/run/user/",
    "/var/run/",
)
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")
LOOPBACK_HOSTS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "*",
    "::",
    "",
}


def classify(
    snap: Snapshot,
    *,
    checks: Iterable[Check] | None = None,
    recent_days: int = 14,
) -> Report:
    wanted = list(checks or CHECKS)
    wanted_set = set(wanted)
    findings: list[Finding] = []
    if "ghost" in wanted_set:
        findings.extend(_ghosts(snap.ghosts, snap.sockets if "join" in wanted_set else []))
    if "channel" in wanted_set:
        findings.extend(
            _channels(
                snap.sockets,
                {g.pid for g in snap.ghosts},
                include_all=wanted == ["channel"] or wanted_set == {"channel"},
            )
        )
    if "open" in wanted_set:
        findings.extend(
            _unlinked(snap.unlinked, include_all=wanted == ["open"] or wanted_set == {"open"})
        )
    if "persist" in wanted_set:
        findings.extend(
            _persist(
                snap.units,
                snap.linger_users,
                recent_days=recent_days,
                include_all=wanted == ["persist"] or wanted_set == {"persist"},
            )
        )
    if "join" in wanted_set:
        findings.extend(_joins(snap.ghosts, snap.sockets))

    return Report(
        hostname=snap.hostname,
        os=snap.os,
        kernel=snap.kernel,
        scanned_at=snap.scanned_at,
        findings=findings,
        tools_used=list(snap.tools_used),
        tools_skipped=list(snap.tools_skipped),
        notes=list(snap.notes),
        incomplete=snap.incomplete,
        snapshot=snap.to_dict(),
    )


def exe_path(exe: str) -> str:
    return exe.replace(" (deleted)", "").strip()


def is_loopback(addr: str) -> bool:
    host = endpoint_host(addr)
    if host in LOOPBACK_HOSTS:
        return True
    if host.startswith("127."):
        return True
    if host.startswith("::ffff:127."):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_suspicious_path(path: str) -> bool:
    p = exe_path(path)
    return any(p.startswith(prefix) for prefix in SUSPICIOUS_PREFIXES)


def is_system_path(path: str) -> bool:
    p = exe_path(path)
    return any(p.startswith(prefix) for prefix in SYSTEM_PREFIXES)


def is_log_name(name: str) -> bool:
    n = name.lower()
    return (
        "/log/" in n
        or n.endswith(".log")
        or n.endswith(".log (deleted)")
        or "journal" in n
        or n.endswith(".gz (deleted)")
    )


def is_benign_unlinked(name: str) -> bool:
    n = name.lower()
    if is_log_name(name):
        return True
    if "memfd:" in n or n.startswith("/memfd"):
        return True
    if n.startswith("anon_inode:") or "anon_inode:" in n:
        return True
    if "/sysv" in n or n.startswith("sysv"):
        return True
    if "/tmp/.com.google.chrome." in n or "/tmp/.org.chromium." in n:
        return True
    if "browsermetrics" in n:
        return True
    if re.search(r"/tmp/#\d+", n):
        return True
    return False


def remote_sockets(sockets: list[SocketRow], pid: int) -> list[SocketRow]:
    return [
        s
        for s in sockets
        if s.pid == pid and s.remote and not is_loopback(s.remote)
    ]


def _ghosts(ghosts: list[GhostProc], sockets: list[SocketRow]) -> list[Finding]:
    out: list[Finding] = []
    for g in ghosts:
        path = exe_path(g.exe)
        remotes = remote_sockets(sockets, g.pid)
        if is_suspicious_path(g.exe):
            sev = "high"
            why = "deleted binary under a writable path"
        elif is_system_path(g.exe):
            sev = "info"
            why = "deleted system binary (often a package upgrade until restart)"
        else:
            sev = "medium"
            why = "deleted binary still running"
        remote = remotes[0].remote if remotes else None
        detail = f"pid {g.pid} exe {g.exe}"
        if g.cmdline:
            detail += f" cmdline {g.cmdline}"
        if remotes:
            detail += " remotes " + ", ".join(s.remote for s in remotes[:4])
        out.append(
            Finding(
                id=f"ghost:{g.pid}",
                check="ghost",
                severity=sev,
                name=g.comm or path or f"pid {g.pid}",
                detail=f"{why}. {detail}",
                pid=g.pid,
                path=g.exe,
                remote=remote,
                suggested=_ghost_suggest(g, remotes),
            )
        )
    return out


def _channels(
    sockets: list[SocketRow],
    ghost_pids: set[int],
    *,
    include_all: bool,
) -> list[Finding]:
    out: list[Finding] = []
    bulk: list[Finding] = []
    for s in sockets:
        if not s.remote or is_loopback(s.remote):
            continue
        pid = s.pid
        ghost = pid in ghost_pids if pid is not None else False
        sev = "high" if ghost else "info"
        why = "established socket on a deleted binary" if ghost else "established remote socket"
        ident = f"{pid if pid is not None else 'unknown'}:{s.remote}"
        finding = Finding(
            id=f"channel:{ident}",
            check="channel",
            severity=sev,
            name=s.name or (f"pid {pid}" if pid is not None else "unknown process"),
            detail=f"{why}. {s.proto} {s.state} {s.local} -> {s.remote}",
            pid=pid,
            remote=s.remote,
        )
        if ghost or pid is None or include_all:
            out.append(finding)
        else:
            bulk.append(finding)
    if bulk and not include_all:
        sample = ", ".join(f"{b.name}->{b.remote}" for b in bulk[:5])
        out.append(
            Finding(
                id="channel:summary",
                check="channel",
                severity="info",
                name=f"{len(bulk)} established remote sockets",
                detail=(
                    "ordinary sessions collapsed; linux-linger channel prints each one. "
                    f"sample: {sample}"
                ),
            )
        )
    return out


def _unlinked(files: list[UnlinkedFile], *, include_all: bool) -> list[Finding]:
    out: list[Finding] = []
    bulk: list[Finding] = []
    for u in files:
        if u.type and u.type.upper() not in {"REG", "unknown", ""}:
            continue
        benign = is_benign_unlinked(u.name)
        sev = "info" if benign else "medium"
        if is_log_name(u.name):
            why = "unlinked log still held (often logrotate)"
        elif benign:
            why = "unlinked memfd/tmp of a browser or compositor (normal)"
        else:
            why = "unlinked file still open"
        size = f" size={u.size}" if u.size is not None else ""
        finding = Finding(
            id=f"open:{u.pid}:{u.fd}",
            check="open",
            severity=sev,
            name=u.command or f"pid {u.pid}",
            detail=f"{why}. pid {u.pid} fd {u.fd} nlink={u.nlink}{size} {u.name}",
            pid=u.pid,
            path=u.name,
            suggested=[
                f"the inode is still at /proc/{u.pid}/fd/{_fd_num(u.fd)} until the process closes it"
            ],
        )
        if sev in {"medium", "high", "critical"} or include_all:
            out.append(finding)
        else:
            bulk.append(finding)
    if bulk and not include_all:
        sample = ", ".join(f"{b.name}:{b.path}" for b in bulk[:3])
        out.append(
            Finding(
                id="open:summary",
                check="open",
                severity="info",
                name=f"{len(bulk)} unlinked logs/memfds",
                detail=f"linux-linger open prints each one. sample: {sample}",
            )
        )
    return out


def _persist(
    units: list[UnitFile],
    linger_users: list[str],
    *,
    recent_days: int,
    include_all: bool,
) -> list[Finding]:
    out: list[Finding] = []
    bulk: list[Finding] = []
    now = datetime.now(timezone.utc)
    for u in units:
        exec_bad = bool(u.exec_start) and any(
            is_suspicious_path(tok) for tok in exec_argv_tokens(u.exec_start)
        )
        session_unit = u.name.startswith("app-") and "@autostart" in u.name
        recent = _is_recent(u.mtime, now, recent_days) and not session_unit
        if exec_bad:
            sev = "high"
            why = f"ExecStart is {u.exec_start}"
        elif recent:
            sev = "medium"
            why = f"local unit mtime {u.mtime} (within {recent_days}d)"
        else:
            sev = "info"
            why = f"local {u.scope} unit, state {u.state or 'unknown'}"
        finding = Finding(
            id=f"persist:{u.scope}:{u.name}",
            check="persist",
            severity=sev,
            name=u.name,
            detail=f"{why}. path {u.path or '-'} exec {u.exec_start or '-'}",
            unit=u.name,
            path=u.path or None,
            suggested=["read the unit file; do not systemctl disable from this tool"],
        )
        if sev in {"medium", "high", "critical"} or include_all:
            out.append(finding)
        else:
            bulk.append(finding)
    if bulk and not include_all:
        out.append(
            Finding(
                id="persist:summary",
                check="persist",
                severity="info",
                name=f"{len(bulk)} local units",
                detail="linux-linger persist prints each one. " + ", ".join(b.name for b in bulk[:8]),
            )
        )
    for user in linger_users:
        out.append(
            Finding(
                id=f"linger:{user}",
                check="persist",
                severity="medium",
                name=f"linger:{user}",
                detail=f"systemd user linger enabled for {user} (user manager starts at boot)",
                unit=user,
                suggested=["loginctl show-user " + user, "ls ~/.config/systemd/user/"],
            )
        )
    return out


def _joins(ghosts: list[GhostProc], sockets: list[SocketRow]) -> list[Finding]:
    out: list[Finding] = []
    for g in ghosts:
        remotes = remote_sockets(sockets, g.pid)
        if not remotes:
            continue
        addrs = ", ".join(f"{s.proto} {s.remote}" for s in remotes[:6])
        out.append(
            Finding(
                id=f"join:{g.pid}",
                check="join",
                severity="critical",
                name=g.comm or exe_path(g.exe) or f"pid {g.pid}",
                detail=(
                    f"deleted binary pid {g.pid} exe {g.exe} has remote socket(s) {addrs}"
                ),
                pid=g.pid,
                path=g.exe,
                remote=remotes[0].remote,
                suggested=[
                    f"copy evidence: cp /proc/{g.pid}/exe linger-{g.pid}.bin",
                    "do not kill the process until the copy exists",
                ],
            )
        )
    return out


def _ghost_suggest(g: GhostProc, remotes: list[SocketRow]) -> list[str]:
    bits = [f"copy /proc/{g.pid}/exe while the process still lives"]
    if remotes:
        bits.append("this pid also has a remote socket (see join)")
    return bits


def _fd_num(fd: str) -> str:
    return "".join(ch for ch in fd if ch.isdigit()) or fd


def _is_recent(mtime: str, now: datetime, recent_days: int) -> bool:
    if not mtime:
        return False
    try:
        when = datetime.strptime(mtime, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return (now - when).total_seconds() <= recent_days * 86400

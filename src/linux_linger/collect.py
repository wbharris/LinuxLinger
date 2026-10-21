from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from linux_linger.models import GhostProc, Snapshot, SocketRow, UnlinkedFile, UnitFile, utc_now
from linux_linger.util import detect_family, endpoint_host, hostname, kernel, os_pretty, run_privileged, which

USER_PID_RE = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')
PID_ONLY_RE = re.compile(r"pid=(\d+)")
EXEC_START_KEY_RE = re.compile(r"^ExecStart\w*$")
SUSPICIOUS_EXEC = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/run/user/")


def collect_live(*, proc_root: Path | None = None, recent_days: int = 14) -> Snapshot:
    snap = Snapshot(
        hostname=hostname(),
        os=os_pretty(),
        kernel=kernel(),
        scanned_at=utc_now(),
    )
    if detect_family() != "linux":
        snap.notes.append(f"OS family is {detect_family()!r}; live collectors are Linux-only.")
        snap.incomplete = True
        snap.tools_skipped.append("linux")
        return snap

    root = proc_root or Path("/proc")
    if not root.is_dir():
        snap.notes.append(f"{root} is not a directory")
        snap.incomplete = True
        snap.tools_skipped.append("proc")
        return snap

    snap.ghosts = collect_ghosts(root, snap)
    snap.sockets = collect_sockets(snap)
    snap.unlinked = collect_unlinked(root, snap)
    snap.units = collect_units(snap, recent_days=recent_days)
    snap.linger_users = collect_linger(snap)
    if os.geteuid() != 0:
        snap.notes.append("not root: other users' /proc entries and sockets may be missing")
        snap.incomplete = True
    return snap


def collect_ghosts(proc_root: Path, snap: Snapshot) -> list[GhostProc]:
    out: list[GhostProc] = []
    seen = 0
    denied = 0
    for pid_dir in _pid_dirs(proc_root):
        seen += 1
        exe_path = pid_dir / "exe"
        try:
            target = os.readlink(exe_path)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        if "(deleted)" not in target:
            continue
        pid = int(pid_dir.name)
        out.append(
            GhostProc(
                pid=pid,
                exe=target,
                cmdline=_cmdline(pid_dir),
                comm=_comm(pid_dir),
                uid=_uid(pid_dir),
            )
        )
    snap.tools_used.append("proc-exe")
    if denied:
        snap.notes.append(f"proc-exe: permission denied on {denied}/{seen} pids")
        snap.incomplete = True
    return out


def collect_sockets(snap: Snapshot) -> list[SocketRow]:
    ss = which("ss")
    if not ss:
        snap.tools_skipped.append("ss")
        snap.notes.append("ss missing; channel and join skip live sockets")
        return []
    argv = [ss, "-H", "-tunap"]
    code, out, err, how = run_privileged(argv, timeout=20)
    text = out
    if code != 0 or not out.strip():
        argv = [ss, "-tunap"]
        code, out, err, how = run_privileged(argv, timeout=20)
        text = out
    if code != 0:
        snap.tools_skipped.append("ss")
        snap.notes.append(f"ss exit {code}: {(err or out).strip()[:200]}")
        snap.incomplete = True
        return []
    rows = parse_ss(text)
    snap.tools_used.append(f"ss({how})")
    return [r for r in rows if _keep_socket(r)]


def collect_unlinked(proc_root: Path, snap: Snapshot) -> list[UnlinkedFile]:
    rows = _unlinked_from_proc(proc_root)
    snap.tools_used.append("proc-fd")
    lsof = which("lsof")
    if lsof:
        code, out, err, how = run_privileged([lsof, "-nP", "+L1"], timeout=45)
        if code == 0 and out.strip():
            extra = parse_lsof(out)
            rows = _merge_unlinked(rows, extra)
            snap.tools_used.append(f"lsof({how})")
        else:
            snap.notes.append(f"lsof skipped: exit {code} {(err or '').strip()[:120]}")
    else:
        snap.tools_skipped.append("lsof")
    return rows


def collect_units(snap: Snapshot, *, recent_days: int = 14) -> list[UnitFile]:
    enabled = _enabled_units(snap)
    units: dict[str, UnitFile] = {}
    home_user = Path.home() / ".config" / "systemd" / "user"
    walks = [
        (Path("/etc/systemd/system"), "system"),
        (Path("/etc/systemd/user"), "user"),
        (home_user, "user"),
    ]
    for directory, scope in walks:
        if not directory.is_dir():
            continue
        for path in _unit_files(directory):
            name = path.name
            exec_start = _exec_start(path)
            mtime = _iso_mtime(path)
            state = enabled.get(name, "unknown")
            key = f"{scope}:{name}"
            units[key] = UnitFile(
                name=name,
                state=state,
                path=str(path),
                mtime=mtime,
                exec_start=exec_start,
                scope=scope,
            )
    for name, state in enabled.items():
        if any(u.name == name for u in units.values()):
            continue
        if _suspicious_text(name):
            units[f"enabled:{name}"] = UnitFile(
                name=name,
                state=state,
                path="",
                mtime="",
                exec_start="",
                scope="system",
            )
    snap.tools_used.append("systemd-units")
    _ = recent_days
    return list(units.values())


def collect_linger(snap: Snapshot) -> list[str]:
    users: list[str] = []
    linger_dir = Path("/var/lib/systemd/linger")
    if linger_dir.is_dir():
        try:
            users = sorted(p.name for p in linger_dir.iterdir() if p.is_file())
            snap.tools_used.append("systemd-linger")
        except PermissionError:
            snap.notes.append("cannot list /var/lib/systemd/linger")
            snap.incomplete = True
    loginctl = which("loginctl")
    if loginctl:
        code, out, err, how = run_privileged(
            [loginctl, "list-users", "--no-legend", "--no-pager"], timeout=15
        )
        if code == 0:
            snap.tools_used.append(f"loginctl({how})")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[-2].lower() == "yes":
                    name = parts[1]
                    if name not in users:
                        users.append(name)
                elif len(parts) >= 2 and "linger" in line.lower() and "yes" in line.lower():
                    if parts[1] not in users:
                        users.append(parts[1])
        else:
            snap.tools_skipped.append("loginctl")
    elif not users:
        snap.tools_skipped.append("loginctl")
    return sorted(set(users))


def parse_ss(text: str) -> list[SocketRow]:
    rows: list[SocketRow] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("netid") or low.startswith("state"):
            continue
        users_m = re.search(r"\susers:\(.*\)\s*$", line)
        proc_part = users_m.group(0) if users_m else ""
        rest = line[: users_m.start()] if users_m else line
        parts = rest.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        if len(parts) >= 6:
            local, remote = parts[4], parts[5]
        else:
            local, remote = parts[-2], parts[-1]
        matches = list(USER_PID_RE.finditer(proc_part))
        if matches:
            for m in matches:
                rows.append(
                    SocketRow(
                        pid=int(m.group("pid")),
                        proto=proto,
                        state=state,
                        local=local,
                        remote=remote,
                        name=m.group("name"),
                    )
                )
        else:
            pids = PID_ONLY_RE.findall(proc_part)
            if pids:
                for pid in pids:
                    rows.append(
                        SocketRow(
                            pid=int(pid),
                            proto=proto,
                            state=state,
                            local=local,
                            remote=remote,
                        )
                    )
            else:
                rows.append(
                    SocketRow(
                        pid=None,
                        proto=proto,
                        state=state,
                        local=local,
                        remote=remote,
                    )
                )
    return rows


def parse_lsof(text: str) -> list[UnlinkedFile]:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    header = lines[0]
    has_header = header.upper().startswith("COMMAND")
    body = lines[1:] if has_header else lines
    name_at = _lsof_name_column(header) if has_header else -1
    rows: list[UnlinkedFile] = []
    for line in body:
        parts, name = _lsof_split(line, name_at)
        if len(parts) < 5:
            continue
        command, pid_s, _user, fd, typ = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        nlink = 0
        size: int | None = None
        if len(parts) >= 8:
            try:
                size = int(parts[6])
            except ValueError:
                size = None
            try:
                nlink = int(parts[7])
            except ValueError:
                nlink = 0
        elif len(parts) >= 7:
            name = name or " ".join(parts[7:])
        if nlink > 0:
            continue
        rows.append(
            UnlinkedFile(
                pid=pid,
                command=command,
                fd=fd,
                nlink=nlink,
                size=size,
                name=name or "(unknown)",
                type=typ,
            )
        )
    return rows


def _lsof_name_column(header: str) -> int:
    up = header.upper()
    idx = up.rfind("NAME")
    return idx if idx >= 0 else -1


def _lsof_split(line: str, name_at: int) -> tuple[list[str], str]:
    if name_at > 0 and len(line) > name_at and line[name_at - 1].isspace():
        return line[:name_at].split(), line[name_at:].strip()
    parts = line.split()
    if len(parts) > 9:
        return parts[:9], " ".join(parts[9:])
    if len(parts) > 8:
        return parts[:8], " ".join(parts[8:])
    return parts, " ".join(parts[7:]) if len(parts) > 7 else ""


def _keep_socket(row: SocketRow) -> bool:
    proto = row.proto.lower()
    state = row.state.upper()
    if proto.startswith("tcp"):
        return state in {"ESTAB", "ESTABLISHED"}
    if proto.startswith("udp"):
        host = endpoint_host(row.remote)
        return host not in {"*", "0.0.0.0", "::", ""}
    return state in {"ESTAB", "ESTABLISHED"}


def _pid_dirs(proc_root: Path):
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return
    for p in entries:
        if p.name.isdigit() and p.is_dir():
            yield p


def _cmdline(pid_dir: Path) -> str:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def _comm(pid_dir: Path) -> str:
    try:
        return (pid_dir / "comm").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _uid(pid_dir: Path) -> int | None:
    try:
        return pid_dir.stat().st_uid
    except OSError:
        return None


def _unlinked_from_proc(proc_root: Path) -> list[UnlinkedFile]:
    out: list[UnlinkedFile] = []
    for pid_dir in _pid_dirs(proc_root):
        fd_dir = pid_dir / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        command = _comm(pid_dir)
        pid = int(pid_dir.name)
        for fd_path in fds:
            try:
                st = fd_path.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 0:
                continue
            try:
                target = os.readlink(fd_path)
            except OSError:
                target = fd_path.name
            out.append(
                UnlinkedFile(
                    pid=pid,
                    command=command,
                    fd=fd_path.name,
                    nlink=st.st_nlink,
                    size=st.st_size,
                    name=target,
                    type="REG",
                )
            )
    return out


def _fd_key(fd: str) -> str:
    digits = "".join(ch for ch in fd if ch.isdigit())
    return digits or fd


def _merge_unlinked(primary: list[UnlinkedFile], extra: list[UnlinkedFile]) -> list[UnlinkedFile]:
    seen = {(u.pid, _fd_key(u.fd), u.name) for u in primary}
    out = list(primary)
    for u in extra:
        key = (u.pid, _fd_key(u.fd), u.name)
        if key not in seen:
            out.append(u)
            seen.add(key)
    return out


def _enabled_units(snap: Snapshot) -> dict[str, str]:
    systemctl = which("systemctl")
    if not systemctl:
        snap.tools_skipped.append("systemctl")
        return {}
    argv = [
        systemctl,
        "list-unit-files",
        "--state=enabled",
        "--type=service,timer",
        "--no-pager",
        "--no-legend",
        "--plain",
    ]
    code, out, err, how = run_privileged(argv, timeout=20)
    if code != 0:
        snap.notes.append(f"systemctl list-unit-files exit {code}")
        return {}
    snap.tools_used.append(f"systemctl({how})")
    enabled: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            enabled[parts[0]] = parts[1]
    return enabled


def _unit_files(directory: Path):
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for p in entries:
        if p.is_file() and p.suffix in {".service", ".timer"}:
            yield p
        elif p.is_symlink() and p.suffix in {".service", ".timer"}:
            yield p


def _exec_start(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return parse_exec_start(text)


def parse_exec_start(text: str) -> str:
    """Collect ExecStart* command text from a unit file.

    Handles ``\\`` line continuations, multiple ExecStart* keys, and
    systemd command prefixes (``-``, ``@``, ``+``, ``!``, ``:``). Quoted
    arguments are kept so ``exec_argv_tokens()`` can split them.

    Specifiers (``%h``), drop-ins, and C-style escapes are not expanded.
    """
    commands: list[str] = []
    for line in _unfold_unit(text).splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith(";"):
            continue
        eq = raw.find("=")
        if eq < 1:
            continue
        key = raw[:eq].strip()
        if not EXEC_START_KEY_RE.fullmatch(key):
            continue
        value = _strip_exec_prefixes(raw[eq + 1 :].strip())
        if value:
            commands.append(value)
    return " ".join(commands)


def exec_argv_tokens(value: str) -> list[str]:
    """Split an ExecStart value with systemd-style single/double quotes."""
    tokens: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if quote == "'":
            if c == "'":
                quote = ""
            else:
                buf.append(c)
        elif quote == '"':
            if c == "\\":
                i += 1
                if i < n:
                    buf.append(value[i])
            elif c == '"':
                quote = ""
            else:
                buf.append(c)
        elif c in " \t":
            if buf:
                tokens.append("".join(buf))
                buf = []
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
            if i < n:
                buf.append(value[i])
        else:
            buf.append(c)
        i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


def _unfold_unit(text: str) -> str:
    lines: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if buf:
            line = buf + line.lstrip()
            buf = ""
        if line.endswith("\\"):
            buf = line[:-1]
            continue
        lines.append(line)
    if buf:
        lines.append(buf)
    return "\n".join(lines)


def _strip_exec_prefixes(value: str) -> str:
    i = 0
    while i < len(value) and value[i] in "+@:-!|":
        i += 1
    return value[i:].lstrip()


def _iso_mtime(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
    except OSError:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _suspicious_text(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in SUSPICIOUS_EXEC)

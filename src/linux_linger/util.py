from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    argv: list[str],
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", f"not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(argv)}"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def run_privileged(argv: list[str], *, timeout: int = 30) -> tuple[int, str, str, str]:
    """Run argv as root when possible. how is root | sudo | user."""
    if os.geteuid() == 0:
        code, out, err = run(argv, timeout=timeout)
        return code, out, err, "root"
    sudo = which("sudo")
    if sudo:
        code, out, err = run([sudo, "-n", *argv], timeout=timeout)
        if code == 0:
            return code, out, err, "sudo"
    code, out, err = run(argv, timeout=timeout)
    return code, out, err, "user"


def detect_family() -> str:
    return platform.system().lower() or "unknown"


def endpoint_host(addr: str) -> str:
    """Host part of an ss-style local/remote endpoint.

    Bracketed IPv6 uses the text inside ``[...]``. Unbracketed IPv6 (more
    than one colon) is the whole address; a port belongs in brackets, as
    ``ss`` prints ``[::1]:443``. A single colon is IPv4 or a name plus port.
    """
    if not addr:
        return ""
    s = addr.strip()
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            return s[1:end].lower()
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        if port.isdigit():
            return host.lower()
        return s.lower()
    return s.lower()


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return ensure_private_dir(Path(base) / "linux-linger")


def ensure_private_dir(path: Path) -> Path:
    """Create or tighten a directory to owner-only (0700), user-owned, not a symlink."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _require_safe_parent(path)
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"{path} is a symlink; refuse to use it as a data directory")
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"{path} is not a directory")
    if st.st_uid != os.geteuid():
        raise PermissionError(f"{path} is not owned by the current user")
    os.chmod(path, 0o700)
    st = os.lstat(path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise PermissionError(f"{path} is accessible to other users")
    return path


def _require_safe_parent(path: Path) -> None:
    """Refuse a parent whose directory entries other users can replace.

    Owner-only and 0755 parents are fine. Group/world-writable parents are
    not, even when owned by the operator, unless the sticky bit is set so
    others cannot rename ``linux-linger``.
    """
    parent = path.parent
    st = os.stat(parent)
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"{parent} is not a directory")
    if st.st_mode & 0o022 and not (st.st_mode & stat.S_ISVTX):
        raise PermissionError(f"{parent} is writable by other users")


def write_private_file(path: Path, text: str, *, mode: int = 0o600) -> Path:
    """Write ``text`` without following a symlink. Set ``mode`` on the fd."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        os.unlink(path)
    elif st is not None and not stat.S_ISREG(st.st_mode):
        raise PermissionError(f"{path} is not a regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(os.fspath(path), flags, mode)
    try:
        os.fchmod(fd, mode)
        data = text.encode("utf-8")
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
    finally:
        os.close(fd)
    return path


def notify(title: str, body: str) -> bool:
    if which("notify-send"):
        code, _out, _err = run(["notify-send", title, body], timeout=10)
        return code == 0
    return False


def hostname() -> str:
    return platform.node() or "unknown"


def kernel() -> str:
    return platform.release()


def os_pretty() -> str:
    path = Path("/etc/os-release")
    if path.exists():
        data: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
        return data.get("PRETTY_NAME") or data.get("NAME") or platform.platform()
    return platform.platform()

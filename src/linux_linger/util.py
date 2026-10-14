from __future__ import annotations

import os
import platform
import shutil
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


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    path = Path(base) / "linux-linger"
    path.mkdir(parents=True, exist_ok=True)
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

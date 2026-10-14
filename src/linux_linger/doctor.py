from __future__ import annotations

import os
from pathlib import Path

from linux_linger.util import detect_family, run, which


def doctor_lines() -> list[str]:
    rows = [
        ("linux", detect_family() == "linux", detect_family()),
        ("/proc", Path("/proc").is_dir(), str(Path("/proc"))),
        ("ss", bool(which("ss")), which("ss") or "optional for channel/join"),
        ("lsof", bool(which("lsof")), which("lsof") or "optional; proc-fd is enough"),
        ("systemctl", bool(which("systemctl")), which("systemctl") or "optional for persist"),
        ("loginctl", bool(which("loginctl")), which("loginctl") or "optional for linger"),
        ("osqueryi", bool(which("osqueryi")), which("osqueryi") or "optional; join is native"),
        ("notify-send", bool(which("notify-send")), which("notify-send") or "optional --notify"),
    ]
    euid = os.geteuid()
    if euid == 0:
        rows.append(("root", True, "euid 0"))
    else:
        sudo = which("sudo")
        if sudo:
            code, _out, err = run([sudo, "-n", "true"], timeout=5)
            rows.append(("sudo -n", code == 0, "ok" if code == 0 else (err.strip()[:80] or "needs a password")))
        else:
            rows.append(("sudo -n", False, "sudo missing; other users' processes may be hidden"))
        rows.append(("euid", euid == 0, f"euid {euid}"))

    lines = ["LinuxLinger doctor", ""]
    width = max(len(name) for name, _ok, _detail in rows)
    for name, ok, detail in rows:
        flag = "ok" if ok else "skip"
        lines.append(f"{name.ljust(width)}  {flag:4}  {detail}")
    lines.append("")
    lines.append("Collectors are read-only. Missing tools are skipped, not installed.")
    return lines


def doctor_text() -> str:
    return "\n".join(doctor_lines()) + "\n"

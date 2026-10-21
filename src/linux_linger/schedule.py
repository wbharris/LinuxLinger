from __future__ import annotations

import shlex
import sys
from pathlib import Path

from linux_linger.util import data_dir, run, which

SERVICE = "linux-linger.service"
TIMER = "linux-linger.timer"


def runner_cmd() -> list[str]:
    exe = which("linux-linger")
    if exe:
        return [exe]
    return [sys.executable, "-m", "linux_linger"]


def write_runner_script(*, notify: bool) -> Path:
    root = data_dir()
    html = root / "last.html"
    cmd = runner_cmd()
    scan_html = shlex.join(cmd + ["-o", str(html)])
    path = root / "run.sh"
    lines = [
        "#!/bin/sh",
        "set +e",
        scan_html,
        "status=$?",
        "set -e",
        'if [ "$status" -gt 1 ]; then exit "$status"; fi',
    ]
    if notify and which("notify-send"):
        msg = f"Leftovers written to {html}"
        lines.append(
            'if [ "$status" -eq 1 ]; then '
            f"notify-send {shlex.quote('LinuxLinger')} {shlex.quote(msg)}; fi"
        )
    lines.append('exit "$status"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def install(*, every: str = "hourly", notify: bool = True) -> str:
    script = write_runner_script(notify=notify)
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    oncal = {"hourly": "hourly", "daily": "daily", "weekly": "weekly"}.get(every, "hourly")
    (unit_dir / SERVICE).write_text(
        "[Unit]\nDescription=LinuxLinger live triage\n\n"
        f"[Service]\nType=oneshot\nExecStart={_systemd_exec_start(script)}\n",
        encoding="utf-8",
    )
    (unit_dir / TIMER).write_text(
        "[Unit]\nDescription=LinuxLinger schedule\n\n"
        f"[Timer]\nOnCalendar={oncal}\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    code, out, err = run(["systemctl", "--user", "daemon-reload"])
    if code != 0:
        return f"wrote {unit_dir / TIMER}; daemon-reload failed: {(err or out).strip()}"
    code, out, err = run(["systemctl", "--user", "enable", "--now", TIMER])
    if code != 0:
        return f"wrote {unit_dir / TIMER}; enable failed: {(err or out).strip()}"
    return f"enabled systemd --user {TIMER} ({oncal}) -> {script}"


def remove() -> str:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    code, out, err = run(["systemctl", "--user", "stop", TIMER])
    if code != 0 and not _unit_already_idle(out, err):
        return f"stop failed: {(err or out).strip()}; left units in place"
    for name in (TIMER, SERVICE):
        (unit_dir / name).unlink(missing_ok=True)
    (unit_dir / "timers.target.wants" / TIMER).unlink(missing_ok=True)
    code, out, err = run(["systemctl", "--user", "daemon-reload"])
    if code != 0:
        return f"removed {TIMER}; daemon-reload failed: {(err or out).strip()}"
    return f"removed systemd --user {TIMER}"


def _unit_already_idle(out: str, err: str) -> bool:
    text = f"{err}\n{out}".lower()
    return any(
        token in text
        for token in ("not loaded", "not found", "does not exist", "could not be found")
    )


def _systemd_exec_start(path: Path) -> str:
    """Serialize a filesystem path for systemd ExecStart=.

    Double quotes handle spaces. ``$$`` and ``%%`` keep ``$`` and ``%``
    literal; quoting alone does not disable env or specifier expansion.
    """
    s = str(path)
    escaped = (
        s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$").replace("%", "%%")
    )
    if escaped != s or any(c.isspace() or c in "'" for c in s):
        return f'"{escaped}"'
    return escaped

from __future__ import annotations

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
    report = root / "last.txt"
    html = root / "last.html"
    cmd = runner_cmd()
    scan_txt = _shell_join(cmd + ["scan", "--problems-only", "-o", str(report)])
    scan_html = _shell_join(cmd + ["scan", "--html", "-o", str(html)])
    path = root / "run.sh"
    lines = [
        "#!/bin/sh",
        "set -e",
        "status=0",
        "set +e",
        scan_txt,
        "status=$?",
        scan_html,
        "html_status=$?",
        "set -e",
        'if [ "$status" -gt 1 ]; then exit "$status"; fi',
        'if [ "$html_status" -gt 1 ]; then exit "$html_status"; fi',
    ]
    if notify and which("notify-send"):
        lines.append(
            f'if grep -Eq "problems=[1-9][0-9]*" "{report}" 2>/dev/null; then '
            f'notify-send "LinuxLinger" "Problems written to {report}"; fi'
        )
    lines.append('exit "$status"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def install(*, every: str, notify: bool) -> str:
    script = write_runner_script(notify=notify)
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    oncal = {"hourly": "hourly", "daily": "daily", "weekly": "weekly"}.get(every, "daily")
    (unit_dir / SERVICE).write_text(
        "[Unit]\nDescription=LinuxLinger live triage\n\n"
        f"[Service]\nType=oneshot\nExecStart={script}\n",
        encoding="utf-8",
    )
    (unit_dir / TIMER).write_text(
        "[Unit]\nDescription=LinuxLinger schedule\n\n"
        f"[Timer]\nOnCalendar={oncal}\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    run(["systemctl", "--user", "daemon-reload"])
    code, out, err = run(["systemctl", "--user", "enable", "--now", TIMER])
    if code != 0:
        return f"wrote {unit_dir / TIMER}; enable failed: {(err or out).strip()}"
    return f"enabled systemd --user {TIMER} ({oncal}) -> {script}"


def remove() -> str:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    for name in (TIMER, SERVICE):
        (unit_dir / name).unlink(missing_ok=True)
    run(["systemctl", "--user", "disable", "--now", TIMER])
    run(["systemctl", "--user", "daemon-reload"])
    return f"removed systemd --user {TIMER}"


def status() -> str:
    code, out, err = run(["systemctl", "--user", "status", TIMER, "--no-pager"])
    return (out or err).strip() or f"systemctl exit {code}"


def _shell_join(parts: list[str]) -> str:
    out = []
    for p in parts:
        if any(c.isspace() for c in p) or any(c in p for c in '"&|<>'):
            out.append('"' + p.replace('"', '\\"') + '"')
        else:
            out.append(p)
    return " ".join(out)

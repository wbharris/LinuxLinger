from __future__ import annotations

from linux_linger.models import PROBLEM_SEVERITIES, Report


def guide_text(report: Report) -> str:
    problems = [f for f in report.findings if f.severity in PROBLEM_SEVERITIES]
    joins = [f for f in problems if f.check == "join"]
    ghosts = [f for f in problems if f.check == "ghost"]
    persist = [f for f in problems if f.check == "persist"]
    opened = [f for f in problems if f.check == "open"]
    lines = [
        f"LinuxLinger guide  {report.hostname}",
        f"problems={len(problems)}  join={len(joins)}  ghost={len(ghosts)}  "
        f"open={len(opened)}  persist={len(persist)}",
        "",
        "This tool is read-only. Do not kill, rm, or systemctl disable from here.",
        "",
    ]
    step = 1
    if joins:
        lines.append(f"{step}. Copy evidence from each join pid while it still lives:")
        step += 1
        for f in joins[:8]:
            if f.pid is not None:
                lines.append(f"   cp /proc/{f.pid}/exe linger-{f.pid}.bin && sha256sum linger-{f.pid}.bin")
            lines.append(f"   {f.name}: {f.detail}")
        lines.append("")
    if ghosts and not joins:
        lines.append(f"{step}. Deleted binaries with no remote socket — often a package upgrade.")
        step += 1
        lines.append("   Restart the service after you confirm the package, or copy /proc/<pid>/exe first.")
        lines.append("")
    if opened:
        lines.append(f"{step}. Unlinked files: the data is /proc/<pid>/fd/<n> until the fd closes.")
        step += 1
        lines.append("")
    if persist:
        lines.append(f"{step}. Local units and linger users — read the unit file, then decide.")
        step += 1
        for f in persist[:8]:
            lines.append(f"   {f.name}: {f.detail}")
        lines.append("")
    if not problems:
        lines.append("No critical/high/medium leftovers on this snapshot.")
        lines.append("Re-run after a package upgrade if you still want a baseline.")
        lines.append("")
    lines.append(f"{step}. Keep the JSON/HTML case. A reboot wipes ghosts and open fds.")
    return "\n".join(lines) + "\n"

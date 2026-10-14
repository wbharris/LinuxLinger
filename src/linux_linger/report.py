from __future__ import annotations

import json

from linux_linger.models import CHECKS, PROBLEM_SEVERITIES, SEVERITY_ORDER, Finding, Report

CHECK_TITLES = {
    "join": "Join — deleted binary with a remote socket",
    "ghost": "Ghost — deleted-but-running binary",
    "channel": "Channel — established sockets",
    "open": "Still open — unlinked files still held",
    "persist": "Survives reboot — local units and linger",
}


def render_text(report: Report, *, problems_only: bool = False) -> str:
    findings = _sorted(report, problems_only=problems_only)
    counts = " ".join(f"{k}={v}" for k, v in report.counts().items() if v)
    lines = [
        f"LinuxLinger  {report.hostname}  {report.os}  {report.kernel}",
        f"scanned {report.scanned_at}  problems={len(report.problems())}  {counts}",
        "",
    ]
    if not findings:
        lines.append("No matching findings.")
        if report.tools_skipped:
            lines.append("skipped: " + ", ".join(report.tools_skipped))
        return "\n".join(lines) + "\n"
    current = None
    for f in findings:
        if problems_only and f.severity not in PROBLEM_SEVERITIES:
            continue
        if f.check != current:
            current = f.check
            lines.append(f"## {CHECK_TITLES.get(f.check, f.check)}")
        extra = []
        if f.pid is not None:
            extra.append(f"pid {f.pid}")
        if f.remote:
            extra.append(f"-> {f.remote}")
        suffix = ("  " + "  ".join(extra)) if extra else ""
        lines.append(f"[{f.severity:8}] {f.name}{suffix}")
        for dl in f.detail.splitlines()[:3]:
            lines.append(f"           {dl}")
    if report.tools_skipped:
        lines.append("")
        lines.append("skipped: " + ", ".join(report.tools_skipped))
    if report.notes:
        lines.append("")
        for n in report.notes:
            lines.append(f"note: {n}")
    return "\n".join(lines) + "\n"


def render_markdown(report: Report, *, problems_only: bool = False) -> str:
    findings = _sorted(report, problems_only=problems_only)
    counts = report.counts()
    lines = [
        "# LinuxLinger",
        "",
        f"- **Host:** {report.hostname}",
        f"- **OS:** {report.os}",
        f"- **Kernel:** {report.kernel}",
        f"- **When:** {report.scanned_at}",
        f"- **Problems:** {len(report.problems())}",
        "",
        "## Counts",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for key in SEVERITY_ORDER:
        if key in counts:
            lines.append(f"| {key} | {counts[key]} |")
    lines += ["", "## Tools", ""]
    if report.tools_used:
        lines.append("Used: " + ", ".join(report.tools_used))
    if report.tools_skipped:
        lines.append("Skipped: " + ", ".join(report.tools_skipped))
    if report.notes:
        lines += ["", "## Notes", ""]
        for n in report.notes:
            lines.append(f"- {n}")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No matching findings.")
        return "\n".join(lines) + "\n"
    current = None
    for f in findings:
        if f.check != current:
            current = f.check
            lines += ["", f"### {CHECK_TITLES.get(f.check, f.check)}", ""]
        lines.append(f"#### `{f.severity}` {f.name}")
        lines.append("")
        lines.append(f.detail)
        lines.append("")
        meta = []
        if f.pid is not None:
            meta.append(f"pid `{f.pid}`")
        if f.path:
            meta.append(f"path `{f.path}`")
        if f.remote:
            meta.append(f"remote `{f.remote}`")
        if f.unit:
            meta.append(f"unit `{f.unit}`")
        if meta:
            lines.append("- " + " · ".join(meta))
            lines.append("")
        if f.suggested:
            lines.append("Next:")
            for s in f.suggested:
                lines.append(f"- {s}")
            lines.append("")
    return "\n".join(lines) + "\n"


def render_json(report: Report, *, problems_only: bool = False) -> str:
    data = report.to_dict()
    if problems_only:
        data["findings"] = [f.to_dict() for f in report.problems()]
    return json.dumps(data, indent=2) + "\n"


def render_html(report: Report, *, problems_only: bool = False) -> str:
    findings = _sorted(report, problems_only=problems_only)
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td class='s {_esc(f.severity)}'>{_esc(f.severity)}</td>"
            f"<td>{_esc(f.check)}</td>"
            f"<td>{_esc(f.name)}</td>"
            f"<td>{_esc('' if f.pid is None else str(f.pid))}</td>"
            f"<td>{_esc(f.remote or f.unit or '')}</td>"
            f"<td>{_esc(f.detail)}</td>"
            "</tr>"
        )
    counts = " ".join(f"{k}={v}" for k, v in report.counts().items() if v)
    skipped = (
        f"<p>skipped: {_esc(', '.join(report.tools_skipped))}</p>" if report.tools_skipped else ""
    )
    notes = "".join(f"<li>{_esc(n)}</li>" for n in report.notes)
    notes_block = f"<ul>{notes}</ul>" if notes else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>LinuxLinger — {_esc(report.hostname)}</title>
<style>
body {{ font: 14px/1.4 system-ui, sans-serif; background:#0d1117; color:#e6edf3; margin:24px; }}
table {{ border-collapse: collapse; width:100%; }}
th, td {{ border-bottom:1px solid #30363d; padding:6px 8px; text-align:left; vertical-align:top; }}
th {{ color:#8b949e; font-weight:600; }}
.s.critical,.s.high {{ color:#f85149; }}
.s.medium {{ color:#d29922; }}
.s.info {{ color:#58a6ff; }}
.s.ok {{ color:#3fb950; }}
.s.skip {{ color:#8b949e; }}
h1 {{ font-size: 22px; }}
</style></head><body>
<h1>LinuxLinger</h1>
<p>{_esc(report.hostname)} — {_esc(report.os)} — {_esc(report.kernel)}</p>
<p>scanned {_esc(report.scanned_at)} — problems={len(report.problems())} — {_esc(counts)}</p>
{skipped}
{notes_block}
<table><thead><tr><th>Status</th><th>Check</th><th>Name</th><th>PID</th><th>Remote / unit</th><th>Detail</th></tr></thead>
<tbody>
{''.join(rows) or '<tr><td colspan="6">No matching findings.</td></tr>'}
</tbody></table>
</body></html>
"""


def _sorted(report: Report, *, problems_only: bool) -> list[Finding]:
    findings = report.problems() if problems_only else list(report.findings)
    check_i = {c: i for i, c in enumerate(("join", "ghost", "channel", "open", "persist"))}
    sev_i = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (check_i.get(f.check, 9), sev_i.get(f.severity, 9), f.id),
    )


def _esc(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# keep CHECKS imported for callers that introspect the report module
_ = CHECKS

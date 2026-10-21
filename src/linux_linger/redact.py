from __future__ import annotations

import re

from linux_linger.models import Report

HOME_RE = re.compile(r"(?i)(?P<prefix>/home/|/Users/)(?P<user>[^/\s]+)")


def redact_report(report: Report) -> Report:
    """Mask command-line arguments, home usernames, and linger names in place."""
    for finding in report.findings:
        finding.name = _redact_home(_redact_linger_name(finding.name))
        finding.detail = _redact_home(_redact_cmdline(finding.detail))
        if finding.path:
            finding.path = _redact_home(finding.path)
        if finding.id.startswith("linger:"):
            finding.id = "linger:<user>"
            finding.unit = "<user>"
            finding.detail = re.sub(r"enabled for \S+", "enabled for <user>", finding.detail)
        finding.suggested = [_redact_home(_redact_linger_suggest(s)) for s in finding.suggested]
    _redact_snapshot(report.snapshot)
    report.notes.append("redacted command-line arguments, home directory names, and linger usernames")
    return report


def _redact_snapshot(snap: object) -> None:
    if not isinstance(snap, dict):
        return
    for ghost in snap.get("ghosts") or []:
        if not isinstance(ghost, dict):
            continue
        cmd = str(ghost.get("cmdline") or "")
        parts = cmd.split()
        if len(parts) > 1:
            ghost["cmdline"] = parts[0] + " ***"
        if ghost.get("exe"):
            ghost["exe"] = _redact_home(str(ghost["exe"]))
    for row in snap.get("unlinked") or []:
        if isinstance(row, dict) and row.get("name"):
            row["name"] = _redact_home(str(row["name"]))
    if snap.get("linger_users"):
        snap["linger_users"] = ["<user>"] * len(list(snap["linger_users"]))
    for unit in snap.get("units") or []:
        if not isinstance(unit, dict):
            continue
        if unit.get("path"):
            unit["path"] = _redact_home(str(unit["path"]))
        if unit.get("exec_start"):
            unit["exec_start"] = _redact_home(str(unit["exec_start"]))


def _redact_home(text: str) -> str:
    return HOME_RE.sub(lambda m: m.group("prefix") + "<user>", text)


def _redact_cmdline(detail: str) -> str:
    marker = " cmdline "
    idx = detail.find(marker)
    if idx == -1:
        return detail
    head = detail[: idx + len(marker)]
    rest = detail[idx + len(marker) :]
    split_at = rest.find(" remotes ")
    if split_at == -1:
        cmd, tail = rest, ""
    else:
        cmd, tail = rest[:split_at], rest[split_at:]
    parts = cmd.split()
    if len(parts) > 1:
        cmd = parts[0] + " ***"
    return head + cmd + tail


def _redact_linger_name(name: str) -> str:
    if name.startswith("linger:") and name != "linger:<user>":
        return "linger:<user>"
    return name


def _redact_linger_suggest(text: str) -> str:
    if text.startswith("loginctl show-user "):
        return "loginctl show-user <user>"
    return text

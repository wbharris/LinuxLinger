from __future__ import annotations

import json
from pathlib import Path

from linux_linger.classify import classify
from linux_linger.collect import collect_live
from linux_linger.ignore import apply_ignore, load_ignored
from linux_linger.models import CHECKS, Check, Report, Snapshot


def scan(
    *,
    checks: list[Check] | None = None,
    include_ignored: bool = False,
    fixture: Path | None = None,
    recent_days: int = 14,
    proc_root: Path | None = None,
) -> Report:
    wanted = _normalize_checks(checks)
    if fixture:
        payload = json.loads(Path(fixture).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"fixture {fixture} is not a JSON object")
        snap = Snapshot.from_dict(payload)
        if "fixture" not in snap.tools_used:
            snap.tools_used.append("fixture")
        snap.notes.append(f"fixture {Path(fixture).resolve()}")
    else:
        snap = collect_live(proc_root=proc_root, recent_days=recent_days)
    report = classify(snap, checks=wanted, recent_days=recent_days)
    # Fixture scans are hermetic: do not apply the operator's live ignore list.
    if fixture is None and not include_ignored:
        apply_ignore(report, load_ignored())
    return report


def _normalize_checks(checks: list[Check] | None) -> list[Check]:
    if not checks:
        return list(CHECKS)
    out: list[Check] = []
    for c in checks:
        if c not in CHECKS:
            raise ValueError(f"unknown check {c!r}")
        if c not in out:
            out.append(c)
    return out

from __future__ import annotations

from pathlib import Path

from linux_linger.models import Finding, Report
from linux_linger.util import data_dir


def ignore_path() -> Path:
    return data_dir() / "ignore.txt"


def load_ignored(path: Path | None = None) -> list[str]:
    file = path or ignore_path()
    if not file.is_file():
        return []
    out: list[str] = []
    for raw in file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def save_ignored(ids: list[str], path: Path | None = None) -> Path:
    file = path or ignore_path()
    file.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted(set(ids), key=str.lower)
    file.write_text("".join(f"{i}\n" for i in unique), encoding="utf-8")
    return file


def add_ignore(item: str, path: Path | None = None) -> list[str]:
    ids = load_ignored(path)
    if item not in ids:
        ids.append(item)
    save_ignored(ids, path)
    return ids


def remove_ignore(item: str, path: Path | None = None) -> list[str]:
    ids = [i for i in load_ignored(path) if i != item]
    save_ignored(ids, path)
    return ids


def is_ignored(finding: Finding, ids: list[str]) -> bool:
    if not ids:
        return False
    keys = {_norm(finding.id), _norm(finding.name)}
    if finding.pid is not None:
        keys.add(_norm(f"pid:{finding.pid}"))
    if finding.unit:
        keys.add(_norm(f"unit:{finding.unit}"))
        keys.add(_norm(finding.unit))
    if finding.path:
        keys.add(_norm(finding.path))
    tokens = {_norm(i) for i in ids if i.strip()}
    return bool(keys & tokens)


def apply_ignore(report: Report, ids: list[str]) -> int:
    n = 0
    for f in report.findings:
        if is_ignored(f, ids) and f.severity != "skip":
            f.detail = f"ignored ({f.severity}): {f.detail}"
            f.severity = "skip"
            n += 1
    if n:
        report.notes.append(f"ignored {n} finding(s) from {ignore_path()}")
    return n


def _norm(value: str) -> str:
    return value.strip().lower()

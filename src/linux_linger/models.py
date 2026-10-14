from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Check = Literal["ghost", "channel", "open", "persist", "join"]
Severity = Literal["critical", "high", "medium", "info", "ok", "skip"]

CHECKS: tuple[Check, ...] = ("ghost", "channel", "open", "persist", "join")
PROBLEM_SEVERITIES = frozenset({"critical", "high", "medium"})
SEVERITY_ORDER = ("critical", "high", "medium", "info", "ok", "skip")


@dataclass
class GhostProc:
    pid: int
    exe: str
    cmdline: str = ""
    comm: str = ""
    uid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SocketRow:
    pid: int | None
    proto: str
    state: str
    local: str
    remote: str
    name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnlinkedFile:
    pid: int
    command: str
    fd: str
    nlink: int
    size: int | None
    name: str
    type: str = "REG"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnitFile:
    name: str
    state: str
    path: str
    mtime: str
    exec_start: str = ""
    scope: str = "system"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    hostname: str
    os: str
    kernel: str
    scanned_at: str
    ghosts: list[GhostProc] = field(default_factory=list)
    sockets: list[SocketRow] = field(default_factory=list)
    unlinked: list[UnlinkedFile] = field(default_factory=list)
    units: list[UnitFile] = field(default_factory=list)
    linger_users: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    tools_skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    incomplete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        return cls(
            hostname=str(data.get("hostname") or "unknown"),
            os=str(data.get("os") or ""),
            kernel=str(data.get("kernel") or ""),
            scanned_at=str(data.get("scanned_at") or utc_now()),
            ghosts=[GhostProc(**g) for g in data.get("ghosts") or []],
            sockets=[SocketRow(**s) for s in data.get("sockets") or []],
            unlinked=[UnlinkedFile(**u) for u in data.get("unlinked") or []],
            units=[UnitFile(**u) for u in data.get("units") or []],
            linger_users=[str(x) for x in data.get("linger_users") or []],
            tools_used=[str(x) for x in data.get("tools_used") or []],
            tools_skipped=[str(x) for x in data.get("tools_skipped") or []],
            notes=[str(x) for x in data.get("notes") or []],
            incomplete=bool(data.get("incomplete", False)),
        )


@dataclass
class Finding:
    id: str
    check: Check
    severity: Severity
    name: str
    detail: str
    pid: int | None = None
    path: str | None = None
    remote: str | None = None
    unit: str | None = None
    suggested: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    hostname: str
    os: str
    kernel: str
    scanned_at: str
    findings: list[Finding] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    tools_skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    incomplete: bool = False
    snapshot: dict[str, Any] = field(default_factory=dict)

    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in PROBLEM_SEVERITIES]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["counts"] = self.counts()
        d["problem_count"] = len(self.problems())
        return d


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

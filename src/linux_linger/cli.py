from __future__ import annotations

import argparse
import sys
from pathlib import Path

from linux_linger import __version__
from linux_linger.doctor import doctor_text
from linux_linger.guide import guide_text
from linux_linger.ignore import add_ignore, load_ignored, remove_ignore
from linux_linger.models import CHECKS, Check
from linux_linger.report import render_html, render_json, render_markdown, render_text
from linux_linger.scan import scan
from linux_linger.schedule import install as schedule_install
from linux_linger.schedule import remove as schedule_remove
from linux_linger.schedule import status as schedule_status
from linux_linger.util import notify as desktop_notify

COMMANDS = ("scan", "doctor", "guide", "ignore", "schedule", *CHECKS)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in CHECKS:
        argv = ["scan", "--check", argv[0], *argv[1:]]
    elif argv and argv[0] not in ("-h", "--help", "--version", *COMMANDS):
        argv = ["scan", *argv]
    elif not argv:
        argv = ["scan"]

    parser = argparse.ArgumentParser(
        prog="linux-linger",
        description=(
            "Live Linux host triage: deleted-but-running binaries, established "
            "sockets, unlinked files still held, and reboot persistence. Read-only. "
            "Check shortcuts: ghost, channel, open, persist, join."
        ),
        epilog="Examples: linux-linger ghost   linux-linger --html -o cases/host.html",
    )
    parser.add_argument("--version", action="version", version=f"linux-linger {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Run the five checks on this host (default)")
    _add_scan_flags(scan_p)

    sub.add_parser("doctor", help="Show which collectors this host can run")

    guide_p = sub.add_parser("guide", help="Read-only next steps from a fresh scan")
    _add_scan_flags(guide_p)

    ign = sub.add_parser("ignore", help="Hide a finding from problem counts")
    ign.add_argument("action", choices=("list", "add", "remove"))
    ign.add_argument("id", nargs="?", help="Finding id, pid:N, unit:NAME, or path")

    sch = sub.add_parser("schedule", help="Install, show, or remove a repeating scan")
    sch.add_argument("action", choices=("install", "status", "remove"))
    sch.add_argument("--every", choices=("hourly", "daily", "weekly"), default="hourly")
    sch.add_argument("--notify", action="store_true", help="Desktop notify when problems > 0")

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "doctor":
        sys.stdout.write(doctor_text())
        return 0
    if args.cmd == "guide":
        return _cmd_guide(args)
    if args.cmd == "ignore":
        return _cmd_ignore(args)
    if args.cmd == "schedule":
        return _cmd_schedule(args)
    return 2


def _add_scan_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--check",
        action="append",
        dest="checks",
        choices=CHECKS,
        help="Repeatable: ghost, channel, open, persist, join (default: all)",
    )
    p.add_argument("--json", action="store_true", help="JSON report on stdout")
    p.add_argument("--markdown", action="store_true", help="Markdown report on stdout")
    p.add_argument("--html", action="store_true", help="Standalone HTML results page")
    p.add_argument("-o", "--output", type=Path, help="Write report to this path")
    p.add_argument("--problems-only", action="store_true", help="Hide info/ok/skip rows")
    p.add_argument("--notify", action="store_true", help="Desktop notify when problems > 0")
    p.add_argument("--include-ignored", action="store_true", help="Do not apply the ignore list")
    p.add_argument(
        "--recent-days",
        type=_positive_int,
        default=14,
        metavar="N",
        help="Local unit mtime newer than this many days is medium (default 14)",
    )
    p.add_argument(
        "--fixture",
        type=Path,
        help="Replay a collector JSON snapshot (no live /proc)",
    )


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _scan_kwargs(args: argparse.Namespace) -> dict:
    checks: list[Check] | None = getattr(args, "checks", None)
    return {
        "checks": checks,
        "include_ignored": getattr(args, "include_ignored", False),
        "fixture": getattr(args, "fixture", None),
        "recent_days": getattr(args, "recent_days", 14),
    }


def _render(args: argparse.Namespace, report) -> str:
    if args.json:
        return render_json(report, problems_only=args.problems_only)
    if args.markdown:
        return render_markdown(report, problems_only=args.problems_only)
    if args.html:
        return render_html(report, problems_only=args.problems_only)
    return render_text(report, problems_only=args.problems_only)


def _cmd_scan(args: argparse.Namespace) -> int:
    report = scan(**_scan_kwargs(args))
    body = _render(args, report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
        sys.stderr.write(f"wrote {args.output}\n")
    sys.stdout.write(body)
    if args.notify and report.problems():
        desktop_notify("LinuxLinger", f"{len(report.problems())} leftover(s) on {report.hostname}")
    if report.incomplete or report.problems():
        return 1
    return 0


def _cmd_guide(args: argparse.Namespace) -> int:
    report = scan(**_scan_kwargs(args))
    body = guide_text(report)
    if args.json:
        body = _render(args, report)
    elif args.markdown or args.html:
        body = _render(args, report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
        sys.stderr.write(f"wrote {args.output}\n")
    sys.stdout.write(body)
    if report.incomplete or report.problems():
        return 1
    return 0


def _cmd_ignore(args: argparse.Namespace) -> int:
    if args.action == "list":
        ids = load_ignored()
        if not ids:
            sys.stdout.write("(empty)\n")
            return 0
        sys.stdout.write("".join(f"{i}\n" for i in ids))
        return 0
    if not args.id:
        sys.stderr.write("ignore add|remove needs an id\n")
        return 2
    if args.action == "add":
        ids = add_ignore(args.id)
    else:
        ids = remove_ignore(args.id)
    sys.stdout.write("".join(f"{i}\n" for i in ids) or "(empty)\n")
    return 0


def _cmd_schedule(args: argparse.Namespace) -> int:
    if args.action == "install":
        sys.stdout.write(schedule_install(every=args.every, notify=args.notify) + "\n")
        return 0
    if args.action == "remove":
        sys.stdout.write(schedule_remove() + "\n")
        return 0
    sys.stdout.write(schedule_status() + "\n")
    return 0

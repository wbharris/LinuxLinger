from __future__ import annotations

import argparse
import sys
from pathlib import Path

from linux_linger import __version__
from linux_linger.doctor import doctor_text
from linux_linger.report import render_html, render_json, render_markdown, render_text
from linux_linger.scan import scan
from linux_linger.util import write_private_file
from linux_linger.schedule import install as schedule_install
from linux_linger.schedule import remove as schedule_remove

JOBS = ("doctor", "schedule", "unschedule")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "scan":
        argv = argv[1:]
    if argv and argv[0] in JOBS:
        return _job(argv[0], argv[1:])
    return _cmd_scan(_scan_parser().parse_args(argv))


def _scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-linger",
        description="Live leftovers on this Linux host. Read-only.",
        epilog=(
            "linux-linger                 scan this host\n"
            "linux-linger -o case.html    write an HTML case\n"
            "linux-linger doctor          which collectors this host can run\n"
            "linux-linger schedule        hourly background scan\n"
            "linux-linger unschedule      stop the timer"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"linux-linger {__version__}")
    parser.add_argument("-o", "--output", type=Path, help="Write the case here (.html .json .md)")
    parser.add_argument("--json", action="store_true", help="JSON on stdout")
    parser.add_argument("--all", action="store_true", help="Include info summaries")
    parser.add_argument(
        "--fixture",
        type=Path,
        help=argparse.SUPPRESS,
    )
    return parser


def _job(name: str, rest: list[str]) -> int:
    if rest and rest[0] in ("-h", "--help"):
        sys.stdout.write(_job_help(name))
        return 0
    if rest:
        sys.stderr.write(f"linux-linger {name} takes no extra arguments\n")
        return 2
    if name == "doctor":
        sys.stdout.write(doctor_text())
        return 0
    if name == "schedule":
        msg = schedule_install(every="hourly", notify=True)
        sys.stdout.write(msg + "\n")
        return 1 if "failed:" in msg else 0
    msg = schedule_remove()
    sys.stdout.write(msg + "\n")
    return 1 if "failed:" in msg else 0


def _job_help(name: str) -> str:
    if name == "doctor":
        return "usage: linux-linger doctor\nShow which collectors this host can run.\n"
    if name == "schedule":
        return "usage: linux-linger schedule\nHourly systemd --user scan; notify when leftovers appear.\n"
    return "usage: linux-linger unschedule\nStop the hourly timer.\n"


def _cmd_scan(args: argparse.Namespace) -> int:
    report = scan(fixture=args.fixture)
    problems_only = not args.all
    fmt = _format(args)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_private_file(
                args.output,
                _render(report, fmt, problems_only=problems_only),
                mode=0o600,
            )
        except PermissionError as exc:
            sys.stderr.write(f"linux-linger: {exc}\n")
            return 1
        sys.stderr.write(f"wrote {args.output}\n")
    if args.json:
        sys.stdout.write(render_json(report, problems_only=problems_only))
    else:
        sys.stdout.write(render_text(report, problems_only=problems_only))
    if report.incomplete or report.problems():
        return 1
    return 0


def _format(args: argparse.Namespace) -> str:
    if args.output:
        suf = args.output.suffix.lower()
        if suf == ".html":
            return "html"
        if suf == ".json":
            return "json"
        if suf in {".md", ".markdown"}:
            return "markdown"
    if args.json:
        return "json"
    return "text"


def _render(report, fmt: str, *, problems_only: bool) -> str:
    if fmt == "json":
        return render_json(report, problems_only=problems_only)
    if fmt == "html":
        return render_html(report, problems_only=problems_only)
    if fmt == "markdown":
        return render_markdown(report, problems_only=problems_only)
    return render_text(report, problems_only=problems_only)

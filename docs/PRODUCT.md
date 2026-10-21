# LinuxLinger™ product contract

End goal: a CLI (and optional user timer) that takes a **read-only live snapshot of this Linux host** for leftovers that remain after they should be gone: a deleted binary still running, an established socket, an unlinked file still held, and a unit or linger user that survives reboot.

Repo: https://github.com/wbharris/LinuxLinger

**LinuxLinger™** is a trademark of wbharris (common-law ™). See [`TRADEMARK.md`](../TRADEMARK.md).

## Why this exists

1. Which processes are still running after their file left the disk?
2. Which of those have a remote socket?
3. Which deleted files are still held open?
4. What local systemd unit or linger user will come back after reboot?
5. Can I run that as one click, or on a timer, and keep a case file?

LinuxLinger does (1)–(5). It does not kill processes, disable units, quarantine files, look up remote IPs, or install osquery.

## User journey

```
this Linux host
     │
     ▼
1. Collect (read-only)
   ghost    /proc/<pid>/exe contains (deleted)
   channel  ss -tunap established (ss optional)
   open     /proc/<pid>/fd nlink=0  (lsof +L1 optional)
   persist  local unit files + loginctl linger
     │
     ▼
2. Join  ghost PID ∩ non-loopback remote socket
     │
     ▼
3. Classify  critical | high | medium | info | skip
     │
     ▼
4. Report  text (default) or `-o case.html` / `--json`
     └─ schedule  hourly systemd --user timer
```

## Commands

| Command | Behavior |
|---------|----------|
| `linux-linger` | All five checks. Default text is leftovers only (`critical`/`high`/`medium`) |
| `-o FILE` | Write a case; `.html` `.json` `.md` pick the format |
| `--json` | JSON on stdout |
| `--all` | Include info summaries |
| `doctor` | Name missing tools. Skip, do not install |
| `schedule` | Hourly user timer; notify when leftovers appear. Exit 1 if reload or enable fails |
| `unschedule` | Stop the timer and remove the user units. Does not run `systemctl disable`. Exit 1 if stop or reload fails |

## Classification

| Severity | Rule |
|----------|------|
| `critical` | Ghost PID with a non-loopback remote socket (the join) |
| `high` | Ghost under `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/root`; or a local unit whose `ExecStart=` is there; or a channel on a ghost PID |
| `medium` | Other deleted binaries; unlinked regular files that are not logs; local unit mtime within 14 days; systemd linger users |
| `info` | Deleted binary under `/usr` `/bin` `/lib` (package upgrade until restart); logrotate, memfd, and browser tmp leftovers; ordinary remote sockets collapsed to one summary row. Hidden unless `--all` |
| `skip` | Ignore list |

## Collectors

| Check | Required | Optional |
|-------|----------|----------|
| ghost | `/proc` | sudo/root to see other users |
| channel | `ss` | sudo `-n` |
| open | `/proc/<pid>/fd` | `lsof +L1` |
| persist | walk `/etc/systemd/system`, `~/.config/systemd/user` | `systemctl`, `loginctl`, `/var/lib/systemd/linger` |
| join | ghost + channel | `osqueryi` is never required |

Missing tools are **skipped and named**, not a crash. osquery is optional forever; the join is native Python.

## Out of scope

Kill, `rm`, `systemctl disable`, network isolate, remote IP reputation, fleet SSH, eBPF, installing packages, scanning a host you do not operate.

## Cases

JSON/HTML under `cases/` or `$XDG_DATA_HOME/linux-linger/` stay off git. The data directory is created `0700` and owned by the operator; reports, `ignore.txt`, and `run.sh` are owner-only (`0600` / `0700`) and are not written through a symlink. Any group- or world-writable ancestor of that path without the sticky bit is refused. A reboot drops ghosts and open fds. Keep the case.

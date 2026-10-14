# LinuxLinger™

A small CLI that takes a **live snapshot of this Linux host** for leftovers that remain after they should be gone: a deleted binary still running, an established socket, an unlinked file still held, and a unit or linger user that survives reboot.

It does **not** kill processes, disable units, or look up remote addresses.

Repo: https://github.com/wbharris/LinuxLinger

Contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

**LinuxLinger™** is a trademark of wbharris (common-law ™). See [`TRADEMARK.md`](TRADEMARK.md).

## What it does

| Command | Job |
|---------|-----|
| `linux-linger` / `scan` | All five checks |
| `ghost` | `/proc/<pid>/exe` still running after unlink |
| `channel` | Established sockets (`ss -tunap`) |
| `open` | Unlinked files still held (`nlink=0`, `lsof +L1` optional) |
| `persist` | Local systemd units + `loginctl` linger |
| `join` | Deleted binary **and** a remote socket |
| `guide` | Read-only next steps |
| `doctor` | Which collectors this host can run |
| `schedule install` | Repeat the scan on a systemd `--user` timer |
| `scan --html` | Stand-alone results page |

| Severity | Meaning |
|----------|---------|
| `critical` | Ghost PID with a non-loopback remote socket |
| `high` | Deleted binary under `/tmp` `/dev/shm` `/home`, or `ExecStart=` there |
| `medium` | Other leftovers: unlinked data files, recent local units, linger users |
| `info` | Package-upgrade ghosts, logrotate, ordinary sessions |
| `skip` | Ignore list |

## Install

```bash
git clone https://github.com/wbharris/LinuxLinger.git
cd LinuxLinger
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Python 3.11+. No extra runtime packages. `PYTHONPATH=src` works without an install:

```bash
PYTHONPATH=src python3 -m linux_linger --version
```

## Usage

```bash
linux-linger
linux-linger --problems-only
linux-linger --json
linux-linger --html -o cases/$(hostname).html
linux-linger ghost
linux-linger channel
linux-linger open
linux-linger persist
linux-linger join
linux-linger guide
linux-linger doctor
linux-linger ignore add pid:4242
linux-linger --notify
linux-linger schedule install --every hourly --notify
linux-linger schedule status
linux-linger schedule remove
```

Root (or `sudo -n`) sees other users' processes. Without it, the report notes that the snapshot is incomplete.

## One click

[`extra/linux-linger.desktop`](extra/linux-linger.desktop) runs a scan and opens the HTML case. Copy it to `~/.local/share/applications/`.

## Tests

```bash
PYTHONPATH=src python3 -m pytest -q
```

Live sudo is not required. Fixtures under `tests/data/` replay collector JSON.

## License

GPL-3.0-or-later. See `LICENSE`.

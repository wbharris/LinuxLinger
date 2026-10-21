# LinuxLinger™

A small CLI that takes a **live snapshot of this Linux host** for leftovers that remain after they should be gone: a deleted binary still running, an established socket, an unlinked file still held, and a unit or linger user that survives reboot.

It does **not** kill processes, disable units, or look up remote addresses.

Repo: https://github.com/wbharris/LinuxLinger

Contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

**LinuxLinger™** is a trademark of wbharris (common-law ™). See [`TRADEMARK.md`](TRADEMARK.md).

## Usage

```bash
linux-linger                 # scan this host
linux-linger -o case.html    # same scan, write an HTML case
linux-linger doctor          # which collectors this host can run
linux-linger schedule        # hourly background scan
linux-linger unschedule      # stop the timer
```

`--json` prints JSON. `--all` includes info summaries (package-upgrade ghosts, logrotate, ordinary sessions). `--redact` masks command-line arguments, home usernames, and linger names. Root (or `sudo -n`) sees other users' processes.

Reports include process command lines, paths, and usernames. On-disk cases are owner-only (`0600`). `--json` and the default text go to stdout and can land in terminal scrollback, CI logs, or a pipe. Use `--redact` before sharing a transcript. Scheduled `last.html` is a full (unredacted) case in the private data dir.

| Severity | Meaning |
|----------|---------|
| `critical` | Deleted binary with a non-loopback remote socket |
| `high` | Deleted binary or `ExecStart=` under `/tmp` `/dev/shm` `/home` |
| `medium` | Other leftovers: unlinked data files, recent local units, linger users |
| `info` | Noise, hidden unless `--all` |

## Install

Python 3.11+. No extra runtime packages. See [`docs/INSTALL.md`](docs/INSTALL.md) for tagged installs, upgrade, and uninstall. Environments: [`docs/COMPAT.md`](docs/COMPAT.md).

```bash
git clone https://github.com/wbharris/LinuxLinger.git
cd LinuxLinger
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

`PYTHONPATH=src` works without an install:

```bash
PYTHONPATH=src python3 -m linux_linger --version
```

## One click

[`extra/linux-linger.desktop`](extra/linux-linger.desktop) runs a scan and opens the HTML case. Copy it to `~/.local/share/applications/`.

## Tests

```bash
PYTHONPATH=src python3 -m pytest -q
```

GitHub Actions runs that suite on Python 3.11–3.13 and builds an sdist/wheel. `v*` tags upload those artifacts to a GitHub Release.

Live sudo is not required. Fixtures under `tests/data/` replay collector JSON.

## License

GPL-3.0-or-later. See `LICENSE`.

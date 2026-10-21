# LinuxLinger

Live leftovers on this Linux host. Collectors and reports only.

- Do not add kill, `rm`, `systemctl disable`, quarantine, iptables/nft isolate, or any write to the target host beyond the case file, ignore list, and user timer units.
- Do not add an HTTP client, IP reputation, or a GeoIP lookup. Remote addresses stay as the host reported them.
- Do not install osquery, lsof, or ss. `linux-linger doctor` names missing tools. The join is native Python.
- Do not scan a host other than the one running the CLI. No SSH fleet.
- Cases under `cases/` and `$XDG_DATA_HOME/linux-linger/` are gitignored. Do not commit a live report. The data dir is 0700; reports, ignore.txt, and run.sh are owner-only. Do not follow symlinks when writing those files. Refuse a group/world-writable parent unless it has the sticky bit.
- Public CLI is `linux-linger`, `-o`, `--json`, `--all`, `doctor`, `schedule`, `unschedule`. Do not add `ghost` / `channel` / `open` / `persist` / `join` as commands.
- Tests: `PYTHONPATH=src python3 -m pytest -q` from this repo. The repo root is the `LinuxLinger` directory, not the parent `Projects` directory. Fixtures under `tests/data/` — no live sudo in CI. `--fixture` is a test hook, hidden from `--help`.

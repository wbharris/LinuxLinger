# Supported environments

LinuxLinger is a **Linux `/proc` tool**. Collectors and `schedule` are not supported on other kernels.

## Tested shape

| Piece | Expectation |
|-------|-------------|
| Python | 3.11+ |
| Kernel | Linux with `/proc/<pid>/exe` and `/proc/<pid>/fd` |
| systemd | Optional. `persist` walks unit files without `systemctl`. `schedule` needs `systemctl --user` |
| ss | Optional. Without it, channel and join skip live sockets |
| lsof | Optional. `/proc/<pid>/fd` is enough for unlinked files |
| Root | Without root (or `sudo -n`), other users' `/proc` entries are skipped and the scan is marked incomplete |

CI runs the fixture test suite on Python 3.11–3.13. Live `ss`/`lsof`/`systemctl` calls are not required in CI.

## Containers and restricted `/proc`

- **hidepid=2** or a container `/proc` that only shows the current pid: ghosts, open files, and join for other processes are missing. `doctor` still runs. The report sets `incomplete`.
- **No systemd** (many containers): persist finds no linger directory and skips `systemctl`/`loginctl`. `linux-linger schedule` fails if the user manager is absent.
- **User namespaces**: `/proc/<pid>/exe` may read as `PermissionError`; those pids are counted in the denied note.

## Scheduling

`linux-linger schedule` writes a systemd **user** timer (`linux-linger.timer`) and a `run.sh` under the private data dir. It needs:

- a working `systemctl --user` bus (typical graphical or lingering session)
- a private `XDG_DATA_HOME` (see the product contract)

It does not install a system unit.

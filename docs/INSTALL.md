# Install, upgrade, uninstall

Python 3.11+ on Linux. No runtime PyPI dependencies.

## From git

```bash
python3 -m pip install --user "git+https://github.com/wbharris/LinuxLinger.git"
linux-linger --version
```

Pin a tag when one exists: `git+https://github.com/wbharris/LinuxLinger.git@v0.1.0`. GitHub Release assets on each `v*` tag are the sdist and wheel from `python -m build`. Verify the tag commit on GitHub before you install.

## From a clone (development)

```bash
git clone https://github.com/wbharris/LinuxLinger.git
cd LinuxLinger
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
linux-linger --version
```

`PYTHONPATH=src python3 -m linux_linger` works without installing.

## Upgrade

```bash
python3 -m pip install --user --upgrade "git+https://github.com/wbharris/LinuxLinger.git"
```

Or in a clone: `git pull` then `.venv/bin/pip install -e ".[dev]"`.

If a user timer is enabled, `linux-linger unschedule` then `linux-linger schedule` after the upgrade so `run.sh` and the unit files match this version.

## Uninstall

```bash
linux-linger unschedule     # if you scheduled a timer
python3 -m pip uninstall linux-linger
```

Case files under `$XDG_DATA_HOME/linux-linger/` (default `~/.local/share/linux-linger/`) are left in place. Remove that directory yourself if you want them gone. The desktop file, if you copied it, lives in `~/.local/share/applications/linux-linger.desktop`.

import shlex
from pathlib import Path

from linux_linger.schedule import install, remove, write_runner_script


def _stub_which(linger=None, notify=None):
    def which(name: str):
        if name == "linux-linger":
            return linger
        if name == "notify-send":
            return notify
        return None

    return which


def _stub_run(calls: list):
    def run(argv, **_kwargs):
        calls.append(list(argv))
        return 0, "", ""

    return run


def test_remove_stops_timer_without_disable(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "linux-linger.timer").write_text("[Timer]\n", encoding="utf-8")
    (unit_dir / "linux-linger.service").write_text("[Service]\n", encoding="utf-8")
    wants = unit_dir / "timers.target.wants"
    wants.mkdir()
    (wants / "linux-linger.timer").symlink_to(unit_dir / "linux-linger.timer")
    calls: list[list[str]] = []
    monkeypatch.setattr("linux_linger.schedule.run", _stub_run(calls))
    msg = remove()
    assert "linux-linger.timer" in msg
    assert calls[0] == ["systemctl", "--user", "stop", "linux-linger.timer"]
    assert calls[1] == ["systemctl", "--user", "daemon-reload"]
    assert not any("disable" in argv for argv in calls)
    assert not (unit_dir / "linux-linger.timer").exists()
    assert not (unit_dir / "linux-linger.service").exists()
    leftover = unit_dir / "timers.target.wants" / "linux-linger.timer"
    assert not leftover.is_symlink()
    assert not leftover.exists()


def test_run_sh_quotes_metacharacter_paths(tmp_path, monkeypatch):
    data = tmp_path / 'share dir$`";\\()'
    linger = tmp_path / "bin" / "linux-linger;rm"
    linger.parent.mkdir(parents=True)
    linger.write_text("#!/bin/sh\n", encoding="utf-8")
    notify = tmp_path / "bin" / "notify-send"
    notify.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setattr("linux_linger.schedule.which", _stub_which(str(linger), str(notify)))
    path = write_runner_script(notify=True)
    text = path.read_text(encoding="utf-8")
    scan_line = next(ln for ln in text.splitlines() if "-o" in ln)
    argv = shlex.split(scan_line)
    assert argv[0] == str(linger)
    assert argv[1] == "-o"
    assert argv[2].endswith("last.html")
    assert data.name in argv[2]
    notify_line = next(ln for ln in text.splitlines() if "notify-send" in ln)
    notify_argv = shlex.split(notify_line[notify_line.index("notify-send") :])
    assert notify_argv[0] == "notify-send"
    assert notify_argv[1] == "LinuxLinger"
    assert str(data) in notify_argv[2]


def test_install_quotes_execstart_and_enables(tmp_path, monkeypatch):
    home = tmp_path / "home with space"
    home.mkdir()
    data = tmp_path / "share with $dollar"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setattr(
        "linux_linger.schedule.which",
        _stub_which(str(tmp_path / "linux-linger")),
    )
    calls: list[list[str]] = []
    monkeypatch.setattr("linux_linger.schedule.run", _stub_run(calls))
    msg = install(every="hourly", notify=False)
    service = (home / ".config" / "systemd" / "user" / "linux-linger.service").read_text(
        encoding="utf-8"
    )
    exec_line = next(ln for ln in service.splitlines() if ln.startswith("ExecStart="))
    value = exec_line.split("=", 1)[1]
    assert value.startswith('"')
    assert "$dollar" in value
    assert ["systemctl", "--user", "enable", "--now", "linux-linger.timer"] in calls
    assert "disable" not in " ".join(msg)
    run_sh = Path(data / "linux-linger" / "run.sh")
    assert run_sh.is_file()
    assert "set +e" in run_sh.read_text(encoding="utf-8")

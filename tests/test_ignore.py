from linux_linger.ignore import apply_ignore, is_ignored
from linux_linger.models import Finding, Report


def test_ignore_pid_and_unit():
    report = Report(
        hostname="box",
        os="Debian",
        kernel="1",
        scanned_at="2026-10-14T00:00:00Z",
        findings=[
            Finding(
                id="ghost:4242",
                check="ghost",
                severity="high",
                name=".x",
                detail="deleted",
                pid=4242,
            ),
            Finding(
                id="persist:system:evil.service",
                check="persist",
                severity="high",
                name="evil.service",
                detail="tmp",
                unit="evil.service",
            ),
        ],
    )
    assert is_ignored(report.findings[0], ["pid:4242"])
    n = apply_ignore(report, ["unit:evil.service"])
    assert n == 1
    assert report.findings[1].severity == "skip"
    assert report.findings[0].severity == "high"

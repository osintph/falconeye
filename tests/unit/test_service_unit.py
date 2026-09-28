"""The service must not write to a directory nothing creates.

Reported against v3.34.0: on a fresh or an upgraded self-host, gunicorn died
with a PermissionError on `/var/log/falconeye/error.log` and systemd
crash-looped the unit. The unit has always pointed `--access-logfile` and
`--error-logfile` at `/var/log/falconeye/`, and nothing in the unit created it.
`scripts/provision.sh` did, so the reference deployment and anyone who ran the
provisioner never saw it; the manual install in the README never created it, and
neither did an upgrade, so a box that had lost the directory (or never had it)
could not start the service at all.

The fix is `LogsDirectory=falconeye`, which makes systemd create `/var/log/falconeye`
before ExecStart, owned by User=/Group=, on every start. Quoting systemd.exec(5)
as shipped on the deployment target:

    the specified names will be created (including their parents) below the
    locations defined in the following table [LogsDirectory= -> /var/log/]

    Except in case of ConfigurationDirectory=, the innermost specified
    directories will be owned by the user and group specified in User= and
    Group=. If the specified directories already exist and their owning user or
    group do not match the configured ones, all files and directories below the
    specified directories as well as the directories themselves will have their
    file ownership recursively changed to match what is configured.

So it both creates the directory on a fresh box and repairs one that exists with
the wrong owner.

The tests below are written against the bug class rather than against the one
path: any file the unit is told to write under `/var/log/<name>/` must have a
matching `LogsDirectory=<name>`. A second log file added tomorrow under a new
directory fails here until the unit creates it.
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
UNIT = REPO / "falconeye.service"
PROVISION = REPO / "scripts" / "provision.sh"
README = REPO / "README.md"
RUNBOOK = REPO / "docs" / "deploy-runbook.md"


def _unit_text() -> str:
    return UNIT.read_text(encoding="utf-8")


def _directive(name: str) -> list:
    """Every value of a directive in the [Service] section, continuations joined."""
    text = re.sub(r"\\\s*\n\s*", " ", _unit_text())
    return [m.group(1).strip() for m in re.finditer(rf"^{name}=(.*)$", text, re.M)]


def _exec_start() -> str:
    values = _directive("ExecStart")
    assert values, "falconeye.service has no ExecStart"
    return values[0]


def _log_paths() -> list:
    """Absolute paths the unit tells gunicorn to write to."""
    return re.findall(r"--(?:access|error)-logfile\s+(\S+)", _exec_start())


# ---------- the bug class ----------

def test_the_unit_writes_to_at_least_one_log_file():
    """If this ever stops being true the rest of the file is vacuous."""
    assert _log_paths(), "no --access-logfile/--error-logfile in ExecStart"


def test_every_log_path_has_a_directory_systemd_creates():
    """The rule, stated once: nothing may be written to a directory no one makes."""
    declared = set()
    for value in _directive("LogsDirectory"):
        declared.update(value.split())

    for path in _log_paths():
        assert path.startswith("/var/log/"), (
            f"{path} is not under /var/log/, so LogsDirectory= cannot create it; "
            "either move it or create the directory another way"
        )
        directory = path[len("/var/log/"):].split("/")[0]
        assert directory in declared, (
            f"the unit writes {path} but does not declare LogsDirectory={directory}. "
            "On a fresh or upgraded host that directory does not exist and gunicorn "
            "dies with a PermissionError before serving anything."
        )


def test_the_unit_declares_the_logs_directory():
    assert "LogsDirectory=falconeye" in _unit_text()


def test_the_logs_directory_is_a_bare_name_not_a_path():
    """systemd takes a name relative to /var/log/; an absolute path is rejected
    and the unit fails to load, which is a worse failure than the one being fixed."""
    for value in _directive("LogsDirectory"):
        for name in value.split():
            assert not name.startswith("/"), (
                f"LogsDirectory={name} must be a name below /var/log/, not a path"
            )
            assert ".." not in name


def test_the_unit_still_runs_as_the_service_user():
    """LogsDirectory owns the directory to User=/Group=, so those have to be set
    or the directory lands on root and gunicorn still cannot write."""
    assert _directive("User") == ["ubuntu"]
    assert _directive("Group") == ["ubuntu"]


def test_the_forwarded_allow_ips_pin_survives():
    """Editing ExecStart is how the rate-limit pin gets lost. It has its own test
    in test_client_ip.py; this is the cheap guard next to the edit."""
    assert "--forwarded-allow-ips 127.0.0.1" in re.sub(r"\\\s*\n\s*", " ", _unit_text())


# ---------- the manual and provisioned paths ----------

def test_provision_creates_the_log_directory_for_the_service_user():
    text = PROVISION.read_text(encoding="utf-8")
    assert "/var/log/falconeye" in text, "provision.sh does not create the log directory"
    # Created AND handed to the service user: a root-owned directory is the same
    # PermissionError with extra steps.
    creating = [line for line in text.splitlines()
                if "/var/log/falconeye" in line and ("mkdir" in line or "install -d" in line)]
    assert creating, "provision.sh mentions the log directory but never creates it"
    assert any("SERVICE_USER" in line for line in creating) or any(
        "SERVICE_USER" in line and "/var/log/falconeye" in line
        for line in text.splitlines()), (
        "provision.sh creates the log directory but never gives it to the service user"
    )


def test_the_manual_install_creates_the_log_directory():
    """The README path that produced the report: copy the unit, enable, crash."""
    text = README.read_text(encoding="utf-8")
    install = text[text.index("# 6. Install systemd unit"):]
    install = install[:install.index("# 7.")]
    assert "/var/log/falconeye" in install, (
        "the manual install does not create the log directory; a fresh host "
        "following the README crash-loops on first start"
    )


def test_the_runbook_tells_an_upgrader_about_it():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "LogsDirectory" in text, "the runbook does not mention the unit change"
    assert "/var/log/falconeye" in text
    # It has to be reachable from the release sequence, not buried in an appendix.
    sequence = text[text.index("## Standard release sequence"):]
    sequence = sequence[:sequence.index("## Rollback")]
    assert "daemon-reload" in sequence, (
        "the release sequence does not tell the operator to reload systemd, so a "
        "changed unit file is not picked up"
    )

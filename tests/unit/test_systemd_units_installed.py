"""Every systemd unit shipped in the repo must be installed by the upgrade path.

The bug class, reported for v3.38.18: app/hunt/nrd_fetch.py and app/config.py both
assumed a daily `falconeye-nrd.timer` ran the NRD feed, but no unit file was in the
repo and no script installed one. The feature was enabled by default and silently
did nothing on every deploy except the one box where the timer had been installed
by hand.

This test states the rule once: a .service or .timer that ships in the repo
(falconeye.service at the root, or anything under deploy/) has to be installed by
scripts/upgrade.sh, through a function defined in scripts/lib/common.sh. A unit
added tomorrow without wiring an installer, or an installer that upgrade.sh never
calls, fails here. Timers must also be enabled, not merely copied.

Units an operator installs by hand and the repo does not ship (the cf-ufw-refresh
timer in /opt/falconeye/ops, ransomware-collect.*) are out of scope by
construction: they are not files this test enumerates.

v3.39.0 widened the rule to every system file under deploy/, not only units:
the journald drop-in had shipped in deploy/journald since v3.33.3 and was copied
by hand, and the new logrotate file and sweep timer must not repeat that. Every
file under deploy/ must be installed by an fe_* function that BOTH upgrade.sh and
provision.sh call.
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
COMMON = REPO / "scripts" / "lib" / "common.sh"
UPGRADE = REPO / "scripts" / "upgrade.sh"
PROVISION = REPO / "scripts" / "provision.sh"
DEPLOY = REPO / "deploy"


def _repo_units() -> list:
    """Every unit file the repo ships: the root service plus deploy/*.{service,timer}."""
    units = []
    if (REPO / "falconeye.service").is_file():
        units.append("falconeye.service")
    for pat in ("*.service", "*.timer"):
        units.extend(sorted(p.name for p in DEPLOY.glob(pat)))
    return units


def _fe_functions(text: str) -> dict:
    """{function name: body} for every fe_* shell function in the text."""
    out = {}
    for m in re.finditer(r"^([a-z0-9_]+)\(\)\s*\{", text, re.M):
        name = m.group(1)
        body = text[m.end():]
        end = body.find("\n}\n")
        out[name] = body[:end if end != -1 else len(body)]
    return out


def test_the_repo_ships_at_least_the_known_units():
    """If this ever returns nothing the rest of the file is vacuous."""
    units = _repo_units()
    assert "falconeye.service" in units
    assert "falconeye-asm-monitor.timer" in units
    assert "falconeye-nrd.timer" in units, (
        "the NRD feed timer is missing from deploy/; the Hunt's local newly-"
        "registered-domain store will never be populated"
    )


def test_every_repo_unit_is_installed_by_the_upgrade_path():
    common = COMMON.read_text(encoding="utf-8")
    upgrade = UPGRADE.read_text(encoding="utf-8")
    funcs = _fe_functions(common)
    called = set(re.findall(r"\bfe_[a-z0-9_]+", upgrade))

    for unit in _repo_units():
        if unit == "falconeye.service":
            # The main app unit is installed by fe_install_unit (via FE_UNIT_DEST),
            # which does not spell the filename literally.
            assert "fe_install_unit" in funcs, "fe_install_unit is not defined"
            assert "fe_install_unit" in called, "upgrade.sh does not call fe_install_unit"
            continue

        installers = [name for name, body in funcs.items()
                      if name.startswith("fe_") and unit in body]
        assert installers, (
            f"no fe_* function in common.sh installs {unit}. Ship it in deploy/ AND "
            "add an installer function that upgrade.sh calls, or the unit never "
            "reaches a deployed box."
        )
        assert any(name in called for name in installers), (
            f"{unit} is installed by {installers}, but upgrade.sh never calls any of "
            "them, so the unit is not installed on an upgrade."
        )


def test_every_repo_timer_is_enabled_not_only_copied():
    """A timer that is copied but never `systemctl enable`d does not fire."""
    common = COMMON.read_text(encoding="utf-8")
    for unit in _repo_units():
        if not unit.endswith(".timer"):
            continue
        assert re.search(rf"systemctl\s+enable[^\n]*{re.escape(unit)}", common), (
            f"{unit} is never enabled in common.sh; copying the file is not enough, "
            "systemd will not start a timer that was not enabled"
        )


def _deploy_files() -> list:
    """Every system file the repo ships under deploy/, as (relative path, name)."""
    return sorted((str(p.relative_to(REPO)), p.name) for p in DEPLOY.rglob("*")
                  if p.is_file() and not p.name.startswith(".") and p.suffix != ".md")


def test_the_v3_39_0_system_files_ship_in_deploy():
    names = {name for _, name in _deploy_files()}
    for required in ("falconeye-sweep.service", "falconeye-sweep.timer",
                     "falconeye", "falconeye-retention.conf"):
        assert required in names, f"deploy/ is missing {required}"
    assert (DEPLOY / "logrotate" / "falconeye").is_file()


def test_every_deploy_file_is_installed_by_both_scripts():
    common = COMMON.read_text(encoding="utf-8")
    funcs = _fe_functions(common)
    for script in (UPGRADE, PROVISION):
        called = set(re.findall(r"\bfe_[a-z0-9_]+", script.read_text(encoding="utf-8")))
        for rel, name in _deploy_files():
            needle = rel if name == "falconeye" else name  # the logrotate file is just "falconeye"
            installers = [f for f, body in funcs.items() if f.startswith("fe_") and needle in body]
            assert installers, f"no fe_* function in common.sh installs {rel}"
            assert any(f in called for f in installers), (
                f"{rel} is installed by {installers}, but {script.name} never calls them")


def test_the_sweep_timer_runs_every_15_minutes_and_calls_the_sweep():
    timer = (DEPLOY / "falconeye-sweep.timer").read_text(encoding="utf-8")
    service = (DEPLOY / "falconeye-sweep.service").read_text(encoding="utf-8")
    assert re.search(r"^OnUnitActiveSec=15min$", timer, re.M)
    assert re.search(r"^ExecStart=\S+python -m app\.sweep$", service, re.M)


def test_the_logrotate_file_has_the_required_policy():
    text = (DEPLOY / "logrotate" / "falconeye").read_text(encoding="utf-8")
    assert "/var/log/falconeye/*.log {" in text
    for directive in ("daily", "rotate 14", "compress", "delaycompress", "missingok", "notifempty"):
        assert re.search(rf"^\s+{directive}$", text, re.M), f"logrotate file lacks {directive}"
    # gunicorn reopens its logs on USR1 to the master (docs.gunicorn.org/en/stable/signals.html).
    assert re.search(r"postrotate\n\s+systemctl kill --signal=USR1 --kill-whom=main falconeye\.service", text)


def test_journald_is_restarted_only_when_the_drop_in_changed():
    body = _fe_functions(COMMON.read_text(encoding="utf-8"))["fe_install_journald"]
    unchanged = body.index("cmp -s")
    restart = body.index("systemctl restart systemd-journald")
    assert unchanged < restart and "return 0" in body[unchanged:restart]


def test_the_sweep_is_installed_after_the_hash_key_and_release_actions():
    """A timer fires at once when started, so installing it before FE_HASH_KEY
    exists would hash rows with a throwaway key."""
    up = UPGRADE.read_text(encoding="utf-8")
    assert up.index("fe_ensure_hash_key") < up.index("fe_apply_release_actions") < up.index("fe_install_sweep")

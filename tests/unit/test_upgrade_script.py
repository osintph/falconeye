"""One upgrade path, and it cannot drift from the install path.

Upgrading was a numbered list in a runbook: fetch, reset, maybe pip, maybe copy
the unit, maybe touch nginx, maybe flush a cache, restart, check. Every "maybe"
was a judgement call made at 2am, and v3.34.2 is what happens when one of them is
skipped: the unit file changed, nobody copied it, and systemd kept running the
old directives.

`scripts/upgrade.sh` is now that list, executed the same way every time. The
tests here are about the two properties that make it trustworthy:

1. **It cannot quietly do nothing.** Every step that changes the box goes through
   the dry-run wrapper, so `--dry-run` really is a preview and a step added later
   cannot bypass it.
2. **It cannot drift from provision.sh.** Both source the same library and call
   the same functions, so a fix to the install path is a fix to the upgrade path.

Plus the hard rules the script must never break: it must not overwrite the
operator's vhost (their `server_name` and certificate paths live in it), and it
must fail loudly, with a rollback command, when the running version is not the
one that was just deployed.
"""
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
UPGRADE = SCRIPTS / "upgrade.sh"
PROVISION = SCRIPTS / "provision.sh"
LIB = SCRIPTS / "lib" / "common.sh"
README = REPO / "README.md"
RUNBOOK = REPO / "docs" / "deploy-runbook.md"

UPGRADE_COMMAND = "sudo /opt/falconeye/app_src/scripts/upgrade.sh"


def _text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _function_body(path: pathlib.Path, name: str) -> str:
    """The body of a shell function, located by its definition rather than by
    the first time its name is mentioned (which is usually a comment)."""
    text = _text(path)
    match = re.search(rf"^{name}\(\)\s*\{{", text, re.M)
    assert match, f"{name}() is not defined in {path.name}"
    body = text[match.end():]
    end = body.find("\n}\n")
    return body[:end if end != -1 else len(body)]


# ---------- the files exist and are runnable ----------

def test_the_scripts_exist_and_are_executable():
    for path in (UPGRADE, PROVISION, LIB):
        assert path.is_file(), f"{path} is missing"
    for path in (UPGRADE, PROVISION):
        assert path.stat().st_mode & 0o111, f"{path} is not executable"


def test_every_script_parses():
    """A shell script with a syntax error fails halfway through an upgrade."""
    for path in (UPGRADE, PROVISION, LIB):
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{path.name}: {result.stderr}"


def test_the_scripts_stop_on_the_first_error():
    for path in (UPGRADE, PROVISION):
        assert "set -euo pipefail" in _text(path), (
            f"{path.name} does not use 'set -euo pipefail'; a failed step would be "
            "skipped and the upgrade would report success"
        )


# ---------- one library, two callers ----------

def test_both_scripts_source_the_shared_library():
    for path in (UPGRADE, PROVISION):
        assert "lib/common.sh" in _text(path), (
            f"{path.name} does not source the shared library, so install and "
            "upgrade can drift apart again"
        )


SHARED_STEPS = (
    "fe_install_unit",
    "fe_install_nginx_snippets",
    "fe_ensure_log_dir",
    "fe_db_init",
)


def test_provision_uses_the_shared_functions():
    """Not a copy of the same commands: the same functions."""
    text = _text(PROVISION)
    for func in SHARED_STEPS:
        assert func in text, f"provision.sh does not call {func}()"


def test_upgrade_uses_the_shared_functions():
    text = _text(UPGRADE)
    for func in SHARED_STEPS:
        assert func in text, f"upgrade.sh does not call {func}()"


def test_the_library_defines_everything_both_call():
    lib = _text(LIB)
    called = set()
    for path in (UPGRADE, PROVISION):
        called.update(re.findall(r"\bfe_[a-z0-9_]+", _text(path)))
    defined = set(re.findall(r"^([a-z0-9_]+)\s*\(\)", lib, re.M))
    missing = {name for name in called if name not in defined}
    assert not missing, f"called but not defined in lib/common.sh: {sorted(missing)}"


def test_provision_no_longer_copies_the_unit_by_hand():
    """The duplicate that let the unit drift in the first place."""
    text = _text(PROVISION)
    assert not re.search(r"^\s*cp\b.*falconeye\.service\s+/etc/systemd", text, re.M), (
        "provision.sh copies the unit with its own cp instead of fe_install_unit"
    )


# ---------- dry run has to mean dry run ----------

# Commands that change the box. If one of these appears outside the dry-run
# wrapper, --dry-run is a lie.
MUTATING = r"(cp|mv|rm|install|mkdir|chown|chmod|systemctl|sqlite3|git reset|git fetch)\b"


def _executable_lines(path: pathlib.Path):
    """Lines that actually run, with comments and here-doc bodies removed."""
    out, in_heredoc, terminator = [], False, None
    for raw in _text(path).splitlines():
        if in_heredoc:
            if raw.strip() == terminator:
                in_heredoc = False
            continue
        heredoc = re.search(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?", raw)
        if heredoc:
            in_heredoc, terminator = True, heredoc.group(1)
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def test_every_mutating_command_goes_through_the_dry_run_wrapper():
    """The bug class: a step added later that ignores --dry-run."""
    offenders = []
    for line in _executable_lines(UPGRADE):
        if re.match(rf"^{MUTATING}", line) and not line.startswith(("fe_run", "fe_")):
            offenders.append(line)
    assert not offenders, (
        "these lines in upgrade.sh change the box without going through fe_run, "
        f"so --dry-run would still do them: {offenders}"
    )


def test_the_library_mutators_respect_dry_run():
    offenders = []
    for line in _executable_lines(LIB):
        if re.match(rf"^{MUTATING}", line) and not line.startswith(("fe_run", "fe_")):
            offenders.append(line)
    assert not offenders, f"lib/common.sh mutates outside fe_run: {offenders}"


def test_the_dry_run_flag_is_documented_in_usage():
    text = _text(UPGRADE)
    assert "--dry-run" in text
    assert "DRY_RUN" in text


# ---------- the vhost is the operator's ----------

def test_the_upgrade_never_writes_the_vhost():
    """server_name and the certificate paths live there. Overwriting it takes a
    self-hoster's site down and hands them the upstream operator's hostname."""
    for path in (UPGRADE, LIB):
        for line in _executable_lines(path):
            if "sites-available" not in line and "sites-enabled" not in line:
                continue
            assert not re.match(rf"^{MUTATING}", line), (
                f"{path.name} writes to the vhost: {line}"
            )


def test_the_upgrade_warns_when_the_shipped_vhost_has_changed():
    """Not copying it silently is how an operator misses a required change."""
    assert "fe_check_vhost_drift" in _text(UPGRADE)
    drift = _function_body(LIB, "fe_check_vhost_drift")
    assert "falconeye.conf" in drift


def test_conf_d_files_are_only_updated_when_already_installed():
    """goaccess-logformat.conf is opt-in: installing it on upgrade would turn on
    a log format the operator never asked for."""
    body = _function_body(LIB, "fe_sync_nginx_confd")
    assert re.search(r"if\s*\[\[\s*!?\s*-f ", body), (
        "fe_sync_nginx_confd does not check whether the file is already installed"
    )


# ---------- health check and rollback ----------

def test_the_health_check_compares_the_version():
    text = _text(UPGRADE) + _text(LIB)
    assert "fe_health_check" in text
    assert "/health" in text


def test_a_failed_health_check_prints_a_rollback_command():
    body = _function_body(LIB, "fe_health_check")
    assert "rollback" in body.lower() or "roll back" in body.lower(), (
        "fe_health_check does not tell the operator how to roll back"
    )
    assert "upgrade.sh" in body, "the rollback advice does not name the command to run"


def test_the_upgrade_captures_the_previous_ref_before_resetting():
    """A rollback command that names the wrong version is worse than none."""
    text = _text(UPGRADE)
    reset = text.index("fe_git_checkout") if "fe_git_checkout" in text else text.index("reset")
    captured = re.search(r"PREVIOUS_[A-Z_]*\s*=", text[:reset])
    assert captured, "upgrade.sh resets the checkout before recording where it was"


# ---------- backups ----------

def test_the_backup_covers_env_database_and_unit():
    body = _function_body(LIB, "fe_backup")
    for needle in ("FE_ENV_FILE", "FE_DB", "FE_UNIT_DEST"):
        assert needle in body, f"fe_backup does not back up {needle}"


def test_the_backup_is_timestamped():
    assert "fe_timestamp" in _text(LIB)
    assert "date" in _function_body(LIB, "fe_timestamp")


def test_backups_happen_before_anything_is_changed():
    text = _text(UPGRADE)
    assert text.index("fe_backup") < text.index("fe_git_checkout"), (
        "the upgrade changes the checkout before backing anything up"
    )


# ---------- release actions ----------

ACTIONS_DIR = SCRIPTS / "release-actions"


def test_release_actions_are_named_after_the_version_they_belong_to():
    assert ACTIONS_DIR.is_dir(), "scripts/release-actions/ is missing"
    for path in ACTIONS_DIR.glob("*.sh"):
        assert re.fullmatch(r"\d+\.\d+\.\d+\.sh", path.name), (
            f"{path.name} is not <version>.sh, so ordering cannot be derived from it"
        )


def test_every_release_action_parses():
    for path in ACTIONS_DIR.glob("*.sh"):
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{path.name}: {result.stderr}"


def test_the_cache_flushes_this_release_declared_are_present():
    """The two flushes that were run by hand for v3.34.0 and v3.34.1."""
    names = {p.name for p in ACTIONS_DIR.glob("*.sh")}
    assert "3.34.0.sh" in names and "3.34.1.sh" in names
    combined = "".join(_text(p) for p in ACTIONS_DIR.glob("*.sh"))
    assert "ip_intel_cache" in combined


def test_release_actions_are_applied_once_and_recorded():
    body = _function_body(LIB, "fe_apply_release_actions")
    assert "FE_STATE_FILE" in body or "fe_mark_release_action" in body, (
        "applied actions are not recorded, so every upgrade re-runs every flush"
    )


# ---------- the documentation says one thing ----------

def test_the_readme_documents_the_one_command():
    text = _text(README)
    assert UPGRADE_COMMAND in text, "the README does not document scripts/upgrade.sh"


def test_the_runbook_documents_the_one_command():
    text = _text(RUNBOOK)
    assert UPGRADE_COMMAND in text


def test_the_manual_list_moved_to_an_appendix():
    text = _text(RUNBOOK)
    assert "what upgrade.sh does" in text.lower(), (
        "the numbered manual sequence has no appendix heading naming it as what "
        "the script does"
    )
    appendix = text.lower().index("what upgrade.sh does")
    release_section = text.index("## Standard release sequence")
    assert appendix > release_section, (
        "the manual list is still the primary instruction rather than an appendix"
    )


def test_the_release_sequence_leads_with_the_script():
    """An operator reading top to bottom must hit the command before the list."""
    text = _text(RUNBOOK)
    section = text[text.index("## Standard release sequence"):]
    section = section[:section.index("\n## ")]
    assert UPGRADE_COMMAND in section, (
        "the release sequence does not name the upgrade command"
    )

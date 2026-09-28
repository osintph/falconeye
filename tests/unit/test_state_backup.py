"""What has to survive the box, and the two scripts that move it.

`git reset --hard` restores the application. It restores none of the state that
makes an install *that operator's* install: the API keys in `.env`, the abuse
audit trail in the database, the Telegram session that took an interactive login
to create, the Cloudflare Origin CA private key that cannot be downloaded again.

Until now that list lived in nobody's head in one piece. It is now
`fe_state_paths()` in `scripts/lib/common.sh`, and the docs, `scripts/backup.sh`
and `scripts/restore.sh` all read from it, so the list cannot be right in one
place and wrong in another.

The tests below hold the properties that make a restore trustworthy:

- the documented list and the code list are the same list
- a backup is verifiable (sha256, recorded next to it)
- a restore refuses an archive it cannot verify, and refuses one carrying paths
  outside the known roots, because it runs as root and `tar` will happily write
  `/etc/passwd` if you let it
- a restore never overwrites without keeping what it overwrote
"""
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
LIB = SCRIPTS / "lib" / "common.sh"
BACKUP = SCRIPTS / "backup.sh"
RESTORE = SCRIPTS / "restore.sh"
README = REPO / "README.md"
RUNBOOK = REPO / "docs" / "deploy-runbook.md"


def _text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _state_paths():
    """Run fe_state_paths() and parse its records: class|path|why."""
    script = f'source "{LIB}"; fe_state_paths'
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    records = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        assert len(parts) == 3, f"malformed record: {line!r}"
        records.append({"class": parts[0].strip(), "path": parts[1].strip(),
                        "why": parts[2].strip()})
    return records


# ---------- the scripts exist and run ----------

def test_the_scripts_exist_and_are_executable():
    for path in (BACKUP, RESTORE):
        assert path.is_file(), f"{path} is missing"
        assert path.stat().st_mode & 0o111, f"{path} is not executable"


def test_the_scripts_parse():
    for path in (BACKUP, RESTORE):
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{path.name}: {result.stderr}"


def test_the_scripts_stop_on_the_first_error():
    for path in (BACKUP, RESTORE):
        assert "set -euo pipefail" in _text(path)


def test_both_scripts_use_the_shared_list():
    for path in (BACKUP, RESTORE):
        assert "fe_state_paths" in _text(path), (
            f"{path.name} has its own idea of what state is, which is how the "
            "list goes stale"
        )


def test_both_scripts_have_a_dry_run():
    for path in (BACKUP, RESTORE):
        assert "--dry-run" in _text(path)


# ---------- the list itself ----------

def test_the_list_is_not_empty_and_is_classified():
    records = _state_paths()
    assert records, "fe_state_paths() produced nothing"
    for record in records:
        assert record["class"] in ("essential", "convenience"), record
        assert record["path"].startswith("/"), record
        assert len(record["why"]) > 15, f"no reason given for {record['path']}"


def test_the_essentials_are_all_there():
    """Verified against app/config.py, falconeye.service and the live vhost, not
    against anyone's recollection."""
    paths = {r["path"] for r in _state_paths() if r["class"] == "essential"}
    # EnvironmentFile= in falconeye.service
    assert any(p.endswith("/.env") for p in paths), "the .env is not listed"
    # FALCONEYE_DB in app/config.py
    assert any(p.endswith("falconeye.db") or p.rstrip("/").endswith("/data") for p in paths), (
        "the application database is not listed"
    )
    # TELEGRAM_SESSION_PATH in app/config.py, used by app/telegram/tier3_mtproto.py
    assert any("session" in p or p.rstrip("/").endswith("/private") for p in paths), (
        "the Telegram session is not listed"
    )
    # ssl_certificate / ssl_certificate_key in nginx/falconeye.conf
    assert any("/etc/ssl/falconeye" in p for p in paths), "the origin certificate is not listed"
    # The operator's own vhost
    assert any("sites-available" in p for p in paths), "the nginx vhost is not listed"


def test_every_listed_path_is_reachable_from_code_or_config():
    """A path nobody references is a path nobody has to back up."""
    sources = "".join(_text(REPO / name) for name in (
        "app/config.py", "falconeye.service", "nginx/falconeye.conf",
        "scripts/provision.sh", "app/image_search/upload.py",
    ))
    sources += _text(LIB)
    for record in _state_paths():
        stem = record["path"].rstrip("/").split("/")[-1]
        root = "/".join(record["path"].rstrip("/").split("/")[:3])
        assert stem in sources or root in sources, (
            f"{record['path']} is listed as state but nothing in the app, the "
            "unit, the vhost or the provisioner refers to it"
        )


def test_the_database_and_the_env_are_essential_not_convenience():
    by_path = {r["path"]: r["class"] for r in _state_paths()}
    for path, klass in by_path.items():
        if path.endswith("/.env") or path.endswith("falconeye.db"):
            assert klass == "essential", f"{path} is marked {klass}"


# ---------- the docs say the same thing ----------

def test_both_documents_have_the_section():
    for path in (README, RUNBOOK):
        assert "State to persist" in _text(path), f"{path.name} has no such section"


def test_every_path_in_the_code_list_appears_in_both_documents():
    """The list cannot be right in the code and stale in the runbook."""
    records = _state_paths()
    for path in (README, RUNBOOK):
        text = _text(path)
        for record in records:
            assert record["path"] in text, (
                f"{record['path']} is in fe_state_paths() but not in {path.name}"
            )


def test_the_documents_mention_ephemeral_root_disks():
    for path in (README, RUNBOOK):
        text = _text(path).lower()
        assert "ephemeral" in text, f"{path.name} does not cover ephemeral root disks"
        assert "persistent volume" in text or "persistent disk" in text, path.name


def test_the_runbook_names_both_scripts():
    text = _text(RUNBOOK)
    assert "scripts/backup.sh" in text and "scripts/restore.sh" in text


# ---------- a backup you can verify ----------

def test_the_backup_records_a_checksum():
    text = _text(BACKUP)
    assert "sha256" in text.lower(), "backup.sh does not checksum the archive"
    assert ".sha256" in text, "the checksum is not written next to the archive"


def test_the_backup_is_timestamped():
    assert "fe_timestamp" in _text(BACKUP)


def test_the_archive_is_not_world_readable():
    """It contains .env and a TLS private key."""
    text = _text(BACKUP)
    assert "umask 077" in text or "chmod 600" in text or "chmod 0600" in text, (
        "backup.sh does not restrict the archive's permissions, and it holds "
        "the API keys and the origin private key"
    )


# ---------- a restore that cannot be talked into anything ----------

def test_the_restore_verifies_the_checksum():
    text = _text(RESTORE)
    assert "sha256" in text.lower()
    assert "--skip-verify" in text or "verify" in text.lower()


def test_the_restore_rejects_paths_outside_the_known_roots():
    """It runs as root and tar writes what it is told to write. An archive with
    ../../etc/passwd in it must be refused, not extracted."""
    text = _text(RESTORE)
    assert ".." in text, "restore.sh does not check for traversal entries"
    body = text.lower()
    assert "refus" in body or "reject" in body or "fe_die" in body


def test_the_restore_keeps_what_it_overwrites():
    text = _text(RESTORE)
    assert "pre-restore" in text or "pre_restore" in text, (
        "restore.sh does not preserve the files it overwrites"
    )


def test_the_restore_stops_the_service_before_touching_the_database():
    """SQLite plus a running writer plus a file swap is how a database gets
    corrupted rather than restored."""
    text = _text(RESTORE)
    stop = text.find("systemctl stop")
    extract = text.find("tar -xzf") if "tar -xzf" in text else text.find("tar ")
    assert stop != -1, "restore.sh never stops the service"
    assert stop < extract, "restore.sh extracts before stopping the service"


def test_the_restore_starts_the_service_and_checks_health():
    text = _text(RESTORE)
    assert "fe_health_check" in text or "/health" in text


# ---------- dry run means dry run, here too ----------

MUTATING = r"(cp|mv|rm|install|mkdir|chown|chmod|systemctl|tar -x|sqlite3)\b"


def _executable_lines(path: pathlib.Path):
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


def test_neither_script_mutates_outside_the_wrapper():
    for path in (BACKUP, RESTORE):
        offenders = [line for line in _executable_lines(path)
                     if re.match(rf"^{MUTATING}", line) and not line.startswith("fe_")]
        assert not offenders, f"{path.name} changes the box outside fe_run: {offenders}"

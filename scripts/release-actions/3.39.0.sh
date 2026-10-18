# v3.39.0: retention and revoke catch up with what the privacy policy states.
#
#   1. Company dossiers older than PROSPECT_RETENTION_DAYS (default 30) are
#      deleted, and the unused ip_hash column is dropped from the rest.
#   2. Domains whose Attack Surface grants were already revoked lose everything
#      revoke now deletes (app.asm.store.delete_domain).
#   3. Run rows and audit rows replace plain domains and keywords with
#      HMAC-SHA256(FE_HASH_KEY, value); an unconvertible unsalted audit hash is
#      dropped.
#
# upgrade.sh has already backed up the database (step 1) and generated
# FE_HASH_KEY (fe_ensure_hash_key, just before this). Dossier files are not in
# that backup set, so they are archived into this run's backup directory first.
# The work is scripts/migrate_3_39_0.py, which prints the row counts. Idempotent:
# a second run deletes and converts nothing.
fe_say "3.39.0: dossier retention, revoked-grant cleanup and run-record HMAC"
if [[ -n "${FE_BACKUP_PATH:-}" && -d "$FE_INSTALL_DIR/data/prospect" ]]; then
    fe_run tar -C "$FE_INSTALL_DIR/data" -czf "$FE_BACKUP_PATH/prospect-dossiers.tar.gz" prospect
    fe_run chmod 600 "$FE_BACKUP_PATH/prospect-dossiers.tar.gz"
    fe_say "dossier files archived to $FE_BACKUP_PATH/prospect-dossiers.tar.gz"
fi
# .env is read by this root shell and handed over on stdin: it is usually
# root-owned 0600, and the migration runs as the service user so the database
# files keep their owner.
fe_as_service_user "$FE_VENV/bin/python" "$FE_APP_SRC/scripts/migrate_3_39_0.py" \
    "$FE_APP_SRC" - "$FE_DB" < "$FE_ENV_FILE"

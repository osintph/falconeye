#!/bin/bash
# Back up everything git cannot regenerate.
#
#   sudo /opt/falconeye/app_src/scripts/backup.sh
#   sudo /opt/falconeye/app_src/scripts/backup.sh --dry-run
#   sudo /opt/falconeye/app_src/scripts/backup.sh --out /mnt/backups
#
# WHAT IT TAKES
# -------------
# The list in fe_state_paths() (scripts/lib/common.sh), which is also what the
# "State to persist" section of the README and the runbook documents. Nothing
# here decides what state is; there is one list and three readers.
#
# Anything else you keep outside git goes in FE_BACKUP_EXTRA as a
# space-separated list of paths. This script never writes to those paths.
#
# WHAT YOU GET
# ------------
#   <out>/falconeye-state-<timestamp>.tar.gz          mode 0600
#   <out>/falconeye-state-<timestamp>.tar.gz.sha256   the checksum, for restore
#
# The archive holds the API keys and the origin private key, so it is created
# under umask 077 and is 0600. Treat a copy of it exactly like a copy of .env.
#
# Paths are stored relative to / so a restore is unambiguous about where each
# file goes, and scripts/restore.sh refuses an archive holding anything outside
# the known roots.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

DRY_RUN="${DRY_RUN:-false}"
OUT_DIR="$FE_BACKUP_DIR"

usage() {
    sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    printf '\nFlags:\n'
    printf '  --dry-run      list what would be archived, write nothing\n'
    printf '  --out <dir>    where to write the archive (default %s)\n' "$FE_BACKUP_DIR"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --out) shift; OUT_DIR="${1:-}"; [[ -n "$OUT_DIR" ]] || { echo "--out needs a directory" >&2; exit 1; } ;;
        -h|--help) usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage 1 ;;
    esac
    shift
done
export DRY_RUN

fe_need_root

STAMP="$(fe_timestamp)"
ARCHIVE="$OUT_DIR/falconeye-state-$STAMP.tar.gz"

printf '%s=== FalconEye state backup ===%s\n' "$_FE_BOLD" "$_FE_OFF"
[[ "$DRY_RUN" == "true" ]] && fe_warn "dry run: nothing will be written"

fe_step "What is being archived"
INCLUDE=()
MISSING=()
while IFS='|' read -r class path why; do
    [[ -n "${path:-}" ]] || continue
    if [[ -e "$path" ]]; then
        INCLUDE+=("${path#/}")
        printf '    %-12s %s\n' "[$class]" "$path"
    else
        MISSING+=("$path")
    fi
done < <(fe_state_paths)

for extra in $FE_BACKUP_EXTRA; do
    if [[ -e "$extra" ]]; then
        INCLUDE+=("${extra#/}")
        printf '    %-12s %s\n' "[extra]" "$extra"
    else
        fe_warn "FE_BACKUP_EXTRA names $extra, which does not exist"
    fi
done

for path in "${MISSING[@]:-}"; do
    [[ -n "$path" ]] || continue
    fe_say "not present, skipping: $path"
done

[[ ${#INCLUDE[@]} -gt 0 ]] || fe_die "nothing to back up: none of the state paths exist"

fe_step "Writing $ARCHIVE"
fe_run install -d -m 0700 "$OUT_DIR"

if [[ "$DRY_RUN" == "true" ]]; then
    printf '    %s[dry-run]%s tar -czf %s -C / %s\n' \
        "$_FE_YEL" "$_FE_OFF" "$ARCHIVE" "${INCLUDE[*]}"
    printf '    %s[dry-run]%s sha256sum > %s.sha256\n' "$_FE_YEL" "$_FE_OFF" "$ARCHIVE"
    printf '\n%sDry run: %d paths would be archived.%s\n' "$_FE_YEL" "${#INCLUDE[@]}" "$_FE_OFF"
    exit 0
fi

# 077 so the archive is never group- or world-readable even for an instant: it
# carries .env and the origin private key.
(umask 077 && tar -czf "$ARCHIVE" -C / --numeric-owner "${INCLUDE[@]}")
fe_run chmod 600 "$ARCHIVE"

SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
printf '%s  %s\n' "$SHA" "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256"
fe_run chmod 600 "$ARCHIVE.sha256"

SIZE="$(du -h "$ARCHIVE" | awk '{print $1}')"

fe_step "Done"
fe_ok "$ARCHIVE ($SIZE)"
printf '    sha256: %s\n' "$SHA"
printf '    %d paths archived, checksum in %s\n' "${#INCLUDE[@]}" "$(basename "$ARCHIVE.sha256")"
printf '\nRestore with:\n'
printf '  sudo %s/scripts/restore.sh %s\n' "$FE_APP_SRC" "$ARCHIVE"
printf '\nThis archive contains secrets. Copy it off the box the way you would\n'
printf 'copy .env, and keep the checksum with it.\n'

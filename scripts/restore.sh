#!/bin/bash
# Restore the state an archive from scripts/backup.sh holds.
#
#   sudo /opt/falconeye/app_src/scripts/restore.sh /path/to/falconeye-state-<stamp>.tar.gz
#   sudo /opt/falconeye/app_src/scripts/restore.sh <archive> --dry-run
#
# WHAT IT DOES, IN ORDER
# ----------------------
# 1. Verifies the archive against its .sha256 sidecar (or --sha256 <hex>).
# 2. Refuses the archive if it carries any entry outside the known state roots,
#    or any absolute or "../" path. This runs as root and tar writes what it is
#    told to write: an archive is untrusted input like any other.
# 3. Stops the service. SQLite plus a live writer plus a file swap is how a
#    database gets corrupted rather than restored.
# 4. Copies anything it is about to overwrite into
#    <backups>/pre-restore-<timestamp>/, so a restore of the wrong archive is
#    itself recoverable.
# 5. Extracts, starts the service, and checks /health.
#
# It does not run migrations and it does not touch the checkout. Restoring state
# onto a *newer* release is the normal case (that is what a rebuild looks like);
# run scripts/upgrade.sh afterwards if the code needs to move too.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

DRY_RUN="${DRY_RUN:-false}"
ARCHIVE=""
EXPECTED_SHA=""
SKIP_VERIFY=false

usage() {
    sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    printf '\nFlags:\n'
    printf '  --dry-run         show what would be restored, change nothing\n'
    printf '  --sha256 <hex>    expected checksum, when there is no .sha256 sidecar\n'
    printf '  --skip-verify     restore an archive with no checksum at all (say why to yourself first)\n'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --sha256) shift; EXPECTED_SHA="${1:-}" ;;
        --skip-verify) SKIP_VERIFY=true ;;
        -h|--help) usage 0 ;;
        -*) echo "Unknown flag: $1" >&2; usage 1 ;;
        *) ARCHIVE="$1" ;;
    esac
    shift
done
export DRY_RUN

[[ -n "$ARCHIVE" ]] || { echo "Give the archive to restore." >&2; usage 1; }
[[ -f "$ARCHIVE" ]] || fe_die "$ARCHIVE does not exist"
fe_need_root

printf '%s=== FalconEye state restore ===%s\n' "$_FE_BOLD" "$_FE_OFF"
fe_say "archive: $ARCHIVE"
[[ "$DRY_RUN" == "true" ]] && fe_warn "dry run: nothing will be changed"

# ---- 1. verify --------------------------------------------------------------
fe_step "1/5 Verifying the archive"
ACTUAL_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
fe_say "sha256: $ACTUAL_SHA"

if [[ -z "$EXPECTED_SHA" && -f "$ARCHIVE.sha256" ]]; then
    EXPECTED_SHA="$(awk '{print $1}' "$ARCHIVE.sha256")"
    fe_say "checksum sidecar found"
fi

if [[ -n "$EXPECTED_SHA" ]]; then
    [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] \
        || fe_die "checksum mismatch. Expected $EXPECTED_SHA, got $ACTUAL_SHA. Refusing to restore."
    fe_ok "checksum matches"
elif [[ "$SKIP_VERIFY" == "true" ]]; then
    fe_warn "no checksum to verify against, continuing because --skip-verify was given"
else
    fe_die "no $ARCHIVE.sha256 and no --sha256 given. Pass one, or --skip-verify."
fi

# ---- 2. what is in it, and is any of it somewhere it should not be ----------
fe_step "2/5 Checking the contents"
ENTRIES="$(tar -tzf "$ARCHIVE")"
[[ -n "$ENTRIES" ]] || fe_die "the archive is empty"

# The roots any entry is allowed to sit under, derived from the same list the
# backup was built from rather than hardcoded here.
ALLOWED_ROOTS=()
while IFS='|' read -r _ path _; do
    [[ -n "${path:-}" ]] || continue
    ALLOWED_ROOTS+=("${path#/}")
done < <(fe_state_paths)
for extra in $FE_BACKUP_EXTRA; do
    ALLOWED_ROOTS+=("${extra#/}")
done

REJECTED=()
while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    # Absolute paths and traversal never appear in an archive this project wrote.
    if [[ "$entry" == /* ]] || [[ "$entry" == *".."* ]]; then
        REJECTED+=("$entry")
        continue
    fi
    ok=false
    for root in "${ALLOWED_ROOTS[@]}"; do
        if [[ "$entry" == "$root" || "$entry" == "$root/"* ]]; then
            ok=true
            break
        fi
    done
    [[ "$ok" == "true" ]] || REJECTED+=("$entry")
done <<< "$ENTRIES"

if [[ ${#REJECTED[@]} -gt 0 ]]; then
    fe_warn "entries outside the known state paths:"
    printf '      %s\n' "${REJECTED[@]:0:10}" >&2
    fe_die "refusing to extract: this archive writes paths this tool does not own."
fi
fe_ok "$(wc -l <<< "$ENTRIES") entries, all within the known state paths"

# The top-level targets that exist now and would be replaced.
TARGETS=()
while IFS='|' read -r class path why; do
    [[ -n "${path:-}" ]] || continue
    if grep -qE "^${path#/}(/|\$)" <<< "$ENTRIES"; then
        TARGETS+=("$path")
        printf '    %-12s %s\n' "[$class]" "$path"
    fi
done < <(fe_state_paths)

# ---- 3. stop the service ----------------------------------------------------
fe_step "3/5 Stopping $FE_SERVICE"
fe_run systemctl stop "$FE_SERVICE"

# ---- 4. keep what is about to be overwritten --------------------------------
fe_step "4/5 Preserving what is there now"
PRE="$FE_BACKUP_DIR/pre-restore-$(fe_timestamp)"
fe_run install -d -m 0700 "$PRE"
for target in "${TARGETS[@]:-}"; do
    [[ -n "$target" && -e "$target" ]] || continue
    fe_run install -d -m 0700 "$PRE/$(dirname "${target#/}")"
    fe_run cp -a "$target" "$PRE/${target#/}"
    fe_say "kept $target"
done
fe_ok "previous state in $PRE"

# ---- 5. extract, start, prove ------------------------------------------------
fe_step "5/5 Restoring"
if [[ "$DRY_RUN" == "true" ]]; then
    printf '    %s[dry-run]%s tar -xzf %s -C / --numeric-owner\n' "$_FE_YEL" "$_FE_OFF" "$ARCHIVE"
else
    tar -xzf "$ARCHIVE" -C / --numeric-owner -p
fi
fe_run systemctl start "$FE_SERVICE"

EXPECTED_VERSION="$(fe_source_version)"
fe_health_check "$EXPECTED_VERSION" "$(fe_current_ref)"

if [[ "$DRY_RUN" == "true" ]]; then
    printf '\n%s=== dry run complete ===%s\n' "$_FE_YEL$_FE_BOLD" "$_FE_OFF"
    printf '%sNothing was changed.%s\n' "$_FE_YEL" "$_FE_OFF"
else
    printf '\n%s=== restored from %s ===%s\n' "$_FE_GRN$_FE_BOLD" "$(basename "$ARCHIVE")" "$_FE_OFF"
    printf 'What was replaced is in: %s\n' "$PRE"
fi

#!/bin/bash
# FalconEye upgrade. The only supported way to move an existing install forward.
#
#   sudo /opt/falconeye/app_src/scripts/upgrade.sh v3.34.3
#   sudo /opt/falconeye/app_src/scripts/upgrade.sh              # latest tag
#   sudo /opt/falconeye/app_src/scripts/upgrade.sh --dry-run    # show, change nothing
#
# WHY A SCRIPT AND NOT A LIST
# ---------------------------
# Upgrading used to be a numbered list in docs/deploy-runbook.md: fetch, reset,
# check whether requirements.txt moved, check whether the unit moved, check
# whether nginx moved, flush whatever the release notes said to flush, restart,
# curl /health. Every "check whether" was a judgement call, and v3.34.2 is what a
# missed one looks like: the unit file changed, nobody copied it to
# /etc/systemd/system, and systemd went on running the old directives.
#
# A machine does not skip step four. The list is now here, the runbook documents
# this command, and the old sequence survives as an appendix describing what this
# does.
#
# WHAT IT WILL NOT DO
# -------------------
# It never writes nginx/falconeye.conf over your vhost: your server_name, your
# certificate paths and any rate-limit zones live there. If the shipped vhost has
# changed it says so and prints the diff command. It never installs an optional
# conf.d file you did not already have. It never touches .env.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

TARGET=""
DRY_RUN="${DRY_RUN:-false}"

usage() {
    # The synopsis block at the top of this file, up to the first blank comment.
    sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    printf '\nFlags:\n'
    printf '  --dry-run      print every change it would make, change nothing\n'
    printf '  --force-deps   reinstall dependencies even if requirements.txt did not move\n'
    printf '\nPaths come from FE_* environment variables (see scripts/lib/common.sh);\nthe defaults are the standard /opt/falconeye layout.\n'
    exit "${1:-0}"
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --force-deps) FE_FORCE_DEPS=true ;;
        -h|--help) usage 0 ;;
        -*) echo "Unknown flag: $arg" >&2; usage 1 ;;
        *)
            [[ -z "$TARGET" ]] || { echo "Give at most one tag." >&2; exit 1; }
            TARGET="$arg"
            ;;
    esac
done
export DRY_RUN

fe_need_root
[[ -d "$FE_APP_SRC/.git" ]] || fe_die "$FE_APP_SRC is not a git checkout. Use scripts/provision.sh for a first install."

# Where we are now, captured before anything moves, so the rollback command in a
# failed health check names the version the operator actually had.
PREVIOUS_REF="$(fe_current_ref)"
PREVIOUS_VERSION="$(fe_source_version)"
FE_ROLLBACK_REF="$PREVIOUS_REF"
trap 'fe_on_error $LINENO' ERR

printf '%s=== FalconEye upgrade ===%s\n' "$_FE_BOLD" "$_FE_OFF"
fe_say "checkout:  $FE_APP_SRC"
fe_say "currently: $PREVIOUS_REF (version $PREVIOUS_VERSION)"
[[ "$DRY_RUN" == "true" ]] && fe_warn "dry run: nothing will be changed"

# ---- 1. backups, before anything is touched -----------------------------------
fe_step "1/8 Backing up .env, database and the installed unit"
fe_backup

# ---- 2. move the checkout ------------------------------------------------------
fe_step "2/8 Fetching tags and checking out the target"
if [[ -z "$TARGET" ]]; then
    # Fetch first or "the latest tag" is whatever this clone last heard about.
    git -C "$FE_APP_SRC" fetch --tags --prune origin
    TARGET="$(fe_latest_tag)"
    [[ -n "$TARGET" ]] || fe_die "no v* tags found; pass one explicitly"
    fe_say "no tag given, using the latest: $TARGET"
fi
fe_say "target: $TARGET"
# Read the target's version from the ref, so a dry run reports what the upgrade
# would produce rather than what is already checked out.
export FE_TARGET_REF="$TARGET"
fe_git_checkout "$TARGET"
TARGET_VERSION="$(fe_source_version "$TARGET")"
[[ -n "$TARGET_VERSION" ]] || TARGET_VERSION="$(fe_source_version)"
fe_say "version in $TARGET: $TARGET_VERSION"

# ---- 3. dependencies -----------------------------------------------------------
fe_step "3/8 Python dependencies"
fe_pip_sync "$PREVIOUS_REF" "$TARGET"

# ---- 4. systemd unit -----------------------------------------------------------
fe_step "4/8 systemd unit"
fe_ensure_log_dir
fe_install_unit

# ---- 5. nginx ------------------------------------------------------------------
fe_step "5/8 nginx snippets and conf.d"
fe_install_nginx_snippets
fe_sync_nginx_confd
fe_check_vhost_drift
fe_nginx_test_reload

# ---- 6. migrations and cache flushes the release declares ----------------------
fe_step "6/8 Database migrations and release actions"
fe_db_init
fe_apply_release_actions "$PREVIOUS_VERSION" "$TARGET_VERSION"

# ---- 7. restart ----------------------------------------------------------------
fe_step "7/8 Restarting $FE_SERVICE"
fe_restart_service

# ---- 8. prove it ---------------------------------------------------------------
fe_step "8/8 Health check"
fe_health_check "$TARGET_VERSION" "$PREVIOUS_REF"
fe_preflight_env

if [[ "$DRY_RUN" == "true" ]]; then
    printf '\n%s=== dry run complete: %s would replace %s ===%s\n' \
        "$_FE_YEL$_FE_BOLD" "$TARGET" "$PREVIOUS_REF" "$_FE_OFF"
    printf '%sNothing above was changed. Re-run without --dry-run to apply it.%s\n' \
        "$_FE_YEL" "$_FE_OFF"
else
    printf '\n%s=== %s is live (was %s) ===%s\n' \
        "$_FE_GRN$_FE_BOLD" "$TARGET" "$PREVIOUS_REF" "$_FE_OFF"
fi
if [[ -n "${FE_BACKUP_PATH:-}" ]]; then
    printf 'Backups: %s\n' "$FE_BACKUP_PATH"
fi
printf 'Roll back with: sudo %s/scripts/upgrade.sh %s\n' "$FE_APP_SRC" "$PREVIOUS_REF"
exit 0

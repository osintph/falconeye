#!/bin/bash
# FalconEye upgrade. The only supported way to move an existing install forward.
#
#   sudo /opt/falconeye/app_src/scripts/upgrade.sh v3.34.4
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
# The original arguments, captured before parsing, so the re-exec into the target
# version's upgrade.sh (below) runs with exactly what the operator passed.
FE_UPGRADE_ARGS=("$@")

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

if [[ "${FE_UPGRADE_REEXECED:-}" == "1" ]]; then
    # We were re-exec'd by the pre-checkout copy of this script after it backed up
    # and checked out the target, so from here on this IS the target version's
    # upgrade.sh and common.sh. Inherit the state the first process captured: the
    # checkout has already moved, so re-reading "where we are" would wrongly report
    # the target as the previous version and break the rollback command.
    PREVIOUS_REF="${FE_PREVIOUS_REF:-$(fe_current_ref)}"
    PREVIOUS_VERSION="${FE_PREVIOUS_VERSION:-unknown}"
    TARGET="${FE_TARGET_REF:-$TARGET}"
    TARGET_VERSION="$(fe_source_version)"
    FE_ROLLBACK_REF="$PREVIOUS_REF"
    trap 'fe_on_error $LINENO' ERR
    printf '%s=== FalconEye upgrade (continuing in %s) ===%s\n' "$_FE_BOLD" "$TARGET" "$_FE_OFF"
    fe_say "now running the target's own upgrade.sh and common.sh (was $PREVIOUS_REF)"
else
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

    # ---- 1. backups, before anything is touched -------------------------------
    fe_step "1/9 Backing up .env, database and the installed unit"
    fe_backup

    # ---- 2. move the checkout -------------------------------------------------
    fe_step "2/9 Fetching tags and checking out the target"
    if [[ -z "$TARGET" ]]; then
        # Fetch first or "the latest tag" is whatever this clone last heard about.
        fe_git_fetch
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

    # Re-exec into the just-checked-out scripts so the REST of the upgrade runs the
    # target version's upgrade.sh and common.sh, not this pre-checkout copy. Without
    # this, a new installer step added in the target only takes effect on the NEXT
    # upgrade, because this process loaded the old library before the checkout.
    # Guarded by FE_UPGRADE_REEXECED so it happens at most once, and
    # skipped in a dry run, where the checkout did not move and there is nothing new
    # to re-exec into.
    if [[ "$DRY_RUN" != "true" ]]; then
        export FE_UPGRADE_REEXECED=1
        export FE_PREVIOUS_REF="$PREVIOUS_REF"
        export FE_PREVIOUS_VERSION="$PREVIOUS_VERSION"
        export FE_TARGET_REF="$TARGET"
        export FE_BACKUP_PATH="${FE_BACKUP_PATH:-}"
        fe_step "Re-exec into $TARGET's upgrade.sh"
        fe_say "running $FE_APP_SRC/scripts/upgrade.sh from $TARGET"
        exec "$FE_APP_SRC/scripts/upgrade.sh" ${FE_UPGRADE_ARGS[@]+"${FE_UPGRADE_ARGS[@]}"}
    fi
fi

# ---- 3. dependencies -----------------------------------------------------------
fe_step "3/9 System packages and Python dependencies"
# System packages first: a release that needs a new native library needs it
# before the import smoke test, and before the restart at step 7. This is the
# step whose absence meant a new apt package only ever reached fresh installs.
fe_install_system_packages
fe_check_binaries || true
fe_pip_sync "$PREVIOUS_REF" "$TARGET"

# ---- 4. systemd unit -----------------------------------------------------------
fe_step "4/9 systemd unit"
fe_ensure_log_dir
fe_install_unit
# The ASM monitoring timer, installed only when ASM_MONITORING_ENABLED is set.
fe_install_asm_timer
# The Phishing Hunt NRD feed timer, installed unless HUNT_NRD_ENABLED=false.
fe_install_nrd

# ---- 5. nginx ------------------------------------------------------------------
fe_step "5/9 nginx snippets and conf.d"
fe_install_nginx_snippets
fe_sync_nginx_confd
fe_check_vhost_drift
fe_nginx_test_reload

# ---- 6. migrations and cache flushes the release declares ----------------------
fe_step "6/9 Database migrations and release actions"
fe_db_init
# ASM needs a signing key before the restart below (without it the feature
# disables itself); generate one if the operator has not set it.
fe_ensure_asm_signing_key
fe_apply_release_actions "$PREVIOUS_VERSION" "$TARGET_VERSION"

# ---- 7. restart ----------------------------------------------------------------
fe_step "7/9 Restarting $FE_SERVICE"
fe_restart_service

# ---- 8. prove it ---------------------------------------------------------------
fe_step "8/9 Health check"
fe_health_check "$TARGET_VERSION" "$PREVIOUS_REF"
fe_preflight_env

# ---- 9. the MCP server, if this box has one ------------------------------------
# v3.36.0 left the MCP venv unable to satisfy its own SDK and nothing said so.
fe_step "9/9 MCP server"
fe_check_mcp

if [[ "$DRY_RUN" == "true" ]]; then
    printf '\n%s=== dry run complete: %s would replace %s ===%s\n' \
        "$_FE_YEL$_FE_BOLD" "$TARGET" "$PREVIOUS_REF" "$_FE_OFF"
    printf '%sNothing was changed except fetching tags into the local clone.%s\n' \
        "$_FE_YEL" "$_FE_OFF"
    printf '%sRe-run without --dry-run to apply it.%s\n' "$_FE_YEL" "$_FE_OFF"
else
    printf '\n%s=== %s is live (was %s) ===%s\n' \
        "$_FE_GRN$_FE_BOLD" "$TARGET" "$PREVIOUS_REF" "$_FE_OFF"
fi
if [[ -n "${FE_BACKUP_PATH:-}" ]]; then
    printf 'Backups: %s\n' "$FE_BACKUP_PATH"
fi
printf 'Roll back with: sudo %s/scripts/upgrade.sh %s\n' "$FE_APP_SRC" "$PREVIOUS_REF"
exit 0

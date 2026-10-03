#!/bin/bash
# Shared steps for scripts/provision.sh (install) and scripts/upgrade.sh (upgrade).
#
# WHY THIS FILE EXISTS
# --------------------
# Installing and upgrading touched the same six things (log directory, systemd
# unit, nginx snippets, venv, database, health check) through two different sets
# of commands: one in provision.sh, one in a numbered list in the runbook that a
# human retyped each release. They drifted, and the drift is not theoretical:
#
#   - v3.34.2 shipped a unit-file change. Nothing in the documented upgrade
#     sequence copied the unit, so systemd kept running the old directives.
#   - provision.sh installed exactly one nginx snippet. The vhost includes two,
#     so "nginx -t" on a genuinely fresh box failed on the missing one.
#
# Both are the same bug: a step that exists in one path and not the other. There
# is now one implementation of each step and two callers.
#
# CONVENTIONS
# -----------
# Every function is `fe_`-prefixed and every command that changes the box goes
# through `fe_run`, so `--dry-run` is a real preview rather than a promise. A
# test asserts that: see tests/unit/test_upgrade_script.py.
#
# Paths come from FE_* environment variables with production defaults, so the
# same scripts drive a staging install, a self-hoster's different layout, or a
# test, without a second code path.

# ---------------------------------------------------------------- settings ----

FE_INSTALL_DIR="${FE_INSTALL_DIR:-/opt/falconeye}"
FE_APP_SRC="${FE_APP_SRC:-$FE_INSTALL_DIR/app_src}"
FE_VENV="${FE_VENV:-$FE_INSTALL_DIR/venv}"
# Only used if it exists: the MCP server's SDK cannot live in the app venv
# (mcp requires uvicorn>=0.31.1, the app pins 0.29.0). See docs/mcp.md.
FE_MCP_VENV="${FE_MCP_VENV:-$FE_INSTALL_DIR/mcp-venv}"
FE_ENV_FILE="${FE_ENV_FILE:-$FE_INSTALL_DIR/.env}"
FE_DB="${FE_DB:-$FE_INSTALL_DIR/data/falconeye.db}"
FE_BACKUP_DIR="${FE_BACKUP_DIR:-$FE_INSTALL_DIR/backups}"
FE_SERVICE="${FE_SERVICE:-falconeye}"
FE_UNIT_SRC="${FE_UNIT_SRC:-$FE_APP_SRC/falconeye.service}"
FE_UNIT_DEST="${FE_UNIT_DEST:-/etc/systemd/system/${FE_SERVICE}.service}"
FE_NGINX_DIR="${FE_NGINX_DIR:-/etc/nginx}"
FE_HEALTH_URL="${FE_HEALTH_URL:-http://127.0.0.1:8000/health}"
FE_SERVICE_USER="${FE_SERVICE_USER:-ubuntu}"
FE_LOG_DIR="${FE_LOG_DIR:-/var/log/falconeye}"
# Which release actions have already run on this box, one version per line.
FE_STATE_FILE="${FE_STATE_FILE:-$FE_INSTALL_DIR/data/.release_actions_applied}"
FE_REPO_URL="${FE_REPO_URL:-https://github.com/osintph/falconeye.git}"

# State locations, overridable the same way everything else is. The defaults are
# what app/config.py, falconeye.service and nginx/falconeye.conf actually use.
FE_TELEGRAM_SESSION="${FE_TELEGRAM_SESSION:-$FE_INSTALL_DIR/private/telegram.session}"
FE_RANSOMWARE_DB="${FE_RANSOMWARE_DB:-$FE_INSTALL_DIR/data/ransomware.db}"
FE_WATCHLIST="${FE_WATCHLIST:-$FE_INSTALL_DIR/private/ransomware_watchlist.txt}"
FE_SSL_DIR="${FE_SSL_DIR:-/etc/ssl/falconeye}"
FE_VHOST="${FE_VHOST:-$FE_NGINX_DIR/sites-available/falconeye}"
FE_NGINX_CONFD="${FE_NGINX_CONFD:-$FE_NGINX_DIR/conf.d}"
# Anything else this operator keeps outside git: a space-separated path list.
# Deliberately empty by default and never written to by these scripts.
FE_BACKUP_EXTRA="${FE_BACKUP_EXTRA:-}"

DRY_RUN="${DRY_RUN:-false}"

# Set by fe_install_unit / fe_install_nginx_snippets / fe_sync_nginx_confd so the
# caller can skip a reload nothing needs.
FE_UNIT_CHANGED=false
FE_NGINX_CHANGED=false

# ----------------------------------------------------------------- output -----

if [[ -t 1 ]]; then
    _FE_BOLD=$'\033[1m'; _FE_RED=$'\033[31m'; _FE_YEL=$'\033[33m'
    _FE_GRN=$'\033[32m'; _FE_OFF=$'\033[0m'
else
    _FE_BOLD=""; _FE_RED=""; _FE_YEL=""; _FE_GRN=""; _FE_OFF=""
fi

fe_step() { printf '\n%s==> %s%s\n' "$_FE_BOLD" "$*" "$_FE_OFF"; }
fe_say()  { printf '    %s\n' "$*"; }
fe_ok()   { printf '    %s%s%s\n' "$_FE_GRN" "$*" "$_FE_OFF"; }
fe_warn() { printf '    %s[WARNING] %s%s\n' "$_FE_YEL" "$*" "$_FE_OFF" >&2; }

fe_die() {
    printf '\n%s[FAILED] %s%s\n' "$_FE_RED$_FE_BOLD" "$*" "$_FE_OFF" >&2
    exit 1
}

# Run a command, or print it when DRY_RUN=true. Everything that changes the box
# goes through here; nothing else may.
fe_run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf '    %s[dry-run]%s %s\n' "$_FE_YEL" "$_FE_OFF" "$*"
        return 0
    fi
    "$@"
}

fe_need_root() {
    if [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        fe_die "run this with sudo (it writes to /etc/systemd/system and $FE_INSTALL_DIR)"
    fi
}

fe_timestamp() { date +%Y%m%d-%H%M%S; }

# ---------------------------------------------------------------- backups -----

# Everything that cannot be recovered from git: the operator's .env, the SQLite
# database, and the installed unit (which may carry local edits). One timestamped
# directory per run, printed so the rollback advice can name it.
fe_backup() {
    local stamp dest
    stamp="$(fe_timestamp)"
    dest="$FE_BACKUP_DIR/$stamp"
    FE_BACKUP_PATH="$dest"

    local verb="backed up"
    [[ "$DRY_RUN" == "true" ]] && verb="would back up"

    fe_run install -d -m 0700 "$dest"
    local item
    for item in "$FE_ENV_FILE" "$FE_DB" "$FE_UNIT_DEST"; do
        if [[ -f "$item" ]]; then
            fe_run cp -a "$item" "$dest/"
            fe_say "$verb $item"
        else
            fe_say "skipped $item (not present)"
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        fe_say "backups would go to $dest"
    else
        fe_ok "backups in $dest"
    fi
}

# ------------------------------------------------------------ the checkout ----

fe_current_ref() {
    git -C "$FE_APP_SRC" describe --tags --exact-match 2>/dev/null \
        || git -C "$FE_APP_SRC" rev-parse --short HEAD 2>/dev/null \
        || echo "unknown"
}

fe_latest_tag() {
    git -C "$FE_APP_SRC" tag -l 'v*' --sort=-v:refname | head -1
}

# Move the checkout to a tag. Deliberately reset --hard to a *tag*, never a
# branch: a deploy has to be a named thing you can roll back to.
# Fetching is the one thing a dry run does for real: it writes only to the local
# clone's refs, changes nothing that is deployed, and without it the preview
# cannot see the tag it is being asked about.
fe_git_fetch() {
    git -C "$FE_APP_SRC" fetch --tags --prune origin
}

fe_git_checkout() {
    local ref="$1"
    fe_git_fetch
    if ! git -C "$FE_APP_SRC" rev-parse -q --verify "${ref}^{commit}" >/dev/null 2>&1; then
        fe_die "$ref does not exist. Available: $(git -C "$FE_APP_SRC" tag -l 'v*' --sort=-v:refname | head -5 | tr '\n' ' ')"
    fi
    fe_run git -C "$FE_APP_SRC" reset --hard "$ref"
    fe_run chown -R "$FE_SERVICE_USER:$FE_SERVICE_USER" "$FE_APP_SRC"
}

# The version the code reports, which is what /health must echo back. With a ref
# it reads that ref instead of the working tree, so a dry run can say what the
# target *would* report without checking anything out.
fe_source_version() {
    local ref="${1:-}"
    if [[ -n "$ref" ]]; then
        git -C "$FE_APP_SRC" show "$ref:app/main.py" 2>/dev/null \
            | sed -n 's/^    version="\([0-9.]*\)",$/\1/p' | head -1
        return 0
    fi
    sed -n 's/^    version="\([0-9.]*\)",$/\1/p' "$FE_APP_SRC/app/main.py" | head -1
}

# --------------------------------------------------------------- the venvs ----

# Only reinstall when requirements.txt actually changed between the two revisions,
# which is what the runbook told an operator to check by hand. FE_FORCE_DEPS=true
# overrides (a rebuilt venv, a changed pin outside the file).
fe_pip_sync() {
    local from="$1" to="$2"
    local changed=true

    if [[ "${FE_FORCE_DEPS:-false}" != "true" && -n "$from" && "$from" != "unknown" ]]; then
        if git -C "$FE_APP_SRC" diff --quiet "$from" "$to" -- requirements.txt 2>/dev/null; then
            changed=false
        fi
    fi

    if [[ "$changed" != "true" ]]; then
        fe_say "requirements.txt unchanged between $from and $to, skipping pip"
        return 0
    fi

    if [[ -x "$FE_VENV/bin/pip" ]]; then
        fe_say "installing into $FE_VENV"
        fe_run "$FE_VENV/bin/pip" install -r "$FE_APP_SRC/requirements.txt" --quiet
    else
        fe_warn "$FE_VENV/bin/pip not found, skipping the app venv"
    fi

    # The MCP venv is optional and holds the same app requirements plus the SDK.
    # It exists only where an operator set it up, so its absence is normal.
    if [[ -x "$FE_MCP_VENV/bin/pip" ]]; then
        fe_say "installing into $FE_MCP_VENV (MCP server)"
        fe_run "$FE_MCP_VENV/bin/pip" install -r "$FE_APP_SRC/requirements.txt" --quiet
    fi
}

# ------------------------------------------------- system packages -----------

# Native dependencies, and why each is here. pip installs none of them.
#
# WHY THIS LIVES IN THE SHARED LIBRARY
# Until v3.35.0 the apt list existed only in provision.sh, so a package added
# for a new feature reached a fresh install and never reached an existing box:
# the upgrade path simply had no step for it. That is the same drift class as
# the unit file in v3.34.2 and the nginx snippet in v3.34.3, and it gets the
# same fix. One list, two callers.
#
# The wheels for lxml, Pillow and rapidfuzz statically link what they need, so
# compiled extension modules are self-contained. The real gaps are the two
# mechanisms ldd cannot see: libraries dlopened at runtime through ctypes, and
# binaries invoked as subprocesses. Both fail late, and neither shows up as a
# pip error.
#
#   libzbar0  pyzbar dlopens it via ctypes.util.find_library("zbar") for the QR
#             Code tab. Without it, importing the app dies with "ImportError:
#             Unable to find zbar shared library". On Ubuntu 24.04 the real
#             package is libzbar0t64 after the time_t transition, but it
#             Provides: libzbar0, so this one name works on 22.04 and 24.04.
#   whois     app/routers/domain_intel.py runs "whois <domain>" as the fallback
#             when RDAP returns nothing useful. Its absence is caught and
#             logged, so the tab silently loses that fallback rather than
#             erroring, which makes it easy to miss. Priority "standard", so it
#             is present on a full Ubuntu install but NOT on the minimal cloud
#             images most VPS and AWS instances use.
#   redis-server  the Route Map upload handshake and the Prospect/Image caches.
#
# The Route Map tab (v3.35.0) adds NO package: it never runs a traceroute, so
# there is no traceroute or mtr binary to install and no raw-socket capability
# to grant. Its traces come from a RIPE Atlas probe or from the user's own
# machine.
FE_SYSTEM_PACKAGES="${FE_SYSTEM_PACKAGES:-python3 python3-pip python3-venv git redis-server libzbar0 whois}"

fe_install_system_packages() {
    fe_say "packages: $FE_SYSTEM_PACKAGES"
    fe_run apt-get update -qq
    # shellcheck disable=SC2086 - the list is intentionally word-split
    fe_run apt-get install -y --no-install-recommends $FE_SYSTEM_PACKAGES
}

# Every binary the app shells out to must exist before the service is enabled.
# Not fatal on an upgrade, because the app handles each absence; loud, because
# a silently missing binary is a tab that quietly returns less than it should.
fe_check_binaries() {
    local missing=""
    local binary
    for binary in whois; do
        command -v "$binary" >/dev/null 2>&1 || missing="$missing $binary"
    done
    if [[ -n "$missing" ]]; then
        fe_warn "missing binaries:$missing"
        fe_warn "install them with: apt-get install -y$missing"
        return 1
    fi
    fe_say "required binaries present"
}

# ------------------------------------------------------------ the log dir -----

# systemd creates this too (LogsDirectory= in the unit), but only from the moment
# the new unit is installed and only for processes it starts. Anyone running
# gunicorn by hand still needs it, and on a fresh box it has to exist before the
# first start.
fe_ensure_log_dir() {
    fe_run install -d -o "$FE_SERVICE_USER" -g "$FE_SERVICE_USER" -m 0755 "$FE_LOG_DIR"
}

# ----------------------------------------------------------- systemd unit -----

# The copy at /etc/systemd/system is a second copy: systemd reads it, not the
# checkout. Comparing and reloading is the step that was missing from the manual
# upgrade, so it is not optional here.
fe_install_unit() {
    local src="$FE_UNIT_SRC"

    # In a dry run the checkout has not moved, so comparing the unit on disk
    # would report "unchanged" for exactly the change being previewed. Compare
    # the target tag's copy instead.
    if [[ "$DRY_RUN" == "true" && -n "${FE_TARGET_REF:-}" ]]; then
        local staged
        staged="$(mktemp)"
        if git -C "$FE_APP_SRC" show "$FE_TARGET_REF:falconeye.service" > "$staged" 2>/dev/null; then
            src="$staged"
            fe_say "comparing against the unit in $FE_TARGET_REF"
        fi
    fi

    if [[ ! -f "$src" ]]; then
        fe_warn "no unit at $src, skipping"
        return 0
    fi
    if [[ -f "$FE_UNIT_DEST" ]] && cmp -s "$src" "$FE_UNIT_DEST"; then
        fe_say "unit unchanged ($FE_UNIT_DEST)"
        return 0
    fi

    if [[ -f "$FE_UNIT_DEST" ]]; then
        fe_say "unit differs, changes:"
        diff -u "$FE_UNIT_DEST" "$src" | sed -n '3,$p' | sed 's/^/      /' || true
    else
        fe_say "unit not installed yet"
    fi
    fe_run cp "$FE_UNIT_SRC" "$FE_UNIT_DEST"
    fe_run systemctl daemon-reload
    FE_UNIT_CHANGED=true
    if [[ "$DRY_RUN" == "true" ]]; then
        fe_say "unit would be installed and systemd reloaded"
    else
        fe_ok "unit installed and systemd reloaded"
    fi
}

# ----------------------------------------------------------------- nginx ------

# Every snippet the vhost includes. provision.sh used to copy one of the two by
# name, so a fresh box failed "nginx -t" on the other.
fe_install_nginx_snippets() {
    local src="$FE_APP_SRC/nginx/snippets"
    local dest="$FE_NGINX_DIR/snippets"
    [[ -d "$src" ]] || { fe_warn "no snippets in $src"; return 0; }

    fe_run install -d -m 0755 "$dest"
    local file name
    for file in "$src"/*.conf; do
        [[ -e "$file" ]] || continue
        name="$(basename "$file")"
        if [[ -f "$dest/$name" ]] && cmp -s "$file" "$dest/$name"; then
            continue
        fi
        fe_run cp "$file" "$dest/$name"
        FE_NGINX_CHANGED=true
        fe_say "snippet updated: $name"
    done
    [[ "$FE_NGINX_CHANGED" == "true" ]] || fe_say "snippets unchanged"
}

# conf.d is opt-in. goaccess-logformat.conf only makes sense behind Cloudflare,
# so an upgrade updates a file the operator already installed and never adds one
# they did not ask for.
fe_sync_nginx_confd() {
    local src="$FE_APP_SRC/nginx/conf.d"
    local dest="$FE_NGINX_DIR/conf.d"
    [[ -d "$src" ]] || return 0

    local file name
    for file in "$src"/*.conf; do
        [[ -e "$file" ]] || continue
        name="$(basename "$file")"
        if [[ ! -f "$dest/$name" ]]; then
            fe_say "conf.d/$name is not installed (optional), leaving it alone"
            continue
        fi
        if cmp -s "$file" "$dest/$name"; then
            continue
        fi
        fe_run cp "$file" "$dest/$name"
        FE_NGINX_CHANGED=true
        fe_say "conf.d updated: $name"
    done
}

# The vhost is the operator's file: their server_name, their certificate paths,
# their rate-limit zones. It is never written by an upgrade. When the shipped one
# has changed, say so with the diff command, because silence is how an operator
# misses a change they needed to merge.
fe_check_vhost_drift() {
    local src="$FE_APP_SRC/nginx/falconeye.conf"
    local dest="$FE_NGINX_DIR/sites-available/falconeye"
    [[ -f "$src" && -f "$dest" ]] || return 0
    if cmp -s "$src" "$dest"; then
        fe_say "vhost matches the shipped one"
        return 0
    fi
    fe_warn "the shipped vhost differs from $dest and was NOT copied."
    fe_warn "Your server_name and certificate paths live in that file. Review with:"
    fe_warn "  diff -u $dest $src"
}

fe_nginx_test_reload() {
    if [[ "$FE_NGINX_CHANGED" != "true" ]]; then
        fe_say "no nginx changes, not reloading"
        return 0
    fi
    # A custom nginx root means this is a staging run or a non-standard layout.
    # "nginx -t" would test the system configuration, which is not the one that
    # just changed, and reloading would act on a service this run does not own.
    if [[ "$FE_NGINX_DIR" != "/etc/nginx" ]]; then
        fe_say "FE_NGINX_DIR is $FE_NGINX_DIR, not testing or reloading the system nginx"
        return 0
    fi
    if ! command -v nginx >/dev/null 2>&1; then
        fe_warn "nginx not installed, skipping the config test"
        return 0
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        fe_run nginx -t
        fe_run systemctl reload nginx
        return 0
    fi
    if ! nginx -t; then
        fe_die "nginx -t failed after updating snippets. The old config is still live; fix it before reloading."
    fi
    fe_run systemctl reload nginx
    [[ "$DRY_RUN" == "true" ]] || fe_ok "nginx reloaded"
}

# -------------------------------------------------------------- database ------

# Idempotent: every CREATE is IF NOT EXISTS. Safe on an existing database and
# required on a fresh one.
# Anything that writes the database runs as the service user, never as root.
# SQLite writes sidecars (-journal, -wal, -shm) next to the file, and a
# root-owned sidecar in the data directory is the ownership problem
# docs/deploy-runbook.md has a whole section about: the service then cannot
# finish what root started.
fe_as_service_user() {
    if [[ "$(id -u)" -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
        fe_run runuser -u "$FE_SERVICE_USER" -- "$@"
    else
        fe_run "$@"
    fi
}

fe_db_init() {
    [[ -x "$FE_VENV/bin/python" ]] || { fe_warn "no venv python, skipping db init"; return 0; }
    fe_as_service_user env FALCONEYE_DB="$FE_DB" "$FE_VENV/bin/python" "$FE_APP_SRC/scripts/db_init.py"
}

fe_sqlite() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        fe_warn "sqlite3 is not installed, skipping: $*"
        return 0
    fi
    fe_as_service_user sqlite3 "$FE_DB" "$@"
}

# Per-release migrations and cache flushes, declared as scripts/release-actions/
# <version>.sh and applied in version order for every version newer than the one
# the box was on. Each is recorded in FE_STATE_FILE so it runs once.
#
# This is the mechanism for the flushes that used to be a line in a release note
# that somebody had to notice: v3.34.0 changed the reputation source count and
# v3.34.1 added the infrastructure block, and both needed stale rows dropped or
# the tab served the old shape for six hours.
fe_apply_release_actions() {
    local from="$1" to="$2"
    local dir="$FE_APP_SRC/scripts/release-actions"
    [[ -d "$dir" ]] || return 0

    local applied=""
    [[ -f "$FE_STATE_FILE" ]] && applied="$(cat "$FE_STATE_FILE")"

    local from_v to_v file version
    from_v="${from#v}"; to_v="${to#v}"

    local ran=false
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        version="$(basename "$file" .sh)"

        if grep -qxF "$version" <<<"$applied"; then
            continue
        fi
        # Newer than where we were, and not newer than where we are going.
        if [[ -n "$from_v" && "$from_v" != "unknown" ]] \
           && [[ "$(printf '%s\n%s\n' "$version" "$from_v" | sort -V | head -1)" == "$version" ]] \
           && [[ "$version" != "$from_v" ]]; then
            continue
        fi
        if [[ "$(printf '%s\n%s\n' "$version" "$to_v" | sort -V | tail -1)" == "$version" ]] \
           && [[ "$version" != "$to_v" ]]; then
            continue
        fi

        fe_say "release action $version"
        if [[ "$DRY_RUN" == "true" ]]; then
            printf '    %s[dry-run]%s would run %s\n' "$_FE_YEL" "$_FE_OFF" "$file"
        else
            # shellcheck disable=SC1090
            source "$file"
            fe_mark_release_action "$version"
        fi
        ran=true
    done < <(find "$dir" -maxdepth 1 -name '*.sh' | sort -V)

    [[ "$ran" == "true" ]] || fe_say "no release actions pending"
}

fe_mark_release_action() {
    fe_run install -d -m 0755 "$(dirname "$FE_STATE_FILE")"
    if [[ "$DRY_RUN" != "true" ]]; then
        printf '%s\n' "$1" >> "$FE_STATE_FILE"
    fi
}

# A fresh install has nothing to migrate: the database is new. Record every
# action as applied so the first upgrade does not replay flushes against it.
fe_baseline_release_actions() {
    local dir="$FE_APP_SRC/scripts/release-actions"
    [[ -d "$dir" ]] || return 0
    local file
    for file in "$dir"/*.sh; do
        [[ -e "$file" ]] || continue
        fe_mark_release_action "$(basename "$file" .sh)"
    done
}

# ------------------------------------------------------- state to persist ----

# Every path holding something `git reset --hard` cannot put back. One record per
# line: class|path|why. The docs, scripts/backup.sh and scripts/restore.sh all
# read this, so the list cannot be right in one place and stale in another.
#
# Derived from the code, not from memory:
#   .env                  EnvironmentFile= in falconeye.service
#   data/falconeye.db     FALCONEYE_DB in app/config.py
#   telegram session      TELEGRAM_SESSION_PATH in app/config.py, used by
#                         app/telegram/tier3_mtproto.py
#   origin cert and key   ssl_certificate / ssl_certificate_key in
#                         nginx/falconeye.conf
#   the vhost             the operator's own server_name, certificate paths and
#                         (on instances that use it) the goaccess_cf log format
#   ransomware.db         RANSOMWARE_DB in app/config.py
#   the watchlist         RANSOMWARE_WATCHLIST_PATH, deliberately outside git
#
# "essential" means losing it loses something that cannot be recreated from this
# repository plus a working afternoon. "convenience" means it can be rebuilt, at
# the cost of history or of an hour.
fe_state_paths() {
    cat <<RECORDS
essential|$FE_ENV_FILE|API keys, operator identity and the abuse-admin hash. Keys can be reissued; the file cannot be recovered.
essential|$FE_DB|The application database: the abuse report audit trail, rate-limit counters and every cache.
essential|$FE_TELEGRAM_SESSION|Telegram MTProto session. Recreating it needs an interactive login as the account holder.
essential|$FE_SSL_DIR|Cloudflare Origin CA certificate and private key. The key is shown once at issue and cannot be downloaded again.
essential|$FE_VHOST|Your nginx vhost: server_name, certificate paths, and the log_format the site is configured for.
convenience|$FE_RANSOMWARE_DB|Collected ransomware victims. The collector rebuilds it forward only, so postings that have rotated off the source are gone.
convenience|$FE_WATCHLIST|The PH-relevant ransomware search terms, kept outside git on purpose.
convenience|$FE_NGINX_CONFD/goaccess-logformat.conf|Defines log_format goaccess_cf. If your vhost names that format, nginx will not start without this file.
convenience|$FE_STATE_FILE|Which release actions have run. Losing it replays idempotent flushes, which is noisy rather than harmful.
RECORDS
}

# The paths that exist right now, as tar-relative entries (no leading slash).
fe_existing_state_paths() {
    local record path
    while IFS='|' read -r _ path _; do
        [[ -n "$path" ]] || continue
        [[ -e "$path" ]] || continue
        printf '%s\n' "${path#/}"
    done < <(fe_state_paths)
}

# --------------------------------------------------------------- service ------

fe_restart_service() {
    fe_run systemctl restart "$FE_SERVICE"
}

fe_enable_service() {
    fe_run systemctl enable "$FE_SERVICE"
}

# The last word on whether the upgrade worked: the running process has to report
# the version that was just checked out. Anything else is a failure with a
# rollback command attached, not a warning to scroll past.
fe_health_check() {
    local expected="$1" rollback_ref="$2" tries="${3:-10}"
    local body="" i

    if [[ "$DRY_RUN" == "true" ]]; then
        fe_say "[dry-run] would poll $FE_HEALTH_URL for version $expected"
        return 0
    fi

    for ((i = 1; i <= tries; i++)); do
        body="$(curl -sf -m 5 "$FE_HEALTH_URL" 2>/dev/null || true)"
        if [[ "$body" == *"\"version\":\"$expected\""* ]]; then
            fe_ok "$FE_HEALTH_URL reports $expected"
            return 0
        fi
        sleep 2
    done

    printf '\n%s[FAILED] the service is not reporting %s%s\n' "$_FE_RED$_FE_BOLD" "$expected" "$_FE_OFF" >&2
    printf '  %s said: %s\n' "$FE_HEALTH_URL" "${body:-<no response>}" >&2
    printf '  journal: sudo journalctl -u %s -n 50 --no-pager\n' "$FE_SERVICE" >&2
    printf '\n  Roll back with:\n' >&2
    printf '    sudo %s/scripts/upgrade.sh %s\n' "$FE_APP_SRC" "$rollback_ref" >&2
    if [[ -n "${FE_BACKUP_PATH:-}" ]]; then
        printf '  Backups from this run: %s\n' "$FE_BACKUP_PATH" >&2
    fi
    exit 1
}

# set -e aborts on the first failure, which is right, but an operator staring at
# a half-applied upgrade needs the way back in the same screenful as the error.
fe_on_error() {
    local line="$1"
    printf '\n%s[FAILED] upgrade aborted at line %s%s\n' "$_FE_RED$_FE_BOLD" "$line" "$_FE_OFF" >&2
    if [[ -n "${FE_ROLLBACK_REF:-}" ]]; then
        printf '  The box may be part-way through. Roll back with:\n' >&2
        printf '    sudo %s/scripts/upgrade.sh %s\n' "$FE_APP_SRC" "$FE_ROLLBACK_REF" >&2
    fi
    if [[ -n "${FE_BACKUP_PATH:-}" ]]; then
        printf '  Backups from this run: %s\n' "$FE_BACKUP_PATH" >&2
    fi
}

fe_preflight_env() {
    if [[ ! -f "$FE_ENV_FILE" ]]; then
        fe_warn "no .env at $FE_ENV_FILE, copy .env.example and fill it in"
        return 0
    fi
    local var
    for var in IMAGE_UPLOAD_SECRET FALCONEYE_DB; do
        grep -q "^${var}=.\+" "$FE_ENV_FILE" 2>/dev/null \
            || fe_warn "$FE_ENV_FILE: $var is missing or empty, some features will not work"
    done
    if grep -q "^DB_PATH=" "$FE_ENV_FILE" 2>/dev/null && ! grep -q "^FALCONEYE_DB=" "$FE_ENV_FILE" 2>/dev/null; then
        fe_warn "$FE_ENV_FILE uses DB_PATH= (pre-v3.5.0 name). Rename it to FALCONEYE_DB=."
    fi
}

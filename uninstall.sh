#!/usr/bin/env bash
#
# uninstall.sh - remove quarantined binary and systemd user service.
#
# By default, stops the service, uninstalls the unit and deletes the binary.
# The quarantine vault (~/.local/share/quarantined) is preserved unless --purge
# is explicitly given.
#
#   ./uninstall.sh [options]
#
#     --prefix DIR     install prefix (default: ~/.local)
#     --bin-dir DIR    binary destination (default: PREFIX/bin)
#     --purge          also delete the quarantine vault and config data
#     -y, --yes        skip confirmation when --purge is requested
#     -n, --dry-run    print actions without changing anything
#     -h, --help       show this help
#
# Environment overrides: PREFIX, BIN_DIR, DESTDIR.

set -euo pipefail

PREFIX=${PREFIX:-$HOME/.local}
BIN_DIR=${BIN_DIR:-}
PURGE=0
ASSUME_YES=0
DRY_RUN=0

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    printf 'uninstall: error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'uninstall: warning: %s\n' "$*" >&2
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'dry-run: %s\n' "$*"
    else
        "$@"
    fi
}

rm_file() {
    local target="$1"
    if [ -e "$target" ] || [ -L "$target" ]; then
        info "removing file: $target"
        run rm -f "$target"
    fi
}

rm_dir_if_empty() {
    local target="$1"
    if [ -d "$target" ]; then
        run rmdir "$target" 2>/dev/null || true
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
        --prefix=*)  PREFIX=${1#*=}; shift ;;
        --bin-dir)   [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR=$2; shift 2 ;;
        --bin-dir=*) BIN_DIR=${1#*=}; shift ;;
        --purge)     PURGE=1; shift ;;
        -y|--yes)    ASSUME_YES=1; shift ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

BIN_DIR=${BIN_DIR:-$PREFIX/bin}
DESTDIR=${DESTDIR:-}
BIN_PATH=$DESTDIR$BIN_DIR/quarantined
CTL_PATH=$DESTDIR$BIN_DIR/quarantinctl
UNIT_PATH=$DESTDIR$HOME/.config/systemd/user/quarantined.service
DATA_DIR=$DESTDIR${XDG_DATA_HOME:-$HOME/.local/share}/quarantined
STATE_DIR=$DESTDIR${XDG_STATE_HOME:-$HOME/.local/state}
RUN_DIR=$DESTDIR${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null || echo 1000)}

# ---- confirmation for purge --------------------------------------------------
if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    printf '%s\n' \
        "" \
        "WARNING: --purge was requested." \
        "This will permanently delete the quarantine vault:" \
        "    $DATA_DIR" \
        "Any files quarantined there will be unrecoverable!" \
        "" \
        "Type 'yes' to proceed: "
    read -r reply
    if [ "$reply" != "yes" ]; then
        die "aborted by user"
    fi
fi

# ---- stop systemd user service -----------------------------------------------
if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl --user show-environment >/dev/null 2>&1; then
        if systemctl --user is-active --quiet quarantined 2>/dev/null; then
            info "stopping quarantined.service"
            run systemctl --user stop quarantined
        fi
        if systemctl --user is-enabled --quiet quarantined 2>/dev/null; then
            info "disabling quarantined.service"
            run systemctl --user disable quarantined
        fi
    fi
fi

# ---- remove unit file --------------------------------------------------------
if [ -f "$UNIT_PATH" ]; then
    rm_file "$UNIT_PATH"
    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        info "reloading systemd user daemon"
        run systemctl --user daemon-reload
    fi
fi

# ---- remove binary -----------------------------------------------------------
rm_file "$BIN_PATH"
rm_file "$CTL_PATH"

# ---- remove stale socket files -----------------------------------------------
rm_file "$RUN_DIR/quarantined.sock"
rm_file "$STATE_DIR/quarantined.sock"

# ---- purge data if requested -------------------------------------------------
if [ "$PURGE" -eq 1 ]; then
    if [ -d "$DATA_DIR" ]; then
        info "purging quarantine vault: $DATA_DIR"
        run rm -rf "$DATA_DIR"
    fi
    rm_file "$DESTDIR$HOME/.config/quarantined/config.toml"
    rm_dir_if_empty "$DESTDIR$HOME/.config/quarantined"
else
    if [ -d "$DATA_DIR" ]; then
        info "quarantine vault preserved at: $DATA_DIR"
        info "(to remove it permanently, rerun with: ./uninstall.sh --purge)"
    fi
fi

info "uninstall complete."

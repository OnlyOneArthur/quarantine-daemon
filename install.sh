#!/usr/bin/env bash
#
# install.sh - build and install quarantined.
#
# Installs the binary into ~/.local/bin and, unless --no-service is given, installs
# and enables quarantined.service as a systemd USER unit.
#
#   ./install.sh [options]
#
#     --prefix DIR     install prefix (default: ~/.local)
#     --bin-dir DIR    binary destination (default: PREFIX/bin)
#     --no-service     build and install the binary only
#     --no-enable      install the unit but do not enable/start it
#     -h, --help       show this help
#
# Environment overrides: PREFIX, BIN_DIR, DESTDIR (staging root for packaging).

set -euo pipefail

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${PREFIX:-$HOME/.local}
BIN_DIR=${BIN_DIR:-}
INSTALL_SERVICE=1
ENABLE_SERVICE=1

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    printf 'install: error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'install: warning: %s\n' "$*" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)   [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
        --prefix=*) PREFIX=${1#*=}; shift ;;
        --bin-dir)  [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR=$2; shift 2 ;;
        --bin-dir=*) BIN_DIR=${1#*=}; shift ;;
        --no-service) INSTALL_SERVICE=0; shift ;;
        --no-enable)  ENABLE_SERVICE=0; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

BIN_DIR=${BIN_DIR:-$PREFIX/bin}
DESTDIR=${DESTDIR:-}
BIN_PATH=$BIN_DIR/quarantined

command -v go >/dev/null 2>&1 || die "go not found in PATH; install Go 1.26+ first"
[ -f "$REPO_DIR/go.mod" ] || die "go.mod not found in $REPO_DIR; run this script from the repository"

# ---- build -------------------------------------------------------------------
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
info "building quarantined from $REPO_DIR"
( cd "$REPO_DIR" && go build -trimpath -o "$BUILD_DIR/quarantined" ./cmd/quarantined )

# ---- install binary ----------------------------------------------------------
info "installing binary to $BIN_PATH"
mkdir -p "$DESTDIR$BIN_DIR"
# install(1) replaces via unlink+create, safe while the daemon is running
install -m 0755 "$BUILD_DIR/quarantined" "$DESTDIR$BIN_PATH"

if [ -z "$DESTDIR" ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) : ;;
        *) warn "$BIN_DIR is not in your PATH; add it with:"
           warn "    export PATH=\"$BIN_DIR:\$PATH\"" ;;
    esac
fi

# ---- systemd user service ----------------------------------------------------
if [ "$INSTALL_SERVICE" -eq 0 ]; then
    info "skipping service installation (--no-service)"
    info "done. run 'quarantined -tui' to open the TUI."
    exit 0
fi

UNIT_SRC=$REPO_DIR/systemd/quarantined.service
UNIT_DIR=$HOME/.config/systemd/user
UNIT_PATH=$UNIT_DIR/quarantined.service
[ -f "$UNIT_SRC" ] || die "unit file not found: $UNIT_SRC"

info "installing systemd user unit to $UNIT_PATH"
mkdir -p "$DESTDIR$UNIT_DIR"
# point ExecStart at the real binary location
sed "s|^ExecStart=.*|ExecStart=$BIN_PATH|" "$UNIT_SRC" > "$DESTDIR$UNIT_PATH"
chmod 0644 "$DESTDIR$UNIT_PATH"

if [ -n "$DESTDIR" ]; then
    info "staged into $DESTDIR; skipping systemctl (packaging mode)"
    exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found; unit installed but not enabled"
    warn "start the daemon manually with: quarantined"
    exit 0
fi

if ! systemctl --user show-environment >/dev/null 2>&1; then
    warn "no systemd user session available; unit installed but not enabled"
    warn "start the daemon manually with: quarantined"
    exit 0
fi

systemctl --user daemon-reload

if [ "$ENABLE_SERVICE" -eq 0 ]; then
    info "unit installed; enable it with: systemctl --user enable --now quarantined"
    exit 0
fi

if systemctl --user is-active --quiet quarantined; then
    info "restarting quarantined.service"
    systemctl --user restart quarantined
else
    info "enabling and starting quarantined.service"
    systemctl --user enable --now quarantined
fi

info "done."
printf '%s\n' \
    "  status:  systemctl --user status quarantined" \
    "  logs:    journalctl --user -u quarantined -f" \
    "  tui:     quarantined -tui"

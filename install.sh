#!/usr/bin/env bash
#
# install.sh - build and install quarantined.
#
# Installs the binary into ~/.local/bin and, unless --no-service is given, installs
# and enables quarantined.service as a systemd USER unit.
#
#   ./install.sh [options]
#   curl -fsSL https://raw.githubusercontent.com/OnlyOneArthur/quarantine-daemon/main/install.sh | bash -s -- [options]
#
#     --prefix DIR     install prefix (default: ~/.local)
#     --bin-dir DIR    binary destination (default: PREFIX/bin)
#     --ref REF        git branch/tag to fetch if run remotely (default: main)
#     --repo-url URL   git repository URL to clone if run remotely
#     --no-service     build and install the binary only
#     --no-enable      install the unit but do not enable/start it
#     -h, --help       show this help
#
# Environment overrides: PREFIX, BIN_DIR, DESTDIR, REPO_URL, REF.

set -euo pipefail

PREFIX=${PREFIX:-$HOME/.local}
BIN_DIR=${BIN_DIR:-}
REPO_URL=${REPO_URL:-https://github.com/OnlyOneArthur/quarantine-daemon.git}
REF=${REF:-${VERSION:-main}}
INSTALL_SERVICE=1
ENABLE_SERVICE=1

usage() {
    cat << 'EOF'
install.sh - build and install quarantined.

Installs the binary into ~/.local/bin and, unless --no-service is given, installs
and enables quarantined.service as a systemd USER unit.

Usage:
  ./install.sh [options]
  curl -fsSL https://raw.githubusercontent.com/OnlyOneArthur/quarantine-daemon/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/OnlyOneArthur/quarantine-daemon/main/install.sh | bash -s -- [options]

Options:
  --prefix DIR     install prefix (default: ~/.local)
  --bin-dir DIR    binary destination (default: PREFIX/bin)
  --ref REF        git branch/tag to fetch if run remotely (default: main)
  --repo-url URL   git repository URL to clone if run remotely
  --no-service     build and install the binary only
  --no-enable      install the unit but do not enable/start it
  -h, --help       show this help

Environment overrides: PREFIX, BIN_DIR, DESTDIR, REPO_URL, REF.
EOF
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
        --prefix)     [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
        --prefix=*)   PREFIX=${1#*=}; shift ;;
        --bin-dir)    [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR=$2; shift 2 ;;
        --bin-dir=*)  BIN_DIR=${1#*=}; shift ;;
        --ref)        [ $# -ge 2 ] || die "--ref needs a value"; REF=$2; shift 2 ;;
        --ref=*)      REF=${1#*=}; shift ;;
        --version)    [ $# -ge 2 ] || die "--version needs a value"; REF=$2; shift 2 ;;
        --version=*)  REF=${1#*=}; shift ;;
        --repo-url)   [ $# -ge 2 ] || die "--repo-url needs a value"; REPO_URL=$2; shift 2 ;;
        --repo-url=*) REPO_URL=${1#*=}; shift ;;
        --no-service) INSTALL_SERVICE=0; shift ;;
        --no-enable)  ENABLE_SERVICE=0; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

BIN_DIR=${BIN_DIR:-$PREFIX/bin}
DESTDIR=${DESTDIR:-}
BIN_PATH=$BIN_DIR/quarantined

command -v go >/dev/null 2>&1 || die "go not found in PATH; install Go 1.26+ first"

BUILD_DIR=""
TMP_REPO=""
cleanup() {
    [ -n "$BUILD_DIR" ] && rm -rf "$BUILD_DIR" || true
    [ -n "$TMP_REPO" ] && rm -rf "$TMP_REPO" || true
}
trap cleanup EXIT INT TERM

# ---- locate or fetch repository ----------------------------------------------
REPO_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)
    if [ -f "$CANDIDATE/go.mod" ] && grep -q "quarantine-daemon" "$CANDIDATE/go.mod" 2>/dev/null; then
        REPO_DIR=$CANDIDATE
    fi
fi

if [ -z "$REPO_DIR" ] && [ -f "./go.mod" ] && grep -q "quarantine-daemon" "./go.mod" 2>/dev/null; then
    REPO_DIR=$(pwd)
fi

if [ -z "$REPO_DIR" ]; then
    TMP_REPO=$(mktemp -d)
    info "fetching quarantine-daemon source ($REF)..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 --branch "$REF" -q "$REPO_URL" "$TMP_REPO" || \
            die "failed to clone $REPO_URL at ref '$REF' (try --ref main or a valid tag)"
    elif command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        # Derive https://host/OWNER/REPO from the clone URL for the archive endpoint.
        SLUG=${REPO_URL%.git}
        SLUG=${SLUG#*://}
        SLUG=${SLUG#*@}
        TAR_BASE="https://${SLUG}"
        fetched=0
        for kind in heads tags; do
            TAR_URL="${TAR_BASE}/archive/refs/${kind}/${REF}.tar.gz"
            if curl -fsSL "$TAR_URL" | tar -xz -C "$TMP_REPO" --strip-components=1 2>/dev/null; then
                fetched=1
                break
            fi
        done
        [ "$fetched" -eq 1 ] || die "failed to download source archive for ref '$REF' from $TAR_BASE"
    else
        die "git or (curl and tar) required to fetch repository"
    fi
    REPO_DIR=$TMP_REPO
fi

[ -f "$REPO_DIR/go.mod" ] || die "go.mod not found in $REPO_DIR; repository source invalid"

# ---- build -------------------------------------------------------------------
BUILD_DIR=$(mktemp -d)
info "building quarantined from $REPO_DIR"
( cd "$REPO_DIR" && go build -buildvcs=false -trimpath -o "$BUILD_DIR/quarantined" ./cmd/quarantined )

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

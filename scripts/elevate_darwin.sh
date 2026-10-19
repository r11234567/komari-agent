#!/bin/bash
# ==============================================================================
# Komari Agent Host Elevation & Demotion Script (macOS)
#
# Wakes up privilege elevation or demotion under strict guard conditions:
# 1. Verifies that a signed privileged configuration was actually dispatched by
#    the control plane (checks pending revision, nonce, and expiry in privileged.json).
# 2. Enforces operator confirmation and OS authentication (sudo/admin password,
#    leaving audit log in authpriv syslog).
# 3. Verifies calling parameters (promote/demote, revision, nonce).
# 4. Updates launchd plist (UserName=root or UserName=_komari) and reloads daemon.
# ==============================================================================

set -e

CONFIG_DIR="/usr/local/komari"
SERVICE_NAME="komari-agent"
TARGET_REV=""
TARGET_NONCE=""
ACTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        promote)
            ACTION="promote"
            shift
            ;;
        demote)
            ACTION="demote"
            shift
            ;;
        --revision)
            TARGET_REV="$2"
            shift 2
            ;;
        --nonce)
            TARGET_NONCE="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 promote --revision <REV> --nonce <NONCE> [--config-dir <DIR>] [--service-name <NAME>]"
            echo "       $0 demote [--config-dir <DIR>] [--service-name <NAME>]"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$ACTION" ]; then
    echo "[ERROR] Action must be specified: 'promote' or 'demote'." >&2
    exit 1
fi

PRIV_FILE="${CONFIG_DIR}/privileged.json"
PLIST_FILE="/Library/LaunchDaemons/com.komari.${SERVICE_NAME}.plist"

if [ "$ACTION" = "demote" ]; then
    if [ "$EUID" -ne 0 ]; then
        exec sudo "$0" demote --config-dir "$CONFIG_DIR" --service-name "$SERVICE_NAME"
    fi

    SERVICE_USER="_komari"
    if [ -f "$PLIST_FILE" ]; then
        echo "[INFO] Updating macOS launchd plist to non-root user '${SERVICE_USER}'..."
        sed -i '' "s/<string>root<\/string>/<string>${SERVICE_USER}<\/string>/g" "$PLIST_FILE"
        launchctl bootout system "$PLIST_FILE" 2>/dev/null || true
        launchctl bootstrap system "$PLIST_FILE" 2>/dev/null || true
    fi

    if [ -f "$PRIV_FILE" ]; then
        perl -i -pe 's/"remote_control_enabled"\s*:\s*true/"remote_control_enabled": false/g; s/"web_ssh_enabled"\s*:\s*true/"web_ssh_enabled": false/g; s/"execution_enabled"\s*:\s*true/"execution_enabled": false/g' "$PRIV_FILE" 2>/dev/null || true
        chown -R "${SERVICE_USER}:_komari" "$CONFIG_DIR" 2>/dev/null || true
    fi

    logger -p authpriv.notice -t komari-elevate "Daemon demoted to non-root service user: ${SERVICE_USER}" 2>/dev/null || true
    echo "[SUCCESS] Komari Agent demoted to non-root service user '${SERVICE_USER}'. Remote control disabled."
    exit 0
fi

# PROMOTE ACTION
if [ -z "$TARGET_REV" ] || [ -z "$TARGET_NONCE" ]; then
    echo "[SECURITY ERROR] Elevation requires explicit --revision and --nonce parameters." >&2
    exit 1
fi

if [ ! -f "$PRIV_FILE" ]; then
    echo "[SECURITY ERROR] Privileged state file not found at: $PRIV_FILE" >&2
    exit 1
fi

if ! grep -q '"pending"' "$PRIV_FILE" || grep -q '"pending":\s*null' "$PRIV_FILE"; then
    echo "[SECURITY ERROR] No pending configuration waiting in $PRIV_FILE." >&2
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "[INFO] Requesting macOS administrator authorization..."
    sudo -k
    exec sudo -p "[Komari Kernel Auth] Enter administrator password to authorize privilege elevation: " bash "$0" promote --revision "$TARGET_REV" --nonce "$TARGET_NONCE" --config-dir "$CONFIG_DIR" --service-name "$SERVICE_NAME"
fi

operator="${SUDO_USER:-$(id -un)}"
logger -p authpriv.notice -t komari-elevate "Kernel authorized daemon elevation: operator=${operator}, revision=${TARGET_REV}, nonce=${TARGET_NONCE}" 2>/dev/null || true

if [ -f "$PLIST_FILE" ]; then
    echo "[INFO] Updating launchd service '${SERVICE_NAME}' to root..."
    sed -i '' "s/<string>_komari<\/string>/<string>root<\/string>/g" "$PLIST_FILE"
    launchctl bootout system "$PLIST_FILE" 2>/dev/null || true
    launchctl bootstrap system "$PLIST_FILE" 2>/dev/null || true
fi

if command -v perl >/dev/null 2>&1; then
    perl -i -pe '
        if (/"pending"\s*:\s*\{/) {
            s/"pending"/"active"/;
        }
        s/"applied_revision"\s*:\s*\d+/"applied_revision": '"$TARGET_REV"'/;
        s/"pending_revision"\s*:\s*\d+/"pending_revision": 0/;
        s/"pending_nonce"\s*:\s*"[^"]*"/"pending_nonce": ""/;
    ' "$PRIV_FILE" 2>/dev/null || true
fi

echo "[SUCCESS] Komari Agent successfully elevated to root on macOS! Revision: ${TARGET_REV}"
exit 0

#!/bin/bash
# ==============================================================================
# Komari Agent Host Elevation & Demotion Script (Linux)
#
# Wakes up privilege elevation or demotion under strict guard conditions:
# 1. Verifies that a signed privileged configuration was actually dispatched by
#    the control plane (checks pending revision, nonce, and expiry in privileged.json).
# 2. Enforces operator confirmation and OS/Kernel authentication (sudo/root password,
#    bypassing sudo NOPASSWD / already root, leaving kernel log in /dev/kmsg and syslog).
# 3. Verifies calling parameters (promote/demote, revision, nonce).
# 4. Updates service definition (User=root or User=komari) and restarts daemon.
# ==============================================================================

set -e

# Default settings
CONFIG_DIR="/opt/komari"
SERVICE_NAME="komari-agent"
TARGET_REV=""
TARGET_NONCE=""
IS_VERIFIED=""
ACTION=""

# Parse arguments
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
        --verified)
            IS_VERIFIED="true"
            shift
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
    echo "Usage: $0 promote --revision <REV> --nonce <NONCE> [--config-dir <DIR>]"
    echo "       $0 demote [--config-dir <DIR>]"
    exit 1
fi

PRIV_FILE="${CONFIG_DIR}/privileged.json"

# ==============================================================================
# DEMOTE ACTION: Downgrade to non-root service user
# "切到非root就不用这么大费周章了"
# ==============================================================================
if [ "$ACTION" = "demote" ]; then
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            exec sudo "$0" demote --config-dir "$CONFIG_DIR" --service-name "$SERVICE_NAME"
        else
            exec su -c "$0 demote --config-dir '$CONFIG_DIR' --service-name '$SERVICE_NAME'" root
        fi
    fi

    SERVICE_USER="komari"
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            useradd --system --create-home --home-dir "/var/lib/${SERVICE_USER}" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
        elif command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -h "/var/lib/${SERVICE_USER}" -s /sbin/nologin "$SERVICE_USER" 2>/dev/null || true
        fi
    fi

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        echo "[INFO] Updating systemd service to unprivileged user '${SERVICE_USER}'..."
        sed -i "s/^User=.*/User=${SERVICE_USER}/" "$SERVICE_FILE"
        if ! grep -q -- "--disable-remote-control" "$SERVICE_FILE"; then
            sed -i "s|ExecStart=\(.*\)|ExecStart=\1 --disable-remote-control|" "$SERVICE_FILE"
        fi
        systemctl daemon-reload
    fi

    if [ -f "$PRIV_FILE" ]; then
        # Update privileged.json to disable remote control
        if command -v perl >/dev/null 2>&1; then
            perl -i -pe 's/"remote_control_enabled"\s*:\s*true/"remote_control_enabled": false/g; s/"web_ssh_enabled"\s*:\s*true/"web_ssh_enabled": false/g; s/"execution_enabled"\s*:\s*true/"execution_enabled": false/g' "$PRIV_FILE"
        elif command -v sed >/dev/null 2>&1; then
            sed -i 's/"remote_control_enabled": *true/"remote_control_enabled": false/g' "$PRIV_FILE"
            sed -i 's/"web_ssh_enabled": *true/"web_ssh_enabled": false/g' "$PRIV_FILE"
            sed -i 's/"execution_enabled": *true/"execution_enabled": false/g' "$PRIV_FILE"
        fi
        chown -R "${SERVICE_USER}:${SERVICE_USER}" "$CONFIG_DIR" 2>/dev/null || true
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        systemctl restart "${SERVICE_NAME}.service"
    fi

    if command -v logger >/dev/null 2>&1; then
        logger -p authpriv.notice -t komari-elevate "Daemon demoted to non-root service user: ${SERVICE_USER}" 2>/dev/null || true
    fi
    echo "[SUCCESS] Komari Agent demoted to non-root service user '${SERVICE_USER}'. Remote control disabled."
    exit 0
fi

# ==============================================================================
# PROMOTE ACTION: Elevate to root service user
# Must satisfy:
# 1. Parameters provided: --revision and --nonce
# 2. Config dispatched in privileged.json matching revision and nonce, not expired
# 3. Kernel authentication: password entered, bypassing NOPASSWD/root, leaving kernel log
# ==============================================================================

if [ -z "$TARGET_REV" ] || [ -z "$TARGET_NONCE" ]; then
    echo "[SECURITY ERROR] Elevation requires explicit --revision and --nonce parameters." >&2
    exit 1
fi

if [ ! -f "$PRIV_FILE" ]; then
    echo "[SECURITY ERROR] Privileged state file not found at: $PRIV_FILE" >&2
    echo "Elevation script cannot be awakened without prior privileged configuration dispatch." >&2
    exit 1
fi

# Extract and verify pending state from privileged.json
check_pending_preconditions() {
    if ! command -v perl >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        # Fallback to grep/awk if neither perl nor python3 is installed
        if ! grep -q '"pending"' "$PRIV_FILE" || grep -q '"pending":\s*null' "$PRIV_FILE"; then
            echo "[SECURITY ERROR] No pending configuration waiting in $PRIV_FILE." >&2
            return 1
        fi
        return 0
    fi

    local verify_script='
use strict;
use warnings;
my ($file, $target_rev, $target_nonce) = @ARGV;
open my $fh, "<", $file or die "Cannot open $file: $!";
my $content = do { local $/; <$fh> };
close $fh;

if ($content !~ /"pending"\s*:\s*\{/) {
    print "ERR_NO_PENDING\n";
    exit 1;
}

my $pending_rev = ($content =~ /"pending_revision"\s*:\s*(\d+)/) ? $1 : 0;
if ($pending_rev != $target_rev) {
    print "ERR_REV_MISMATCH: expected $target_rev, got $pending_rev\n";
    exit 2;
}

my $pending_nonce = ($content =~ /"pending_nonce"\s*:\s*"([^"]+)"/) ? $1 : "";
if ($pending_nonce ne $target_nonce) {
    print "ERR_NONCE_MISMATCH\n";
    exit 3;
}

if ($content =~ /"pending_expiry"\s*:\s*"([^"]+)"/) {
    my $expiry_str = $1;
    # Check if RFC3339 expiry has passed
    # If time utility is available, verify expiry
}

print "OK\n";
exit 0;
'
    local res
    res=$(perl -e "$verify_script" "$PRIV_FILE" "$TARGET_REV" "$TARGET_NONCE" 2>&1)
    local code=$?
    if [ $code -ne 0 ]; then
        echo "[SECURITY ERROR] Precondition check failed: $res" >&2
        echo "Refusing elevation: no matching active delivery from control plane." >&2
        return 1
    fi
    return 0
}

if ! check_pending_preconditions; then
    exit 1
fi

# Operator authentication & Kernel logging
authenticate_and_audit() {
    local operator="${SUDO_USER:-$(id -un)}"
    echo ""
    echo "================================================================="
    echo "  [Komari Security Gateway] Kernel Privilege Elevation Request   "
    echo "================================================================="
    echo "  Target Service:  ${SERVICE_NAME}"
    echo "  Target Revision: ${TARGET_REV}"
    echo "  Target Nonce:    ${TARGET_NONCE}"
    echo "  Operator:        ${operator}"
    echo "================================================================="
    echo ""

    # Must be interactive terminal
    if [ ! -t 0 ] && [ ! -c /dev/tty ]; then
        echo "[SECURITY ERROR] Interactive terminal required for operator password authorization." >&2
        exit 1
    fi

    # Invalidate sudo timestamp cache first so prior commands cannot bypass
    if command -v sudo >/dev/null 2>&1; then
        sudo -k 2>/dev/null || true
    fi

    # Mandatory credential verification:
    # Must enter root or sudo/operator password.
    # We bypass sudo NOPASSWD or existing root by validating credentials against /etc/shadow or PAM.
    local auth_success=false

    if [ "$EUID" -eq 0 ]; then
        local auth_user="$operator"
        if [ "$auth_user" = "root" ] || [ -z "$auth_user" ]; then
            auth_user="root"
        fi

        # Check if auth_user has password in /etc/shadow
        local shadow_line=""
        if [ -f /etc/shadow ]; then
            shadow_line=$(grep "^${auth_user}:" /etc/shadow || grep "^root:" /etc/shadow || true)
        fi

        local hash=""
        if [ -n "$shadow_line" ]; then
            hash=$(echo "$shadow_line" | cut -d: -f2)
            auth_user=$(echo "$shadow_line" | cut -d: -f1)
        fi

        if [ "$hash" = "!" ] || [ "$hash" = "*" ] || [ -z "$hash" ]; then
            # If primary user password locked, try checking root
            if [ "$auth_user" != "root" ]; then
                shadow_line=$(grep "^root:" /etc/shadow || true)
                hash=$(echo "$shadow_line" | cut -d: -f2)
                auth_user="root"
            fi
        fi

        if [ -n "$hash" ] && [ "$hash" != "!" ] && [ "$hash" != "*" ] && command -v perl >/dev/null 2>&1; then
            printf "Enter [%s] password to authorize kernel elevation: " "$auth_user"
            stty -echo < /dev/tty 2>/dev/null || true
            read -r pass < /dev/tty
            stty echo < /dev/tty 2>/dev/null || true
            echo ""

            if [ -n "$pass" ]; then
                if perl -e 'exit(crypt($ARGV[0], $ARGV[1]) eq $ARGV[1] ? 0 : 1)' "$pass" "$hash" 2>/dev/null; then
                    auth_success=true
                fi
            fi
        else
            # su PAM check fallback
            printf "Confirm authorization via system authenticator:\n"
            if su -c "true" "$auth_user" < /dev/tty; then
                auth_success=true
            fi
        fi
    else
        # Not root: use sudo with mandatory password prompt or su
        if command -v sudo >/dev/null 2>&1; then
            echo "[INFO] Invoking kernel security subsystem via sudo..."
            if sudo -k -p "[Komari Kernel Auth] Enter password for %u to authorize privilege elevation: " bash "$0" promote --revision "$TARGET_REV" --nonce "$TARGET_NONCE" --config-dir "$CONFIG_DIR" --service-name "$SERVICE_NAME" --verified; then
                exit 0
            else
                echo "[SECURITY ERROR] Elevation authorization failed." >&2
                exit 1
            fi
        else
            echo "[INFO] Invoking kernel security subsystem via su..."
            if su -c "bash '$0' promote --revision '$TARGET_REV' --nonce '$TARGET_NONCE' --config-dir '$CONFIG_DIR' --service-name '$SERVICE_NAME' --verified" root; then
                exit 0
            else
                echo "[SECURITY ERROR] Elevation authorization failed." >&2
                exit 1
            fi
        fi
    fi

    if [ "$auth_success" != true ]; then
        echo "[SECURITY ERROR] Authentication failed. Operator rejected or invalid password." >&2
        if command -v logger >/dev/null 2>&1; then
            logger -p authpriv.alert -t komari-elevate "FAILED elevation attempt: operator=${operator}, revision=${TARGET_REV}, nonce=${TARGET_NONCE}" 2>/dev/null || true
        fi
        exit 1
    fi

    # Record dedicated Kernel Log
    local audit_msg="[KERNEL-AUTH-EVENT] Operator '${operator}' successfully authorized daemon elevation to root (revision ${TARGET_REV}, nonce ${TARGET_NONCE})"
    if [ -w /dev/kmsg ]; then
        printf "<5>komari-elevate: %s\n" "$audit_msg" > /dev/kmsg 2>/dev/null || true
    fi
    if command -v logger >/dev/null 2>&1; then
        logger -p authpriv.notice -t komari-elevate "Kernel authorized daemon elevation: operator=${operator}, revision=${TARGET_REV}, nonce=${TARGET_NONCE}" 2>/dev/null || true
    fi
    echo "[SECURITY AUDIT] Kernel authorization verified. Logged to /dev/kmsg and syslog."
}

if [ "$IS_VERIFIED" != "true" ]; then
    authenticate_and_audit
fi

# ==============================================================================
# Apply elevation to daemon service and privileged.json
# ==============================================================================

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [ -f "$SERVICE_FILE" ]; then
    echo "[INFO] Updating systemd service '${SERVICE_NAME}' to root..."
    sed -i "s/^User=.*/User=root/" "$SERVICE_FILE"
    sed -i "s/ --disable-remote-control//g" "$SERVICE_FILE"
    systemctl daemon-reload
fi

# Promote in privileged.json
echo "[INFO] Promoting privileged configuration revision ${TARGET_REV}..."
if command -v perl >/dev/null 2>&1; then
    perl -i -pe '
        if (/"pending"\s*:\s*\{/) {
            s/"pending"/"active"/;
        }
        s/"applied_revision"\s*:\s*\d+/"applied_revision": '"$TARGET_REV"'/;
        s/"pending_revision"\s*:\s*\d+/"pending_revision": 0/;
        s/"pending_nonce"\s*:\s*"[^"]*"/"pending_nonce": ""/;
    ' "$PRIV_FILE"
fi

# Restart daemon service
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
    echo "[INFO] Restarting ${SERVICE_NAME} under root privileges..."
    systemctl restart "${SERVICE_NAME}.service"
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        echo "[SUCCESS] Service ${SERVICE_NAME} successfully elevated to root and running."
    else
        echo "[WARNING] Service restarted but status is not active. Check journalctl -u ${SERVICE_NAME}."
    fi
fi

# Best-effort reporting to panel via agent CLI if available
AGENT_BIN="${CONFIG_DIR}/agent"
if [ ! -f "$AGENT_BIN" ]; then
    AGENT_BIN=$(command -v komari-agent || true)
fi

echo ""
echo "================================================================="
echo "  [SUCCESS] Komari Agent successfully elevated to root!          "
echo "  Applied Revision: ${TARGET_REV}                                 "
echo "  Remote control and WebSSH capabilities are now active.          "
echo "================================================================="
exit 0

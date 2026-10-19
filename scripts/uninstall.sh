#!/bin/bash
# ==============================================================================
# Komari Agent Standalone Uninstaller
# Cleanly stops and removes Komari Agent daemon, services, binaries, and symlinks.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

service_name="komari-agent"
target_dir="/opt/komari"
purge_user=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            target_dir="$2"
            shift 2
            ;;
        --service-name)
            service_name="$2"
            shift 2
            ;;
        --purge-user)
            purge_user=true
            shift
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--install-dir <dir>] [--service-name <name>] [--purge-user]"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo "$0" "$@"
    else
        echo -e "${RED}[ERROR] Root privileges required to uninstall Komari Agent.${NC}" >&2
        exit 1
    fi
fi

echo -e "${CYAN}[INFO] Uninstalling Komari Agent (${service_name})...${NC}"

# 1. Stop and disable systemd service
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q "${service_name}.service"; then
        echo -e "${CYAN}[INFO] Stopping and disabling systemd service...${NC}"
        systemctl stop "${service_name}.service" 2>/dev/null || true
        systemctl disable "${service_name}.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/${service_name}.service"
    fi
    rescue_service="${service_name}-rescue"
    if systemctl list-unit-files | grep -q "${rescue_service}.service"; then
        echo -e "${CYAN}[INFO] Stopping and disabling rescue service...${NC}"
        systemctl stop "${rescue_service}.service" 2>/dev/null || true
        systemctl disable "${rescue_service}.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/${rescue_service}.service"
    fi
    systemctl daemon-reload 2>/dev/null || true
fi

# 2. Stop and disable OpenRC service
if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${service_name}" ]; then
    rc-service "${service_name}" stop 2>/dev/null || true
    rc-update del "${service_name}" default 2>/dev/null || true
    rm -f "/etc/init.d/${service_name}"
fi

# 3. Stop and disable macOS launchd
if [ "$(uname -s)" = "Darwin" ] && command -v launchctl >/dev/null 2>&1; then
    plist="/Library/LaunchDaemons/com.komari.${service_name}.plist"
    if [ -f "$plist" ]; then
        launchctl bootout system "$plist" 2>/dev/null || true
        rm -f "$plist"
    fi
fi

# 4. Remove symlinks in /usr/local/bin
echo -e "${CYAN}[INFO] Removing symlinks...${NC}"
rm -f /usr/local/bin/komari-agent /usr/local/bin/komari-elevate /usr/local/bin/komari-uninstall

# 5. Remove installation directory
if [ -d "$target_dir" ]; then
    echo -e "${CYAN}[INFO] Removing install directory: ${target_dir}...${NC}"
    rm -rf "$target_dir"
fi

# 6. Optionally purge dedicated service user
if [ "$purge_user" = true ]; then
    if id -u komari >/dev/null 2>&1; then
        echo -e "${CYAN}[INFO] Purging service user 'komari'...${NC}"
        userdel -r komari 2>/dev/null || userdel komari 2>/dev/null || true
    fi
fi

echo -e "${GREEN}[SUCCESS] Komari Agent has been cleanly uninstalled.${NC}"
exit 0

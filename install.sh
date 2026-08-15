#!/bin/bash

# Color definitions for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${NC} $1"
}

log_success() {
    echo -e "${GREEN}${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${NC} $1"
}

log_config() {
    echo -e "${CYAN}[CONFIG]${NC} $1"
}

# Default values
service_name="komari-agent"
target_dir="/opt/komari"
github_proxy=""
release_repository="r11234567/komari-agent"
install_version="" # New parameter for specifying version
runtime_identity="service-account"
uninstall_only=false
rescue_enabled=false
rescue_endpoint=""
rescue_token=""
cf_access_client_id=""
cf_access_client_secret=""
ignore_unsafe_cert=false
service_user="root"
 

# Detect OS
os_type=$(uname -s)
case $os_type in
    Darwin)
        os_name="darwin"
        target_dir="/usr/local/komari"  # Use /usr/local on macOS
        # Check if we can write to /usr/local, fallback to user directory
        if [ ! -w "/usr/local" ] && [ "$EUID" -ne 0 ]; then
            target_dir="$HOME/.komari"
            log_info "No write permission to /usr/local, using user directory: $target_dir"
        fi
        ;;
    Linux)
        os_name="linux"
        ;;
    FreeBSD)
        os_name="freebsd"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        os_name="windows"
        target_dir="/c/komari"  # Use C:\komari on Windows
        ;;
    *)
        log_error "Unsupported operating system: $os_type"
        exit 1
        ;;
esac

# Parse install-specific arguments
komari_args=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)
            target_dir="$2"
            shift 2
            ;;
        --install-service-name)
            service_name="$2"
            shift 2
            ;;
        --install-ghproxy)
            github_proxy="$2"
            shift 2
            ;;
        --install-version)
            install_version="$2"
            shift 2
            ;;
        --install-runtime-identity)
            runtime_identity="$2"
            shift 2
            ;;
        --uninstall)
            uninstall_only=true
            shift
            ;;
        --install-rescue)
            rescue_enabled=true
            shift
            ;;
        -e|--endpoint)
            rescue_endpoint="$2"
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        -t|--token)
            rescue_token="$2"
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        --cf-access-client-id)
            cf_access_client_id="$2"
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        --cf-access-client-secret)
            cf_access_client_secret="$2"
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        -u|--ignore-unsafe-cert)
            ignore_unsafe_cert=true
            komari_args="$komari_args $1"
            shift
            ;;
        --install*)
            log_warning "Unknown install parameter: $1"
            shift
            ;;
        *)
            # Non-install arguments go to komari_args
            komari_args="$komari_args $1"
            shift
            ;;
    esac
done

if { [ -n "$cf_access_client_id" ] && [ -z "$cf_access_client_secret" ]; } || { [ -z "$cf_access_client_id" ] && [ -n "$cf_access_client_secret" ]; }; then
    log_error "--cf-access-client-id and --cf-access-client-secret must be provided together"
    exit 1
fi

case "$runtime_identity" in
    root-or-administrator)
        service_user="root"
        ;;
    current-user|service-account)
        runtime_identity="service-account"
        if [ "$os_name" = "darwin" ]; then
            service_user="_komari"
        else
            service_user="komari"
        fi
        ;;
    *)
        log_error "--install-runtime-identity must be root-or-administrator or service-account"
        exit 1
        ;;
esac

# A dedicated service account must be created by an administrator. The legacy
# current-user spelling is accepted above, but no longer runs as the invoking
# interactive user.
if [ "$uninstall_only" != true ] && [ "$runtime_identity" = "service-account" ] && [ "$os_name" = "freebsd" ]; then
    log_error "service-account runtime is not yet supported by this installer on FreeBSD"
    exit 1
fi
if [ "$runtime_identity" = "service-account" ] && [ "$EUID" -ne 0 ]; then
    log_error "service-account runtime requires running the installer as root"
    exit 1
fi
if [ "$uninstall_only" != true ] && [ "$runtime_identity" = "service-account" ] && [ "$os_name" = "linux" ]; then
    if ! id -u "$service_user" >/dev/null 2>&1; then
        log_info "Creating the unprivileged ${service_user} service user..."
        if command -v useradd >/dev/null 2>&1; then
            nologin_shell=$(command -v nologin || printf '/usr/sbin/nologin')
            useradd --system --create-home --home-dir "/var/lib/${service_user}" --shell "$nologin_shell" "$service_user"
        elif command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -h "/var/lib/${service_user}" -s /sbin/nologin "$service_user"
            mkdir -p "/var/lib/${service_user}"
            chown "$service_user" "/var/lib/${service_user}"
        else
            log_error "Cannot create the unprivileged komari user: useradd/adduser is unavailable"
            exit 1
        fi
    elif [ "$(id -u "$service_user")" -eq 0 ]; then
        log_error "The existing komari account is privileged; refusing a non-privileged installation"
        exit 1
    elif id -nG "$service_user" | tr ' ' '\n' | grep -Eq '^(sudo|wheel|admin)$'; then
        log_error "The existing komari account belongs to an administrative group; refusing installation"
        exit 1
    elif user_shell=$(getent passwd "$service_user" | cut -d: -f7) && [ "$user_shell" != "/usr/sbin/nologin" ] && [ "$user_shell" != "/sbin/nologin" ] && [ "$user_shell" != "/bin/false" ]; then
        log_error "The existing komari account has a login shell; refusing installation"
        exit 1
    fi
elif [ "$uninstall_only" != true ] && [ "$runtime_identity" = "service-account" ] && [ "$os_name" = "darwin" ]; then
    if ! id -u "$service_user" >/dev/null 2>&1; then
		service_group="_komari"
		if ! dscl . -read "/Groups/${service_group}" >/dev/null 2>&1; then
			service_gid=$(dscl . -list /Groups PrimaryGroupID | awk '$2 >= 200 && $2 < 500 { used[$2] = 1 } END { for (id = 499; id >= 200; id--) if (!used[id]) { print id; exit } }')
			if [ -z "$service_gid" ]; then
				log_error "Cannot allocate a system GID for ${service_group}"
				exit 1
			fi
			dscl . -create "/Groups/${service_group}"
			dscl . -create "/Groups/${service_group}" PrimaryGroupID "$service_gid"
		else
			service_gid=$(dscl . -read "/Groups/${service_group}" PrimaryGroupID | awk '{print $2}')
		fi
        service_uid=$(dscl . -list /Users UniqueID | awk '$2 >= 200 && $2 < 500 { used[$2] = 1 } END { for (id = 499; id >= 200; id--) if (!used[id]) { print id; exit } }')
        if [ -z "$service_uid" ]; then
            log_error "Cannot allocate a system UID for ${service_user}"
            exit 1
        fi
        log_info "Creating the non-login ${service_user} service user..."
        dscl . -create "/Users/${service_user}"
        dscl . -create "/Users/${service_user}" UniqueID "$service_uid"
        dscl . -create "/Users/${service_user}" PrimaryGroupID "$service_gid"
        dscl . -create "/Users/${service_user}" UserShell /usr/bin/false
        dscl . -create "/Users/${service_user}" NFSHomeDirectory /var/empty
        dscl . -create "/Users/${service_user}" IsHidden 1
    elif [ "$(id -u "$service_user")" -eq 0 ]; then
        log_error "The existing ${service_user} account is privileged; refusing installation"
        exit 1
    elif id -nG "$service_user" | tr ' ' '\n' | grep -Eq '^(admin|wheel)$'; then
        log_error "The existing ${service_user} account belongs to an administrative group; refusing installation"
        exit 1
    elif user_shell=$(dscl . -read "/Users/${service_user}" UserShell | awk '{print $2}') && [ "$user_shell" != "/usr/bin/false" ] && [ "$user_shell" != "/usr/sbin/nologin" ]; then
        log_error "The existing ${service_user} account has a login shell; refusing installation"
        exit 1
    fi
fi

# Remote command execution and terminal access run with the Agent process
# identity and therefore require root/administrator privileges. Keep the old
# --disable-web-ssh spelling as an accepted alias, but persist the canonical
# all-remote-control switch for every unprivileged installation.
if [ "$runtime_identity" = "service-account" ]; then
    case " $komari_args " in
        *" --disable-remote-control "*|*" --disable-web-ssh "*) ;;
        *) komari_args="$komari_args --disable-remote-control" ;;
    esac
fi

if [ "$EUID" -ne 0 ] && [ "$runtime_identity" = "root-or-administrator" ]; then
    log_error "root-or-administrator runtime requires running the installer as root"
    exit 1
fi
if [ "$rescue_enabled" = true ]; then
    if [ "$os_name" != "linux" ]; then
        log_error "The privileged rescue helper is currently supported by this installer only on Linux"
        exit 1
    fi
    if [ "$EUID" -ne 0 ]; then
        log_error "The rescue helper must be installed by root even when the ordinary Agent runs as the current user"
        exit 1
    fi
    case " $komari_args " in
        *" --disable-remote-control "*|*" --disable-web-ssh "*) ;;
        *)
            log_error "The rescue helper is available only when normal remote control is disabled"
            exit 1
            ;;
    esac
    if [ -z "$rescue_endpoint" ] || [ -z "$rescue_token" ]; then
        log_error "The rescue helper requires explicit --endpoint and --token Agent arguments"
        exit 1
    fi
fi

# Remove leading space from komari_args if present
komari_args="${komari_args# }"

komari_agent_path="${target_dir}/agent"
runtime_state_path="${target_dir}/runtime-config.json"

echo -e "${WHITE}===========================================${NC}"
echo -e "${WHITE}    Komari Agent Installation Script     ${NC}"
echo -e "${WHITE}===========================================${NC}"
echo ""
log_config "Installation configuration:"
log_config "  Service name: ${GREEN}$service_name${NC}"
log_config "  Service user: ${GREEN}$service_user${NC}"
log_config "  Runtime identity: ${GREEN}$runtime_identity${NC}"
log_config "  Rescue helper: ${GREEN}$rescue_enabled${NC}"
log_config "  Install directory: ${GREEN}$target_dir${NC}"
log_config "  GitHub proxy: ${GREEN}${github_proxy:-"(direct)"}${NC}"
log_config "  Binary arguments: ${GREEN}$komari_args${NC}"
if [ -n "$install_version" ]; then
    log_config "  Specified agent version: ${GREEN}$install_version${NC}"
else
    log_config "  Agent version: ${GREEN}Latest${NC}"
fi
echo ""

# Function to uninstall the previous installation
uninstall_previous() {
    log_step "Checking for previous installation..."
    
    # Stop and disable service if it exists
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "${service_name}.service"; then
        log_info "Stopping and disabling existing systemd service..."
        systemctl stop ${service_name}.service
        systemctl disable ${service_name}.service
        rm -f "/etc/systemd/system/${service_name}.service"
        systemctl daemon-reload
    elif command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${service_name}" ]; then
        log_info "Stopping and disabling existing OpenRC service..."
        rc-service ${service_name} stop
        rc-update del ${service_name} default
        rm -f "/etc/init.d/${service_name}"
    elif command -v uci >/dev/null 2>&1 && [ -f "/etc/init.d/${service_name}" ]; then
        log_info "Stopping and disabling existing procd service..."
        /etc/init.d/${service_name} stop
        /etc/init.d/${service_name} disable
        rm -f "/etc/init.d/${service_name}"
    elif command -v initctl >/dev/null 2>&1 && [ -f "/etc/init/${service_name}.conf" ]; then
        log_info "Stopping and removing existing upstart service..."
        initctl stop ${service_name}
        rm -f "/etc/init/${service_name}.conf"
    elif [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        # macOS launchd service - check both system and user locations
        system_plist="/Library/LaunchDaemons/com.komari.${service_name}.plist"
        user_plist="$HOME/Library/LaunchAgents/com.komari.${service_name}.plist"
        
        if [ -f "$system_plist" ]; then
            log_info "Stopping and removing existing system launchd service..."
            launchctl bootout system "$system_plist" 2>/dev/null || true
            rm -f "$system_plist"
        fi
        
        if [ -f "$user_plist" ]; then
            log_info "Stopping and removing existing user launchd service..."
            launchctl bootout gui/$(id -u) "$user_plist" 2>/dev/null || true
            rm -f "$user_plist"
        fi
    fi
    
    # Remove old binary if it exists
    if [ -f "$komari_agent_path" ]; then
        log_info "Removing old binary..."
        rm -f "$komari_agent_path"
    fi
    rescue_service_name="${service_name}-rescue"
    if [ "$EUID" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "${rescue_service_name}.service"; then
        systemctl disable --now "${rescue_service_name}.service" || true
        rm -f "/etc/systemd/system/${rescue_service_name}.service"
        systemctl daemon-reload
    fi
	rescue_env_dir="/etc/komari-agent"
	# Remove the marker/rule created by older installers. New installations do
	# not install a firewall package or change firewall policy.
	rescue_marker="${rescue_env_dir}/${rescue_service_name}.firewall-managed"
    if [ "$EUID" -eq 0 ] && [ -f "$rescue_marker" ] && command -v ufw >/dev/null 2>&1; then
        ufw --force delete allow out 443/tcp comment 'komari-rescue' || true
    fi
    if [ "$EUID" -eq 0 ]; then
		rm -f "${rescue_env_dir}/${rescue_service_name}.env" "${rescue_env_dir}/${rescue_service_name}.instance" \
			"${rescue_env_dir}/${rescue_service_name}.network-isolation.json" "$rescue_marker"
        rm -f "/usr/local/lib/komari-agent/komari-agent-rescue"
    fi
}

# Uninstall previous installation
uninstall_previous
if [ "$uninstall_only" = true ]; then
    case "$target_dir" in
        /opt/komari|/usr/local/komari|/c/komari|"$HOME/.komari")
            rm -rf -- "$target_dir"
            ;;
        *)
            log_warning "Custom install directory was not removed automatically: $target_dir"
            ;;
    esac
    log_success "Komari Agent uninstalled. The dedicated service account was retained."
    exit 0
fi

install_dependencies() {
    log_step "Checking and installing dependencies..."

    local deps="curl"
    local missing_deps=""
    for cmd in $deps; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps="$missing_deps $cmd"
        fi
    done

    if [ -n "$missing_deps" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "Missing required dependencies:$missing_deps"
            log_info "Install them with your system package manager, then run this script again."
            exit 1
        fi
        # Check package manager and install dependencies
        if command -v apt >/dev/null 2>&1; then
            log_info "Using apt to install dependencies..."
            apt update
            apt install -y $missing_deps
        elif command -v yum >/dev/null 2>&1; then
            log_info "Using yum to install dependencies..."
            yum install -y $missing_deps
        elif command -v apk >/dev/null 2>&1; then
            log_info "Using apk to install dependencies..."
            apk add $missing_deps
        elif command -v brew >/dev/null 2>&1; then
            log_info "Using Homebrew to install dependencies..."
            brew install $missing_deps
        else
            log_error "No supported package manager found (apt/yum/apk/brew)"
            exit 1
        fi
        
        # Verify installation
        for cmd in $missing_deps; do
            if ! command -v $cmd >/dev/null 2>&1; then
                log_error "Failed to install $cmd"
                exit 1
            fi
        done
        log_success "Dependencies installed successfully"
    else
        log_success "Dependencies already satisfied"
    fi
}

 
# Install dependencies
install_dependencies

 

# Architecture detection with platform-specific support
arch=$(uname -m)
case $arch in
    x86_64)
        arch="amd64"
        ;;
    aarch64|arm64)
        arch="arm64"
        ;;
    loongarch64|loong64)
        arch="loong64"
        ;;
    i386|i686)
        # x86 (32-bit) support
        case $os_name in
            freebsd|linux|windows)
                arch="386"
                ;;
            *)
                log_error "32-bit x86 architecture not supported on $os_name"
                exit 1
                ;;
        esac
        ;;
    armv7*|armv6*)
        # ARM 32-bit support
        case $os_name in
            freebsd|linux)
                arch="arm"
                ;;
            *)
                log_error "32-bit ARM architecture not supported on $os_name"
                exit 1
                ;;
        esac
        ;;
    *)
        log_error "Unsupported architecture: $arch on $os_name"
        exit 1
        ;;
esac
log_info "Detected OS: ${GREEN}$os_name${NC}, Architecture: ${GREEN}$arch${NC}"

version_to_install="latest"
if [ -n "$install_version" ]; then
    log_info "Attempting to install specified version: ${GREEN}$install_version${NC}"
    version_to_install="$install_version"
else
    log_info "No version specified, installing the latest version."
fi

# Construct download URL
file_name="komari-agent-${os_name}-${arch}"
if [ "$version_to_install" = "latest" ]; then
    download_path="latest/download"
else
    download_path="download/${version_to_install}"
fi

if [ -n "$github_proxy" ]; then
    # Use proxy for GitHub releases
    download_url="${github_proxy}/https://github.com/${release_repository}/releases/${download_path}/${file_name}"
else
    # Direct access to GitHub releases
    download_url="https://github.com/${release_repository}/releases/${download_path}/${file_name}"
fi

log_step "Creating installation directory: ${GREEN}$target_dir${NC}"
mkdir -p "$target_dir"
if [ "$EUID" -eq 0 ] && [ "$service_user" != "root" ]; then
    chown -R "$service_user" "$target_dir"
fi

# Download binary
if [ -n "$github_proxy" ]; then
    log_step "Downloading $file_name via proxy..."
    log_info "URL: ${CYAN}$download_url${NC}"
else
    log_step "Downloading $file_name directly..."
    log_info "URL: ${CYAN}$download_url${NC}"
fi
if ! curl -L -o "$komari_agent_path" "$download_url"; then
    log_error "Download failed"
    exit 1
fi

# Set executable permissions
chmod +x "$komari_agent_path"
if [ "$EUID" -eq 0 ] && [ "$service_user" != "root" ]; then
    chown "$service_user" "$komari_agent_path"
fi
log_success "Komari-agent installed to ${GREEN}$komari_agent_path${NC}"

# Keep the online-dispatch snapshot alongside this installation so the
# separately privileged helper can roll it back without reading a user home.
case " $komari_args " in
    *" --runtime-state-file "*) ;;
    *) komari_args="$komari_args --runtime-state-file ${runtime_state_path}" ;;
esac

# Detect init system and configure service
log_step "Configuring system service..."

# Function to detect actual init system
detect_init_system() {
    # Check if running on NixOS (special case)
    if [ -f /etc/NIXOS ]; then
        echo "nixos"
        return
    fi
    
    # Alpine Linux MUST be checked first
    # Alpine always uses OpenRC, even in containers where PID 1 might be different
    if [ -f /etc/alpine-release ]; then
        if command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
            echo "openrc"
            return
        fi
    fi
    
    # Get PID 1 process for other detection
    local pid1_process=$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')
    
    # If PID 1 is systemd, use systemd
    if [ "$pid1_process" = "systemd" ] || [ -d /run/systemd/system ]; then
        if command -v systemctl >/dev/null 2>&1; then
            # Additional verification that systemd is actually functioning
            if systemctl list-units >/dev/null 2>&1; then
                echo "systemd"
                return
            fi
        fi
    fi
    
    # Check for Gentoo OpenRC (PID 1 is openrc-init)
    if [ "$pid1_process" = "openrc-init" ]; then
        if command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
    fi
    
    # Check for other OpenRC systems (not Alpine, already handled)
    # Some systems use traditional init with OpenRC
    if [ "$pid1_process" = "init" ] && [ ! -f /etc/alpine-release ]; then
        # Check if OpenRC is actually managing services
        if [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
        # Check for OpenRC files
        if [ -f /sbin/openrc ] && command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
    fi
    
    # Check for OpenWrt's procd
    if command -v uci >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
        echo "procd"
        return
    fi
    
    # Check for macOS launchd
    if [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        echo "launchd"
        return
    fi
    
    # Fallback: if systemctl exists and appears functional, assume systemd
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-units >/dev/null 2>&1; then
            echo "systemd"
            return
        fi
    fi
    
    # Last resort: check for OpenRC without other indicators
    if command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
        echo "openrc"
        return
    fi

    # check for Upstart (CentOS 6)
    if command -v initctl >/dev/null 2>&1 && [ -d /etc/init ]; then
        echo "upstart"
        return
    fi
    
    echo "unknown"
}

init_system=$(detect_init_system)
log_info "Detected init system: ${GREEN}$init_system${NC}"
if [ "$rescue_enabled" = true ] && [ "$init_system" != "systemd" ]; then
    log_error "The rescue helper requires Linux systemd to keep its privileged guardian separate from the ordinary Agent service"
    exit 1
fi

# Handle each init system
if [ "$init_system" = "nixos" ]; then
    log_warning "NixOS detected. System services must be configured declaratively."
    log_info "Please add the following to your NixOS configuration:"
    echo ""
    echo -e "${CYAN}systemd.services.${service_name} = {${NC}"
    echo -e "${CYAN}  description = \"Komari Agent Service\";${NC}"
    echo -e "${CYAN}  after = [ \"network.target\" ];${NC}"
    echo -e "${CYAN}  wantedBy = [ \"multi-user.target\" ];${NC}"
    echo -e "${CYAN}  serviceConfig = {${NC}"
    echo -e "${CYAN}    Type = \"simple\";${NC}"
    echo -e "${CYAN}    ExecStart = \"${komari_agent_path} ${komari_args}\";${NC}"
    echo -e "${CYAN}    WorkingDirectory = \"${target_dir}\";${NC}"
    echo -e "${CYAN}    Restart = \"always\";${NC}"
    echo -e "${CYAN}    User = \"${service_user}\";${NC}"
    echo -e "${CYAN}    AmbientCapabilities = [ \"CAP_NET_RAW\" ];${NC}"
    echo -e "${CYAN}    CapabilityBoundingSet = [ \"CAP_NET_RAW\" ];${NC}"
    echo -e "${CYAN}  };${NC}"
    echo -e "${CYAN}};${NC}"
    echo ""
    log_info "Then run: sudo nixos-rebuild switch"
    log_warning "Service not started automatically on NixOS. Please rebuild your configuration."
elif [ "$init_system" = "openrc" ]; then
    # OpenRC service configuration
    log_info "Using OpenRC for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/sbin/openrc-run

name="Komari Agent Service"
description="Komari monitoring agent"
command="${komari_agent_path}"
command_args="${komari_args}"
command_user="${service_user}"
directory="${target_dir}"
pidfile="/run/${service_name}.pid"
retry="SIGTERM/30"
supervisor=supervise-daemon

depend() {
    need net
    after network
}
EOF

    # Set permissions and enable service
    chmod +x "$service_file"
    rc-update add ${service_name} default
    rc-service ${service_name} start
    log_success "OpenRC service configured and started"
elif [ "$init_system" = "systemd" ]; then
    # Systemd service configuration
    log_info "Using systemd for service management"
    service_file="/etc/systemd/system/${service_name}.service"
    cat > "$service_file" << EOF
[Unit]
Description=Komari Agent Service
After=network.target

[Service]
Type=simple
ExecStart=${komari_agent_path} ${komari_args}
WorkingDirectory=${target_dir}
Restart=always
User=${service_user}
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and start service
    systemctl daemon-reload
    systemctl enable ${service_name}.service
    systemctl start ${service_name}.service
    log_success "Systemd service configured and started"
elif [ "$init_system" = "procd" ]; then
    # procd service configuration (OpenWrt)
    log_info "Using procd for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

PROG="${komari_agent_path}"
ARGS="${komari_args}"

start_service() {
    procd_open_instance
    procd_set_param command \$PROG \$ARGS
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param user ${service_user}
    procd_close_instance
}

stop_service() {
    killall \$(basename \$PROG)
}

reload_service() {
    stop
    start
}
EOF

    # Set permissions and enable service
    chmod +x "$service_file"
    /etc/init.d/${service_name} enable
    /etc/init.d/${service_name} start
    log_success "procd service configured and started"
elif [ "$init_system" = "launchd" ]; then
    # macOS launchd service configuration
    log_info "Using launchd for service management"
    
    plist_dir="/Library/LaunchDaemons"
    plist_file="$plist_dir/com.komari.${service_name}.plist"
    log_info "Installing as system-level service (LaunchDaemon)"
    log_dir="/var/log"
    
    # Create the launchd plist file
    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.komari.${service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${komari_agent_path}</string>
EOF
    
    # Add program arguments if provided
    if [ -n "$komari_args" ]; then
        echo "$komari_args" | xargs -n1 printf "        <string>%s</string>\n" >> "$plist_file"
    fi
    
    cat >> "$plist_file" << EOF
    </array>
    <key>WorkingDirectory</key>
    <string>${target_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>${service_user}</string>
    <key>StandardOutPath</key>
    <string>${log_dir}/${service_name}.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/${service_name}.log</string>
</dict>
</plist>
EOF
    
    # Load and start the service
    if launchctl bootstrap system "$plist_file"; then
        log_success "System launchd service configured and started as ${service_user}"
    else
        log_error "Failed to load system-level launchd service"
        exit 1
    fi
elif [ "$init_system" = "upstart" ]; then
    # Upstart service configuration
    log_info "Using upstart for service management"
    service_file="/etc/init/${service_name}.conf"
    cat > "$service_file" << EOF
# KOMARI Agent
description "Komari Agent Service"

chdir ${target_dir}
start on filesystem or runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5
umask 022

console none

setuid ${service_user}

pre-start script
    test -x ${komari_agent_path} || { stop; exit 0; }
end script

# Start
script
    exec ${komari_agent_path} ${komari_args}
end script
EOF
    # enable Upstart unit
    initctl reload-configuration
    initctl start ${service_name}
    log_success "Upstart service configured and started"
else
    log_error "Unsupported or unknown init system detected: $init_system"
    log_error "Supported init systems: systemd, openrc, procd, launchd"
    exit 1
fi

install_rescue_helper() {
    [ "$rescue_enabled" = true ] || return 0
    rescue_dir="/usr/local/lib/komari-agent"
    rescue_path="${rescue_dir}/komari-agent-rescue"
    rescue_service_name="${service_name}-rescue"
    rescue_env_dir="/etc/komari-agent"
    rescue_env_file="${rescue_env_dir}/${rescue_service_name}.env"
    rescue_marker="${rescue_env_dir}/${rescue_service_name}.firewall-managed"
	if [ "$EUID" -eq 0 ] && command -v nft >/dev/null 2>&1 && nft list table inet komari_rescue >/dev/null 2>&1; then
		if ! nft delete table inet komari_rescue; then
			log_error "Failed to remove active Komari network isolation; restore it before reinstalling or uninstalling"
			exit 1
		fi
	fi
    rescue_file="komari-agent-rescue-linux-${arch}"
    if [ "$version_to_install" = "latest" ]; then
        rescue_download_path="latest/download"
    else
        rescue_download_path="download/${version_to_install}"
    fi
    if [ -n "$github_proxy" ]; then
        rescue_download_url="${github_proxy}/https://github.com/${release_repository}/releases/${rescue_download_path}/${rescue_file}"
    else
        rescue_download_url="https://github.com/${release_repository}/releases/${rescue_download_path}/${rescue_file}"
    fi
    case "${rescue_endpoint}${rescue_token}${cf_access_client_id}${cf_access_client_secret}" in
    *$'\n'*|*$'\r'*)
        log_error "Rescue endpoint or credentials contain unsupported control characters"
        exit 1
        ;;
    esac
    mkdir -p "$rescue_dir" "$rescue_env_dir"
    chmod 700 "$rescue_dir" "$rescue_env_dir"
    log_step "Downloading separately privileged rescue helper..."
    if ! curl -L -o "$rescue_path" "$rescue_download_url"; then
        log_error "Failed to download rescue helper"
        exit 1
    fi
    chmod 700 "$rescue_path"
    systemd_env_value() {
        local value="$1"
        value="${value//\\/\\\\}"
        value="${value//\"/\\\"}"
        printf '"%s"' "$value"
    }
    {
		printf 'KOMARI_RESCUE_ENDPOINT=%s\n' "$(systemd_env_value "$rescue_endpoint")"
		printf 'KOMARI_RESCUE_TOKEN=%s\n' "$(systemd_env_value "$rescue_token")"
		if [ -n "$cf_access_client_id" ]; then
			printf 'KOMARI_RESCUE_CF_ACCESS_CLIENT_ID=%s\n' "$(systemd_env_value "$cf_access_client_id")"
			printf 'KOMARI_RESCUE_CF_ACCESS_CLIENT_SECRET=%s\n' "$(systemd_env_value "$cf_access_client_secret")"
		fi
		printf 'KOMARI_RESCUE_AGENT_PATH=%s\n' "$(systemd_env_value "$komari_agent_path")"
		printf 'KOMARI_RESCUE_RUNTIME_STATE_FILE=%s\n' "$(systemd_env_value "$runtime_state_path")"
		printf 'KOMARI_RESCUE_AGENT_SERVICE_NAME=%s\n' "$(systemd_env_value "$service_name")"
		printf 'KOMARI_RESCUE_AGENT_RUNTIME_IDENTITY=%s\n' "$(systemd_env_value "$runtime_identity")"
		printf 'KOMARI_RESCUE_AGENT_RUNTIME_USER=%s\n' "$(systemd_env_value "$service_user")"
		printf 'KOMARI_RESCUE_INSTANCE_ID_FILE=%s\n' "$(systemd_env_value "${rescue_env_dir}/${rescue_service_name}.instance")"
		printf 'KOMARI_RESCUE_CONTROL_PLANE_URL=%s\n' "$(systemd_env_value "$rescue_endpoint")"
		printf 'KOMARI_RESCUE_ISOLATION_STATE_FILE=%s\n' "$(systemd_env_value "${rescue_env_dir}/${rescue_service_name}.network-isolation.json")"
        if [ "$ignore_unsafe_cert" = true ]; then
            printf 'KOMARI_RESCUE_IGNORE_UNSAFE_CERT=true\n'
        fi
    } > "$rescue_env_file"
    chmod 600 "$rescue_env_file"
    cat > "/etc/systemd/system/${rescue_service_name}.service" << EOF
[Unit]
Description=Komari Rescue Helper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${rescue_env_file}
ExecStart=${rescue_path}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${target_dir} ${rescue_env_dir}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${rescue_service_name}.service"
    log_success "Privileged rescue helper installed separately as ${rescue_service_name}.service"
}

install_rescue_helper

echo ""
echo -e "${WHITE}===========================================${NC}"
if [ -f /etc/NIXOS ]; then
    log_success "Komari-agent binary installed!"
    log_warning "NixOS requires declarative service configuration."
    log_info "Please add the service configuration to your NixOS config and rebuild."
else
    log_success "Komari-agent installation completed!"
fi
log_config "Service: ${GREEN}$service_name${NC}"
log_config "Arguments: ${GREEN}$komari_args${NC}"
echo -e "${WHITE}===========================================${NC}"

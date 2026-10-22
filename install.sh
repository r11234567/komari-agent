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
target_dir="/usr/lib/komari/komari-agent"
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
install_dir_explicit=false
runtime_identity_explicit=false
register_only=false
metrics_only=false
panel_key_id=""
panel_public_key=""
host_service_user=""
host_access_config=""
 

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
komari_argv=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir|--install-service-name|--install-ghproxy|--install-version|--install-runtime-identity|-e|--endpoint|-t|--token|--auto-discovery|--cf-access-client-id|--cf-access-client-secret|--runtime-state-file|--credentials-file|--privileged-state-file|--replay-state-file)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then log_error "Missing value for $1"; exit 64; fi ;;
    esac
    case $1 in
        --interval|--interval=*|-i|-i[0-9]*|--memory-include-cache|--memory-include-cache=*|--include-nics|--include-nics=*|--exclude-nics|--exclude-nics=*|--include-mountpoint|--include-mountpoint=*|--month-rotate|--month-rotate=*|--get-ip-addr-from-nic|--get-ip-addr-from-nic=*|--enable-gpu|--enable-gpu=*|--gpu|--gpu=*|--detailed-gpu|--detailed-gpu=*|--max-retries|--max-retries=*|-r|-r[0-9]*|--disable-compression|--disable-compression=*)
            log_error "Removed agent option: $1; use panel configuration or administrator migration"
            exit 64
            ;;
        --install-dir)
            target_dir="$2"
            install_dir_explicit=true
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
            runtime_identity_explicit=true
            shift 2
            ;;
        --install-register-only)
            register_only=true
            shift
            ;;
        --install-metrics-only)
            metrics_only=true
            shift
            ;;
        --install-panel-key-id|--install-panel-public-key|--install-host-service-user|--install-host-access-config)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then log_error "Missing value for $1"; exit 64; fi
            case "$1" in
                --install-panel-key-id) panel_key_id="$2" ;;
                --install-panel-public-key) panel_public_key="$2" ;;
                --install-host-service-user) host_service_user="$2" ;;
                --install-host-access-config) host_access_config="$2" ;;
            esac
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
        --endpoint=*)
            rescue_endpoint="${1#*=}"
            komari_argv+=(--endpoint "$rescue_endpoint")
            komari_args="$komari_args --endpoint $rescue_endpoint"
            shift
            ;;
        -e|--endpoint)
            rescue_endpoint="$2"
            komari_argv+=("$1" "$2")
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        -t|--token)
            rescue_token="$2"
            komari_argv+=("$1" "$2")
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        --auto-discovery)
            auto_discovery_key="$2"
            komari_argv+=("$1" "$2")
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        --cf-access-client-id)
            cf_access_client_id="$2"
            komari_argv+=("$1" "$2")
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        --cf-access-client-secret)
            cf_access_client_secret="$2"
            komari_argv+=("$1" "$2")
            komari_args="$komari_args $1 $2"
            shift 2
            ;;
        -u|--ignore-unsafe-cert)
            ignore_unsafe_cert=true
            komari_argv+=("$1")
            komari_args="$komari_args $1"
            shift
            ;;
        --runtime-state-file|--credentials-file|--privileged-state-file|--replay-state-file)
            case "$1" in
                --runtime-state-file) runtime_state_override="$2" ;;
                --credentials-file) credentials_override="$2" ;;
                --privileged-state-file) privileged_state_override="$2" ;;
                --replay-state-file) replay_state_override="$2" ;;
            esac
            shift 2
            ;;
        --runtime-state-file=*|--credentials-file=*|--privileged-state-file=*|--replay-state-file=*)
            case "${1%%=*}" in
                --runtime-state-file) runtime_state_override="${1#*=}" ;;
                --credentials-file) credentials_override="${1#*=}" ;;
                --privileged-state-file) privileged_state_override="${1#*=}" ;;
                --replay-state-file) replay_state_override="${1#*=}" ;;
            esac
            shift
            ;;
        --install*)
            log_error "Unknown install parameter: $1"
            exit 64
            ;;
        *)
            # Non-install arguments go to komari_args
            komari_argv+=("$1")
            komari_args="$komari_args $1"
            shift
            ;;
    esac
done

if { [ -n "$cf_access_client_id" ] && [ -z "$cf_access_client_secret" ]; } || { [ -z "$cf_access_client_id" ] && [ -n "$cf_access_client_secret" ]; }; then
    log_error "--cf-access-client-id and --cf-access-client-secret must be provided together"
    exit 1
fi

# Detect before account creation: updates preserve the actual installed identity.
install_mode=fresh
installed_manifest="/etc/komari/services/$service_name.json"
if [ "$uninstall_only" != true ] && [ "$os_name" = linux ]; then
    if [[ ! "$service_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || [[ "$service_name" = *.service ]]; then
        log_error "Invalid service name"; exit 64
    fi
    if [ -e "$installed_manifest" ] || [ -L "$installed_manifest" ]; then
        install_mode=update
    elif systemctl cat "${service_name}.service" >/dev/null 2>&1; then
        install_mode=migrate
    fi
    if [ "$install_mode" != fresh ] && [ "$runtime_identity_explicit" = true ]; then
        log_error "An update preserves service identity; change it through an approved host action"; exit 64
    fi
    if [ "$install_dir_explicit" = false ]; then target_dir="/usr/lib/komari/$service_name"; fi
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
if [ "$uninstall_only" != true ] && [ "$install_mode" = fresh ] && [ "$runtime_identity" = "service-account" ] && [ "$os_name" = "linux" ]; then
    create_linux_service_account() {
    if ! id -u "$service_user" >/dev/null 2>&1; then
        log_info "Creating the unprivileged ${service_user} service user..."
        if command -v useradd >/dev/null 2>&1; then
            nologin_shell=$(command -v nologin || printf '/usr/sbin/nologin')
            useradd --system --no-create-home --home-dir /nonexistent --shell "$nologin_shell" "$service_user" || exit 1
        elif command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -h /nonexistent -s /sbin/nologin "$service_user" || exit 1
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
    }
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

# Installation, identity-preserving migration and binary updates use the same
# reviewed host tool. Re-running this script never uninstalls an existing node.
if [ "$uninstall_only" != true ]; then
    if [ "$os_name" != linux ] || [ ! -d /run/systemd/system ]; then
        log_error "Trusted v2 installation currently supports Linux systemd only"
        exit 1
    fi
    if [ "$EUID" -ne 0 ]; then
        log_error "Run this installer as root"
        exit 1
    fi
    if [ "$rescue_enabled" = true ] && { [ "$register_only" = true ] || [ "$metrics_only" = true ]; }; then
        log_error "--install-rescue requires enrollment and full host preparation"; exit 64
    fi
    if [ -n "$runtime_state_override$credentials_override$privileged_state_override$replay_state_override" ]; then
        log_error "Custom state paths require an explicit reviewed host migration"
        exit 1
    fi
    [[ "$target_dir" = /* ]] || target_dir="$PWD/$target_dir"
    ensure_root_dir() {
        local path="$1" owner mode
        if [ -L "$path" ]; then log_error "Symlink in trusted path: $path"; exit 1; fi
        if [ ! -d "$path" ]; then
            ensure_root_dir "$(dirname "$path")"
            mkdir -m 755 "$path" || exit 1
        fi
        owner=$(stat -c '%u' "$path") || exit 1
        mode=$(stat -c '%a' "$path") || exit 1
        if [ "$owner" != 0 ] || (( (8#$mode & 0022) != 0 )); then
            log_error "Untrusted owner or permissions at $path"; exit 1
        fi
        [ "$path" = / ] || ensure_root_dir "$(dirname "$path")"
    }
    ensure_root_file() {
        local path="$1" owner mode
        ensure_root_dir "$(dirname "$path")"
        if [ -L "$path" ] || [ ! -f "$path" ]; then
            log_error "Trusted regular file required: $path"; exit 1
        fi
        owner=$(stat -c '%u' "$path") || exit 1
        mode=$(stat -c '%a' "$path") || exit 1
        if [ "$owner" != 0 ] || (( (8#$mode & 0022) != 0 )); then
            log_error "Untrusted owner or permissions at $path"; exit 1
        fi
    }
    prepare_service_directories() {
        local binary_dir="$1" path
        # Host's mkdir(0755) inherits our private umask(077). Prepare the
        # public program/registry directories explicitly, including repair of
        # mode-0700 directories left by earlier installs or migrations. Never
        # recurse into credentials, state, bootstrap files or host journals.
        ensure_root_dir "$binary_dir"
        for path in /etc/komari /etc/komari/services; do
            ensure_root_dir "$path"
            chmod 755 "$path" || exit 1
        done
        if [ "$binary_dir" = "/usr/lib/komari/$service_name" ]; then
            chmod 755 /usr/lib/komari || exit 1
        fi
        chmod 755 "$binary_dir" || exit 1
    }
    prepare_state_parent() {
        local path=/var/lib/komari owner mode legacy_uid legacy_home
        ensure_root_dir /var/lib
        if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
            log_error "State parent must be a real directory: $path"; exit 1
        fi
        if [ -d "$path" ]; then
            owner=$(stat -c '%u' "$path") || exit 1
            mode=$(stat -c '%a' "$path") || exit 1
            if [ "$owner" != 0 ]; then
                legacy_uid=$(id -u komari 2>/dev/null) || { log_error "Unknown state parent owner"; exit 1; }
                legacy_home=$(getent passwd komari | cut -d: -f6) || exit 1
                if [ "$owner" != "$legacy_uid" ] || [ "$legacy_home" != "$path" ] || (( (8#$mode & 0022) != 0 )); then
                    log_error "Refusing to adopt an unknown or writable state parent: $path"; exit 1
                fi
                # /var/lib is already trusted, so the account cannot rename this
                # entry. Remove its ownership before chmod; never recurse into
                # state or credentials, follow a link, or reset node identity.
                chown --no-dereference root:root "$path" || exit 1
                chmod 755 "$path" || exit 1
                log_info "Repaired the legacy service-home/state-parent collision; existing contents retained."
            fi
        fi
        ensure_root_dir "$path"
        chmod 755 "$path" || exit 1
    }
    # Ubuntu may grant syslog group write access to /var/log. Keep recovery
    # binaries and private diagnostics under the protected host state tree.
    ensure_root_dir /var/lib/komari-host/installer-logs
    log_directory=$(mktemp -d /var/lib/komari-host/installer-logs/run.XXXXXXXX) || exit 1
    chmod 700 "$log_directory" || exit 1
    install_log="$log_directory/install.log"
    (umask 077; touch "$install_log") || exit 1
    exec > >(tee -a "$install_log") 2>&1
    installer_cleanup() {
        local status=$?
        trap - EXIT
        set +e
        if [ "$status" -ne 0 ] && [ "${update_started:-false}" = true ]; then
            log_error "Update did not complete; restoring the previous Agent and Host binaries."
            rollback_ok=true
            [ -z "${host_stage:-}" ] || rm -f -- "$host_stage"
            if [ -n "${agent_rollback:-}" ] && [ -f "$agent_rollback" ]; then
                rollback_stage=$(mktemp "$(dirname "$agent_path")/.komari-agent-rollback.XXXXXXXX") || {
                    rollback_ok=false
                    log_error "Could not stage the previous Agent binary."
                    rollback_stage=""
                }
                if [ -n "$rollback_stage" ]; then
                    if install -m 755 "$agent_rollback" "$rollback_stage" && mv -fT -- "$rollback_stage" "$agent_path"; then
                        log_info "Restored previous Agent binary."
                    else
                        rm -f -- "$rollback_stage"
                        rollback_ok=false
                        log_error "Could not restore the previous Agent binary."
                    fi
                fi
            else
                rollback_ok=false
                log_error "Previous Agent binary backup is missing."
            fi
            if [ -n "${host_rollback:-}" ] && [ -f "$host_rollback" ]; then
                rollback_stage=$(mktemp "$(dirname "$host_path")/.komari-host-rollback.XXXXXXXX") || {
                    rollback_ok=false
                    log_error "Could not stage the previous Host binary."
                    rollback_stage=""
                }
                if [ -n "$rollback_stage" ]; then
                    if install -m 755 "$host_rollback" "$rollback_stage" && mv -fT -- "$rollback_stage" "$host_path"; then
                        log_info "Restored previous Host binary."
                    else
                        rm -f -- "$rollback_stage"
                        rollback_ok=false
                        log_error "Could not restore the previous Host binary."
                    fi
                fi
            else
                rollback_ok=false
                log_error "Previous Host binary backup is missing."
            fi
            if [ "${service_was_active:-false}" = true ]; then
                systemctl reset-failed "${service_name}.service" >/dev/null 2>&1
                if systemctl restart "${service_name}.service" && systemctl is-active --quiet "${service_name}.service"; then
                    log_info "Restarted the service with the previous binaries."
                else
                    rollback_ok=false
                    log_error "Service did not recover after binary rollback; inspect the retained journal."
                fi
            fi
            if [ "$rollback_ok" = true ]; then log_info "Binary rollback completed."; else log_error "Binary rollback was incomplete; manual recovery is required."; fi
        fi
        if [ "$status" -ne 0 ]; then
            systemctl show "${service_name}.service" --property=ActiveState,SubState,Result,NRestarts > "$log_directory/service-status.log" 2>&1 || true
            journalctl -u "${service_name}.service" -n 120 --no-pager > "$log_directory/service-journal.log" 2>&1 || true
            log_error "Installation failed (exit $status). Logs: $log_directory"
        else
            log_info "Installation log: $install_log"
        fi
        printf '%s\n' "$status" > "$log_directory/exit-code.txt"
        [ -z "${staging:-}" ] || rm -rf -- "$staging"
        exit "$status"
    }
    trap installer_cleanup EXIT
    trap 'log_error "Installer failed at line $LINENO"' ERR
    set -Ee -o pipefail
    umask 077
    log_info "Service: $service_name; operation: $install_mode"
    # Install every missing dependency in one package-manager transaction,
    # before account creation, downloads or replacement of installed binaries.
    missing_packages=()
    require_command() { command -v "$1" >/dev/null 2>&1 || missing_packages+=("$2"); }
    require_command python3 python3
    require_command curl curl
    require_command flock util-linux
    require_command runuser util-linux
    require_command useradd passwd
    if [ "$metrics_only" != true ]; then
        [ -x /usr/bin/pamtester ] || missing_packages+=(pamtester)
    fi
    has_system_ca_bundle() {
        [ -s /etc/ssl/certs/ca-certificates.crt ] ||
            [ -s /etc/pki/tls/certs/ca-bundle.crt ] ||
            [ -s /etc/ssl/ca-bundle.pem ]
    }
    has_system_ca_bundle || missing_packages+=(ca-certificates)
    if [ "${#missing_packages[@]}" -gt 0 ]; then
        mapfile -t missing_packages < <(printf '%s\n' "${missing_packages[@]}" | sort -u)
        log_info "Installing host prerequisites in one package-manager transaction: ${missing_packages[*]}"
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update
            apt-get install -y --no-install-recommends "${missing_packages[@]}"
        elif command -v dnf >/dev/null 2>&1; then
            for i in "${!missing_packages[@]}"; do
                case "${missing_packages[$i]}" in
                    passwd) missing_packages[$i]=shadow-utils ;;
                esac
            done
            dnf install -y "${missing_packages[@]}"
        elif command -v yum >/dev/null 2>&1; then
            for i in "${!missing_packages[@]}"; do
                case "${missing_packages[$i]}" in
                    passwd) missing_packages[$i]=shadow-utils ;;
                esac
            done
            yum install -y "${missing_packages[@]}"
        elif command -v pacman >/dev/null 2>&1; then
            for i in "${!missing_packages[@]}"; do
                case "${missing_packages[$i]}" in passwd) missing_packages[$i]=shadow ;; esac
            done
            pacman -S --noconfirm --needed "${missing_packages[@]}"
        else
            log_error "Install these dependencies with your distribution package manager, then retry: ${missing_packages[*]}"; exit 1
        fi
    fi
    for required_command in python3 curl flock runuser useradd; do
        command -v "$required_command" >/dev/null 2>&1 || { log_error "Required command remains unavailable after dependency installation: $required_command"; exit 1; }
    done
    if [ "$metrics_only" != true ] && [ ! -x /usr/bin/pamtester ]; then
        log_error "pamtester is still unavailable at /usr/bin/pamtester after dependency installation"; exit 1
    fi
    has_system_ca_bundle || { log_error "No usable system CA bundle found after dependency installation"; exit 1; }
    # Serialize installer invocations; host commands retain their own independent lock.
    # /run/lock is normally shared and writable. Do not chmod it or require
    # exclusive root ownership of the distribution's shared lock directory.
    ensure_root_dir /run/komari-installer
    installer_lock=/run/komari-installer/installer.lock
    if [ -e "$installer_lock" ] || [ -L "$installer_lock" ]; then ensure_root_file "$installer_lock"; fi
    exec 9>"$installer_lock"
    flock -n 9 || { log_error "Another installer is running"; exit 1; }
    if [ "$install_mode" = fresh ] && [ "$runtime_identity" = service-account ]; then create_linux_service_account; fi
    if [ "$install_mode" = fresh ]; then
        prepare_state_parent
        if [ -e "/var/lib/komari/$service_name" ] || [ -L "/var/lib/komari/$service_name" ]; then
            log_error "Existing node state has no service registration: /var/lib/komari/$service_name. Preserve it and recover its registration before reinstalling."
            exit 1
        fi
        ensure_root_dir "$target_dir"
    fi
    if [ "$install_mode" != fresh ]; then
        for arg in "${komari_argv[@]}"; do
            case "$arg" in
                --endpoint|-e|"$rescue_endpoint") ;;
                *) log_error "Existing node configuration is preserved. Change local flags in the installed config, not update arguments."; exit 64 ;;
            esac
        done
    fi
    service_was_active=false
    if systemctl is-active --quiet "${service_name}.service"; then service_was_active=true; fi
    case "$(uname -m)" in
        x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; i?86) arch=386 ;;
        armv7*|armv6*) arch=arm ;; loongarch64) arch=loong64 ;;
        *) log_error "Unsupported architecture"; exit 1 ;;
    esac
    release_base="https://github.com/${release_repository}/releases"
    [ -z "$github_proxy" ] || release_base="${github_proxy%/}/${release_base}"
    if [ -n "$install_version" ]; then
        release_path="download/${install_version}"
    else
        # Resolve latest exactly once so agent and host cannot come from two
        # releases if a publication happens between downloads.
        latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "${release_base}/latest") || exit 1
        install_version="${latest_url##*/}"
        release_path="download/${install_version}"
    fi
    ensure_root_dir /var/cache/komari-installer
    staging=$(mktemp -d /var/cache/komari-installer/download.XXXXXXXX) || exit 1
    agent_digest=""
    for component in komari-agent komari-host; do
        asset="${component}-linux-${arch}"
        binary_path="${staging}/${component}"
        checksum=$(curl -fsSL "${release_base}/${release_path}/${asset}.sha256") || exit 1
        expected="${checksum%% *}"
        [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || { log_error "Invalid release checksum"; exit 1; }
        (umask 077; curl -fsSL -o "$binary_path" "${release_base}/${release_path}/${asset}") || exit 1
        actual=$(sha256sum "$binary_path") || exit 1
        [ "${actual%% *}" = "$expected" ] || { log_error "Checksum mismatch for $asset"; exit 1; }
        chmod 755 "$binary_path" || exit 1
        [ "$component" != komari-agent ] || agent_digest="$expected"
    done
    case "$install_mode" in
        fresh)
            prepare_service_directories "$target_dir"
            # Failed attempts may have left trusted binaries but no node. Both
            # downloads are complete and verified before either is published.
            for component in komari-agent komari-host; do
                destination="${target_dir}/${component}"
                if [ -e "$destination" ] || [ -L "$destination" ]; then ensure_root_file "$destination"; fi
            done
            for component in komari-agent komari-host; do
                destination="${target_dir}/${component}"
                mv -fT -- "$staging/$component" "$destination" || exit 1
            done
            "${target_dir}/komari-host" install --service "$service_name" --user "$service_user" --binary-dir "$target_dir" -- "${komari_argv[@]}" || exit 1
            agent_path="${target_dir}/komari-agent"
            host_path="${target_dir}/komari-host"
            ;;
        migrate)
            log_info "Migrating the existing service; preserving node files, service identity and local remote-control restrictions."
            "$staging/komari-host" migrate --service "$service_name" --legacy-disable preserve > "$log_directory/migration-preview.json" || exit 1
            prepare_service_directories "/usr/lib/komari/$service_name"
            "$staging/komari-host" migrate --service "$service_name" --legacy-disable preserve --agent-artifact "$staging/komari-agent" --sha256 "$agent_digest" --commit || exit 1
            agent_path="/usr/lib/komari/$service_name/komari-agent"
            host_path="/usr/lib/komari/$service_name/komari-host"
            ;;
        update)
            ensure_root_file "$installed_manifest"
            python3 - "$installed_manifest" "$service_name" > "$staging/installed-paths" <<'INSTALLED_PATHS'
import json, os, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
if m.get('version') != 2 or m.get('service_name') != sys.argv[2]:
    raise SystemExit('Installed manifest version or service does not match')
for field in ('executable', 'host_tool'):
    path = m.get(field)
    if not isinstance(path, str) or not os.path.isabs(path) or any(c in path for c in '\x00\r\n'):
        raise SystemExit('Invalid installed binary path')
    sys.stdout.write(path + '\n')
INSTALLED_PATHS
            [ "$?" -eq 0 ] || exit 1
            mapfile -t installed_paths < "$staging/installed-paths"
            agent_path="${installed_paths[0]}"
            host_path="${installed_paths[1]}"
            ensure_root_file "$agent_path"
            ensure_root_file "$host_path"
            # Use the currently installed host to authorize the update. A
            # target downgrade may have an older CLI and must never be trusted
            # to mutate the current installation before compatibility is known.
            "$host_path" diagnose --manifest "$installed_manifest" || exit 1
            "$staging/komari-host" diagnose --manifest "$installed_manifest" > "$log_directory/target-host-readiness.log" || {
                log_error "Target Host binary cannot read this installed manifest; refusing an incompatible upgrade/downgrade before changing files."
                exit 1
            }
            prepare_service_directories "$(dirname "$agent_path")"
            # Prepare both rollback copies and the replacement Host before the
            # Agent is touched. Keep recovery copies in the protected log dir.
            agent_rollback="$log_directory/agent.previous"
            host_rollback="$log_directory/host.previous"
            install -m 700 "$agent_path" "$agent_rollback" || exit 1
            install -m 700 "$host_path" "$host_rollback" || exit 1
            host_stage=$(mktemp "$(dirname "$host_path")/.komari-host-update.XXXXXXXX") || exit 1
            if ! cp "$staging/komari-host" "$host_stage" || ! chmod 755 "$host_stage"; then
                rm -f -- "$host_stage"; exit 1
            fi
            ensure_root_dir "/var/lib/komari-host/$service_name"
            host_backup="/var/lib/komari-host/$service_name/host.previous"
            if [ -e "$host_backup" ] || [ -L "$host_backup" ]; then ensure_root_file "$host_backup"; fi
            install -m 700 "$host_rollback" "$host_backup" || { rm -f -- "$host_stage"; exit 1; }
            update_started=true
            "$host_path" update --manifest "$installed_manifest" --artifact "$staging/komari-agent" --sha256 "$agent_digest" || exit 1
            # The host binary is not resident in the daemon. Replace it only
            # after the installed host has atomically updated the Agent.
            mv -fT -- "$host_stage" "$host_path" || { rm -f -- "$host_stage"; exit 1; }
            ;;
    esac
    ensure_root_dir /usr/local/bin
    if [ "$service_name" = komari-agent ]; then
        for component in komari-agent komari-host; do
            link_path="/usr/local/bin/$component"
            if [ -e "$link_path" ] && [ ! -L "$link_path" ]; then
                log_warning "Existing regular command retained: $link_path"
                continue
            fi
            if [ "$component" = komari-agent ]; then link_target="$agent_path"; else link_target="$host_path"; fi
            ln -sfnT -- "$link_target" "$link_path" || exit 1
        done
    fi
    # Read only reviewed root-owned metadata. Never source JSON as shell code.
    ensure_root_file "$installed_manifest"
    python3 - "$installed_manifest" "$service_name" > "$staging/service-fields" <<'SERVICE_FIELDS'
import json, os, re, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
if m.get('version') != 2 or m.get('service_name') != sys.argv[2]:
    raise SystemExit('Installed manifest version or service does not match')
for field in ('service_user', 'executable', 'host_tool', 'credentials_file', 'host_policy_file'):
    value = m.get(field)
    if not isinstance(value, str) or not value or any(c in value for c in '\x00\r\n'):
        raise SystemExit('Invalid installed service field')
    if field == 'service_user':
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', value):
            raise SystemExit('Invalid service account')
    elif not os.path.isabs(value):
        raise SystemExit('Absolute installed paths required')
    print(value)
SERVICE_FIELDS
    mapfile -t service_fields < "$staging/service-fields"
    # The manifest keeps the original account for demotion. A host operation
    # changes the effective systemd User and ownership without rewriting it.
    service_user=$(systemctl show "${service_name}.service" --property=User --value)
    service_user="${service_user:-root}"
    if [[ ! "$service_user" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || ! id -u "$service_user" >/dev/null 2>&1; then
        log_error "Cannot establish the effective installed service account"; exit 1
    fi
    agent_path="${service_fields[1]}"
    host_path="${service_fields[2]}"
    credentials_path="${service_fields[3]}"
    trust_path="$(dirname "${service_fields[4]}")/$service_name.trust.json"
    ensure_root_file "$agent_path"
    ensure_root_file "$host_path"
    # Root can execute through a mode-0700 parent, so root-only diagnostics
    # missed broken non-root migrations. Check as the actual service account
    # before enrollment or declaring even a registration-only install ready.
    if ! runuser -u "$service_user" -- test -x "$agent_path" ||
       ! runuser -u "$service_user" -- test -r "$installed_manifest" ||
       ! runuser -u "$service_user" -- test -r "${service_fields[4]}"; then
        log_error "Service account $service_user cannot access its executable or installation metadata. Inspect parent directory permissions; node state has been preserved."
        exit 1
    fi
    enrolled_now=false
    if [ "$register_only" != true ]; then
        # Read node metadata as its own account, never log the credentials JSON.
        read_identity() {
            runuser -u "$service_user" -- python3 - "$credentials_path" > "$staging/identity-fields" <<'IDENTITY_FIELDS'
import json, os, sys, uuid
if not os.path.exists(sys.argv[1]):
    raise SystemExit(0)
try:
    with open(sys.argv[1]) as f:
        i = json.load(f)
    agent = str(uuid.UUID(i['agent_id']))
    endpoint = i['endpoint']
    if not isinstance(endpoint, str) or not endpoint or any(c in endpoint for c in '\x00\r\n'):
        raise ValueError()
except Exception:
    raise SystemExit('Existing credentials cannot be read; preserve them and use reauth/recovery instead of reinstalling')
print(agent)
print(endpoint)
IDENTITY_FIELDS
        }
        read_identity
        mapfile -t identity_fields < "$staging/identity-fields"
        if [ "${#identity_fields[@]}" -eq 0 ]; then
            if [ -z "$rescue_endpoint" ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
                read -r -p 'Panel HTTPS address: ' rescue_endpoint </dev/tty
            fi
            [ -n "$rescue_endpoint" ] || { log_error "Enrollment needs --endpoint https://your-panel; rerun this command with it. Registration is retained."; exit 1; }
            log_info "Opening browser approval enrollment as $service_user (no system password is requested)."
            runuser -u "$service_user" -- "$agent_path" login --endpoint "$rescue_endpoint"
            read_identity
            mapfile -t identity_fields < "$staging/identity-fields"
            [ "${#identity_fields[@]}" -eq 2 ] || { log_error "Enrollment did not create a node identity"; exit 1; }
            enrolled_now=true
        fi
        node_id="${identity_fields[0]}"
        node_endpoint="${identity_fields[1]}"
        if [ -n "$rescue_endpoint" ] && [ "${rescue_endpoint%/}" != "${node_endpoint%/}" ]; then
            log_error "Endpoint differs from the enrolled node; existing credentials are preserved"; exit 1
        fi
        if [ "$metrics_only" != true ]; then
            if [ -e "$trust_path" ] || [ -L "$trust_path" ]; then
                ensure_root_file "$trust_path"
                # Reuse trust only for this node/endpoint. Never silently rotate keys.
                python3 - "$trust_path" "$node_id" "$node_endpoint" "$panel_key_id" "$panel_public_key" "$host_service_user" "$host_access_config" <<'CHECK_TRUST'
import json, sys
with open(sys.argv[1]) as f:
    t = json.load(f)
if t.get('agent_id') != sys.argv[2] or t.get('endpoint', '').rstrip('/') != sys.argv[3].rstrip('/'):
    raise SystemExit('Host trust belongs to another node or endpoint; explicit reviewed trust rotation required')
if (sys.argv[4] or sys.argv[5]) and not any(k.get('key_id') == sys.argv[4] and k.get('value') == sys.argv[5] for k in t.get('panel_keys', [])):
    raise SystemExit('Panel pin differs from installed host trust; explicit reviewed rotation required')
if sys.argv[6] and t.get('service_user') != sys.argv[6]:
    raise SystemExit('Demotion account differs from existing trust')
if sys.argv[7] and t.get('access_config_file') != sys.argv[7]:
    raise SystemExit('Access configuration differs from existing trust')
CHECK_TRUST
            else
                if [ -r /dev/tty ] && [ -w /dev/tty ]; then
                    log_info "Copy the panel signing key from your independently verified administrator source. Agent enrollment keys are not promoted to root authority."
                    [ -n "$panel_key_id" ] || read -r -p 'Panel signing key ID: ' panel_key_id </dev/tty
                    [ -n "$panel_public_key" ] || read -r -p 'Panel Ed25519 public key (base64): ' panel_public_key </dev/tty
                fi
                if [ -z "$panel_key_id" ] || [ -z "$panel_public_key" ]; then
                    log_error "Host preparation needs --install-panel-key-id and --install-panel-public-key (public data). Use --install-metrics-only only when host actions are intentionally unnecessary."
                    exit 1
                fi
                if [ -z "$host_service_user" ]; then
                    host_service_user="$service_user"
                    if [ "$service_user" = root ]; then
                        if [ -r /dev/tty ] && [ -w /dev/tty ]; then
                            read -r -p 'Existing non-root account for later demotion: ' host_service_user </dev/tty
                        else
                            log_error "Root installs need --install-host-service-user naming the original non-root account"; exit 1
                        fi
                    fi
                fi
                host_trust_args=(--manifest "$installed_manifest" --endpoint "$node_endpoint" --agent-id "$node_id"
                    --panel-key-id "$panel_key_id" --panel-public-key "$panel_public_key"
                    --service-user "$host_service_user"
                    --release-key-id komari-release-8372cfc532b8f1bf
                    --release-public-key Bii7plda32t+iJAWXT2zBoy3uOiUuLqZa8dLqwmBQ6o=)
                [ -z "$host_access_config" ] || host_trust_args+=(--access-config "$host_access_config")
                [ "$rescue_enabled" != true ] || host_trust_args+=(--allow-rescue-helper)
                "$host_path" trust "${host_trust_args[@]}"
            fi
            if [ "$rescue_enabled" = true ]; then
                log_info "Verifying and caching the signed rescue release; the rescue service will be installed only by a separately approved host action."
                "$host_path" fetch-helper --manifest "$installed_manifest" --version "$install_version"
                policy_path="${service_fields[4]}"
                ensure_root_file "$policy_path"
                # Compatibility prefetch; a later PAM-authorized apply can grant consent.
                # Publish atomically; preserve every other policy field.
                python3 - "$policy_path" <<'ALLOW_HELPER'
import json, os, sys, tempfile
path = sys.argv[1]
with open(path) as f:
    policy = json.load(f)
if policy.get('force_deny_rescue_helper'):
    raise SystemExit('Rescue is prohibited by protected local policy; explicit local policy review required')
if policy.get('allow_rescue_helper') is not True:
    policy['allow_rescue_helper'] = True
    fd, temporary = tempfile.mkstemp(prefix='.helper-policy-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(policy, f, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
ALLOW_HELPER
            fi
            ensure_root_dir /etc/pam.d
            if [ -e /etc/pam.d/komari-host ] || [ -L /etc/pam.d/komari-host ]; then
                ensure_root_file /etc/pam.d/komari-host
            else
                pam_stage=$(mktemp /etc/pam.d/.komari-host.XXXXXXXX)
                printf '# Komari host: fresh local password and account validity\nauth required pam_unix.so\naccount required pam_unix.so\n' > "$pam_stage"
                chmod 644 "$pam_stage"
                mv -fT -- "$pam_stage" /etc/pam.d/komari-host
            fi
            "$host_path" diagnose --manifest "$installed_manifest" | tee "$log_directory/host-readiness.log"
            if ! grep -qx 'host_actions_ready=true' "$log_directory/host-readiness.log"; then
                log_error "Host preparation is incomplete; inspect $log_directory/host-readiness.log"; exit 1
            fi
        else
            log_warning "Metrics-only mode: privileged host action preparation was explicitly skipped."
        fi
        if [ "$service_was_active" = true ] || [ "$enrolled_now" = true ] || [ "$install_mode" = fresh ]; then
            systemctl reset-failed "${service_name}.service"
            systemctl restart "${service_name}.service"
            initial_restarts=$(systemctl show "${service_name}.service" --property=NRestarts --value)
            for observation in 1 2 3 4 5; do
                sleep 1
                if ! systemctl is-active --quiet "${service_name}.service" || [ "$(systemctl show "${service_name}.service" --property=NRestarts --value)" != "$initial_restarts" ]; then
                    log_error "Service failed after restart; the installer will restore the previous binaries. No node state was erased."; exit 1
                fi
            done
        else
            log_info "Previously stopped service remains stopped. Start with: sudo systemctl start $service_name"
        fi
    else
        log_info "Registration-only mode: enrollment, host setup and service restart were explicitly skipped."
    fi
    log_success "$install_mode complete: $install_version. Node identity and existing state retained."
    log_info "Privileged changes still require panel approval and local PAM authentication via komari-host apply."
    exit 0
fi

# Remote command execution and terminal access run with the Agent process
# identity and therefore require root/administrator privileges. Persist the canonical
# all-remote-control switch for every unprivileged installation.
if [ "$runtime_identity" = "service-account" ]; then
    case " $komari_args " in
        *" --disable-remote-control "*) ;;
        *)
            komari_args="$komari_args --disable-remote-control"
            komari_argv+=("--disable-remote-control")
            ;;
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
        *" --disable-remote-control "*) ;;
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

if [[ ! "$service_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
    log_error "Invalid service name: $service_name"
    exit 1
fi
[[ "$target_dir" = /* ]] || target_dir="$PWD/$target_dir"
komari_agent_path="${target_dir}/agent"
runtime_state_path="${runtime_state_override:-${target_dir}/runtime-config.json}"
# Credentials and privileged state live beside the installation rather than in
# a user home. The service runs as an unprivileged account whose home may not
# exist, and the separately privileged helper has to read the same files
# without guessing which user installed the Agent.
credentials_path="${credentials_override:-${target_dir}/credentials.json}"
privileged_state_path="${privileged_state_override:-${target_dir}/privileged.json}"
replay_state_path="${replay_state_override:-${target_dir}/nonces.json}"
[[ "$runtime_state_path" = /* ]] || runtime_state_path="$target_dir/$runtime_state_path"
[[ "$credentials_path" = /* ]] || credentials_path="$target_dir/$credentials_path"
[[ "$privileged_state_path" = /* ]] || privileged_state_path="$target_dir/$privileged_state_path"
[[ "$replay_state_path" = /* ]] || replay_state_path="$target_dir/$replay_state_path"

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
    
    # Remove old binary and symlinks
    rm -f /usr/local/bin/komari-agent /usr/local/bin/komari-elevate /usr/local/bin/komari-uninstall
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
if ! curl -fL -o "$komari_agent_path" "$download_url"; then
    log_error "Download failed"
    exit 1
fi

# Set executable permissions
chmod +x "$komari_agent_path"
if [ "$EUID" -eq 0 ] && [ "$service_user" != "root" ]; then
    chown "$service_user" "$komari_agent_path"
fi
log_success "Komari-agent installed to ${GREEN}$komari_agent_path${NC}"

# Create a symlink in /usr/local/bin so operators can run komari-agent commands
# directly (e.g. komari-agent login, komari-agent status) without knowing the
# Install elevate.sh and uninstall.sh scripts
elevate_script_path="${target_dir}/elevate.sh"
uninstall_script_path="${target_dir}/uninstall.sh"
script_source_dir="$(dirname "$0")"
elevate_source_name="elevate.sh"
[ "$os_name" = "darwin" ] && elevate_source_name="elevate_darwin.sh"

if [ -f "${script_source_dir}/scripts/${elevate_source_name}" ]; then
    cp "${script_source_dir}/scripts/${elevate_source_name}" "$elevate_script_path"
elif [ -f "${script_source_dir}/${elevate_source_name}" ]; then
    cp "${script_source_dir}/${elevate_source_name}" "$elevate_script_path"
else
    elevate_download_url="https://raw.githubusercontent.com/${release_repository}/main/scripts/${elevate_source_name}"
    [ -n "$github_proxy" ] && elevate_download_url="${github_proxy}/${elevate_download_url}"
    curl -fsSL -o "$elevate_script_path" "$elevate_download_url" 2>/dev/null || true
fi
if [ -f "$elevate_script_path" ]; then
    chmod 750 "$elevate_script_path"
    log_success "Host elevation script installed to ${GREEN}$elevate_script_path${NC}"
fi

if [ -f "${script_source_dir}/uninstall.sh" ]; then
    cp "${script_source_dir}/uninstall.sh" "$uninstall_script_path"
elif [ -f "${script_source_dir}/scripts/uninstall.sh" ]; then
    cp "${script_source_dir}/scripts/uninstall.sh" "$uninstall_script_path"
else
    uninstall_download_url="https://raw.githubusercontent.com/${release_repository}/main/uninstall.sh"
    [ -n "$github_proxy" ] && uninstall_download_url="${github_proxy}/${uninstall_download_url}"
    curl -fsSL -o "$uninstall_script_path" "$uninstall_download_url" 2>/dev/null || true
fi
if [ -f "$uninstall_script_path" ]; then
    chmod 750 "$uninstall_script_path"
    log_success "Uninstaller script installed to ${GREEN}$uninstall_script_path${NC}"
fi

# Create symlinks in /usr/local/bin so operators can run commands directly
if [ "$os_name" != "windows" ] && [ "$EUID" -eq 0 ]; then
    symlink_dir="/usr/local/bin"
    if [ -d "$symlink_dir" ]; then
        ln -sf "$komari_agent_path" "${symlink_dir}/komari-agent"
        [ -f "$elevate_script_path" ] && ln -sf "$elevate_script_path" "${symlink_dir}/komari-elevate"
        [ -f "$uninstall_script_path" ] && ln -sf "$uninstall_script_path" "${symlink_dir}/komari-uninstall"
        log_success "Symlinks created: komari-agent, komari-elevate, komari-uninstall in ${symlink_dir}"
    fi
elif [ "$os_name" != "windows" ] && [ "$EUID" -ne 0 ]; then
    log_info "Not running as root; skipping /usr/local/bin symlinks."
fi

komari_argv+=("--runtime-state-file" "$runtime_state_path" "--credentials-file" "$credentials_path"
    "--privileged-state-file" "$privileged_state_path" "--replay-state-file" "$replay_state_path")

# Preserve argument boundaries in service definitions (paths may contain spaces).
shell_quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
komari_args=""
systemd_args=""
systemd_quote() {
    local escaped="${1//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    escaped="${escaped//%/%%}"
    escaped="${escaped//\$/\$\$}"
    printf '"%s"' "$escaped"
}
for argument in "${komari_argv[@]}"; do
    komari_args="$komari_args $(shell_quote "$argument")"
    systemd_args="$systemd_args $(systemd_quote "$argument")"
done
komari_args="${komari_args# }"
shell_args_literal=$(shell_quote "$komari_args")
xml_escape() {
    printf '%s' "$1" | sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&apos;/g'
}
json_string() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '"%s"' "$value"
}

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

# Share the exact state paths with every CLI subcommand. This manifest contains
# no tokens or private keys and is readable by operators without exposing them.
service_config_path="${target_dir}/service-config.json"
if ! (umask 022; cat > "$service_config_path" << EOF
{
  "service_name": $(json_string "$service_name"),
  "service_user": $(json_string "$service_user"),
  "init_system": $(json_string "$init_system"),
  "credentials_file": $(json_string "$credentials_path"),
  "runtime_state_file": $(json_string "$runtime_state_path"),
  "privileged_state_file": $(json_string "$privileged_state_path"),
  "replay_state_file": $(json_string "$replay_state_path")
}
EOF
); then
    log_error "Could not write installed service configuration"
    exit 1
fi
chmod 644 "$service_config_path"
if [ "$service_user" != "root" ]; then
    chown "$service_user" "$service_config_path"
fi

agent_ready=false
if [ -s "$credentials_path" ] || [ -n "$rescue_token" ] || [ -n "$auto_discovery_key" ]; then
    agent_ready=true
fi
for argument in "${komari_argv[@]}"; do
    case "$argument" in
        --token=?*|-t=?*|--auto-discovery=?*|--config|--config=?*) agent_ready=true ;;
    esac
done

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
command=$(shell_quote "$komari_agent_path")
command_args=${shell_args_literal}
command_user="${service_user}"
directory=$(shell_quote "$target_dir")
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
    if [ "$agent_ready" = true ]; then
        rc-service "${service_name}" start || exit 1
    fi
    log_success "OpenRC service configured"
elif [ "$init_system" = "systemd" ]; then
    # Systemd service configuration
    log_info "Using systemd for service management"
    service_file="/etc/systemd/system/${service_name}.service"
    cat > "$service_file" << EOF
[Unit]
Description=Komari Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(systemd_quote "$komari_agent_path")${systemd_args}
WorkingDirectory=${target_dir//%/%%}
Restart=always
RestartSec=5
User=${service_user}
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and start service
    systemctl daemon-reload || exit 1
    systemctl enable "${service_name}.service" || exit 1
    systemctl reset-failed "${service_name}.service" 2>/dev/null || true
    if [ "$agent_ready" = true ]; then
        if ! systemctl start "${service_name}.service"; then
            journalctl -u "${service_name}.service" -n 30 --no-pager
            exit 1
        fi
        sleep 2
        if ! systemctl is-active --quiet "${service_name}.service"; then
            log_error "Agent service failed to stay running"
            journalctl -u "${service_name}.service" -n 30 --no-pager
            exit 1
        fi
        log_success "Systemd service started"
    else
        log_info "Systemd service enabled; waiting for enrollment before starting"
    fi
elif [ "$init_system" = "procd" ]; then
    # procd service configuration (OpenWrt)
    log_info "Using procd for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

PROG=$(shell_quote "$komari_agent_path")

start_service() {
    procd_open_instance
    procd_set_param command "\$PROG" ${komari_args}
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
    if [ "$agent_ready" = true ]; then
        /etc/init.d/${service_name} start || exit 1
    fi
    log_success "procd service configured"
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
        <string>$(xml_escape "$komari_agent_path")</string>
EOF
    
    for argument in "${komari_argv[@]}"; do
        printf '        <string>%s</string>\n' "$(xml_escape "$argument")" >> "$plist_file"
    done
    
    cat >> "$plist_file" << EOF
    </array>
    <key>WorkingDirectory</key>
    <string>$(xml_escape "$target_dir")</string>
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
    
    # launchd requires a root-owned, non-writable plist. Loading a job does not
    # by itself prove that its child process has stayed alive.
    chown root:wheel "$plist_file"
    chmod 644 "$plist_file"
    if ! plutil -lint "$plist_file" || ! launchctl bootstrap system "$plist_file"; then
        log_error "Failed to load system-level launchd service"
        exit 1
    fi
    if [ "$agent_ready" = true ]; then
        sleep 2
        if ! launchctl print "system/com.komari.${service_name}" | grep -q 'state = running'; then
            log_error "Agent service failed to stay running; see ${log_dir}/${service_name}.log"
            tail -n 30 "${log_dir}/${service_name}.log" 2>/dev/null
            exit 1
        fi
        log_success "System launchd service started as ${service_user}"
    else
        log_info "System launchd service loaded; waiting for enrollment"
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
    exec $(shell_quote "$komari_agent_path") ${komari_args}
end script
EOF
    # enable Upstart unit
    initctl reload-configuration
    if [ "$agent_ready" = true ]; then
        initctl start ${service_name} || exit 1
    fi
    log_success "Upstart service configured"
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
		printf 'KOMARI_RESCUE_PRIVILEGED_STATE_FILE=%s\n' "$(systemd_env_value "$privileged_state_path")"
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

# An Agent installed without a token is not yet enrolled. Enrolment is a
# separate, deliberate step: it needs a human to approve this machine in the
# panel, so the installer explains it rather than trying to automate it away.
if [ "$agent_ready" != true ]; then
        echo ""
        log_step "This machine is not enrolled yet."
        echo ""
        log_info "Enrol it by running:"
        if [ "$runtime_identity" = "service-account" ]; then
            # The credentials file belongs to the service account, so writing it
            # as anyone else would leave the daemon unable to read its own
            # identity.
            printf '    sudo -u %s %s login --endpoint %s\n' "$service_user" "$(shell_quote "$komari_agent_path")" "$(shell_quote "${rescue_endpoint:-panel.example.com}")"
        else
            printf '    sudo %s login --endpoint %s\n' "$(shell_quote "$komari_agent_path")" "$(shell_quote "${rescue_endpoint:-panel.example.com}")"
        fi
        echo ""
        log_info "That prints a link. Open it, sign in to the panel, and approve this machine."
        case "$init_system" in
            launchd) restart_command="sudo launchctl kickstart -k system/com.komari.${service_name}" ;;
            openrc) restart_command="sudo rc-service ${service_name} restart" ;;
            procd) restart_command="sudo /etc/init.d/${service_name} restart" ;;
            upstart) restart_command="sudo initctl restart ${service_name}" ;;
            nixos) restart_command="sudo nixos-rebuild switch" ;;
            *) restart_command="sudo systemctl reset-failed ${service_name} && sudo systemctl restart ${service_name}" ;;
        esac
        log_info "Then start the service: ${GREEN}${restart_command}${NC}"
        echo -e "${WHITE}===========================================${NC}"
fi

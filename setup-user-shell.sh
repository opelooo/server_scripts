#!/usr/bin/env bash
#
# Generic Linux User Shell Switcher Script
# Target: Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux
# Scope: Installs target shell (fish/zsh/bash) if missing, ensures /etc/shells entry,
#        and safely updates default login shell for the specified user.
#
set -euo pipefail

TARGET_SHELL="${1:-fish}"
TARGET_USER="${2:-${SUDO_USER:-$USER}}"

log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
        return 1
    fi
    return 0
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
        return 0
    fi
    if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
        return 0
    fi
    log_error "Unsupported package manager. Only apt and dnf are supported."
    return 1
}

validate_target_user() {
    if ! id "${TARGET_USER}" >/dev/null 2>&1; then
        log_error "Target user '${TARGET_USER}' does not exist on this system."
        return 1
    fi
    log_info "Target user to modify: ${TARGET_USER}"
    return 0
}

install_shell_package() {
    log_info "Verifying if '${TARGET_SHELL}' is installed..."
    if command -v "${TARGET_SHELL}" >/dev/null 2>&1; then
        log_info "Shell '${TARGET_SHELL}' is already installed at: $(command -v "${TARGET_SHELL}")"
        return 0
    fi

    log_info "Shell '${TARGET_SHELL}' not found. Installing via ${PKG_MGR}..."
    if [[ "${PKG_MGR}" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends "${TARGET_SHELL}"
    elif [[ "${PKG_MGR}" == "dnf" ]]; then
        dnf install -y -q epel-release || true
        dnf install -y -q "${TARGET_SHELL}"
    fi

    log_info "Shell package installed successfully."
    return 0
}

register_and_change_shell() {
    local shell_bin
    shell_bin=$(command -v "${TARGET_SHELL}" || true)

    if [[ -z "${shell_bin}" ]] || [[ ! -x "${shell_bin}" ]]; then
        log_error "Executable binary for '${TARGET_SHELL}' could not be located."
        return 1
    fi

    # Register binary in /etc/shells if missing
    if ! grep -q "^${shell_bin}$" /etc/shells 2>/dev/null; then
        log_info "Registering ${shell_bin} into /etc/shells..."
        echo "${shell_bin}" >> /etc/shells
    fi

    log_info "Changing default login shell for '${TARGET_USER}' to ${shell_bin}..."
    chsh -s "${shell_bin}" "${TARGET_USER}" || usermod -s "${shell_bin}" "${TARGET_USER}"

    local user_home
    user_home=$(getent passwd "${TARGET_USER}" | cut -d: -f6)

    # Basic initial setup for fish shell if selected
    if [[ "${TARGET_SHELL}" == "fish" ]] && [[ -d "${user_home}" ]]; then
        local fish_conf_dir="${user_home}/.config/fish"
        mkdir -p "${fish_conf_dir}"
        if [[ ! -f "${fish_conf_dir}/config.fish" ]]; then
            cat <<'EOF' > "${fish_conf_dir}/config.fish"
# Ensure standard system binary paths are available
fish_add_path /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin
EOF
            chown -R "${TARGET_USER}:${TARGET_USER}" "${user_home}/.config" 2>/dev/null || true
            log_info "Created initial fish config at ${fish_conf_dir}/config.fish"
        fi
    fi

    return 0
}

verify_shell_change() {
    local current_shell
    current_shell=$(getent passwd "${TARGET_USER}" | cut -d: -f7)
    log_info "Current configured shell for '${TARGET_USER}': ${current_shell}"

    if [[ "${current_shell}" == *"${TARGET_SHELL}"* ]]; then
        log_info "Verification SUCCESS: Shell updated successfully."
        return 0
    fi

    log_error "Verification FAILED: Shell does not match requested '${TARGET_SHELL}'."
    return 1
}

main() {
    check_root
    detect_pkg_manager
    validate_target_user
    install_shell_package
    register_and_change_shell
    verify_shell_change

    echo "====================================================="
    echo "Default shell for user '${TARGET_USER}' is now '${TARGET_SHELL}'."
    echo "Note: Log out and log back in for the change to take full effect."
    echo "====================================================="
}

main "$@"

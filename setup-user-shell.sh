#!/usr/bin/env bash
#
# Generic Linux User Shell Switcher Script
# Target: Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux
# Scope: Supports multiple shells: fish, zsh, bash, nushell, mksh, tcsh.
#        Includes interactive menu, non-interactive flags, PATH setup,
#        custom configs, optional Starship prompt, and system-wide defaults (--all).
#
set -euo pipefail

TARGET_SHELL=""
TARGET_USER=""
ENABLE_STARSHIP=false
APPLY_ALL=false

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

parse_arguments() {
    TARGET_USER="${SUDO_USER:-$USER}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all|--all-users|--system-wide)
                APPLY_ALL=true
                shift 1
                ;;
            --starship)
                ENABLE_STARSHIP=true
                shift 1
                ;;
            --user)
                TARGET_USER="$2"
                shift 2
                ;;
            fish|zsh|bash|nushell|nu|mksh|ksh|tcsh)
                TARGET_SHELL="$1"
                shift 1
                ;;
            *)
                if [[ -z "${TARGET_SHELL}" ]] && [[ ! "$1" =~ ^-- ]]; then
                    TARGET_SHELL="$1"
                elif [[ -z "${TARGET_USER}" ]]; then
                    TARGET_USER="$1"
                fi
                shift 1
                ;;
        esac
    done

    # Normalize aliases
    if [[ "${TARGET_SHELL}" == "nu" ]]; then
        TARGET_SHELL="nushell"
    fi
    if [[ "${TARGET_SHELL}" == "ksh" ]]; then
        TARGET_SHELL="mksh"
    fi
    return 0
}

prompt_interactive_selection() {
    if [[ -n "${TARGET_SHELL}" ]]; then
        return 0
    fi

    # If running interactively with a TTY, display menu
    if [[ -t 0 ]]; then
        echo "====================================================="
        echo "Select a login shell to install and configure:"
        echo "  1) fish    - Friendly Interactive Shell (autosuggestions, syntax highlighting)"
        echo "  2) zsh     - Z Shell (popular, robust, customizable)"
        echo "  3) bash    - Bourne Again Shell (enhanced modern aliases & colors)"
        echo "  4) nushell - Structured data shell (fast, typed tables, written in Rust)"
        echo "  5) mksh    - MirBSD KornShell (ultra-lightweight, minimal memory footprint)"
        echo "  6) tcsh    - TENEX C Shell (C-like syntax)"
        echo "====================================================="
        read -r -p "Enter choice [1-6] (default: 1): " choice
        case "${choice}" in
            2) TARGET_SHELL="zsh" ;;
            3) TARGET_SHELL="bash" ;;
            4) TARGET_SHELL="nushell" ;;
            5) TARGET_SHELL="mksh" ;;
            6) TARGET_SHELL="tcsh" ;;
            *) TARGET_SHELL="fish" ;;
        esac
    else
        # Default to fish for headless pipe execution
        TARGET_SHELL="fish"
    fi

    log_info "Selected target shell: ${TARGET_SHELL}"
    return 0
}

validate_target_user() {
    if ! id "${TARGET_USER}" >/dev/null 2>&1; then
        log_error "Target user '${TARGET_USER}' does not exist on this system."
        return 1
    fi
    log_info "Target user to modify: ${TARGET_USER}"
    return 0
}

install_nushell_binary() {
    if command -v nu >/dev/null 2>&1; then
        return 0
    fi

    log_info "Downloading standalone Nushell release from GitHub..."
    local arch
    arch=$(uname -m)
    local nu_arch="x86_64"
    if [[ "${arch}" == "aarch64" ]]; then
        nu_arch="aarch64"
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local nu_url
    nu_url=$(curl -s https://api.github.com/repos/nushell/nushell/releases/latest | grep "browser_download_url.*${nu_arch}-unknown-linux-musl.tar.gz" | cut -d : -f 2,3 | tr -d '" ' | head -n 1)

    if [[ -z "${nu_url}" ]]; then
        nu_url="https://github.com/nushell/nushell/releases/download/0.100.0/nu-0.100.0-${nu_arch}-unknown-linux-musl.tar.gz"
    fi

    curl -sL "${nu_url}" -o "${tmp_dir}/nu.tar.gz"
    tar -xzf "${tmp_dir}/nu.tar.gz" -C "${tmp_dir}"
    local extracted_bin
    extracted_bin=$(find "${tmp_dir}" -type f -name "nu" | head -n 1)

    if [[ -n "${extracted_bin}" ]]; then
        cp "${extracted_bin}" /usr/local/bin/nu
        chmod 755 /usr/local/bin/nu
        ln -sf /usr/local/bin/nu /usr/local/bin/nushell
    fi

    rm -rf "${tmp_dir}"
    log_info "Nushell installed at /usr/local/bin/nu"
    return 0
}

install_shell_package() {
    local bin_name="${TARGET_SHELL}"
    if [[ "${TARGET_SHELL}" == "nushell" ]]; then
        bin_name="nu"
    fi

    if command -v "${bin_name}" >/dev/null 2>&1; then
        log_info "Shell binary '${bin_name}' is already installed."
        return 0
    fi

    log_info "Installing '${TARGET_SHELL}' via ${PKG_MGR}..."
    if [[ "${TARGET_SHELL}" == "nushell" ]]; then
        install_nushell_binary
        return 0
    fi

    if [[ "${PKG_MGR}" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends "${TARGET_SHELL}" curl tar
    elif [[ "${PKG_MGR}" == "dnf" ]]; then
        dnf install -y -q epel-release || true
        dnf install -y -q "${TARGET_SHELL}" curl tar
    fi

    log_info "Package installation completed."
    return 0
}

write_user_shell_config() {
    local username="$1"
    local user_home
    user_home=$(getent passwd "${username}" | cut -d: -f6)

    if [[ ! -d "${user_home}" ]]; then
        return 0
    fi

    case "${TARGET_SHELL}" in
        fish)
            mkdir -p "${user_home}/.config/fish"
            cat <<'EOF' > "${user_home}/.config/fish/config.fish"
fish_add_path /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin
alias ll='ls -lha --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
EOF
            chown -R "${username}:${username}" "${user_home}/.config" 2>/dev/null || true
            ;;
        zsh)
            if [[ ! -f "${user_home}/.zshrc" ]]; then
                cat <<'EOF' > "${user_home}/.zshrc"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
alias ll='ls -lha --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
autoload -Uz compinit && compinit
zstyle ':completion:*' menu select
PROMPT='%F{green}%n@%m%f:%F{blue}%~%f$ '
EOF
                chown "${username}:${username}" "${user_home}/.zshrc" 2>/dev/null || true
            fi
            ;;
        bash)
            if [[ -f "${user_home}/.bashrc" ]] && ! grep -q "alias ll=" "${user_home}/.bashrc"; then
                cat <<'EOF' >> "${user_home}/.bashrc"
alias ll='ls -lha --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
EOF
            fi
            ;;
        nushell)
            mkdir -p "${user_home}/.config/nushell"
            touch "${user_home}/.config/nushell/config.nu"
            chown -R "${username}:${username}" "${user_home}/.config" 2>/dev/null || true
            ;;
    esac
    return 0
}

configure_user_environment() {
    log_info "Configuring default environment for user '${TARGET_USER}'..."
    write_user_shell_config "${TARGET_USER}"

    if [[ "${APPLY_ALL}" == "true" ]] && [[ "${TARGET_USER}" != "root" ]]; then
        log_info "Applying shell configuration for root user..."
        write_user_shell_config "root"
    fi
    return 0
}

install_starship_if_requested() {
    if [[ "${ENABLE_STARSHIP}" != "true" ]]; then
        return 0
    fi

    log_info "Installing Starship cross-shell prompt..."
    curl -sS https://starship.rs/install.sh | sh -s -- --yes >/dev/null 2>&1

    local users_to_hook=("${TARGET_USER}")
    if [[ "${APPLY_ALL}" == "true" ]] && [[ "${TARGET_USER}" != "root" ]]; then
        users_to_hook+=("root")
    fi

    for u in "${users_to_hook[@]}"; do
        local user_home
        user_home=$(getent passwd "${u}" | cut -d: -f6)
        case "${TARGET_SHELL}" in
            fish)
                echo "starship init fish | source" >> "${user_home}/.config/fish/config.fish"
                ;;
            zsh)
                echo 'eval "$(starship init zsh)"' >> "${user_home}/.zshrc"
                ;;
            bash)
                echo 'eval "$(starship init bash)"' >> "${user_home}/.bashrc"
                ;;
        esac
    done

    log_info "Starship prompt hooked into ${TARGET_SHELL}."
    return 0
}

register_and_change_shell() {
    local bin_name="${TARGET_SHELL}"
    if [[ "${TARGET_SHELL}" == "nushell" ]]; then
        bin_name="nu"
    fi

    local shell_bin
    shell_bin=$(command -v "${bin_name}" || true)

    if [[ -z "${shell_bin}" ]] || [[ ! -x "${shell_bin}" ]]; then
        log_error "Executable binary for '${TARGET_SHELL}' not found."
        return 1
    fi

    if ! grep -q "^${shell_bin}$" /etc/shells 2>/dev/null; then
        log_info "Registering ${shell_bin} into /etc/shells..."
        echo "${shell_bin}" >> /etc/shells
    fi

    log_info "Changing default login shell for '${TARGET_USER}' to ${shell_bin}..."
    chsh -s "${shell_bin}" "${TARGET_USER}" || usermod -s "${shell_bin}" "${TARGET_USER}"

    # If --all is passed, also update root and system defaults for future new users
    if [[ "${APPLY_ALL}" == "true" ]]; then
        log_info "Setting default shell for root..."
        chsh -s "${shell_bin}" root || usermod -s "${shell_bin}" root

        log_info "Setting system default shell for future new users..."
        useradd -D -s "${shell_bin}" 2>/dev/null || true
        if [[ -f /etc/adduser.conf ]]; then
            sed -i -E "s|^#?DSHELL=.*|DSHELL=${shell_bin}|" /etc/adduser.conf
        fi
    fi

    return 0
}

verify_shell_change() {
    local current_shell
    current_shell=$(getent passwd "${TARGET_USER}" | cut -d: -f7)
    log_info "Current shell in /etc/passwd for '${TARGET_USER}': ${current_shell}"

    local check_name="${TARGET_SHELL}"
    if [[ "${TARGET_SHELL}" == "nushell" ]]; then
        check_name="nu"
    fi

    if [[ "${current_shell}" == *"${check_name}"* ]]; then
        log_info "Verification SUCCESS: Login shell successfully updated."
        return 0
    fi

    log_error "Verification FAILED: Shell does not match '${TARGET_SHELL}'."
    return 1
}

main() {
    check_root
    detect_pkg_manager
    parse_arguments "$@"
    prompt_interactive_selection
    validate_target_user
    install_shell_package
    configure_user_environment
    install_starship_if_requested
    register_and_change_shell
    verify_shell_change

    echo "====================================================="
    echo "Summary of shell configuration:"
    echo "  Target User    : ${TARGET_USER}"
    echo "  Login Shell    : ${TARGET_SHELL}"
    echo "  Applied System : ${APPLY_ALL}"
    echo "  Starship       : ${ENABLE_STARSHIP}"
    echo "====================================================="
    echo "Note: Log out and reconnect via SSH to enter your new shell."
}

main "$@"

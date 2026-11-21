#!/usr/bin/env bash
#
# Tailscale Peer Relay & Firewall Add-on Script
# Target: Any Linux server with Tailscale installed
# Scope: Configures Tailscale Peer Relay port, UFW rules, and Fail2ban whitelist
#
set -euo pipefail

DEFAULT_RELAY_PORT=41641
RELAY_PORT="${1:-${DEFAULT_RELAY_PORT}}"

log_info() {
    echo "[INFO] $1"
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

check_tailscale_installed() {
    if ! command -v tailscale >/dev/null 2>&1; then
        log_error "Tailscale CLI is not installed. Please install Tailscale first."
        return 1
    fi
    return 0
}

configure_ufw_for_tailscale() {
    if ! command -v ufw >/dev/null 2>&1; then
        log_info "UFW not found. Skipping UFW configuration."
        return 0
    fi

    log_info "Allowing full traffic on tailscale0 interface..."
    ufw allow in on tailscale0 comment "Tailscale mesh network"

    log_info "Allowing inbound UDP port ${RELAY_PORT} for Peer Relay..."
    ufw allow "${RELAY_PORT}/udp" comment "Tailscale Peer Relay UDP"

    ufw reload >/dev/null 2>&1 || true
    log_info "UFW updated for Tailscale."
    return 0
}

whitelist_tailscale_in_fail2ban() {
    local jail_file="/etc/fail2ban/jail.d/sshd-hardening.local"
    if [[ ! -f "${jail_file}" ]]; then
        return 0
    fi

    log_info "Whitelisting Tailscale CGNAT subnet (100.64.0.0/10) in Fail2ban..."
    if grep -q "100.64.0.0/10" "${jail_file}"; then
        log_info "Subnet 100.64.0.0/10 already whitelisted."
        return 0
    fi

    sed -i 's/ignoreip = /ignoreip = 100.64.0.0\/10 /' "${jail_file}"
    systemctl restart fail2ban 2>/dev/null || true
    log_info "Fail2ban whitelist updated."
    return 0
}

activate_peer_relay() {
    log_info "Configuring Tailscale client relay port to ${RELAY_PORT}..."
    tailscale set --relay-server-port="${RELAY_PORT}"
    log_info "Tailscale Peer Relay port successfully enabled."
    return 0
}

main() {
    check_root
    check_tailscale_installed
    configure_ufw_for_tailscale
    whitelist_tailscale_in_fail2ban
    activate_peer_relay

    echo "====================================================="
    echo "Tailscale Peer Relay setup completed successfully."
    echo "Relay UDP Port: ${RELAY_PORT}"
    echo "Next step: Ensure 'tailscale.com/cap/relay' capability"
    echo "is granted in your Tailscale / Headscale ACL policy."
    echo "====================================================="
}

main "$@"

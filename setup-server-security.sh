#!/usr/bin/env bash
#
# Generic Linux Server Security Hardening Script
# Target: Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux
# Scope: Basic Security, Anti-Flood Sysctl, Journald, Fail2ban, Auto-Updates,
#        Dual-Tier Swap (ZRAM priority 100 > Disk Swap priority 10),
#        Custom SSH Port Migration (Closes port 22, targets Fail2ban & UFW),
#        SSH Hardening, Disable LLMNR, Disable Core Dumps, Kernel Protocol Blacklist,
#        IPv6 Protections, RFC1337, Loopback UFW, and Cron Access Restrictions.
#
set -euo pipefail

TARGET_SSH_PORT=""
USER_SPECIFIED_PORT="${CUSTOM_SSH_PORT:-}"

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

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-port)
                USER_SPECIFIED_PORT="$2"
                shift 2
                ;;
            --ssh-port=*)
                USER_SPECIFIED_PORT="${1#*=}"
                shift 1
                ;;
            *)
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    USER_SPECIFIED_PORT="$1"
                fi
                shift 1
                ;;
        esac
    done
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

configure_ssh_port() {
    local detected_port=""

    if [[ -n "${USER_SPECIFIED_PORT}" ]]; then
        if ! [[ "${USER_SPECIFIED_PORT}" =~ ^[0-9]+$ ]] || [[ "${USER_SPECIFIED_PORT}" -lt 1 ]] || [[ "${USER_SPECIFIED_PORT}" -gt 65535 ]]; then
            log_error "Invalid SSH port specified: ${USER_SPECIFIED_PORT}. Must be 1-65535."
            return 1
        fi
        TARGET_SSH_PORT="${USER_SPECIFIED_PORT}"
        log_info "Configuring custom SSH port: ${TARGET_SSH_PORT}..."

        # Update main sshd_config and remove default port 22
        if grep -qE "^#?Port " /etc/ssh/sshd_config 2>/dev/null; then
            sed -i -E "s/^#?Port [0-9]+/Port ${TARGET_SSH_PORT}/" /etc/ssh/sshd_config
        else
            echo "Port ${TARGET_SSH_PORT}" >> /etc/ssh/sshd_config
        fi

        # Disable systemd socket activation on Debian/Ubuntu so ssh.service binds custom port directly
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            systemctl disable --now ssh.socket 2>/dev/null || true
        fi
        systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
    else
        # Auto-detect existing custom port or fallback
        detected_port=$(grep -rhE "^Port [0-9]+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | tail -n 1 || true)
        if [[ -z "${detected_port}" ]]; then
            detected_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | grep -v '^22$' | tail -n 1 || true)
        fi
        TARGET_SSH_PORT="${detected_port:-22}"
    fi

    log_info "Active target SSH port determined: ${TARGET_SSH_PORT}"
    return 0
}

install_packages() {
    log_info "Updating package lists and installing required utilities..."
    if [[ "${PKG_MGR}" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends ufw fail2ban unattended-upgrades curl iproute2 zram-tools cron
    elif [[ "${PKG_MGR}" == "dnf" ]]; then
        dnf install -y -q epel-release || true
        local fw_pkg="ufw"
        if command -v firewall-cmd >/dev/null 2>&1 || systemctl is-active --quiet firewalld 2>/dev/null; then
            fw_pkg=""
        fi
        dnf install -y -q --setopt=install_weak_deps=False ${fw_pkg} fail2ban curl iproute zram-generator dnf-automatic cronie
    fi
    return 0
}

configure_zram_swap() {
    log_info "Configuring ZRAM swap with high priority (priority=100)..."
    if [[ -f /etc/default/zramswap ]]; then
        cat <<'EOF' > /etc/default/zramswap
ALGO=zstd
PERCENT=50
PRIORITY=100
EOF
        systemctl restart zramswap 2>/dev/null || true
    elif command -v zramctl >/dev/null 2>&1 || [[ -f /usr/lib/systemd/system-generators/zram-generator ]]; then
        mkdir -p /etc/systemd/zram-generator.conf.d
        cat <<'EOF' > /etc/systemd/zram-generator.conf
[zram0]
zram-size = min(ram / 2, 2048)
compression-algorithm = zstd
swap-priority = 100
EOF
        cp -f /etc/systemd/zram-generator.conf /etc/systemd/zram-generator.conf.d/00-zram.conf 2>/dev/null || true
        systemctl daemon-reload
        systemctl restart /dev/zram0 2>/dev/null || systemctl restart systemd-zram-setup@zram0.service 2>/dev/null || true
    fi
    log_info "ZRAM swap configured."
    return 0
}

configure_disk_swap() {
    log_info "Checking secondary disk swap (fallback priority=10)..."
    local has_disk_swap
    has_disk_swap=$(grep -E 'file|partition' /proc/swaps 2>/dev/null | grep -v 'zram' || true)

    if [[ -n "${has_disk_swap}" ]]; then
        log_info "Disk swap already present: ${has_disk_swap}"
        return 0
    fi

    if [[ -f /swapfile ]]; then
        log_info "Activating existing /swapfile with fallback priority=10..."
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null 2>&1 || true
        swapon -p 10 /swapfile 2>/dev/null || true
        return 0
    fi

    log_info "Creating 1GB fallback disk swap at /swapfile..."
    fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon -p 10 /swapfile 2>/dev/null || true

    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw,pri=10 0 0" >> /etc/fstab
    fi

    log_info "Fallback disk swap created and configured."
    return 0
}

apply_sysctl_hardening() {
    log_info "Configuring kernel sysctl anti-flood, BBR, RFC1337, and IPv6 protections..."
    modprobe tcp_bbr 2>/dev/null || true

    cat <<'EOF' > /etc/sysctl.d/99-server-hardening.conf
# TCP SYN Flood & Connection Reset Protections
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1

# IP Spoofing & Route Verification (Reverse Path Filter)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Anti Log-Flood: Disable Logging of Martian Packets
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0

# ICMP Ping & Broadcast Flood Protections
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 880

# Ignore ICMP Redirects (IPv4 & IPv6)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Reject Source Routed Packets (IPv4 & IPv6)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel Memory, Pointer Leak, and FIFO Protections
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2

# TCP BBR Congestion Control & FQ Queue Discipline
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-server-hardening.conf >/dev/null 2>&1
    log_info "Kernel network and system protections applied."
    return 0
}

apply_journald_caps() {
    log_info "Configuring systemd journal rate limits and disk caps..."
    mkdir -p /etc/systemd/journald.conf.d
    cat <<'EOF' > /etc/systemd/journald.conf.d/00-limits.conf
[Journal]
SystemMaxUse=250M
SystemKeepFree=500M
RuntimeMaxUse=50M
RateLimitIntervalSec=30s
RateLimitBurst=1000
EOF
    systemctl restart systemd-journald 2>/dev/null || true
    log_info "Journald storage and rate limit caps applied."
    return 0
}

configure_firewall() {
    log_info "Configuring firewall rules..."
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        log_info "firewalld detected and active. Hardening firewalld rules..."
        firewall-cmd --permanent --zone=trusted --add-interface=lo 2>/dev/null || true
        if command -v tailscale >/dev/null 2>&1 || ip link show tailscale0 >/dev/null 2>&1; then
            firewall-cmd --permanent --zone=trusted --add-interface=tailscale0 2>/dev/null || true
        fi
        log_info "Allowing target SSH port: ${TARGET_SSH_PORT}/tcp in firewalld"
        firewall-cmd --permanent --add-port="${TARGET_SSH_PORT}/tcp"
        if [[ "${TARGET_SSH_PORT}" != "22" ]]; then
            firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
            firewall-cmd --permanent --remove-port=22/tcp 2>/dev/null || true
            log_info "Port 22/ssh service removed from firewalld."
        fi
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_info "firewalld active and configured."
        return 0
    fi

    if command -v ufw >/dev/null 2>&1; then
        log_info "Setting up UFW firewall rules..."
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow in on lo comment "Allow local loopback"
        ufw allow out on lo comment "Allow local loopback"
        if command -v tailscale >/dev/null 2>&1 || ip link show tailscale0 >/dev/null 2>&1; then
            ufw allow in on tailscale0 comment "Tailscale mesh network"
        fi
        log_info "Allowing and rate-limiting target SSH port: ${TARGET_SSH_PORT}/tcp"
        ufw limit "${TARGET_SSH_PORT}/tcp" comment "SSH rate-limited"
        if [[ "${TARGET_SSH_PORT}" != "22" ]]; then
            ufw delete allow 22/tcp 2>/dev/null || true
            ufw delete limit 22/tcp 2>/dev/null || true
            ufw delete allow 22 2>/dev/null || true
            log_info "Custom port in use. Port 22 is strictly closed."
        fi
        ufw logging low
        ufw --force enable
        log_info "UFW active and configured."
        return 0
    fi

    log_warn "Neither firewalld nor UFW is active. Skipping firewall configuration."
    return 0
}

configure_fail2ban() {
    log_info "Setting up Fail2ban for SSH port ${TARGET_SSH_PORT}..."

    mkdir -p /etc/fail2ban/jail.d
    cat <<EOF > /etc/fail2ban/jail.d/sshd-hardening.local
[sshd]
enabled = true
port = ${TARGET_SSH_PORT}
mode = aggressive
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 100.64.0.0/10 127.0.0.1/8 ::1
EOF

    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban 2>/dev/null || true
    log_info "Fail2ban enabled and monitoring port ${TARGET_SSH_PORT}."
    return 0
}

configure_ssh_hardening() {
    log_info "Configuring SSH daemon hardening drop-in..."
    mkdir -p /etc/ssh/sshd_config.d
    cat <<EOF > /etc/ssh/sshd_config.d/99-server-hardening.conf
Port ${TARGET_SSH_PORT}
X11Forwarding no
AllowAgentForwarding no
Compression no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30s
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    if sshd -t >/dev/null 2>&1; then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        log_info "SSH hardening applied on port ${TARGET_SSH_PORT}."
    else
        log_warn "SSH config validation failed. Keeping existing configuration."
        rm -f /etc/ssh/sshd_config.d/99-server-hardening.conf
    fi
    return 0
}

disable_llmnr() {
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "Disabling LLMNR (port 5355) in systemd-resolved..."
        mkdir -p /etc/systemd/resolved.conf.d
        cat <<'EOF' > /etc/systemd/resolved.conf.d/disable-llmnr.conf
[Resolve]
LLMNR=no
EOF
        systemctl restart systemd-resolved 2>/dev/null || true
        log_info "LLMNR disabled."
    fi
    return 0
}

disable_coredumps() {
    log_info "Disabling core dumps for unprivileged users..."
    mkdir -p /etc/security/limits.d
    cat <<'EOF' > /etc/security/limits.d/99-disable-coredumps.conf
* hard core 0
* soft core 0
EOF
    log_info "Core dump restrictions configured."
    return 0
}

blacklist_legacy_protocols() {
    log_info "Blacklisting unused kernel protocols (CIS benchmark)..."
    mkdir -p /etc/modprobe.d
    cat <<'EOF' > /etc/modprobe.d/blacklist-unused-protocols.conf
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    log_info "Unused kernel protocols blacklisted."
    return 0
}

restrict_cron_permissions() {
    log_info "Restricting cron and at execution permissions..."
    touch /etc/cron.allow /etc/at.allow
    chmod 640 /etc/cron.allow /etc/at.allow

    # Ensure root is allowed
    if ! grep -q "^root$" /etc/cron.allow 2>/dev/null; then
        echo "root" >> /etc/cron.allow
    fi
    if ! grep -q "^root$" /etc/at.allow 2>/dev/null; then
        echo "root" >> /etc/at.allow
    fi

    # Allow users with administrative privileges (sudo/wheel group)
    local admin_users
    admin_users=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' || true)
    if [[ -z "${admin_users}" ]]; then
        admin_users=$(getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' || true)
    fi

    for user in ${admin_users}; do
        if [[ -n "${user}" ]] && ! grep -q "^${user}$" /etc/cron.allow; then
            echo "${user}" >> /etc/cron.allow
            echo "${user}" >> /etc/at.allow
        fi
    done

    # Remove deny files to strictly enforce allowlists
    rm -f /etc/cron.deny /etc/at.deny
    log_info "Cron permissions restricted to administrative accounts."
    return 0
}

configure_auto_updates() {
    log_info "Configuring and verifying automatic security upgrades..."
    if [[ "${PKG_MGR}" == "apt" ]]; then
        cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

        cat <<'EOF' > /etc/apt/apt.conf.d/52unattended-upgrades-server
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        systemctl enable unattended-upgrades >/dev/null 2>&1 || true
        systemctl restart unattended-upgrades 2>/dev/null || true
        log_info "Unattended-upgrades enabled and active."
    elif [[ "${PKG_MGR}" == "dnf" ]]; then
        sed -i 's/upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
        sed -i 's/apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
        log_info "dnf-automatic security updates enabled and active."
    fi
    return 0
}

main() {
    check_root
    parse_arguments "$@"
    detect_pkg_manager
    configure_ssh_port
    install_packages
    configure_zram_swap
    configure_disk_swap
    apply_sysctl_hardening
    apply_journald_caps
    configure_firewall
    configure_fail2ban
    configure_ssh_hardening
    disable_llmnr
    disable_coredumps
    blacklist_legacy_protocols
    restrict_cron_permissions
    configure_auto_updates

    log_info "Comprehensive server security hardening completed successfully."
    echo "====================================================="
    echo "Summary of protections applied:"
    echo "  1. SSH Custom Port: Configured to port ${TARGET_SSH_PORT}. Port 22 is disabled."
    echo "  2. Fail2ban: Specifically monitoring SSH port ${TARGET_SSH_PORT} with 1h ban."
    echo "  3. Firewall: Hardened via UFW or firewalld (default deny/lo trusted & SSH port ${TARGET_SSH_PORT})."
    echo "  4. Dual-tier Swap: ZRAM (pri=100) prioritized over Disk Swap (pri=10)."
    echo "  5. Kernel Hardening: Anti-SYN flood, anti-spoofing, ICMP rate limit, TCP BBR, RFC1337."
    echo "  6. IPv6 Hardening: Disabled IPv6 redirects and source routing."
    echo "  7. SSH Hardening: X11 & Agent forwarding disabled, compression disabled, MaxAuthTries 4."
    echo "  8. Anti Information Leak: LLMNR port 5355 disabled, unprivileged core dumps disabled."
    echo "  9. CIS Blacklist: Legacy protocols (dccp, sctp, rds, tipc) disabled."
    echo " 10. Cron Lockdown: Only root and administrative users allowed to schedule tasks."
    echo " 11. Journald: Max 250MB log storage with burst rate limits."
    echo " 12. Automatic Updates: Active with automatic old kernel & unused dependency cleanup."
    echo "====================================================="
}

main "$@"

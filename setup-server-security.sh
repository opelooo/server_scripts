#!/usr/bin/env bash
#
# Generic Linux Server Security Hardening Script
# Target: Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux
# Scope: Basic Security, Anti-Flood Sysctl, Journald, Fail2ban, Auto-Updates,
#        Dual-Tier Swap (ZRAM priority 100 > Disk Swap priority 10),
#        SSH Hardening, Disable LLMNR, Disable Core Dumps, Kernel Protocol Blacklist.
#
set -euo pipefail

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

detect_ssh_ports() {
    local detected_ports=()

    # Read ports from active listening sockets
    while IFS= read -r port; do
        if [[ -n "${port}" ]]; then
            detected_ports+=("${port}")
        fi
    done < <(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)

    # Read ports from sshd_config
    while IFS= read -r port; do
        if [[ -n "${port}" ]]; then
            detected_ports+=("${port}")
        fi
    done < <(grep -rhE "^Port [0-9]+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | sort -u)

    # Fallback to standard port 22 if none detected
    if [[ ${#detected_ports[@]} -eq 0 ]]; then
        detected_ports=(22)
    fi

    # Deduplicate ports
    SSH_PORTS=($(echo "${detected_ports[@]}" | tr ' ' '\n' | sort -un | tr '\n' ' '))
    log_info "Detected active SSH ports: ${SSH_PORTS[*]}"
    return 0
}

install_packages() {
    log_info "Updating package lists and installing required utilities..."
    if [[ "${PKG_MGR}" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq ufw fail2ban unattended-upgrades curl iproute2 zram-tools
    elif [[ "${PKG_MGR}" == "dnf" ]]; then
        dnf install -y -q epel-release || true
        dnf install -y -q ufw fail2ban curl iproute zram-generator
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
    elif command -v zramctl >/dev/null 2>&1; then
        mkdir -p /etc/systemd/zram-generator.conf.d
        cat <<'EOF' > /etc/systemd/zram-generator.conf.d/00-zram.conf
[zram0]
zram-size = min(ram / 2, 2048)
compression-algorithm = zstd
swap-priority = 100
EOF
        systemctl daemon-reload
        systemctl restart systemd-zram-setup@zram0.service 2>/dev/null || true
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
    log_info "Configuring kernel sysctl anti-flood, BBR, and network protections..."
    modprobe tcp_bbr 2>/dev/null || true

    cat <<'EOF' > /etc/sysctl.d/99-server-hardening.conf
# TCP SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

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

# Ignore ICMP Redirects (Mitigate MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Reject Source Routed Packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Kernel Memory and Pointer Leak Protections
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0

# TCP BBR Congestion Control & FQ Queue Discipline
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-server-hardening.conf >/dev/null 2>&1
    log_info "Kernel network hardening applied."
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

configure_ufw() {
    log_info "Setting up UFW rules..."
    ufw --force reset >/dev/null 2>&1 || true

    ufw default deny incoming
    ufw default allow outgoing

    # Limit incoming SSH ports to mitigate brute force
    for port in "${SSH_PORTS[@]}"; do
        log_info "Allowing and rate-limiting SSH port: ${port}/tcp"
        ufw limit "${port}/tcp" comment "SSH rate-limited"
    done

    # Suppress log flooding: set UFW logging to low
    ufw logging low

    # Enable UFW non-interactively
    ufw --force enable
    log_info "UFW active and configured."
    return 0
}

configure_fail2ban() {
    log_info "Setting up Fail2ban with SSH protection..."
    local ports_str
    ports_str=$(echo "${SSH_PORTS[@]}" | tr ' ' ',')

    mkdir -p /etc/fail2ban/jail.d
    cat <<EOF > /etc/fail2ban/jail.d/sshd-hardening.local
[sshd]
enabled = true
port = ${ports_str}
mode = aggressive
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8 ::1
EOF

    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban 2>/dev/null || true
    log_info "Fail2ban enabled and monitoring SSH."
    return 0
}

configure_ssh_hardening() {
    log_info "Configuring SSH daemon hardening drop-in..."
    mkdir -p /etc/ssh/sshd_config.d
    cat <<'EOF' > /etc/ssh/sshd_config.d/99-server-hardening.conf
X11Forwarding no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30s
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    if sshd -t >/dev/null 2>&1; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        log_info "SSH hardening applied and daemon reloaded."
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

configure_auto_updates() {
    if [[ "${PKG_MGR}" == "apt" ]]; then
        log_info "Enabling unattended security upgrades..."
        cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        systemctl enable unattended-upgrades >/dev/null 2>&1 || true
        systemctl restart unattended-upgrades 2>/dev/null || true
        log_info "Unattended security upgrades enabled."
    fi
    return 0
}

main() {
    check_root
    detect_pkg_manager
    detect_ssh_ports
    install_packages
    configure_zram_swap
    configure_disk_swap
    apply_sysctl_hardening
    apply_journald_caps
    configure_ufw
    configure_fail2ban
    configure_ssh_hardening
    disable_llmnr
    disable_coredumps
    blacklist_legacy_protocols
    configure_auto_updates

    log_info "All security and hardening setups completed successfully."
    echo "====================================================="
    echo "Summary of protections applied:"
    echo "  1. Dual-tier Swap: ZRAM (pri=100) prioritized over Disk Swap (pri=10)."
    echo "  2. UFW Firewall: Default deny incoming, allowed SSH ports (${SSH_PORTS[*]}), log low."
    echo "  3. Kernel Hardening: Anti-SYN flood, anti-spoofing, ICMP rate limit, martian log disabled, TCP BBR enabled."
    echo "  4. SSH Hardening: X11 forwarding disabled, root password login disabled, MaxAuthTries 4."
    echo "  5. Anti Information Leak: LLMNR port 5355 disabled, core dumps disabled."
    echo "  6. CIS Blacklist: Legacy protocols (dccp, sctp, rds, tipc) disabled."
    echo "  7. Journald: Max 250MB log storage with rate limits to prevent disk exhaustion."
    echo "  8. Fail2ban: Monitoring SSH on ports ${SSH_PORTS[*]} with 1h ban."
    echo "  9. Automatic Updates: Enabled for security patches."
    echo "====================================================="
}

main "$@"

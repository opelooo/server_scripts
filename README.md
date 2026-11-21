# Server Scripts

Koleksi script otomatisasi dan hardening keamanan untuk server Linux (Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux).

## Isi Repositori

### 1. `setup-server-security.sh`
Script hardening keamanan dan optimalisasi server Linux komprehensif:
* **Dual-Tier Swap**: Mengutamakan **ZRAM** (prioritas 100) di RAM terlebih dahulu, dengan fallback **Disk Swap** (prioritas 10) jika memori fisik penuh untuk mencegah crash OOM.
* **UFW Firewall**: Default deny incoming, default allow outgoing, dengan level log `low` agar tidak membanjiri disk.
* **Dynamic SSH Rate Limiting**: Mendeteksi port SSH aktif dinamis (22, 2291, dll.) dan menerapkan aturan `ufw limit`.
* **SSH Daemon Hardening**: Mematikan X11 forwarding, menonaktifkan login password root (`prohibit-password`), membatasi `MaxAuthTries 4`, dan menyetel timeout idle.
* **Kernel Sysctl Hardening**: Proteksi SYN flood, anti IP spoofing (`rp_filter`), ICMP ping rate limit, menonaktifkan logging martian packet, serta mengaktifkan **TCP BBR** + FQ qdisc.
* **Anti-Information Leak**: Menonaktifkan LLMNR (port 5355 `systemd-resolved`) dan menonaktifkan coredump untuk unprivileged user.
* **CIS Protocol Blacklist**: Menutup modul protokol jaringan lawas yang rentan CVE (`dccp`, `sctp`, `rds`, `tipc`).
* **Journald Log Cap**: Membatasi ukuran log systemd hingga 250 MB dengan rate limiting burst.
* **Fail2ban**: Mengawasi port SSH dengan ban 1 jam setelah 5 kali gagal autentikasi.
* **Unattended Upgrades**: Memasang patch keamanan distro secara otomatis di latar belakang.

#### Penggunaan
```bash
# Langsung via cURL (dari GitHub)
curl -sL https://raw.githubusercontent.com/opelooo/server_scripts/main/setup-server-security.sh | sudo bash

# Atau eksekusi lokal
sudo ./setup-server-security.sh
```

---

### 2. `setup-tailscale-relay.sh`
Script add-on opsional untuk server yang ingin difungsikan sebagai **Tailscale Peer Relay**:
* Membuka akses interface `tailscale0` di UFW.
* Membuka port UDP relay (default: `41641/udp`).
* Menambahkan subnet CGNAT Tailscale (`100.64.0.0/10`) ke whitelist Fail2ban.
* Mengaktifkan client relay port via `tailscale set --relay-server-port`.

#### Penggunaan
```bash
# Menggunakan port default 41641
sudo ./setup-tailscale-relay.sh

# Atau menggunakan port UDP custom
sudo ./setup-tailscale-relay.sh 34780
```

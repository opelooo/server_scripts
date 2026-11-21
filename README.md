# Server Scripts

Koleksi script otomatisasi dan hardening keamanan untuk server Linux (Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux).

## Isi Repositori

### 1. `setup-server-security.sh`
Script hardening keamanan dan optimalisasi server Linux komprehensif:
* **Dual-Tier Swap**: Mengutamakan **ZRAM** (prioritas 100) di RAM terlebih dahulu, dengan fallback **Disk Swap** (prioritas 10) jika memori fisik penuh untuk mencegah crash OOM.
* **UFW Firewall**: Default deny incoming, default allow outgoing, eksplisit allow pada loopback (`lo`), serta level log `low` agar tidak membanjiri disk.
* **Dynamic SSH Rate Limiting**: Mendeteksi port SSH aktif dinamis (22, 2291, dll.) dan menerapkan aturan `ufw limit`.
* **SSH Daemon Hardening**: Mematikan X11 forwarding, menonaktifkan agent forwarding, mematikan kompresi (anti side-channel), menonaktifkan login password root (`prohibit-password`), membatasi `MaxAuthTries 4`, dan menyetel timeout idle.
* **Kernel Sysctl Hardening**: Proteksi SYN flood, anti IP spoofing (`rp_filter`), ICMP ping rate limit, RFC 1337 TIME-WAIT protection, strict FIFO file protection di `/tmp`, menonaktifkan logging martian packet, serta mengaktifkan **TCP BBR** + FQ qdisc.
* **IPv6 Security**: Menonaktifkan IPv6 redirects dan source-routed packets untuk mencegah serangan man-in-the-middle / rogue router.
* **Anti-Information Leak**: Menonaktifkan LLMNR (port 5355 `systemd-resolved`) dan menonaktifkan coredump untuk unprivileged user.
* **CIS Protocol Blacklist**: Menutup modul protokol jaringan lawas yang rentan CVE (`dccp`, `sctp`, `rds`, `tipc`).
* **Cron & At Lockdown**: Membatasi pembuatan jadwal crontab hanya untuk user `root` dan member grup administrative (`sudo`/`wheel`), mencegah persistensi malware pada akun service (`www-data`, `nobody`).
* **Journald Log Cap**: Membatasi ukuran log systemd hingga 250 MB dengan rate limiting burst.
* **Fail2ban**: Mengawasi port SSH dengan ban 1 jam setelah 5 kali gagal autentikasi.
* **Automatic Security Updates**: Memastikan `unattended-upgrades` (Debian/Ubuntu) atau `dnf-automatic` (RHEL) aktif berjalan, serta otomatis membersihkan kernel usang dan dependensi yang tidak terpakai agar disk tidak penuh.

#### Penggunaan

**Opsi 1: Dari Gitea Pribadi**
```bash
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-server-security.sh | sudo bash
```

**Opsi 2: Dari GitHub**
```bash
curl -sL https://raw.githubusercontent.com/opelooo/server_scripts/main/setup-server-security.sh | sudo bash
```

**Opsi 3: Eksekusi Lokal**
```bash
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

**Dari Gitea Pribadi:**
```bash
# Port default 41641
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-tailscale-relay.sh | sudo bash

# Port custom (misal 34780)
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-tailscale-relay.sh | sudo bash -s 34780
```

**Dari GitHub:**
```bash
curl -sL https://raw.githubusercontent.com/opelooo/server_scripts/main/setup-tailscale-relay.sh | sudo bash
```

**Eksekusi Lokal:**
```bash
sudo ./setup-tailscale-relay.sh
```

# Server Scripts

Koleksi script otomatisasi dan hardening keamanan untuk server Linux.

## Isi Repositori

### 1. `setup-server-security.sh`
Script hardening keamanan dasar (pure security) untuk distribusi Linux Debian, Ubuntu, CentOS, AlmaLinux, dan RockyLinux.
* **UFW Firewall**: Default deny incoming, default allow outgoing.
* **Dynamic SSH Rate Limiting**: Mendeteksi port SSH aktif dinamis (22, 2291, dll.) dan menerapkan `ufw limit`.
* **Kernel Sysctl Hardening**: Proteksi SYN flood, anti IP spoofing, ICMP rate limiting, dan menonaktifkan log martian packet untuk mencegah log-flooding.
* **Journald Log Cap**: Membatasi ukuran log systemd hingga 250 MB dan memasang rate limiting agar disk VPS tidak penuh.
* **Fail2ban**: Menjaga port SSH dengan ban 1 jam setelah 5 kali gagal autentikasi.
* **Unattended Upgrades**: Memasang patch keamanan otomatis.

#### Penggunaan
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
```bash
# Menggunakan port default 41641
sudo ./setup-tailscale-relay.sh

# Atau menggunakan port UDP custom
sudo ./setup-tailscale-relay.sh 34780
```

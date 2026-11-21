# Server Scripts

Koleksi script otomatisasi dan hardening keamanan untuk server Linux (Debian, Ubuntu, RHEL, AlmaLinux, RockyLinux).

## Isi Repositori

### 1. `setup-server-security.sh`
Script hardening keamanan dan optimalisasi server Linux komprehensif:
* **Custom SSH Port Migration**: Opsi mengubah port SSH dari default 22 ke port custom (misal 2291). Port 22 ditutup total di firewall dan sshd.
* **Fail2ban Dedicated Port**: Memantau secara spesifik port SSH custom yang aktif dengan ban 1 jam setelah 5 kali gagal autentikasi.
* **Dual-Tier Swap**: Mengutamakan **ZRAM** (prioritas 100) di RAM terlebih dahulu, dengan fallback **Disk Swap** (prioritas 10) jika memori fisik penuh untuk mencegah crash OOM.
* **UFW Firewall**: Default deny incoming, default allow outgoing, eksplisit allow pada loopback (`lo`), membuka port SSH custom (dan menutup port 22), serta level log `low`.
* **SSH Daemon Hardening**: Mematikan X11 forwarding, menonaktifkan agent forwarding, mematikan kompresi (anti side-channel), menonaktifkan login password root (`prohibit-password`), membatasi `MaxAuthTries 4`, dan menyetel timeout idle.
* **Kernel Sysctl Hardening**: Proteksi SYN flood, anti IP spoofing (`rp_filter`), ICMP ping rate limit, RFC 1337 TIME-WAIT protection, strict FIFO file protection di `/tmp`, menonaktifkan logging martian packet, serta mengaktifkan **TCP BBR** + FQ qdisc.
* **IPv6 Security**: Menonaktifkan IPv6 redirects dan source-routed packets untuk mencegah serangan man-in-the-middle / rogue router.
* **Anti-Information Leak**: Menonaktifkan LLMNR (port 5355 `systemd-resolved`) dan menonaktifkan coredump untuk unprivileged user.
* **CIS Protocol Blacklist**: Menutup modul protokol jaringan lawas yang rentan CVE (`dccp`, `sctp`, `rds`, `tipc`).
* **Cron & At Lockdown**: Membatasi pembuatan jadwal crontab hanya untuk user `root` dan member grup administrative (`sudo`/`wheel`).
* **Journald Log Cap**: Membatasi ukuran log systemd hingga 250 MB dengan rate limiting burst.
* **Automatic Security Updates**: Memastikan `unattended-upgrades` (Debian/Ubuntu) atau `dnf-automatic` (RHEL) aktif berjalan, serta otomatis membersihkan kernel usang dan dependensi yang tidak terpakai agar disk tidak penuh.

#### Penggunaan

**Eksekusi dengan Port SSH Custom (Misal Port 2291):**
```bash
# Melalui Gitea Pribadi
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-server-security.sh | sudo bash -s -- --ssh-port 2291

# Melalui GitHub
curl -sL https://raw.githubusercontent.com/opelooo/server_scripts/main/setup-server-security.sh | sudo bash -s -- --ssh-port 2291
```

**Eksekusi Tanpa Parameter (Otomatis Mendeteksi Port yang Ada):**
```bash
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-server-security.sh | sudo bash
```

---

### 2. `setup-user-shell.sh`
Script serbaguna untuk mengganti default login shell user dengan berbagai pilihan shell modern dan hemat memori:
* **Pilihan Shell yang Didukung**:
  * `fish` - Friendly Interactive Shell (autosuggestions, syntax highlighting).
  * `zsh` - Z Shell (ekstensibel, prompt berwarna, autocompletion menu).
  * `bash` - Bourne Again Shell (dilengkapi alias modern `ll`, `la`).
  * `nushell` - Shell data terstruktur berbasis Rust (tabel interaktif & pipelines).
  * `mksh` - MirBSD KornShell (ultra-ringan, RAM < 1 MB).
  * `tcsh` - TENEX C Shell.
* **Mode Interaktif**: Jika dijalankan di terminal, menampilkan menu pemilihan bernomor [1-6].
* **Integrasi Starship Prompt**: Opsi flag `--starship` untuk memasang prompt lintas-shell modern secara otomatis.

#### Penggunaan

**1. Mode Menu Interaktif (Tampil Pilihan 1-6):**
```bash
sudo ./setup-user-shell.sh
```

**2. Langsung Memilih Shell Tertentu via cURL:**
```bash
# Ganti ke Fish
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-user-shell.sh | sudo bash -s -- fish

# Ganti ke ZSH
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-user-shell.sh | sudo bash -s -- zsh

# Ganti ke Nushell
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-user-shell.sh | sudo bash -s -- nushell

# Ganti ke MKSH (Ultra-ringan)
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-user-shell.sh | sudo bash -s -- mksh
```

**3. Ganti Shell Sekaligus Pasang Starship Prompt:**
```bash
curl -sL https://git.opelooo.uk/opelooo/server_scripts/raw/branch/main/setup-user-shell.sh | sudo bash -s -- fish --starship
```

**4. Menentukan User Tertentu:**
```bash
sudo ./setup-user-shell.sh zsh --user opelooo
```

---

### 3. `setup-tailscale-relay.sh`
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

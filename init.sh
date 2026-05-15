#!/bin/bash
# =============================================================
#  init.sh — Replaces Dockerfile build steps, runs at container start
#  Setara dengan semua RUN command di Dockerfile
#  Base image: php:8.2-fpm-trixie
# =============================================================
set -e

FLAG_FILE="/var/run/ctf_setup_done"

# -------------------------------------------------------
# Jalankan setup hanya sekali per container lifecycle
# (skip jika container di-restart, bukan di-recreate)
# -------------------------------------------------------
if [ ! -f "$FLAG_FILE" ]; then

    echo "[*] =============================================="
    echo "[*]  CTF Lab Init — First-time setup starting..."
    echo "[*] =============================================="

    # -------------------------------------------------------
    # 1. Install dependency (setara RUN apt-get install ...)
    # -------------------------------------------------------
    echo "[*] Installing packages: nginx, supervisor, openssh-server ..."

    # DEBIAN_FRONTEND=noninteractive → supaya dpkg tidak pernah minta input
    # --force-confold → jika ada konflik conffile (misal nginx.conf yang
    # sudah ter-mount via volume vs file bawaan paket), pertahankan file
    # yang sudah ada (file kita) tanpa prompt interaktif
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        -o Dpkg::Options::="--force-confold" \
        -o Dpkg::Options::="--force-confdef" \
        nginx \
        supervisor \
        openssh-server
    rm -rf /var/lib/apt/lists/*
    echo "[✓] Packages installed"

    # -------------------------------------------------------
    # 2. Buat user analyst (setara RUN useradd ...)
    #    Kredensial: analyst / blue_team_rocks | port 2275
    # -------------------------------------------------------
    if ! id "analyst" &>/dev/null; then
        useradd -m -s /bin/bash analyst
        echo "analyst:blue_team_rocks" | chpasswd
        echo "[✓] User analyst created"
    else
        echo "[~] User analyst sudah ada, skip"
    fi

    # -------------------------------------------------------
    # 3. Konfigurasi SSH (setara RUN mkdir + sed + echo ...)
    # -------------------------------------------------------
    mkdir -p /var/run/sshd

    # Ganti port 22 → 2275 (idempotent)
    sed -i 's/#Port 22/Port 2275/'                                       /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/'   /etc/ssh/sshd_config

    # Append konfigurasi tambahan (cek dulu agar tidak duplikat)
    grep -qxF 'PermitRootLogin no'   /etc/ssh/sshd_config || echo "PermitRootLogin no"   >> /etc/ssh/sshd_config
    grep -qxF 'X11Forwarding no'     /etc/ssh/sshd_config || echo "X11Forwarding no"     >> /etc/ssh/sshd_config
    grep -qxF 'PrintMotd no'         /etc/ssh/sshd_config || echo "PrintMotd no"         >> /etc/ssh/sshd_config
    echo "[✓] SSH configured on port 2275"

    # -------------------------------------------------------
    # 4. Direktori log CTF (setara RUN mkdir + chown + usermod)
    # -------------------------------------------------------
    mkdir -p /opt/admin/logs
    # www-data perlu write untuk buat feedback.db (SQLite)
    # analyst perlu read untuk forensik log via SSH
    chown root:www-data /opt/admin/logs
    chmod 775 /opt/admin/logs
    usermod -aG www-data analyst   # analyst bisa baca log di /opt/admin/logs
    echo "[✓] Log directory /opt/admin/logs ready"

    # -------------------------------------------------------
    # 5. Nginx — aktifkan site config (setara RUN ln -sf ...)
    #    nginx.conf di-mount via volume ke sites-available/default
    # -------------------------------------------------------
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    echo "[✓] Nginx site enabled"

    # -------------------------------------------------------
    # 5b. Konfigurasi PHP-FPM — pakai Unix socket, bukan port 9000
    #     Host pakai port 9000 → konflik jika network_mode: host
    #     Unix socket tidak punya konflik port sama sekali
    #
    #     Di base image php:8.2-fpm-trixie, listen aktif ada di:
    #       /usr/local/etc/php-fpm.d/docker.conf (listen = 9000)
    # -------------------------------------------------------
    PHP_DOCKER_CONF="/usr/local/etc/php-fpm.d/docker.conf"
    if [ -f "$PHP_DOCKER_CONF" ]; then
        sed -i 's|^listen = .*|listen = /run/php-fpm.sock|' "$PHP_DOCKER_CONF"
        echo "[✓] PHP-FPM configured: unix:/run/php-fpm.sock (via docker.conf)"
    else
        echo "[!] PHP-FPM docker.conf tidak ditemukan: $PHP_DOCKER_CONF"
    fi

    # Tambahan: aktifkan listen.owner/group agar nginx (www-data) bisa akses socket
    PHP_POOL="/usr/local/etc/php-fpm.d/www.conf"
    if [ -f "$PHP_POOL" ]; then
        sed -i 's|^;listen.owner = .*|listen.owner = www-data|' "$PHP_POOL"
        sed -i 's|^;listen.group = .*|listen.group = www-data|' "$PHP_POOL"
        sed -i 's|^;listen.mode = .*|listen.mode = 0660|'       "$PHP_POOL"
        echo "[✓] PHP-FPM socket permissions set (www-data)"
    fi

    # -------------------------------------------------------
    # 6. Permissions web root (setara RUN chown www-data ...)
    #    index.php dan robots.txt di-mount :ro via volume
    #    → tidak bisa chown file langsung, cukup set ownership
    #    pada direktori parent (/var/www/html) saja
    # -------------------------------------------------------
    chown www-data:www-data /var/www/html
    chown -R www-data:www-data /var/www/html 2>/dev/null || true
    echo "[✓] Web root ownership set"

    # -------------------------------------------------------
    # 7. Tandai setup sudah selesai
    # -------------------------------------------------------
    touch "$FLAG_FILE"
    echo "[✓] Setup complete — flag written to $FLAG_FILE"
    echo "[*] =============================================="

else
    echo "[~] Setup sudah pernah dijalankan (container restart) — skip install"
fi

# -------------------------------------------------------
# 8. Inject simulated attack logs (setara entrypoint.sh)
#    inject_logs.py di-mount via volume ke /usr/local/bin/
# -------------------------------------------------------
echo "[*] Injecting CTF attack logs into /opt/admin/logs ..."
python3 /usr/local/bin/inject_logs.py

# -------------------------------------------------------
# 9. Start semua service via supervisord
#    supervisord.conf di-mount via volume
# -------------------------------------------------------
echo "[*] Starting all services via supervisord ..."
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/ctf.conf

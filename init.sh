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
    apt-get update -qq
    apt-get install -y --no-install-recommends \
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
    chown root:root /opt/admin/logs
    chmod 775 /opt/admin/logs
    usermod -aG root analyst
    echo "[✓] Log directory /opt/admin/logs ready"

    # -------------------------------------------------------
    # 5. Nginx — aktifkan site config (setara RUN ln -sf ...)
    #    nginx.conf di-mount via volume ke sites-available/default
    # -------------------------------------------------------
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    echo "[✓] Nginx site enabled"

    # -------------------------------------------------------
    # 6. Permissions web root (setara RUN chown www-data ...)
    #    index.php dan robots.txt sudah ter-mount via volume
    # -------------------------------------------------------
    chown -R www-data:www-data /var/www/html
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

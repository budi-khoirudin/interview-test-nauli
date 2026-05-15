FROM php:8.2-fpm

# =============================================================
#  Single-container CTF Lab
#  Stack: Nginx + PHP-FPM + OpenSSH + Python3
#  Semua service dikelola oleh supervisord
# =============================================================

# Install semua dependency sekaligus dalam 1 layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nginx \
        supervisor \
        openssh-server && \
    rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------
# Buat user analyst untuk Blue Team SSH
# Kredensial: analyst / blue_team_rocks | port 2275
# -------------------------------------------------------
RUN useradd -m -s /bin/bash analyst && \
    echo "analyst:blue_team_rocks" | chpasswd

# Konfigurasi SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#Port 22/Port 2275/'                              /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitRootLogin no"      >> /etc/ssh/sshd_config && \
    echo "X11Forwarding no"        >> /etc/ssh/sshd_config && \
    echo "PrintMotd no"            >> /etc/ssh/sshd_config

# -------------------------------------------------------
# Direktori log CTF — bisa diakses analyst dan www-data
# -------------------------------------------------------
RUN mkdir -p /opt/admin/logs && \
    chown root:root /opt/admin/logs && \
    chmod 775 /opt/admin/logs && \
    usermod -aG root analyst

# -------------------------------------------------------
# Nginx — salin config & file aplikasi
# -------------------------------------------------------
COPY nginx.conf   /etc/nginx/sites-available/default
RUN  ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

COPY index.php    /var/www/html/index.php
COPY robots.txt   /var/www/html/robots.txt
RUN  chown -R www-data:www-data /var/www/html

# -------------------------------------------------------
# Log injector — dijalankan sekali saat container start
# -------------------------------------------------------
COPY inject_logs.py /usr/local/bin/inject_logs.py
RUN  chmod +x /usr/local/bin/inject_logs.py

# -------------------------------------------------------
# Supervisor — orkestrasi semua proses
# -------------------------------------------------------
COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf

# -------------------------------------------------------
# Entrypoint: inject log dulu, lalu supervisor naik
# -------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN  chmod +x /entrypoint.sh

# Port: 80 (web) + 2275 (SSH)
EXPOSE 80 2275

ENTRYPOINT ["/entrypoint.sh"]

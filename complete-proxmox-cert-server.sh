#!/usr/bin/env bash

# Copyright (c) 2021-2025 Enhanced Certificate Server LXC
# Author: Iain Reid, based on tteck methodology
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: Enhanced Certificate Server with Auto-Approval and VLAN Support

# This script creates a Proxmox LXC container for the Enhanced Certificate Server

# App Default Values
APP="Certificate Server"
var_tags="certificate;ssl;tls;ca;security"
var_cpu="2"
var_ram="2048"
var_disk="8"
var_os="debian"
var_version="12"
var_unprivileged="1"

# Color definitions
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="\\033[1m\\033[91m[\\033[1m\\033[96m⌚\\033[1m\\033[91m]\\033[1m\\033[36m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Variables
VERBOSE="no"
SSH_ROOT="yes"
CTID=""
PCT_OSTYPE="$var_os"
PCT_OSVERSION="$var_version"
PCT_DISK_SIZE="$var_disk"
PCT_OPTIONS=""
TEMPLATE_STORAGE="local"
MSG_MAX_LENGTH=0
STORAGE_MENU=()

# Set Temp Dir
if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC" --yesno "This will create a New ${APP} LXC. Proceed?" 10 58); then
    :
else
    clear
    echo -e "⚠ User exited script \n"
    exit
fi

function header_info() {
    clear
    cat <<"EOF"
    ____          _   _  __ _           _         ____                           
   / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
  | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
  | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
   \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   
                                                                                
EOF
    echo -e "                Enhanced ${APP} LXC Container"
    echo ""
}

function msg_info() {
    local msg="$1"
    echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
    local msg="$1"
    echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function PVE_CHECK() {
    if [ $(pgrep -c -f pve-firewall) != 0 ]; then
        if [ -e /etc/proxmox-release ]; then
            if [ "$(pveversion | cut -d'/' -f2 | cut -d'.' -f1)" -lt 7 ]; then
                echo -e "${CROSS} This script requires Proxmox VE 7.0 or higher"
                echo -e "Exiting..."
                sleep 3
                exit 1
            fi
        fi
    fi
}

function ARCH_CHECK() {
    if [ "$(dpkg --print-architecture)" != "amd64" ]; then
        echo -e "\n ${CROSS} This script will not work with PiMox! \n"
        echo -e "Exiting..."
        sleep 3
        exit 1
    fi
}

function exit-script() {
    clear
    echo -e "⚠ User exited script \n"
    exit 1
}

function default_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    # Default settings
    var_container="$CTID"
    var_hostname="cert-server"
    var_disk="$var_disk"
    var_cpu="$var_cpu"
    var_ram="$var_ram"
    var_bridge="vmbr0"
    var_ip="dhcp"
    var_gate=""
    var_ipv6=""
    var_mtu=""
    var_dns=""
    var_ns=""
    var_mac=""
    var_vlan=""
    var_ssh="yes"
    var_verbose="no"
    var_unprivileged="$var_unprivileged"
    var_nesting="1"
    var_password=""
    
    # Certificate Server specific defaults
    CERT_SERVER_PORT="8443"
    CERT_SERVER_HTTP_PORT="8080"
    WEB_ADMIN_USER="admin"
    WEB_ADMIN_PASS="$(openssl rand -base64 12)"
    VLAN_ID=""
    VLAN_INTERFACE=""
    
    clear
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL} ${RD}NO DEVICE PASSTHROUGH${CL}"
    echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
    echo -e "${DGN}Using Container ID: ${BGN}$CTID${CL}"
    echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
    echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
    echo -e "${DGN}Allocated Cores ${BGN}$var_cpu${CL}"
    echo -e "${DGN}Allocated Ram ${BGN}$var_ram${CL}"
    echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
    echo -e "${DGN}Using Static IP: ${BGN}$var_ip${CL}"
    echo -e "${DGN}Using Gateway: ${BGN}$var_gate${CL}"
    echo -e "${DGN}Disable IPv6: ${BGN}$var_ipv6${CL}"
    echo -e "${DGN}Using Interface MTU Size: ${BGN}$var_mtu${CL}"
    echo -e "${DGN}Using DNS Search Domain: ${BGN}$var_dns${CL}"
    echo -e "${DGN}Using DNS Server Address: ${BGN}$var_ns${CL}"
    echo -e "${DGN}Using MAC Address: ${BGN}$var_mac${CL}"
    echo -e "${DGN}Using VLAN Tag: ${BGN}$var_vlan${CL}"
    echo -e "${DGN}Enable Root SSH Access: ${BGN}yes${CL}"
    echo -e "${DGN}Enable Verbose Mode: ${BGN}no${CL}"
    echo -e "${DGN}Certificate Server HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    echo -e "${DGN}Certificate Server Admin User: ${BGN}$WEB_ADMIN_USER${CL}"
    echo -e "${BL}Creating a ${APP} LXC using the above default settings${CL}"
}

function advanced_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    clear
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    echo -e "${YW}Type Advanced, or Press [ENTER] for Default.${CL}"
    echo ""
    sleep 1

    case $(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER TYPE" --menu "\nChoose Type" 10 58 2 \
        "1" "Unprivileged (Recommended)" \
        "0" "Privileged" 3>&2 2>&1 1>&3) in
    1) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    0) var_unprivileged="0"; echo -e "${DGN}Using Container Type: ${BGN}Privileged${CL}" ;;
    *) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    esac

    if PW=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "PASSWORD" --passwordbox "\nSet Root Password (needed for root ssh access)" 9 58 3>&2 2>&1 1>&3); then
        if [[ ! -z "$PW" ]]; then
            var_password="-password $PW"
            echo -e "${DGN}Using Root Password: ${BGN}$PW${CL}"
        else
            var_password=""
            echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
        fi
    else
        exit-script
    fi

    if CT_ID=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER ID" --inputbox "\nSet Container ID" 9 58 $CTID 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_ID" ]]; then
            var_container="$CTID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        else
            var_container="$CT_ID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        fi
    else
        exit-script
    fi

    if CT_NAME=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HOSTNAME" --inputbox "\nSet Hostname" 9 58 "cert-server" 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_NAME" ]]; then
            var_hostname="cert-server"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        else
            var_hostname="$CT_NAME"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        fi
    else
        exit-script
    fi

    if DISK_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DISK SIZE" --inputbox "\nSet Disk Size in GB" 9 58 $var_disk 3>&2 2>&1 1>&3); then
        if [[ -z "$DISK_SIZE" ]]; then
            var_disk="$var_disk"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        else
            var_disk="$DISK_SIZE"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        fi
    else
        exit-script
    fi

    if CORE_COUNT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CORES" --inputbox "\nAllocate CPU Cores" 9 58 $var_cpu 3>&2 2>&1 1>&3); then
        if [[ -z "$CORE_COUNT" ]]; then
            var_cpu="$var_cpu"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        else
            var_cpu="$CORE_COUNT"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        fi
    else
        exit-script
    fi

    if RAM_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "RAM" --inputbox "\nAllocate RAM in MB" 9 58 $var_ram 3>&2 2>&1 1>&3); then
        if [[ -z "$RAM_SIZE" ]]; then
            var_ram="$var_ram"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        else
            var_ram="$RAM_SIZE"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        fi
    else
        exit-script
    fi

    if BRG=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "BRIDGE" --inputbox "\nSet a Bridge" 9 58 "vmbr0" 3>&2 2>&1 1>&3); then
        if [[ -z "$BRG" ]]; then
            var_bridge="vmbr0"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        else
            var_bridge="$BRG"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        fi
    else
        exit-script
    fi

    if NET=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "IP ADDRESS" --inputbox "\nSet a Static IPv4 CIDR Address(/24)" 9 58 dhcp 3>&2 2>&1 1>&3); then
        if [[ "$NET" == "dhcp" ]]; then
            var_ip="dhcp"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        else
            var_ip="$NET"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        fi
    else
        exit-script
    fi

    if GATE1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "GATEWAY" --inputbox "\nSet a Gateway IP (mandatory if Static IP was used)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$GATE1" ]]; then
            var_gate=""
            echo -e "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
        else
            var_gate=",gw=$GATE1"
            echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
        fi
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "IPv6" --yesno "\nDisable IPv6?" 9 58); then
        var_ipv6=""
        echo -e "${DGN}Disable IPv6: ${BGN}Yes${CL}"
    else
        var_ipv6=",ip6=dhcp"
        echo -e "${DGN}Disable IPv6: ${BGN}No${CL}"
    fi

    if MTU1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MTU SIZE" --inputbox "\nSet Interface MTU Size (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MTU1" ]]; then
            var_mtu=""
            echo -e "${DGN}Using Interface MTU Size: ${BGN}Default${CL}"
        else
            var_mtu=",mtu=$MTU1"
            echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU1${CL}"
        fi
    else
        exit-script
    fi

    if SD=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SEARCH DOMAIN" --inputbox "\nSet DNS Search Domain (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$SD" ]]; then
            SX=host
            var_dns=""
            echo -e "${DGN}Using DNS Search Domain: ${BGN}Host${CL}"
        else
            SX=$SD
            var_dns="-searchdomain $SD"
            echo -e "${DGN}Using DNS Search Domain: ${BGN}$SD${CL}"
        fi
    else
        exit-script
    fi

    if NX=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SERVER IP" --inputbox "\nSet DNS Server IP (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$NX" ]]; then
            var_ns=""
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}Host${CL}"
        else
            var_ns="-nameserver $NX"
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}$NX${CL}"
        fi
    else
        exit-script
    fi

    if MAC1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MAC ADDRESS" --inputbox "\nSet MAC Address(leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MAC1" ]]; then
            var_mac=""
            echo -e "${DGN}Using MAC Address: ${BGN}Default${CL}"
        else
            var_mac=",hwaddr=$MAC1"
            echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
        fi
    else
        exit-script
    fi

    if VLAN1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN TAG" --inputbox "\nSet VLAN Tag (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$VLAN1" ]]; then
            var_vlan=""
            echo -e "${DGN}Using VLAN Tag: ${BGN}Default${CL}"
        else
            var_vlan=",tag=$VLAN1"
            echo -e "${DGN}Using VLAN Tag: ${BGN}$VLAN1${CL}"
        fi
    else
        exit-script
    fi

    # Certificate Server specific configurations
    if CS_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CERTIFICATE SERVER PORT" --inputbox "\nSet HTTPS Port (default: 8443)" 9 58 "8443" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_PORT" ]]; then
            CERT_SERVER_PORT="8443"
        else
            CERT_SERVER_PORT="$CS_PORT"
        fi
        echo -e "${DGN}Using HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    else
        exit-script
    fi

    if CS_HTTP_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HTTP PORT" --inputbox "\nSet HTTP Port (default: 8080)" 9 58 "8080" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_HTTP_PORT" ]]; then
            CERT_SERVER_HTTP_PORT="8080"
        else
            CERT_SERVER_HTTP_PORT="$CS_HTTP_PORT"
        fi
        echo -e "${DGN}Using HTTP Port: ${BGN}$CERT_SERVER_HTTP_PORT${CL}"
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN CONFIGURATION" --yesno "\nConfigure VLAN support inside container?" 9 58); then
        if VLAN_ID_INPUT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN ID" --inputbox "\nEnter VLAN ID" 9 58 3>&2 2>&1 1>&3); then
            if [[ ! -z "$VLAN_ID_INPUT" ]]; then
                VLAN_ID="$VLAN_ID_INPUT"
                if VLAN_IFACE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN INTERFACE" --inputbox "\nEnter parent interface (e.g., eth0)" 9 58 "eth0" 3>&2 2>&1 1>&3); then
                    VLAN_INTERFACE="$VLAN_IFACE"
                    echo -e "${DGN}VLAN Configuration: ${BGN}ID=$VLAN_ID Interface=$VLAN_INTERFACE${CL}"
                fi
            fi
        fi
    fi

    if ADM_USER=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN USERNAME" --inputbox "\nSet admin username (default: admin)" 9 58 "admin" 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_USER" ]]; then
            WEB_ADMIN_USER="admin"
        else
            WEB_ADMIN_USER="$ADM_USER"
        fi
        echo -e "${DGN}Using Admin Username: ${BGN}$WEB_ADMIN_USER${CL}"
    else
        exit-script
    fi

    if ADM_PASS=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN PASSWORD" --passwordbox "\nSet admin password (leave blank for auto-generated)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_PASS" ]]; then
            WEB_ADMIN_PASS="$(openssl rand -base64 12)"
            echo -e "${DGN}Using Admin Password: ${BGN}Auto-generated${CL}"
        else
            WEB_ADMIN_PASS="$ADM_PASS"
            echo -e "${DGN}Using Admin Password: ${BGN}Custom${CL}"
        fi
    else
        exit-script
    fi

    var_ssh="yes"
    var_verbose="no"
    var_nesting="1"

    echo -e "${BL}Creating a ${APP} LXC using the above advanced settings${CL}"
}

function install_certificate_server() {
    # Set STD based on VERBOSE
    if [[ "$VERBOSE" == "yes" ]]; then
        STD=""
    else
        STD="silent"
    fi
    silent() { "$@" > /dev/null 2>&1; }

    # Network check
    RESOLVEDIP=$(getent hosts github.com | awk '{ print $1 }')
    if [[ -z "$RESOLVEDIP" ]]; then
        echo "No Network!"
        exit 1
    fi

    echo "Installing Dependencies..."
    $STD apt-get update
    $STD apt-get install -y \
      curl \
      sudo \
      mc \
      gnupg \
      apt-transport-https \
      software-properties-common \
      openssl \
      nginx \
      python3 \
      python3-pip \
      python3-venv \
      sqlite3 \
      wget \
      jq \
      bridge-utils \
      vlan \
      ufw \
      net-tools \
      netcat-openbsd

    # Configuration variables with defaults
    CERT_SERVER_PORT=${CERT_SERVER_PORT:-8443}
    CERT_SERVER_HTTP_PORT=${CERT_SERVER_HTTP_PORT:-8080}
    VLAN_ID=${VLAN_ID:-""}
    VLAN_INTERFACE=${VLAN_INTERFACE:-""}
    CA_COUNTRY=${CA_COUNTRY:-"US"}
    CA_STATE=${CA_STATE:-"State"}
    CA_CITY=${CA_CITY:-"City"}
    CA_ORG=${CA_ORG:-"Organization"}
    CA_OU=${CA_OU:-"IT Department"}
    CA_CN=${CA_CN:-"Certificate Authority"}
    CA_EMAIL=${CA_EMAIL:-"ca@example.com"}
    CERT_VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-3650}
    WEB_ADMIN_USER=${WEB_ADMIN_USER:-"admin"}
    WEB_ADMIN_PASS=${WEB_ADMIN_PASS:-"$(openssl rand -base64 12)"}

    # VLAN Configuration if specified
    if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
        echo "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}..."
        
        # Load 8021q module
        modprobe 8021q
        echo "8021q" >> /etc/modules
        
        # Create VLAN interface configuration
        cat > /etc/systemd/network/10-vlan.netdev << EOF
[NetDev]
Name=$VLAN_INTERFACE.$VLAN_ID
Kind=vlan

[VLAN]
Id=$VLAN_ID
EOF

        cat > /etc/systemd/network/20-vlan.network << EOF
[Match]
Name=$VLAN_INTERFACE.$VLAN_ID

[Network]
DHCP=yes
IPForward=yes
EOF
        
        systemctl restart systemd-networkd
    fi

    echo "Setting up Certificate Server Directory Structure..."
    mkdir -p /opt/cert-server/{ca,certs,keys,csr,config,web,logs,backups}
    mkdir -p /opt/cert-server/web/{static,templates}
    chmod 755 /opt/cert-server
    chmod 700 /opt/cert-server/{ca,keys}
    chmod 755 /opt/cert-server/logs

    echo "Creating Certificate Authority..."
    cd /opt/cert-server/ca

    # Create CA private key
    openssl genrsa -out ca-key.pem 4096
    chmod 600 ca-key.pem

    # Create CA certificate
    cat > ca.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $CA_CN
emailAddress = $CA_EMAIL

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign
EOF

    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca-cert.pem -config ca.conf
    chmod 644 ca-cert.pem

    # Create serial number file
    echo 1000 > serial
    touch index.txt

    echo "Setting up Python Virtual Environment..."
    cd /opt/cert-server
    python3 -m venv venv
    source venv/bin/activate
    pip install flask flask-httpauth cryptography pyopenssl

    echo "Creating Enhanced Certificate Server Web Application..."
    cat > /opt/cert-server/web/app.py << 'EOF'
#!/usr/bin/env python3

import os
import sys
import json
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
import tempfile
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

# Configuration
CA_DIR = '/opt/cert-server/ca'
CERT_DIR = '/opt/cert-server/certs'
KEY_DIR = '/opt/cert-server/keys'
CSR_DIR = '/opt/cert-server/csr'
DB_PATH = '/opt/cert-server/config/certificates.db'

# Authentication
users = {
    os.environ.get('WEB_ADMIN_USER', 'admin'): os.environ.get('WEB_ADMIN_PASS', 'changeme')
}

@auth.verify_password
def verify_password(username, password):
    return users.get(username) == password

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            csr_data TEXT,
            cert_data TEXT,
            key_data TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_date TIMESTAMP,
            expires_date TIMESTAMP,
            auto_approved BOOLEAN DEFAULT 0,
            request_hash TEXT UNIQUE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_hash TEXT UNIQUE NOT NULL,
            submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_ca_key_cert():
    with open(os.path.join(CA_DIR, 'ca-key.pem'), 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_serial_number():
    with open(os.path.join(CA_DIR, 'serial'), 'r') as f:
        serial = int(f.read().strip())
    
    with open(os.path.join(CA_DIR, 'serial'), 'w') as f:
        f.write(str(serial + 1))
    
    return serial

def generate_request_hash(data):
    """Generate hash to prevent duplicate requests"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_certificate(csr_data, auto
#!/usr/bin/env bash

# Copyright (c) 2021-2025 Enhanced Certificate Server LXC
# Author: Enhanced by Claude, based on tteck methodology
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: Enhanced Certificate Server with Auto-Approval and VLAN Support

# This script creates a Proxmox LXC container for the Enhanced Certificate Server

# App Default Values
APP="Certificate Server"
var_tags="certificate;ssl;tls;ca;security"
var_cpu="2"
var_ram="2048"
var_disk="8"
var_os="debian"
var_version="12"
var_unprivileged="1"

# Color definitions
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="\\033[1m\\033[91m[\\033[1m\\033[96m⌚\\033[1m\\033[91m]\\033[1m\\033[36m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Variables
VERBOSE="no"
SSH_ROOT="yes"
CTID=""
PCT_OSTYPE="$var_os"
PCT_OSVERSION="$var_version"
PCT_DISK_SIZE="$var_disk"
PCT_OPTIONS=""
TEMPLATE_STORAGE="local"
MSG_MAX_LENGTH=0
STORAGE_MENU=()

# Set Temp Dir
if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC" --yesno "This will create a New ${APP} LXC. Proceed?" 10 58); then
    :
else
    clear
    echo -e "⚠ User exited script \n"
    exit
fi

function header_info() {
    clear
    cat <<"EOF"
    ____          _   _  __ _           _         ____                           
   / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
  | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
  | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
   \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   
                                                                                
EOF
    echo -e "                Enhanced ${APP} LXC Container"
    echo ""
}

function msg_info() {
    local msg="$1"
    echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
    local msg="$1"
    echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function PVE_CHECK() {
    if [ $(pgrep -c -f pve-firewall) != 0 ]; then
        if [ -e /etc/proxmox-release ]; then
            if [ "$(pveversion | cut -d'/' -f2 | cut -d'.' -f1)" -lt 7 ]; then
                echo -e "${CROSS} This script requires Proxmox VE 7.0 or higher"
                echo -e "Exiting..."
                sleep 3
                exit 1
            fi
        fi
    fi
}

function ARCH_CHECK() {
    if [ "$(dpkg --print-architecture)" != "amd64" ]; then
        echo -e "\n ${CROSS} This script will not work with PiMox! \n"
        echo -e "Exiting..."
        sleep 3
        exit 1
    fi
}

function exit-script() {
    clear
    echo -e "⚠ User exited script \n"
    exit 1
}

function default_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    # Default settings
    var_container="$CTID"
    var_hostname="cert-server"
    var_disk="$var_disk"
    var_cpu="$var_cpu"
    var_ram="$var_ram"
    var_bridge="vmbr0"
    var_ip="dhcp"
    var_gate=""
    var_ipv6=""
    var_mtu=""
    var_dns=""
    var_ns=""
    var_mac=""
    var_vlan=""
    var_ssh="yes"
    var_verbose="no"
    var_unprivileged="$var_unprivileged"
    var_nesting="1"
    var_password=""
    
    # Certificate Server specific defaults
    CERT_SERVER_PORT="8443"
    CERT_SERVER_HTTP_PORT="8080"
    WEB_ADMIN_USER="admin"
    WEB_ADMIN_PASS="$(openssl rand -base64 12)"
    VLAN_ID=""
    VLAN_INTERFACE=""
    
    clear
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL} ${RD}NO DEVICE PASSTHROUGH${CL}"
    echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
    echo -e "${DGN}Using Container ID: ${BGN}$CTID${CL}"
    echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
    echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
    echo -e "${DGN}Allocated Cores ${BGN}$var_cpu${CL}"
    echo -e "${DGN}Allocated Ram ${BGN}$var_ram${CL}"
    echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
    echo -e "${DGN}Using Static IP: ${BGN}$var_ip${CL}"
    echo -e "${DGN}Using Gateway: ${BGN}$var_gate${CL}"
    echo -e "${DGN}Disable IPv6: ${BGN}$var_ipv6${CL}"
    echo -e "${DGN}Using Interface MTU Size: ${BGN}$var_mtu${CL}"
    echo -e "${DGN}Using DNS Search Domain: ${BGN}$var_dns${CL}"
    echo -e "${DGN}Using DNS Server Address: ${BGN}$var_ns${CL}"
    echo -e "${DGN}Using MAC Address: ${BGN}$var_mac${CL}"
    echo -e "${DGN}Using VLAN Tag: ${BGN}$var_vlan${CL}"
    echo -e "${DGN}Enable Root SSH Access: ${BGN}yes${CL}"
    echo -e "${DGN}Enable Verbose Mode: ${BGN}no${CL}"
    echo -e "${DGN}Certificate Server HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    echo -e "${DGN}Certificate Server Admin User: ${BGN}$WEB_ADMIN_USER${CL}"
    echo -e "${BL}Creating a ${APP} LXC using the above default settings${CL}"
}

function advanced_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    clear
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    echo -e "${YW}Type Advanced, or Press [ENTER] for Default.${CL}"
    echo ""
    sleep 1

    case $(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER TYPE" --menu "\nChoose Type" 10 58 2 \
        "1" "Unprivileged (Recommended)" \
        "0" "Privileged" 3>&2 2>&1 1>&3) in
    1) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    0) var_unprivileged="0"; echo -e "${DGN}Using Container Type: ${BGN}Privileged${CL}" ;;
    *) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    esac

    if PW=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "PASSWORD" --passwordbox "\nSet Root Password (needed for root ssh access)" 9 58 3>&2 2>&1 1>&3); then
        if [[ ! -z "$PW" ]]; then
            var_password="-password $PW"
            echo -e "${DGN}Using Root Password: ${BGN}$PW${CL}"
        else
            var_password=""
            echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
        fi
    else
        exit-script
    fi

    if CT_ID=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER ID" --inputbox "\nSet Container ID" 9 58 $CTID 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_ID" ]]; then
            var_container="$CTID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        else
            var_container="$CT_ID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        fi
    else
        exit-script
    fi

    if CT_NAME=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HOSTNAME" --inputbox "\nSet Hostname" 9 58 "cert-server" 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_NAME" ]]; then
            var_hostname="cert-server"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        else
            var_hostname="$CT_NAME"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        fi
    else
        exit-script
    fi

    if DISK_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DISK SIZE" --inputbox "\nSet Disk Size in GB" 9 58 $var_disk 3>&2 2>&1 1>&3); then
        if [[ -z "$DISK_SIZE" ]]; then
            var_disk="$var_disk"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        else
            var_disk="$DISK_SIZE"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        fi
    else
        exit-script
    fi

    if CORE_COUNT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CORES" --inputbox "\nAllocate CPU Cores" 9 58 $var_cpu 3>&2 2>&1 1>&3); then
        if [[ -z "$CORE_COUNT" ]]; then
            var_cpu="$var_cpu"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        else
            var_cpu="$CORE_COUNT"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        fi
    else
        exit-script
    fi

    if RAM_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "RAM" --inputbox "\nAllocate RAM in MB" 9 58 $var_ram 3>&2 2>&1 1>&3); then
        if [[ -z "$RAM_SIZE" ]]; then
            var_ram="$var_ram"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        else
            var_ram="$RAM_SIZE"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        fi
    else
        exit-script
    fi

    if BRG=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "BRIDGE" --inputbox "\nSet a Bridge" 9 58 "vmbr0" 3>&2 2>&1 1>&3); then
        if [[ -z "$BRG" ]]; then
            var_bridge="vmbr0"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        else
            var_bridge="$BRG"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        fi
    else
        exit-script
    fi

    if NET=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "IP ADDRESS" --inputbox "\nSet a Static IPv4 CIDR Address(/24)" 9 58 dhcp 3>&2 2>&1 1>&3); then
        if [[ "$NET" == "dhcp" ]]; then
            var_ip="dhcp"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        else
            var_ip="$NET"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        fi
    else
        exit-script
    fi

    if GATE1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "GATEWAY" --inputbox "\nSet a Gateway IP (mandatory if Static IP was used)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$GATE1" ]]; then
            var_gate=""
            echo -e "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
        else
            var_gate=",gw=$GATE1"
            echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
        fi
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "IPv6" --yesno "\nDisable IPv6?" 9 58); then
        var_ipv6=""
        echo -e "${DGN}Disable IPv6: ${BGN}Yes${CL}"
    else
        var_ipv6=",ip6=dhcp"
        echo -e "${DGN}Disable IPv6: ${BGN}No${CL}"
    fi

    if MTU1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MTU SIZE" --inputbox "\nSet Interface MTU Size (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MTU1" ]]; then
            var_mtu=""
            echo -e "${DGN}Using Interface MTU Size: ${BGN}Default${CL}"
        else
            var_mtu=",mtu=$MTU1"
            echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU1${CL}"
        fi
    else
        exit-script
    fi

    if SD=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SEARCH DOMAIN" --inputbox "\nSet DNS Search Domain (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$SD" ]]; then
            SX=host
            var_dns=""
            echo -e "${DGN}Using DNS Search Domain: ${BGN}Host${CL}"
        else
            SX=$SD
            var_dns="-searchdomain $SD"
            echo -e "${DGN}Using DNS Search Domain: ${BGN}$SD${CL}"
        fi
    else
        exit-script
    fi

    if NX=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SERVER IP" --inputbox "\nSet DNS Server IP (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$NX" ]]; then
            var_ns=""
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}Host${CL}"
        else
            var_ns="-nameserver $NX"
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}$NX${CL}"
        fi
    else
        exit-script
    fi

    if MAC1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MAC ADDRESS" --inputbox "\nSet MAC Address(leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MAC1" ]]; then
            var_mac=""
            echo -e "${DGN}Using MAC Address: ${BGN}Default${CL}"
        else
            var_mac=",hwaddr=$MAC1"
            echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
        fi
    else
        exit-script
    fi

    if VLAN1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN TAG" --inputbox "\nSet VLAN Tag (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$VLAN1" ]]; then
            var_vlan=""
            echo -e "${DGN}Using VLAN Tag: ${BGN}Default${CL}"
        else
            var_vlan=",tag=$VLAN1"
            echo -e "${DGN}Using VLAN Tag: ${BGN}$VLAN1${CL}"
        fi
    else
        exit-script
    fi

    # Certificate Server specific configurations
    if CS_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CERTIFICATE SERVER PORT" --inputbox "\nSet HTTPS Port (default: 8443)" 9 58 "8443" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_PORT" ]]; then
            CERT_SERVER_PORT="8443"
        else
            CERT_SERVER_PORT="$CS_PORT"
        fi
        echo -e "${DGN}Using HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    else
        exit-script
    fi

    if CS_HTTP_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HTTP PORT" --inputbox "\nSet HTTP Port (default: 8080)" 9 58 "8080" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_HTTP_PORT" ]]; then
            CERT_SERVER_HTTP_PORT="8080"
        else
            CERT_SERVER_HTTP_PORT="$CS_HTTP_PORT"
        fi
        echo -e "${DGN}Using HTTP Port: ${BGN}$CERT_SERVER_HTTP_PORT${CL}"
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN CONFIGURATION" --yesno "\nConfigure VLAN support inside container?" 9 58); then
        if VLAN_ID_INPUT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN ID" --inputbox "\nEnter VLAN ID" 9 58 3>&2 2>&1 1>&3); then
            if [[ ! -z "$VLAN_ID_INPUT" ]]; then
                VLAN_ID="$VLAN_ID_INPUT"
                if VLAN_IFACE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN INTERFACE" --inputbox "\nEnter parent interface (e.g., eth0)" 9 58 "eth0" 3>&2 2>&1 1>&3); then
                    VLAN_INTERFACE="$VLAN_IFACE"
                    echo -e "${DGN}VLAN Configuration: ${BGN}ID=$VLAN_ID Interface=$VLAN_INTERFACE${CL}"
                fi
            fi
        fi
    fi

    if ADM_USER=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN USERNAME" --inputbox "\nSet admin username (default: admin)" 9 58 "admin" 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_USER" ]]; then
            WEB_ADMIN_USER="admin"
        else
            WEB_ADMIN_USER="$ADM_USER"
        fi
        echo -e "${DGN}Using Admin Username: ${BGN}$WEB_ADMIN_USER${CL}"
    else
        exit-script
    fi

    if ADM_PASS=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN PASSWORD" --passwordbox "\nSet admin password (leave blank for auto-generated)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_PASS" ]]; then
            WEB_ADMIN_PASS="$(openssl rand -base64 12)"
            echo -e "${DGN}Using Admin Password: ${BGN}Auto-generated${CL}"
        else
            WEB_ADMIN_PASS="$ADM_PASS"
            echo -e "${DGN}Using Admin Password: ${BGN}Custom${CL}"
        fi
    else
        exit-script
    fi

    var_ssh="yes"
    var_verbose="no"
    var_nesting="1"

    echo -e "${BL}Creating a ${APP} LXC using the above advanced settings${CL}"
}

function install_certificate_server() {
    # Set STD based on VERBOSE
    if [[ "$VERBOSE" == "yes" ]]; then
        STD=""
    else
        STD="silent"
    fi
    silent() { "$@" > /dev/null 2>&1; }

    # Network check
    RESOLVEDIP=$(getent hosts github.com | awk '{ print $1 }')
    if [[ -z "$RESOLVEDIP" ]]; then
        echo "No Network!"
        exit 1
    fi

    echo "Installing Dependencies..."
    $STD apt-get update
    $STD apt-get install -y \
      curl \
      sudo \
      mc \
      gnupg \
      apt-transport-https \
      software-properties-common \
      openssl \
      nginx \
      python3 \
      python3-pip \
      python3-venv \
      sqlite3 \
      wget \
      jq \
      bridge-utils \
      vlan \
      ufw \
      net-tools \
      netcat-openbsd

    # Configuration variables with defaults
    CERT_SERVER_PORT=${CERT_SERVER_PORT:-8443}
    CERT_SERVER_HTTP_PORT=${CERT_SERVER_HTTP_PORT:-8080}
    VLAN_ID=${VLAN_ID:-""}
    VLAN_INTERFACE=${VLAN_INTERFACE:-""}
    CA_COUNTRY=${CA_COUNTRY:-"US"}
    CA_STATE=${CA_STATE:-"State"}
    CA_CITY=${CA_CITY:-"City"}
    CA_ORG=${CA_ORG:-"Organization"}
    CA_OU=${CA_OU:-"IT Department"}
    CA_CN=${CA_CN:-"Certificate Authority"}
    CA_EMAIL=${CA_EMAIL:-"ca@example.com"}
    CERT_VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-3650}
    WEB_ADMIN_USER=${WEB_ADMIN_USER:-"admin"}
    WEB_ADMIN_PASS=${WEB_ADMIN_PASS:-"$(openssl rand -base64 12)"}

    # VLAN Configuration if specified
    if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
        echo "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}..."
        
        # Load 8021q module
        modprobe 8021q
        echo "8021q" >> /etc/modules
        
        # Create VLAN interface configuration
        cat > /etc/systemd/network/10-vlan.netdev << EOF
[NetDev]
Name=$VLAN_INTERFACE.$VLAN_ID
Kind=vlan

[VLAN]
Id=$VLAN_ID
EOF

        cat > /etc/systemd/network/20-vlan.network << EOF
[Match]
Name=$VLAN_INTERFACE.$VLAN_ID

[Network]
DHCP=yes
IPForward=yes
EOF
        
        systemctl restart systemd-networkd
    fi

    echo "Setting up Certificate Server Directory Structure..."
    mkdir -p /opt/cert-server/{ca,certs,keys,csr,config,web,logs,backups}
    mkdir -p /opt/cert-server/web/{static,templates}
    chmod 755 /opt/cert-server
    chmod 700 /opt/cert-server/{ca,keys}
    chmod 755 /opt/cert-server/logs

    echo "Creating Certificate Authority..."
    cd /opt/cert-server/ca

    # Create CA private key
    openssl genrsa -out ca-key.pem 4096
    chmod 600 ca-key.pem

    # Create CA certificate
    cat > ca.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $CA_CN
emailAddress = $CA_EMAIL

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign
EOF

    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca-cert.pem -config ca.conf
    chmod 644 ca-cert.pem

    # Create serial number file
    echo 1000 > serial
    touch index.txt

    echo "Setting up Python Virtual Environment..."
    cd /opt/cert-server
    python3 -m venv venv
    source venv/bin/activate
    pip install flask flask-httpauth cryptography pyopenssl

    echo "Creating Enhanced Certificate Server Web Application..."
    cat > /opt/cert-server/web/app.py << 'EOF'
#!/usr/bin/env python3

import os
import sys
import json
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
import tempfile
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

# Configuration
CA_DIR = '/opt/cert-server/ca'
CERT_DIR = '/opt/cert-server/certs'
KEY_DIR = '/opt/cert-server/keys'
CSR_DIR = '/opt/cert-server/csr'
DB_PATH = '/opt/cert-server/config/certificates.db'

# Authentication
users = {
    os.environ.get('WEB_ADMIN_USER', 'admin'): os.environ.get('WEB_ADMIN_PASS', 'changeme')
}

@auth.verify_password
def verify_password(username, password):
    return users.get(username) == password

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            csr_data TEXT,
            cert_data TEXT,
            key_data TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_date TIMESTAMP,
            expires_date TIMESTAMP,
            auto_approved BOOLEAN DEFAULT 0,
            request_hash TEXT UNIQUE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_hash TEXT UNIQUE NOT NULL,
            submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_ca_key_cert():
    with open(os.path.join(CA_DIR, 'ca-key.pem'), 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_serial_number():
    with open(os.path.join(CA_DIR, 'serial'), 'r') as f:
        serial = int(f.read().strip())
    
    with open(os.path.join(CA_DIR, 'serial'), 'w') as f:
        f.write(str(serial + 1))
    
    return serial

def generate_request_hash(data):
    """Generate hash to prevent duplicate requests"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_certificate(csr_data, auto_approve=True):
    try:
        ca_key, ca_cert = load_ca_key_cert()
        csr = x509.load_pem_x509_csr(csr_data.encode())
        
        # Extract common name from CSR
        common_name = None
        for attribute in csr.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                common_name = attribute.value
                break
        
        if not common_name:
            raise ValueError("No common name found in CSR")
        
        # Generate request hash to prevent duplicates
        request_hash = generate_request_hash(csr_data + common_name)
        
        # Check for existing request
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM certificates WHERE request_hash = ?', (request_hash,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Duplicate request detected - certificate already exists")
        
        # Generate serial number
        serial = generate_serial_number()
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_encipherment=True,
                digital_signature=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # Store in database with request hash
        cursor.execute('''
            INSERT INTO certificates 
            (common_name, serial_number, status, csr_data, cert_data, approved_date, expires_date, auto_approved, request_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            common_name,
            str(serial),
            'approved' if auto_approve else 'pending',
            csr_data,
            cert_pem,
            datetime.utcnow() if auto_approve else None,
            cert.not_valid_after,
            auto_approve,
            request_hash
        ))
        conn.commit()
        conn.close()
        
        return cert_pem, str(serial)
        
    except Exception as e:
        raise Exception(f"Certificate signing failed: {str(e)}")

def generate_key_and_csr(common_name, organization='', country='US'):
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Generated Certificate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    
    # Convert to PEM
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    
    return key_pem, csr_pem

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request', methods=['GET', 'POST'])
def request_certificate():
    if request.method == 'POST':
        try:
            if 'csr_data' in request.form:
                # Handle uploaded CSR
                csr_data = request.form['csr_data']
                auto_approve = request.form.get('auto_approve', 'off') == 'on'
                
                # Detect and decode Base64 if needed
                try:
                    decoded_csr = base64.b64decode(csr_data).decode()
                    if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                        csr_data = decoded_csr
                except:
                    pass  # Not base64 or not valid, use as-is
                
                cert_pem, serial = sign_certificate(csr_data, auto_approve)
                
                flash(f'Certificate {"approved" if auto_approve else "submitted"} with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
            else:
                # Generate new certificate
                common_name = request.form['common_name']
                organization = request.form.get('organization', '')
                country = request.form.get('country', 'US')
                
                key_pem, csr_pem = generate_key_and_csr(common_name, organization, country)
                cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
                
                # Store the private key for generated certificates
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
                conn.commit()
                conn.close()
                
                flash(f'Certificate generated and approved with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('request.html')

@app.route('/certificate/<serial>')
def view_certificate(serial):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        flash('Certificate not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('certificate.html', cert=cert_data)

@app.route('/download/<serial>/<file_type>')
def download_certificate(serial, file_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        return "Certificate not found", 404
    
    if file_type == 'cert':
        content = cert_data[5]  # cert_data
        filename = f'certificate_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'key' and cert_data[6]:  # key_data exists
        content = cert_data[6]
        filename = f'private_key_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'csr':
        content = cert_data[4]  # csr_data
        filename = f'csr_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'bundle':
        # Create certificate bundle with key if available
        bundle_content = cert_data[5]  # cert_data
        if cert_data[6]:  # key_data
            bundle_content += "\n" + cert_data[6]
        content = bundle_content
        filename = f'certificate_bundle_{serial}.pem'
        mimetype = 'application/x-pem-file'
    else:
        return "Invalid file type", 400
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    return send_file(temp_file_path, as_attachment=True, download_name=filename, mimetype=mimetype)

@app.route('/certificates')
def list_certificates():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates ORDER BY created_date DESC')
    certificates = cursor.fetchall()
    conn.close()
    
    return render_template('certificates.html', certificates=certificates)

@app.route('/api/submit_csr', methods=['POST'])
def api_submit_csr():
    try:
        data = request.json
        csr_data = data.get('csr')
        auto_approve = data.get('auto_approve', True)
        
        if not csr_data:
            return jsonify({'error': 'CSR data is required'}), 400
        
        # Decode base64 if needed
        try:
            decoded_csr = base64.b64decode(csr_data).decode()
            if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                csr_data = decoded_csr
        except:
            pass  # Not base64 encoded or not valid
        
        cert_pem, serial = sign_certificate(csr_data, auto_approve)
        
        return jsonify({
            'success': True,
            'serial': serial,
            'certificate': cert_pem,
            'status': 'approved' if auto_approve else 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ca_cert')
def api_ca_cert():
    try:
        with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'r') as f:
            ca_cert = f.read()
        return jsonify({'ca_certificate': ca_cert})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('CERT_SERVER_HTTP_PORT', 8080)), debug=False)
EOF

    chmod +x /opt/cert-server/web/app.py

    echo "Creating Web Templates..."
    mkdir -p /opt/cert-server/web/{templates,static}

    # Create base template
    cat > /opt/cert-server/web/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Certificate Server{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="fas fa-certificate"></i> Certificate Server
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="{{ url_for('index') }}">Home</a>
                <a class="nav-link" href="{{ url_for('request_certificate') }}">Request Certificate</a>
                <a class="nav-link" href="{{ url_for('list_certificates') }}">View Certificates</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

    # Create index template
    cat > /opt/cert-server/web/templates/index.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="jumbotron bg-light p-5 rounded">
            <h1 class="display-4"><i class="fas fa-certificate text-primary"></i> Certificate Server</h1>
            <p class="lead">Generate and manage SSL/TLS certificates with automatic approval.</p>
            <hr class="my-4">
            <p>Enhanced features:</p>
            <ul>
                <li>✅ Automatic certificate approval for web interface requests</li>
                <li>✅ Base64 encoded CSR import with auto-approval</li>
                <li>✅ Private key export for server-generated certificates</li>
                <li>✅ Certificate bundle downloads</li>
                <li>✅ Duplicate request prevention</li>
                <li>✅ REST API for automation</li>
            </ul>
            <a class="btn btn-primary btn-lg" href="{{ url_for('request_certificate') }}" role="button">
                <i class="fas fa-plus"></i> Request Certificate
            </a>
            <a class="btn btn-secondary btn-lg" href="{{ url_for('list_certificates') }}" role="button">
                <i class="fas fa-list"></i> View Certificates
            </a>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create request template
    cat > /opt/cert-server/web/templates/request.html << 'EOF'
{% extends "base.html" %}

{% block title %}Request Certificate - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <h2><i class="fas fa-plus-circle"></i> Request Certificate</h2>
        
        <ul class="nav nav-tabs" id="requestTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="generate-tab" data-bs-toggle="tab" data-bs-target="#generate" type="button" role="tab">
                    <i class="fas fa-magic"></i> Generate New Certificate
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="upload-tab" data-bs-toggle="tab" data-bs-target="#upload" type="button" role="tab">
                    <i class="fas fa-upload"></i> Upload CSR
                </button>
            </li>
        </ul>
        
        <div class="tab-content mt-3" id="requestTabsContent">
            <!-- Generate New Certificate Tab -->
            <div class="tab-pane fade show active" id="generate" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Generate New Certificate</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="common_name" class="form-label">Common Name (CN) *</label>
                                <input type="text" class="form-control" id="common_name" name="common_name" required>
                                <div class="form-text">e.g., www.example.com or *.example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="organization" class="form-label">Organization</label>
                                <input type="text" class="form-control" id="organization" name="organization">
                            </div>
                            <div class="mb-3">
                                <label for="country" class="form-label">Country</label>
                                <input type="text" class="form-control" id="country" name="country" value="US" maxlength="2">
                                <div class="form-text">2-letter country code</div>
                            </div>
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-certificate"></i> Generate & Approve Certificate
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Upload CSR Tab -->
            <div class="tab-pane fade" id="upload" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Upload Certificate Signing Request</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="csr_data" class="form-label">CSR Data *</label>
                                <textarea class="form-control" id="csr_data" name="csr_data" rows="10" required placeholder="Paste your PEM encoded CSR or Base64 encoded CSR here"></textarea>
                                <div class="form-text">Supports both PEM format and Base64 encoded CSRs</div>
                            </div>
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="auto_approve" name="auto_approve" checked>
                                <label class="form-check-label" for="auto_approve">
                                    Automatically approve certificate
                                </label>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload"></i> Submit CSR
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Prevent duplicate submissions
const submittedForms = new Set();

function generateFormHash(form) {
    const formData = new FormData(form);
    const data = Array.from(formData.entries()).map(([k, v]) => `${k}:${v}`).join('|');
    return btoa(data).replace(/[^a-zA-Z0-9]/g, '');
}

function handleSubmit(form) {
    const formHash = generateFormHash(form);
    
    if (submittedForms.has(formHash)) {
        alert('This certificate request has already been submitted. Please check the certificates list.');
        return false;
    }
    
    submittedForms.add(formHash);
    
    // Disable submit button
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    }
    
    return true;
}
</script>
{% endblock %}
EOF

    # Create certificate view template
    cat > /opt/cert-server/web/templates/certificate.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificate {{ cert[2] }} - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-10 mx-auto">
        <h2><i class="fas fa-certificate"></i> Certificate Details</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Certificate Information</h5>
                        <table class="table table-borderless">
                            <tr>
                                <td><strong>Common Name:</strong></td>
                                <td>{{ cert[1] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Serial Number:</strong></td>
                                <td>{{ cert[2] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Status:</strong></td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                    {% if cert[10] %}
                                        <span class="badge bg-info ms-1">Auto-Approved</span>
                                    {% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Created:</strong></td>
                                <td>{{ cert[7] }}</td>
                            </tr>
                            {% if cert[8] %}
                            <tr>
                                <td><strong>Approved:</strong></td>
                                <td>{{ cert[8] }}</td>
                            </tr>
                            {% endif %}
                            <tr>
                                <td><strong>Expires:</strong></td>
                                <td>{{ cert[9] }}</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h5>Downloads</h5>
                        <div class="d-grid gap-2">
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='cert') }}" 
                               class="btn btn-primary">
                                <i class="fas fa-download"></i> Download Certificate
                            </a>
                            {% if cert[4] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='csr') }}" 
                               class="btn btn-secondary">
                                <i class="fas fa-download"></i> Download CSR
                            </a>
                            {% endif %}
                            {% if cert[6] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='key') }}" 
                               class="btn btn-warning">
                                <i class="fas fa-key"></i> Download Private Key
                            </a>
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='bundle') }}" 
                               class="btn btn-success">
                                <i class="fas fa-file-archive"></i> Download Bundle (Cert + Key)
                            </a>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                {% if cert[5] %}
                <hr>
                <h5>Certificate Data</h5>
                <pre class="bg-light p-3 small"><code>{{ cert[5] }}</code></pre>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create certificates list template
    cat > /opt/cert-server/web/templates/certificates.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificates - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h2><i class="fas fa-list"></i> Certificates</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Common Name</th>
                                <th>Serial Number</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Auto-Approved</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for cert in certificates %}
                            <tr>
                                <td>{{ cert[1] }}</td>
                                <td>{{ cert[2] }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                </td>
                                <td>{{ cert[7] }}</td>
                                <td>{{ cert[9] }}</td>
                                <td>
                                    {% if cert[10] %}
                                        <i class="fas fa-check text-success"></i>
                                    {% else %}
                                        <i class="fas fa-times text-muted"></i>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="{{ url_for('view_certificate', serial=cert[2]) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    echo "Creating Systemd Service..."
    cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Enhanced Certificate Server with Auto-Approval
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cert-server/web
Environment=PATH=/opt/cert-server/venv/bin
Environment=WEB_ADMIN_USER=$WEB_ADMIN_USER
Environment=WEB_ADMIN_PASS=$WEB_ADMIN_PASS
Environment=CERT_SERVER_HTTP_PORT=$CERT_SERVER_HTTP_PORT
ExecStart=/opt/cert-server/venv/bin/python app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cert-server

    echo "Configuring Nginx Reverse Proxy with SSL..."
    
    # Generate web server certificate for HTTPS
    cd /opt/cert-server/ca
    openssl genrsa -out web-server-key.pem 2048
    chmod 600 web-server-key.pem
    
    cat > web-server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
CN = $(hostname -f)

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $(hostname -f)
DNS.2 = $(hostname -s)
DNS.3 = localhost
IP.1 = $(hostname -I | awk '{print $1}' 2>/dev/null || echo '127.0.0.1')
IP.2 = 127.0.0.1
EOF
    
    openssl req -new -key web-server-key.pem -out web-server.csr -config web-server.conf
    openssl x509 -req -in web-server.csr -CA ca-cert.pem -CAkey ca-key.pem -out web-server.pem -days 365 -extensions v3_req -extfile web-server.conf
    chmod 644 web-server.pem

    cat > /etc/nginx/sites-available/cert-server << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name:$CERT_SERVER_PORT\$request_uri;
}

# HTTPS Certificate Server
server {
    listen $CERT_SERVER_PORT ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /opt/cert-server/ca/web-server.pem;
    ssl_certificate_key /opt/cert-server/ca/web-server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=web:10m rate=30r/m;
    
    # Main application
    location / {
        limit_req zone=web burst=5 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
    
    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=api burst=3 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Content-Type application/json;
    }
    
    # Health check endpoint (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        access_log off;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/cert-server /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl enable nginx

    echo "Creating Management Scripts..."
    
    # Enhanced management script
    cat > /opt/cert-server/manage.sh << 'EOF'
#!/bin/bash

CERT_SERVER_DIR="/opt/cert-server"
VENV_PATH="$CERT_SERVER_DIR/venv"
LOG_FILE="$CERT_SERVER_DIR/logs/management.log"

mkdir -p "$(dirname "$LOG_FILE")"

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

case "$1" in
    start)
        echo "Starting Certificate Server services..."
        log_action "Starting services"
        systemctl start cert-server
        systemctl start nginx
        echo "✓ Certificate Server started"
        ;;
    stop)
        echo "Stopping Certificate Server services..."
        log_action "Stopping services"
        systemctl stop cert-server
        systemctl stop nginx
        echo "✓ Certificate Server stopped"
        ;;
    restart)
        echo "Restarting Certificate Server services..."
        log_action "Restarting services"
        systemctl restart cert-server
        systemctl restart nginx
        echo "✓ Certificate Server restarted"
        ;;
    status)
        echo "=== Certificate Server Status ==="
        echo ""
        echo "Services:"
        systemctl is-active cert-server &>/dev/null && echo "  ✓ Certificate Server: Running" || echo "  ✗ Certificate Server: Stopped"
        systemctl is-active nginx &>/dev/null && echo "  ✓ Nginx: Running" || echo "  ✗ Nginx: Stopped"
        echo ""
        echo "Network:"
        echo "  Web Interface: https://$(hostname -I | awk '{print $1}'):8443"
        echo "  API Endpoint:  https://$(hostname -I | awk '{print $1}'):8443/api"
        echo ""
        if [[ -f "$CERT_SERVER_DIR/config/certificates.db" ]]; then
            echo "Certificate Statistics:"
            source $VENV_PATH/bin/activate
            python3 << 'PYTHON_EOF'
import sqlite3
try:
    conn = sqlite3.connect('/opt/cert-server/config/certificates.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM certificates')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM certificates WHERE status = "approved"')
    approved = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM certificates WHERE auto_approved = 1')
    auto_approved = cursor.fetchone()[0]
    
    print(f"  Total Certificates: {total}")
    print(f"  Approved: {approved}")
    print(f"  Auto-Approved: {auto_approved}")
    
    conn.close()
except Exception as e:
    print(f"  Database Error: {e}")
PYTHON_EOF
        fi
        ;;
    logs)
        echo "Certificate Server Logs (Ctrl+C to exit):"
        journalctl -u cert-server -f --no-pager
        ;;
    backup)
        BACKUP_DIR="/opt/cert-server/backups/backup-$(date +%Y%m%d_%H%M%S)"
        echo "Creating backup in $BACKUP_DIR..."
        log_action "Creating backup: $BACKUP_DIR"
        
        mkdir -p "$BACKUP_DIR"
        systemctl stop cert-server
        
        cp -r $CERT_SERVER_DIR/ca "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/config "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/certs "$BACKUP_DIR/" 2>/dev/null || true
        cp -r $CERT_SERVER_DIR/keys "$BACKUP_DIR/" 2>/dev/null || true
        cp -r $CERT_SERVER_DIR/web "$BACKUP_DIR/"
        
        tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
        rm -rf "$BACKUP_DIR"
        
        systemctl start cert-server
        echo "✓ Backup created: $BACKUP_DIR.tar.gz"
        log_action "Backup completed: $BACKUP_DIR.tar.gz"
        ;;
    generate-cert)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 generate-cert <common_name> [organization]"
            exit 1
        fi
        
        echo "Generating certificate for $2..."
        log_action "Generating certificate for: $2"
        source $VENV_PATH/bin/activate
        python3 << PYTHON_EOF
import sys
sys.path.append('/opt/cert-server/web')
try:
    from app import generate_key_and_csr, sign_certificate, init_db
    import sqlite3
    
    init_db()
    key_pem, csr_pem = generate_key_and_csr('$2', '${3:-Generated Certificate}')
    cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
    
    conn = sqlite3.connect('/opt/cert-server/config/certificates.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
    conn.commit()
    conn.close()
    
    print(f"✓ Certificate generated successfully")
    print(f"  Serial Number: {serial}")
    print(f"  Common Name: $2")
    print(f"  Access via: https://$(hostname -I | awk '{print $1}'):8443/certificate/{serial}")
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
PYTHON_EOF
        ;;
    health)
        echo "=== Certificate Server Health Check ==="
        
        # Check services
        services=("cert-server" "nginx")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                echo "  ✓ $service: Running"
            else
                echo "  ✗ $service: Not running"
            fi
        done
        
        # Check ports
        ports=("8080" "8443")
        for port in "${ports[@]}"; do
            if nc -z localhost "$port" 2>/dev/null; then
                echo "  ✓ Port $port: Open"
            else
                echo "  ✗ Port $port: Closed"
            fi
        done
        
        # Check web interface
        if curl -k -s "https://localhost:8443/health" >/dev/null 2>&1; then
            echo "  ✓ Web Interface: Accessible"
        else
            echo "  ✗ Web Interface: Not accessible"
        fi
        
        # Check API
        if curl -k -s "https://localhost:8443/api/ca_cert" | grep -q "ca_certificate"; then
            echo "  ✓ API: Functional"
        else
            echo "  ✗ API: Not responding"
        fi
        ;;
    *)
        echo "Certificate Server Management Tool"
        echo ""
        echo "Usage: $0 {command}"
        echo ""
        echo "Commands:"
        echo "  start                    Start all services"
        echo "  stop                     Stop all services" 
        echo "  restart                  Restart all services"
        echo "  status                   Show detailed status"
        echo "  health                   Run health check"
        echo "  logs                     Follow application logs"
        echo "  backup                   Create backup"
        echo "  generate-cert <cn> [org] Generate certificate via CLI"
        echo ""
        echo "Web Interface: https://$(hostname -I | awk '{print $1}'):8443"
        echo "API Endpoint:  https://$(hostname -I | awk '{print $1}'):8443/api"
        exit 1
        ;;
esac
EOF

    chmod +x /opt/cert-server/manage.sh
    ln -sf /opt/cert-server/manage.sh /usr/local/bin/cert-server

    # Create API client script
    cat > /opt/cert-server/api-client.sh << 'EOF'
#!/bin/bash

# Certificate Server API Client
SERVER_URL="${CERT_SERVER_URL:-https://localhost:8443}"
API_BASE="$SERVER_URL/api"

case "$1" in
    submit-csr)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 submit-csr <csr_file_path>"
            exit 1
        fi
        
        if [[ ! -f "$2" ]]; then
            echo "CSR file not found: $2"
            exit 1
        fi
        
        CSR_DATA=$(cat "$2")
        
        curl -k -X POST "$API_BASE/submit_csr" \
             -H "Content-Type: application/json" \
             -d "{\"csr\": \"$(echo "$CSR_DATA" | sed 's/$/\\n/' | tr -d '\n')\", \"auto_approve\": true}" \
             | jq .
        ;;
        
    submit-csr-b64)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 submit-csr-b64 <base64_encoded_csr>"
            exit 1
        fi
        
        curl -k -X POST "$API_BASE/submit_csr" \
             -H "Content-Type: application/json" \
             -d "{\"csr\": \"$2\", \"auto_approve\": true}" \
             | jq .
        ;;
        
    get-ca-cert)
        curl -k -X GET "$API_BASE/ca_cert" | jq -r .ca_certificate
        ;;
        
    *)
        echo "Certificate Server API Client"
        echo "Usage: $0 {submit-csr|submit-csr-b64|get-ca-cert}"
        echo ""
        echo "Examples:"
        echo "  $0 submit-csr /path/to/request.csr"
        echo "  $0 submit-csr-b64 LS0tLS1CRUdJTi..."
        echo "  $0 get-ca-cert > ca.pem"
        exit 1
        ;;
esac
EOF

    chmod +x /opt/cert-server/api-client.sh

    echo "Initializing Database and Starting Services..."
    cd /opt/cert-server/web
    source ../venv/bin/activate
    python3 -c "from app import init_db; init_db()"

    systemctl start cert-server
    systemctl start nginx
    
    # Wait for services to start
    sleep 3

    # Create MOTD
    cat > /etc/motd << EOF
   ____          _   _  __ _           _         ____                           
  / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
 | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
 | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
  \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   

Enhanced Certificate Server - LXC Container

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
API Endpoint:  https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT/api
Username:      $WEB_ADMIN_USER
Password:      $WEB_ADMIN_PASS

Management:    cert-server {start|stop|restart|status|logs|backup}

Enhanced Features:
✓ Automatic certificate approval via web interface
✓ Base64 CSR import with auto-approval  
✓ Private key export for server-generated certificates
✓ Certificate bundle downloads (cert + key)
✓ Duplicate request prevention on refresh
✓ REST API for programmatic access

EOF

    # Save credentials to file for easy access
    cat > /root/cert-server-credentials.txt << EOF
Certificate Server Access Information
====================================

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
Username: $WEB_ADMIN_USER
Password: $WEB_ADMIN_PASS

API Endpoint: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT/api

Management Commands:
- cert-server start|stop|restart|status
- cert-server health
- cert-server logs  
- cert-server backup
- cert-server generate-cert <common_name> [org]

CA Certificate Location: /opt/cert-server/ca/ca-cert.pem
Database Location: /opt/cert-server/config/certificates.db

IMPORTANT: Save this password information!
EOF
    
    chmod 600 /root/cert-server-credentials.txt

    echo "Cleaning up..."
    $STD apt-get -y autoremove
    $STD apt-get -y autoclean

    echo "Certificate Server installation completed!"
}

function install_script() {
    ARCH_CHECK
    PVE_CHECK
    
    header_info
    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "SETTINGS" --yesno "\nUse Default Settings?" --no-button Advanced 10 58); then
        default_settings
    else
        advanced_settings
    fi
    
    msg_info "Validating Storage"
    TEMPLATE_STORAGE=$(pvesh get /storage --output-format json | jq -r '.[] | select(.content | contains("vztmpl")) | .storage' | head -1)
    STORAGE_MENU=()
    MSG_MAX_LENGTH=0
    while read -r line; do
        TAG=$(echo $line | awk '{print $1}')
        TYPE=$(echo $line | awk '{printf "%-10s", $2}')
        FREE=$(echo $line | numfmt --field 4-6 --from-unit=K --to=iec --format %.2f | awk '{printf( "%9sB", $6)}')
        ITEM="  Type: $TYPE Free: $FREE "
        OFFSET=2
        if [[ $((${#ITEM} + $OFFSET)) -gt ${MSG_MAX_LENGTH:-} ]]; then
            MSG_MAX_LENGTH=$((${#ITEM} + $OFFSET))
        fi
        STORAGE_MENU+=("$TAG" "$ITEM" "OFF")
    done < <(pvesm status -content rootdir | awk 'NR>1')
    
    VALID=$(pvesm status -content rootdir | awk 'NR>1')
    if [ -z "$VALID" ]; then
        msg_error "Unable to detect a valid storage location."
        exit 1
    elif [ $((${#STORAGE_MENU[@]}/3)) -eq 1 ]; then
        STORAGE=${STORAGE_MENU[0]}
    else
        while [ -z "${STORAGE:+x}" ]; do
            STORAGE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "STORAGE LOCATION" --radiolist "\nSelect the storage location:" $((${#STORAGE_MENU[@]}/3+9)) $MSG_MAX_LENGTH 6 "${STORAGE_MENU[@]}" 3>&1 1>&2 2>&3) || exit
        done
    fi
    msg_ok "Using ${CL}${BL}$STORAGE${CL} ${GN}for Storage Location."
    msg_ok "Container ID is ${CL}${BL}$var_container${CL}."
    
    msg_info "Getting URL for Latest ${APP} Disk Image"
    if [ "$var_os" == "ubuntu" ]; then
        IMAGE="${var_os}-${var_version}-standard_${var_version}.0-1_amd64.tar.zst"
        if [[ ! -f $TEMPLATE_STORAGE:vztmpl/$IMAGE ]]; then
            pveam download $TEMPLATE_STORAGE $IMAGE >/dev/null 2>&1
        fi
    else
        IMAGE="${var_os}-${var_version}-standard_${var_version}.0-1_amd64.tar.zst"
        if [[ ! -f $TEMPLATE_STORAGE:vztmpl/$IMAGE ]]; then
            pveam download $TEMPLATE_STORAGE "${var_os}-${var_version}-standard" >/dev/null 2>&1
        fi
    fi
    msg_ok "Downloaded ${CL}${BL}$IMAGE${CL}"

    msg_info "Creating LXC Container"
    DISK_REF="$STORAGE:$var_disk"
    TEMPLATE_REF="$TEMPLATE_STORAGE:vztmpl/$IMAGE"
    
    # Build PCT options
    PCT_OPTIONS="
      -features nesting=$var_nesting
      -hostname $var_hostname
      -tags $var_tags
      -net0 name=eth0,bridge=$var_bridge,ip=$var_ip$var_gate$var_ipv6$var_mtu$var_mac$var_vlan
      -onboot 1
      -cores $var_cpu
      -memory $var_ram
      -unprivileged $var_unprivileged
      $var_dns
      $var_ns
    "
    
    pct create $var_container $TEMPLATE_REF $PCT_OPTIONS -rootfs $DISK_REF $var_password >/dev/null 2>&1

    # Configure container for certificate server
    LXC_CONFIG=/etc/pve/lxc/${var_container}.conf
    if [ "$var_unprivileged" == "1" ]; then
        cat >>$LXC_CONFIG <<EOF

# Certificate Server specific configurations
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
lxc.mount.auto: "proc:rw sys:rw"
EOF
    fi
    msg_ok "LXC Container $var_container Created"

    msg_info "Starting LXC Container"
    pct start $var_container
    msg_ok "Started LXC Container"

    msg_info "Setting up Container OS"
    pct exec $var_container -- bash -c "apt-get update && apt-get -y upgrade"
    msg_ok "Set up Container OS"

    msg_info "Installing Certificate Server"
    # Export environment variables to container and run installation
    pct exec $var_container -- bash -c "
        export CERT_SERVER_PORT='$CERT_SERVER_PORT'
        export CERT_SERVER_HTTP_PORT='$CERT_SERVER_HTTP_PORT'
        export VLAN_ID='$VLAN_ID'
        export VLAN_INTERFACE='$VLAN_INTERFACE'
        export WEB_ADMIN_USER='$WEB_ADMIN_USER'
        export WEB_ADMIN_PASS='$WEB_ADMIN_PASS'
        export CA_COUNTRY='${CA_COUNTRY:-US}'
        export CA_STATE='${CA_STATE:-State}'
        export CA_CITY='${CA_CITY:-City}'
        export CA_ORG='${CA_ORG:-Organization}'
        export CA_OU='${CA_OU:-IT Department}'
        export CA_CN='${CA_CN:-Certificate Authority}'
        export CA_EMAIL='${CA_EMAIL:-ca@example.com}'
        export CERT_VALIDITY_DAYS='${CERT_VALIDITY_DAYS:-3650}'
        
        $(declare -f install_certificate_server); install_certificate_server
    " || exit
    msg_ok "Installed Certificate Server"

    msg_info "Creating Container Summary"
    pct exec $var_container -- bash -c "cat > /root/container-info.txt << EOF
Enhanced Certificate Server LXC Container
=========================================

Container ID: $var_container
Hostname: $var_hostname
IP Address: \$(hostname -I | awk '{print \$1}')

Access Information:
- Web Interface: https://\$(hostname -I | awk '{print \$1}'):$CERT_SERVER_PORT
- Username: $WEB_ADMIN_USER
- Password: $WEB_ADMIN_PASS

Management Commands:
- cert-server start|stop|restart|status
- cert-server health
- cert-server logs
- cert-server backup
- cert-server generate-cert <common_name> [org]

API Endpoint: https://\$(hostname -I | awk '{print \$1}'):$CERT_SERVER_PORT/api

Enhanced Features:
✓ Automatic certificate approval via web interface
✓ Base64 CSR import with auto-approval
✓ Private key export for server-generated certificates
✓ Certificate bundle downloads (cert + key)
✓ Duplicate request prevention on refresh
✓ REST API for programmatic access
$([ -n \"$VLAN_ID\" ] && echo \"✓ VLAN support: VLAN $VLAN_ID on $VLAN_INTERFACE\")

Important Files:
- CA Certificate: /opt/cert-server/ca/ca-cert.pem
- Database: /opt/cert-server/config/certificates.db
- Logs: /opt/cert-server/logs/

SAVE THIS INFORMATION!
EOF"
    msg_ok "Created Container Summary"

    msg_info "Cleaning up"
    pct exec $var_container -- bash -c "apt-get -y autoremove && apt-get -y autoclean"
    msg_ok "Cleaned"

    # Get container IP for final display
    IP=$(pct exec $var_container -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null)
    
    msg_info "Completed Successfully!\n"
    echo -e "${APP} LXC Container has been created successfully!"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    ACCESS INFORMATION${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "🌐 Web Interface: ${YW}https://${IP}:${CERT_SERVER_PORT}${CL}"
    echo -e "🔑 Username:      ${YW}${WEB_ADMIN_USER}${CL}"
    echo -e "🔒 Password:      ${YW}${WEB_ADMIN_PASS}${CL}"
    echo -e "🚀 API Endpoint:  ${YW}https://${IP}:${CERT_SERVER_PORT}/api${CL}"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    CONTAINER DETAILS${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "📦 Container ID:  ${YW}${var_container}${CL}"
    echo -e "🖥️  Hostname:      ${YW}${var_hostname}${CL}"
    echo -e "💾 Disk Size:     ${YW}${var_disk}GB${CL}"
    echo -e "🖥️  CPU Cores:     ${YW}${var_cpu}${CL}"
    echo -e "🧠 RAM:           ${YW}${var_ram}MB${CL}"
    echo -e "🌐 IP Address:    ${YW}${IP}${CL}"
    if [[ -n "$VLAN_ID" ]]; then
        echo -e "🏷️  VLAN Config:   ${YW}VLAN ${VLAN_ID} on ${VLAN_INTERFACE}${CL}"
    fi
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    ENHANCED FEATURES${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "✅ ${GN}Automatic certificate approval via web interface${CL}"
    echo -e "✅ ${GN}Base64 CSR import with auto-approval${CL}"
    echo -e "✅ ${GN}Private key export for server-generated certificates${CL}"
    echo -e "✅ ${GN}Certificate bundle downloads (cert + key)${CL}"
    echo -e "✅ ${GN}Duplicate request prevention on page refresh${CL}"
    echo -e "✅ ${GN}REST API for programmatic certificate management${CL}"
    echo -e "✅ ${GN}Health monitoring and management tools${CL}"
    echo -e "✅ ${GN}Secure SSL/TLS configuration with modern ciphers${CL}"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    MANAGEMENT COMMANDS${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "🔧 Container Management:"
    echo -e "   ${YW}pct start ${var_container}${CL}     - Start container"
    echo -e "   ${YW}pct stop ${var_container}${CL}      - Stop container"
    echo -e "   ${YW}pct enter ${var_container}${CL}     - Enter container shell"
    echo -e ""
    echo -e "🔧 Certificate Server Management (inside container):"
    echo -e "   ${YW}cert-server start|stop|restart|status${CL}"
    echo -e "   ${YW}cert-server health${CL}                   - Health check"
    echo -e "   ${YW}cert-server logs${CL}                     - View logs"
    echo -e "   ${YW}cert-server backup${CL}                   - Create backup"
    echo -e "   ${YW}cert-server generate-cert <cn> [org]${CL}  - CLI certificate generation"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    API EXAMPLES${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "📋 Get CA Certificate:"
    echo -e "   ${YW}curl -k https://${IP}:${CERT_SERVER_PORT}/api/ca_cert${CL}"
    echo -e ""
    echo -e "📋 Submit CSR for Auto-Approval:"
    echo -e "   ${YW}curl -k -X POST https://${IP}:${CERT_SERVER_PORT}/api/submit_csr \\${CL}"
    echo -e "   ${YW}     -H \"Content-Type: application/json\" \\${CL}"
    echo -e "   ${YW}     -d '{\"csr\": \"<your_csr_here>\", \"auto_approve\": true}'${CL}"
    echo -e ""
    echo -e "${RD}⚠️  IMPORTANT NOTES:${CL}"
    echo -e "• Save the admin password above - it cannot be recovered!"
    echo -e "• Container info is saved in: ${YW}/root/container-info.txt${CL}"
    echo -e "• CA certificate is located at: ${YW}/opt/cert-server/ca/ca-cert.pem${CL}"
    echo -e "• Database is located at: ${YW}/opt/cert-server/config/certificates.db${CL}"
    echo -e ""
    echo -e "${GN}🎉 Your Enhanced Certificate Server LXC Container is ready!${CL}\n"
}

function update_script() {
    header_info
    if [[ ! -d /var/lib/lxc/$1 ]] && [[ ! -d /etc/pve/lxc/$1.conf ]]; then
        echo -e "No LXC container with ID '$1' exists."
        echo -e "Available containers:"
        pct list
        exit 1
    fi

    if ! pct status $1 &>/dev/null; then
        echo -e "${RD}Container $1 does not exist!${CL}"
        exit 1
    fi

    echo -e "${BL}Updating Certificate Server in Container $1${CL}"
    
    # Check if container is running
    if [[ $(pct status $1) == "status: stopped" ]]; then
        echo -e "${YW}Starting container $1...${CL}"
        pct start $1
        sleep 5
    fi
    
    msg_info "Updating Certificate Server"
    pct exec $1 -- bash -c "
        if [[ -f /usr/local/bin/cert-server ]]; then
            # Update system packages
            apt-get update >/dev/null 2>&1
            apt-get -y upgrade >/dev/null 2>&1
            
            # Update Python packages
            cd /opt/cert-server
            source venv/bin/activate
            pip install --upgrade flask flask-httpauth cryptography pyopenssl >/dev/null 2>&1
            
            # Restart services
            systemctl restart cert-server
            systemctl restart nginx
            
            echo 'Certificate Server updated successfully!'
        else
            echo 'Certificate Server not found in this container!'
            exit 1
        fi
    "
    msg_ok "Updated Certificate Server"
    
    IP=$(pct exec $1 -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null)
    echo -e "\n${GN}✅ Update completed successfully!${CL}"
    echo -e "🌐 Access: ${BL}https://${IP}:8443${CL}"
}

# Main execution
if command -v pveversion >/dev/null 2>&1; then
    if [[ ! -z "$1" ]] && [[ "$1" == "update" ]] && [[ ! -z "$2" ]]; then
        update_script $2
    elif [[ ! -z "$1" ]] && [[ "$1" == "update" ]]; then
        echo -e "${RD}Error: Container ID required for update${CL}"
        echo -e "Usage: $0 update <container_id>"
        echo -e "Example: $0 update 100"
        exit#!/usr/bin/env bash

# Copyright (c) 2021-2025 Enhanced Certificate Server LXC
# Author: Enhanced by Claude, based on tteck methodology
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: Enhanced Certificate Server with Auto-Approval and VLAN Support

# This script creates a Proxmox LXC container for the Enhanced Certificate Server

# App Default Values
APP="Certificate Server"
var_tags="certificate;ssl;tls;ca;security"
var_cpu="2"
var_ram="2048"
var_disk="8"
var_os="debian"
var_version="12"
var_unprivileged="1"

# Color definitions
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="\\033[1m\\033[91m[\\033[1m\\033[96m⌚\\033[1m\\033[91m]\\033[1m\\033[36m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Variables
VERBOSE="no"
SSH_ROOT="yes"
CTID=""
PCT_OSTYPE="$var_os"
PCT_OSVERSION="$var_version"
PCT_DISK_SIZE="$var_disk"
PCT_OPTIONS=""
TEMPLATE_STORAGE="local"
MSG_MAX_LENGTH=0
STORAGE_MENU=()

# Set Temp Dir
if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC" --yesno "This will create a New ${APP} LXC. Proceed?" 10 58); then
    :
else
    clear
    echo -e "⚠ User exited script \n"
    exit
fi

function header_info() {
    clear
    cat <<"EOF"
    ____          _   _  __ _           _         ____                           
   / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
  | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
  | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
   \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   
                                                                                
EOF
    echo -e "                Enhanced ${APP} LXC Container"
    echo ""
}

function msg_info() {
    local msg="$1"
    echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
    local msg="$1"
    echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function PVE_CHECK() {
    if [ $(pgrep -c -f pve-firewall) != 0 ]; then
        if [ -e /etc/proxmox-release ]; then
            if [ "$(pveversion | cut -d'/' -f2 | cut -d'.' -f1)" -lt 7 ]; then
                echo -e "${CROSS} This script requires Proxmox VE 7.0 or higher"
                echo -e "Exiting..."
                sleep 3
                exit 1
            fi
        fi
    fi
}

function ARCH_CHECK() {
    if [ "$(dpkg --print-architecture)" != "amd64" ]; then
        echo -e "\n ${CROSS} This script will not work with PiMox! \n"
        echo -e "Exiting..."
        sleep 3
        exit 1
    fi
}

function exit-script() {
    clear
    echo -e "⚠ User exited script \n"
    exit 1
}

function default_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    # Default settings
    var_container="$CTID"
    var_hostname="cert-server"
    var_disk="$var_disk"
    var_cpu="$var_cpu"
    var_ram="$var_ram"
    var_bridge="vmbr0"
    var_ip="dhcp"
    var_gate=""
    var_ipv6=""
    var_mtu=""
    var_dns=""
    var_ns=""
    var_mac=""
    var_vlan=""
    var_ssh="yes"
    var_verbose="no"
    var_unprivileged="$var_unprivileged"
    var_nesting="1"
    var_password=""
    
    # Certificate Server specific defaults
    CERT_SERVER_PORT="8443"
    CERT_SERVER_HTTP_PORT="8080"
    WEB_ADMIN_USER="admin"
    WEB_ADMIN_PASS="$(openssl rand -base64 12)"
    VLAN_ID=""
    VLAN_INTERFACE=""
    
    clear
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL} ${RD}NO DEVICE PASSTHROUGH${CL}"
    echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
    echo -e "${DGN}Using Container ID: ${BGN}$CTID${CL}"
    echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
    echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
    echo -e "${DGN}Allocated Cores ${BGN}$var_cpu${CL}"
    echo -e "${DGN}Allocated Ram ${BGN}$var_ram${CL}"
    echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
    echo -e "${DGN}Using Static IP: ${BGN}$var_ip${CL}"
    echo -e "${DGN}Using Gateway: ${BGN}$var_gate${CL}"
    echo -e "${DGN}Disable IPv6: ${BGN}$var_ipv6${CL}"
    echo -e "${DGN}Using Interface MTU Size: ${BGN}$var_mtu${CL}"
    echo -e "${DGN}Using DNS Search Domain: ${BGN}$var_dns${CL}"
    echo -e "${DGN}Using DNS Server Address: ${BGN}$var_ns${CL}"
    echo -e "${DGN}Using MAC Address: ${BGN}$var_mac${CL}"
    echo -e "${DGN}Using VLAN Tag: ${BGN}$var_vlan${CL}"
    echo -e "${DGN}Enable Root SSH Access: ${BGN}yes${CL}"
    echo -e "${DGN}Enable Verbose Mode: ${BGN}no${CL}"
    echo -e "${DGN}Certificate Server HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    echo -e "${DGN}Certificate Server Admin User: ${BGN}$WEB_ADMIN_USER${CL}"
    echo -e "${BL}Creating a ${APP} LXC using the above default settings${CL}"
}

function advanced_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    clear
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    echo -e "${YW}Type Advanced, or Press [ENTER] for Default.${CL}"
    echo ""
    sleep 1

    case $(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER TYPE" --menu "\nChoose Type" 10 58 2 \
        "1" "Unprivileged (Recommended)" \
        "0" "Privileged" 3>&2 2>&1 1>&3) in
    1) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    0) var_unprivileged="0"; echo -e "${DGN}Using Container Type: ${BGN}Privileged${CL}" ;;
    *) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    esac

    if PW=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "PASSWORD" --passwordbox "\nSet Root Password (needed for root ssh access)" 9 58 3>&2 2>&1 1>&3); then
        if [[ ! -z "$PW" ]]; then
            var_password="-password $PW"
            echo -e "${DGN}Using Root Password: ${BGN}$PW${CL}"
        else
            var_password=""
            echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
        fi
    else
        exit-script
    fi

    if CT_ID=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER ID" --inputbox "\nSet Container ID" 9 58 $CTID 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_ID" ]]; then
            var_container="$CTID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        else
            var_container="$CT_ID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        fi
    else
        exit-script
    fi

    if CT_NAME=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HOSTNAME" --inputbox "\nSet Hostname" 9 58 "cert-server" 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_NAME" ]]; then
            var_hostname="cert-server"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        else
            var_hostname="$CT_NAME"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        fi
    else
        exit-script
    fi

    if DISK_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DISK SIZE" --inputbox "\nSet Disk Size in GB" 9 58 $var_disk 3>&2 2>&1 1>&3); then
        if [[ -z "$DISK_SIZE" ]]; then
            var_disk="$var_disk"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        else
            var_disk="$DISK_SIZE"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        fi
    else
        exit-script
    fi

    if CORE_COUNT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CORES" --inputbox "\nAllocate CPU Cores" 9 58 $var_cpu 3>&2 2>&1 1>&3); then
        if [[ -z "$CORE_COUNT" ]]; then
            var_cpu="$var_cpu"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        else
            var_cpu="$CORE_COUNT"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        fi
    else
        exit-script
    fi

    if RAM_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "RAM" --inputbox "\nAllocate RAM in MB" 9 58 $var_ram 3>&2 2>&1 1>&3); then
        if [[ -z "$RAM_SIZE" ]]; then
            var_ram="$var_ram"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        else
            var_ram="$RAM_SIZE"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        fi
    else
        exit-script
    fi

    if BRG=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "BRIDGE" --inputbox "\nSet a Bridge" 9 58 "vmbr0" 3>&2 2>&1 1>&3); then
        if [[ -z "$BRG" ]]; then
            var_bridge="vmbr0"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        else
            var_bridge="$BRG"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        fi
    else
        exit-script
    fi

    if NET=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "IP ADDRESS" --inputbox "\nSet a Static IPv4 CIDR Address(/24)" 9 58 dhcp 3>&2 2>&1 1>&3); then
        if [[ "$NET" == "dhcp" ]]; then
            var_ip="dhcp"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        else
            var_ip="$NET"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        fi
    else
        exit-script
    fi

    if GATE1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "GATEWAY" --inputbox "\nSet a Gateway IP (mandatory if Static IP was used)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$GATE1" ]]; then
            var_gate=""
            echo -e "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
        else
            var_gate=",gw=$GATE1"
            echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
        fi
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "IPv6" --yesno "\nDisable IPv6?" 9 58); then
        var_ipv6=""
        echo -e "${DGN}Disable IPv6: ${BGN}Yes${CL}"
    else
        var_ipv6=",ip6=dhcp"
        echo -e "${DGN}Disable IPv6: ${BGN}No${CL}"
    fi

    if MTU1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MTU SIZE" --inputbox "\nSet Interface MTU Size (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MTU1" ]]; then
            var_mtu=""
            echo -e "${DGN}Using Interface MTU Size: ${BGN}Default${CL}"
        else
            var_mtu=",mtu=$MTU1"
            echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU1${CL}"
        fi
    else
        exit-script
    fi

    if SD=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SEARCH DOMAIN" --inputbox "\nSet DNS Search Domain (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$SD" ]]; then
            SX=host
            var_dns=""
            echo -e "${DGN}Using DNS Search Domain: ${BGN}Host${CL}"
        else
            SX=$SD
            var_dns="-searchdomain $SD"
            echo -e "${DGN}Using DNS Search Domain: ${BGN}$SD${CL}"
        fi
    else
        exit-script
    fi

    if NX=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SERVER IP" --inputbox "\nSet DNS Server IP (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$NX" ]]; then
            var_ns=""
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}Host${CL}"
        else
            var_ns="-nameserver $NX"
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}$NX${CL}"
        fi
    else
        exit-script
    fi

    if MAC1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MAC ADDRESS" --inputbox "\nSet MAC Address(leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MAC1" ]]; then
            var_mac=""
            echo -e "${DGN}Using MAC Address: ${BGN}Default${CL}"
        else
            var_mac=",hwaddr=$MAC1"
            echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
        fi
    else
        exit-script
    fi

    if VLAN1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN TAG" --inputbox "\nSet VLAN Tag (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$VLAN1" ]]; then
            var_vlan=""
            echo -e "${DGN}Using VLAN Tag: ${BGN}Default${CL}"
        else
            var_vlan=",tag=$VLAN1"
            echo -e "${DGN}Using VLAN Tag: ${BGN}$VLAN1${CL}"
        fi
    else
        exit-script
    fi

    # Certificate Server specific configurations
    if CS_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CERTIFICATE SERVER PORT" --inputbox "\nSet HTTPS Port (default: 8443)" 9 58 "8443" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_PORT" ]]; then
            CERT_SERVER_PORT="8443"
        else
            CERT_SERVER_PORT="$CS_PORT"
        fi
        echo -e "${DGN}Using HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    else
        exit-script
    fi

    if CS_HTTP_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HTTP PORT" --inputbox "\nSet HTTP Port (default: 8080)" 9 58 "8080" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_HTTP_PORT" ]]; then
            CERT_SERVER_HTTP_PORT="8080"
        else
            CERT_SERVER_HTTP_PORT="$CS_HTTP_PORT"
        fi
        echo -e "${DGN}Using HTTP Port: ${BGN}$CERT_SERVER_HTTP_PORT${CL}"
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN CONFIGURATION" --yesno "\nConfigure VLAN support inside container?" 9 58); then
        if VLAN_ID_INPUT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN ID" --inputbox "\nEnter VLAN ID" 9 58 3>&2 2>&1 1>&3); then
            if [[ ! -z "$VLAN_ID_INPUT" ]]; then
                VLAN_ID="$VLAN_ID_INPUT"
                if VLAN_IFACE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN INTERFACE" --inputbox "\nEnter parent interface (e.g., eth0)" 9 58 "eth0" 3>&2 2>&1 1>&3); then
                    VLAN_INTERFACE="$VLAN_IFACE"
                    echo -e "${DGN}VLAN Configuration: ${BGN}ID=$VLAN_ID Interface=$VLAN_INTERFACE${CL}"
                fi
            fi
        fi
    fi

    if ADM_USER=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN USERNAME" --inputbox "\nSet admin username (default: admin)" 9 58 "admin" 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_USER" ]]; then
            WEB_ADMIN_USER="admin"
        else
            WEB_ADMIN_USER="$ADM_USER"
        fi
        echo -e "${DGN}Using Admin Username: ${BGN}$WEB_ADMIN_USER${CL}"
    else
        exit-script
    fi

    if ADM_PASS=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN PASSWORD" --passwordbox "\nSet admin password (leave blank for auto-generated)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_PASS" ]]; then
            WEB_ADMIN_PASS="$(openssl rand -base64 12)"
            echo -e "${DGN}Using Admin Password: ${BGN}Auto-generated${CL}"
        else
            WEB_ADMIN_PASS="$ADM_PASS"
            echo -e "${DGN}Using Admin Password: ${BGN}Custom${CL}"
        fi
    else
        exit-script
    fi

    var_ssh="yes"
    var_verbose="no"
    var_nesting="1"

    echo -e "${BL}Creating a ${APP} LXC using the above advanced settings${CL}"
}

function install_certificate_server() {
    # Set STD based on VERBOSE
    if [[ "$VERBOSE" == "yes" ]]; then
        STD=""
    else
        STD="silent"
    fi
    silent() { "$@" > /dev/null 2>&1; }

    # Network check
    RESOLVEDIP=$(getent hosts github.com | awk '{ print $1 }')
    if [[ -z "$RESOLVEDIP" ]]; then
        echo "No Network!"
        exit 1
    fi

    echo "Installing Dependencies..."
    $STD apt-get update
    $STD apt-get install -y \
      curl \
      sudo \
      mc \
      gnupg \
      apt-transport-https \
      software-properties-common \
      openssl \
      nginx \
      python3 \
      python3-pip \
      python3-venv \
      sqlite3 \
      wget \
      jq \
      bridge-utils \
      vlan \
      ufw \
      net-tools \
      netcat-openbsd

    # Configuration variables with defaults
    CERT_SERVER_PORT=${CERT_SERVER_PORT:-8443}
    CERT_SERVER_HTTP_PORT=${CERT_SERVER_HTTP_PORT:-8080}
    VLAN_ID=${VLAN_ID:-""}
    VLAN_INTERFACE=${VLAN_INTERFACE:-""}
    CA_COUNTRY=${CA_COUNTRY:-"US"}
    CA_STATE=${CA_STATE:-"State"}
    CA_CITY=${CA_CITY:-"City"}
    CA_ORG=${CA_ORG:-"Organization"}
    CA_OU=${CA_OU:-"IT Department"}
    CA_CN=${CA_CN:-"Certificate Authority"}
    CA_EMAIL=${CA_EMAIL:-"ca@example.com"}
    CERT_VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-3650}
    WEB_ADMIN_USER=${WEB_ADMIN_USER:-"admin"}
    WEB_ADMIN_PASS=${WEB_ADMIN_PASS:-"$(openssl rand -base64 12)"}

    # VLAN Configuration if specified
    if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
        echo "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}..."
        
        # Load 8021q module
        modprobe 8021q
        echo "8021q" >> /etc/modules
        
        # Create VLAN interface configuration
        cat > /etc/systemd/network/10-vlan.netdev << EOF
[NetDev]
Name=$VLAN_INTERFACE.$VLAN_ID
Kind=vlan

[VLAN]
Id=$VLAN_ID
EOF

        cat > /etc/systemd/network/20-vlan.network << EOF
[Match]
Name=$VLAN_INTERFACE.$VLAN_ID

[Network]
DHCP=yes
IPForward=yes
EOF
        
        systemctl restart systemd-networkd
    fi

    echo "Setting up Certificate Server Directory Structure..."
    mkdir -p /opt/cert-server/{ca,certs,keys,csr,config,web,logs,backups}
    mkdir -p /opt/cert-server/web/{static,templates}
    chmod 755 /opt/cert-server
    chmod 700 /opt/cert-server/{ca,keys}
    chmod 755 /opt/cert-server/logs

    echo "Creating Certificate Authority..."
    cd /opt/cert-server/ca

    # Create CA private key
    openssl genrsa -out ca-key.pem 4096
    chmod 600 ca-key.pem

    # Create CA certificate
    cat > ca.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $CA_CN
emailAddress = $CA_EMAIL

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign
EOF

    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca-cert.pem -config ca.conf
    chmod 644 ca-cert.pem

    # Create serial number file
    echo 1000 > serial
    touch index.txt

    echo "Setting up Python Virtual Environment..."
    cd /opt/cert-server
    python3 -m venv venv
    source venv/bin/activate
    pip install flask flask-httpauth cryptography pyopenssl

    echo "Creating Enhanced Certificate Server Web Application..."
    cat > /opt/cert-server/web/app.py << 'EOF'
#!/usr/bin/env python3

import os
import sys
import json
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
import tempfile
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

# Configuration
CA_DIR = '/opt/cert-server/ca'
CERT_DIR = '/opt/cert-server/certs'
KEY_DIR = '/opt/cert-server/keys'
CSR_DIR = '/opt/cert-server/csr'
DB_PATH = '/opt/cert-server/config/certificates.db'

# Authentication
users = {
    os.environ.get('WEB_ADMIN_USER', 'admin'): os.environ.get('WEB_ADMIN_PASS', 'changeme')
}

@auth.verify_password
def verify_password(username, password):
    return users.get(username) == password

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            csr_data TEXT,
            cert_data TEXT,
            key_data TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_date TIMESTAMP,
            expires_date TIMESTAMP,
            auto_approved BOOLEAN DEFAULT 0,
            request_hash TEXT UNIQUE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_hash TEXT UNIQUE NOT NULL,
            submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_ca_key_cert():
    with open(os.path.join(CA_DIR, 'ca-key.pem'), 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_serial_number():
    with open(os.path.join(CA_DIR, 'serial'), 'r') as f:
        serial = int(f.read().strip())
    
    with open(os.path.join(CA_DIR, 'serial'), 'w') as f:
        f.write(str(serial + 1))
    
    return serial

def generate_request_hash(data):
    """Generate hash to prevent duplicate requests"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_certificate(csr_data, auto_approve=True):
    try:
        ca_key, ca_cert = load_ca_key_cert()
        csr = x509.load_pem_x509_csr(csr_data.encode())
        
        # Extract common name from CSR
        common_name = None
        for attribute in csr.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                common_name = attribute.value
                break
        
        if not common_name:
            raise ValueError("No common name found in CSR")
        
        # Generate request hash to prevent duplicates
        request_hash = generate_request_hash(csr_data + common_name)
        
        # Check for existing request
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM certificates WHERE request_hash = ?', (request_hash,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Duplicate request detected - certificate already exists")
        
        # Generate serial number
        serial = generate_serial_number()
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_encipherment=True,
                digital_signature=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # Store in database with request hash
        cursor.execute('''
            INSERT INTO certificates 
            (common_name, serial_number, status, csr_data, cert_data, approved_date, expires_date, auto_approved, request_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            common_name,
            str(serial),
            'approved' if auto_approve else 'pending',
            csr_data,
            cert_pem,
            datetime.utcnow() if auto_approve else None,
            cert.not_valid_after,
            auto_approve,
            request_hash
        ))
        conn.commit()
        conn.close()
        
        return cert_pem, str(serial)
        
    except Exception as e:
        raise Exception(f"Certificate signing failed: {str(e)}")

def generate_key_and_csr(common_name, organization='', country='US'):
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Generated Certificate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    
    # Convert to PEM
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    
    return key_pem, csr_pem

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request', methods=['GET', 'POST'])
def request_certificate():
    if request.method == 'POST':
        try:
            if 'csr_data' in request.form:
                # Handle uploaded CSR
                csr_data = request.form['csr_data']
                auto_approve = request.form.get('auto_approve', 'off') == 'on'
                
                # Detect and decode Base64 if needed
                try:
                    decoded_csr = base64.b64decode(csr_data).decode()
                    if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                        csr_data = decoded_csr
                except:
                    pass  # Not base64 or not valid, use as-is
                
                cert_pem, serial = sign_certificate(csr_data, auto_approve)
                
                flash(f'Certificate {"approved" if auto_approve else "submitted"} with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
            else:
                # Generate new certificate
                common_name = request.form['common_name']
                organization = request.form.get('organization', '')
                country = request.form.get('country', 'US')
                
                key_pem, csr_pem = generate_key_and_csr(common_name, organization, country)
                cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
                
                # Store the private key for generated certificates
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
                conn.commit()
                conn.close()
                
                flash(f'Certificate generated and approved with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('request.html')

@app.route('/certificate/<serial>')
def view_certificate(serial):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        flash('Certificate not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('certificate.html', cert=cert_data)

@app.route('/download/<serial>/<file_type>')
def download_certificate(serial, file_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        return "Certificate not found", 404
    
    if file_type == 'cert':
        content = cert_data[5]  # cert_data
        filename = f'certificate_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'key' and cert_data[6]:  # key_data exists
        content = cert_data[6]
        filename = f'private_key_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'csr':
        content = cert_data[4]  # csr_data
        filename = f'csr_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'bundle':
        # Create certificate bundle with key if available
        bundle_content = cert_data[5]  # cert_data
        if cert_data[6]:  # key_data
            bundle_content += "\n" + cert_data[6]
        content = bundle_content
        filename = f'certificate_bundle_{serial}.pem'
        mimetype = 'application/x-pem-file'
    else:
        return "Invalid file type", 400
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    return send_file(temp_file_path, as_attachment=True, download_name=filename, mimetype=mimetype)

@app.route('/certificates')
def list_certificates():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates ORDER BY created_date DESC')
    certificates = cursor.fetchall()
    conn.close()
    
    return render_template('certificates.html', certificates=certificates)

@app.route('/api/submit_csr', methods=['POST'])
def api_submit_csr():
    try:
        data = request.json
        csr_data = data.get('csr')
        auto_approve = data.get('auto_approve', True)
        
        if not csr_data:
            return jsonify({'error': 'CSR data is required'}), 400
        
        # Decode base64 if needed
        try:
            decoded_csr = base64.b64decode(csr_data).decode()
            if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                csr_data = decoded_csr
        except:
            pass  # Not base64 encoded or not valid
        
        cert_pem, serial = sign_certificate(csr_data, auto_approve)
        
        return jsonify({
            'success': True,
            'serial': serial,
            'certificate': cert_pem,
            'status': 'approved' if auto_approve else 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ca_cert')
def api_ca_cert():
    try:
        with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'r') as f:
            ca_cert = f.read()
        return jsonify({'ca_certificate': ca_cert})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('CERT_SERVER_HTTP_PORT', 8080)), debug=False)
EOF

    chmod +x /opt/cert-server/web/app.py

    echo "Creating Web Templates..."
    mkdir -p /opt/cert-server/web/{templates,static}

    # Create base template
    cat > /opt/cert-server/web/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Certificate Server{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="fas fa-certificate"></i> Certificate Server
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="{{ url_for('index') }}">Home</a>
                <a class="nav-link" href="{{ url_for('request_certificate') }}">Request Certificate</a>
                <a class="nav-link" href="{{ url_for('list_certificates') }}">View Certificates</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

    # Create index template
    cat > /opt/cert-server/web/templates/index.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="jumbotron bg-light p-5 rounded">
            <h1 class="display-4"><i class="fas fa-certificate text-primary"></i> Certificate Server</h1>
            <p class="lead">Generate and manage SSL/TLS certificates with automatic approval.</p>
            <hr class="my-4">
            <p>Enhanced features:</p>
            <ul>
                <li>✅ Automatic certificate approval for web interface requests</li>
                <li>✅ Base64 encoded CSR import with auto-approval</li>
                <li>✅ Private key export for server-generated certificates</li>
                <li>✅ Certificate bundle downloads</li>
                <li>✅ Duplicate request prevention</li>
                <li>✅ REST API for automation</li>
            </ul>
            <a class="btn btn-primary btn-lg" href="{{ url_for('request_certificate') }}" role="button">
                <i class="fas fa-plus"></i> Request Certificate
            </a>
            <a class="btn btn-secondary btn-lg" href="{{ url_for('list_certificates') }}" role="button">
                <i class="fas fa-list"></i> View Certificates
            </a>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create request template
    cat > /opt/cert-server/web/templates/request.html << 'EOF'
{% extends "base.html" %}

{% block title %}Request Certificate - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <h2><i class="fas fa-plus-circle"></i> Request Certificate</h2>
        
        <ul class="nav nav-tabs" id="requestTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="generate-tab" data-bs-toggle="tab" data-bs-target="#generate" type="button" role="tab">
                    <i class="fas fa-magic"></i> Generate New Certificate
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="upload-tab" data-bs-toggle="tab" data-bs-target="#upload" type="button" role="tab">
                    <i class="fas fa-upload"></i> Upload CSR
                </button>
            </li>
        </ul>
        
        <div class="tab-content mt-3" id="requestTabsContent">
            <!-- Generate New Certificate Tab -->
            <div class="tab-pane fade show active" id="generate" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Generate New Certificate</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="common_name" class="form-label">Common Name (CN) *</label>
                                <input type="text" class="form-control" id="common_name" name="common_name" required>
                                <div class="form-text">e.g., www.example.com or *.example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="organization" class="form-label">Organization</label>
                                <input type="text" class="form-control" id="organization" name="organization">
                            </div>
                            <div class="mb-3">
                                <label for="country" class="form-label">Country</label>
                                <input type="text" class="form-control" id="country" name="country" value="US" maxlength="2">
                                <div class="form-text">2-letter country code</div>
                            </div>
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-certificate"></i> Generate & Approve Certificate
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Upload CSR Tab -->
            <div class="tab-pane fade" id="upload" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Upload Certificate Signing Request</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="csr_data" class="form-label">CSR Data *</label>
                                <textarea class="form-control" id="csr_data" name="csr_data" rows="10" required placeholder="Paste your PEM encoded CSR or Base64 encoded CSR here"></textarea>
                                <div class="form-text">Supports both PEM format and Base64 encoded CSRs</div>
                            </div>
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="auto_approve" name="auto_approve" checked>
                                <label class="form-check-label" for="auto_approve">
                                    Automatically approve certificate
                                </label>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload"></i> Submit CSR
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Prevent duplicate submissions
const submittedForms = new Set();

function generateFormHash(form) {
    const formData = new FormData(form);
    const data = Array.from(formData.entries()).map(([k, v]) => `${k}:${v}`).join('|');
    return btoa(data).replace(/[^a-zA-Z0-9]/g, '');
}

function handleSubmit(form) {
    const formHash = generateFormHash(form);
    
    if (submittedForms.has(formHash)) {
        alert('This certificate request has already been submitted. Please check the certificates list.');
        return false;
    }
    
    submittedForms.add(formHash);
    
    // Disable submit button
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    }
    
    return true;
}
</script>
{% endblock %}
EOF

    # Create certificate view template
    cat > /opt/cert-server/web/templates/certificate.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificate {{ cert[2] }} - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-10 mx-auto">
        <h2><i class="fas fa-certificate"></i> Certificate Details</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Certificate Information</h5>
                        <table class="table table-borderless">
                            <tr>
                                <td><strong>Common Name:</strong></td>
                                <td>{{ cert[1] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Serial Number:</strong></td>
                                <td>{{ cert[2] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Status:</strong></td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                    {% if cert[10] %}
                                        <span class="badge bg-info ms-1">Auto-Approved</span>
                                    {% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Created:</strong></td>
                                <td>{{ cert[7] }}</td>
                            </tr>
                            {% if cert[8] %}
                            <tr>
                                <td><strong>Approved:</strong></td>
                                <td>{{ cert[8] }}</td>
                            </tr>
                            {% endif %}
                            <tr>
                                <td><strong>Expires:</strong></td>
                                <td>{{ cert[9] }}</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h5>Downloads</h5>
                        <div class="d-grid gap-2">
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='cert') }}" 
                               class="btn btn-primary">
                                <i class="fas fa-download"></i> Download Certificate
                            </a>
                            {% if cert[4] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='csr') }}" 
                               class="btn btn-secondary">
                                <i class="fas fa-download"></i> Download CSR
                            </a>
                            {% endif %}
                            {% if cert[6] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='key') }}" 
                               class="btn btn-warning">
                                <i class="fas fa-key"></i> Download Private Key
                            </a>
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='bundle') }}" 
                               class="btn btn-success">
                                <i class="fas fa-file-archive"></i> Download Bundle (Cert + Key)
                            </a>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                {% if cert[5] %}
                <hr>
                <h5>Certificate Data</h5>
                <pre class="bg-light p-3 small"><code>{{ cert[5] }}</code></pre>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create certificates list template
    cat > /opt/cert-server/web/templates/certificates.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificates - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h2><i class="fas fa-list"></i> Certificates</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Common Name</th>
                                <th>Serial Number</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Auto-Approved</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for cert in certificates %}
                            <tr>
                                <td>{{ cert[1] }}</td>
                                <td>{{ cert[2] }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                </td>
                                <td>{{ cert[7] }}</td>
                                <td>{{ cert[9] }}</td>
                                <td>
                                    {% if cert[10] %}
                                        <i class="fas fa-check text-success"></i>
                                    {% else %}
                                        <i class="fas fa-times text-muted"></i>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="{{ url_for('view_certificate', serial=cert[2]) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    echo "Creating Systemd Service..."
    cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Enhanced Certificate Server with Auto-Approval
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cert-server/web
Environment=PATH=/opt/cert-server/venv/bin
Environment=WEB_ADMIN_USER=$WEB_ADMIN_USER
Environment=WEB_ADMIN_PASS=$WEB_ADMIN_PASS
Environment=CERT_SERVER_HTTP_PORT=$CERT_SERVER_HTTP_PORT
ExecStart=/opt/cert-server/venv/bin/python app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cert-server

    echo "Configuring Nginx Reverse Proxy with SSL..."
    
    # Generate web server certificate for HTTPS
    cd /opt/cert-server/ca
    openssl genrsa -out web-server-key.pem 2048
    chmod 600 web-server-key.pem
    
    cat > web-server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
CN = $(hostname -f)

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $(hostname -f)
DNS.2 = $(hostname -s)
DNS.3 = localhost
IP.1 = $(hostname -I | awk '{print $1}' 2>/dev/null || echo '127.0.0.1')
IP.2 = 127.0.0.1
EOF
    
    openssl req -new -key web-server-key.pem -out web-server.csr -config web-server.conf
    openssl x509 -req -in web-server.csr -CA ca-cert.pem -CAkey ca-key.pem -out web-server.pem -days 365 -extensions v3_req -extfile web-server.conf
    chmod 644 web-server.pem

    cat > /etc/nginx/sites-available/cert-server << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name:$CERT_SERVER_PORT\$request_uri;
}

# HTTPS Certificate Server
server {
    listen $CERT_SERVER_PORT ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /opt/cert-server/ca/web-server.pem;
    ssl_certificate_key /opt/cert-server/ca/web-server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=web:10m rate=30r/m;
    
    # Main application
    location / {
        limit_req zone=web burst=5 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
    
    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=api burst=3 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Content-Type application/json;
    }
    
    # Health check endpoint (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        access_log off;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/cert-server /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl enable nginx

    echo "Creating Management Scripts..."
    
    # Enhanced management script
    cat > /opt/cert-server/manage.sh << 'EOF'
#!/bin/bash

CERT_SERVER_DIR="/opt/cert-server"
VENV_PATH="$CERT_SERVER_DIR/venv"
LOG_FILE="$CERT_SERVER_DIR/logs/management.log"

mkdir -p "$(dirname "$LOG_FILE")"

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

case "$1" in
    start)
        echo "Starting Certificate Server services..."
        log_action "Starting services"
        systemctl start cert-server
        systemctl start nginx
        echo "✓ Certificate Server started"
        ;;
    stop)
        echo "Stopping Certificate Server services..."
        log_action "Stopping services"
        systemctl stop cert-server
        systemctl stop nginx
        echo "✓ Certificate Server stopped"
        ;;
    restart)
        echo "Restarting Certificate Server services..."
        log_action "Restarting services"
        systemctl restart cert-server
        systemctl restart nginx
        echo "✓ Certificate Server restarted"
        ;;
    status)
        echo "=== Certificate Server Status ==="
        echo ""
        echo "Services:"
        systemctl is-active cert-server &>/dev/null && echo "  ✓ Certificate Server: Running" || echo "  ✗ Certificate Server: Stopped"
        systemctl is-active nginx &>/dev/null && echo "  ✓ Nginx: Running" || echo "  ✗ Nginx: Stopped"
        echo ""
        echo "Network:"
        echo "  Web Interface: https://$(hostname -I | awk '{print $1}'):8443"
        echo "  API Endpoint:  https://$(hostname -I | awk '{print $1}'):8443/api"
        echo ""
        if [[ -f "$CERT_SERVER_DIR/config/certificates.db" ]]; then
            echo "Certificate Statistics:"
            source $VENV_PATH/bin/activate
            python3 << 'PYTHON_EOF'
import sqlite3
try:
    conn = sqlite3.connect('/opt/cert-server/config/certificates.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM certificates')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM certificates WHERE status = "approved"')
    approved = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM certificates WHERE auto_approved = 1')
    auto_approved = cursor.fetchone()[0]
    
    print(f"  Total Certificates: {total}")
    print(f"  Approved: {approved}")
    print(f"  Auto-Approved: {auto_approved}")
    
    conn.close()
except Exception as e:
    print(f"  Database Error: {e}")
PYTHON_EOF
        fi
        ;;
    logs)
        echo "Certificate Server Logs (Ctrl+C to exit):"
        journalctl -u cert-server -f --no-pager
        ;;
    backup)
        BACKUP_DIR="/opt/cert-server/backups/backup-$(date +%Y%m%d_%H%M%S)"
        echo "Creating backup in $BACKUP_DIR..."
        log_action "Creating backup: $BACKUP_DIR"
        
        mkdir -p "$BACKUP_DIR"
        systemctl stop cert-server
        
        cp -r $CERT_SERVER_DIR/ca "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/config "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/certs "$BACKUP_DIR/" 2>/dev/null || true
        cp -r $CERT_SERVER_DIR/keys "$BACKUP_DIR/" 2>/dev/null || true
        cp -r $CERT_SERVER_DIR/web "$BACKUP_DIR/"
        
        tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
        rm -rf "$BACKUP_DIR"
        
        systemctl start cert-server
        echo "✓ Backup created: $BACKUP_DIR.tar.gz"
        log_action "Backup completed: $BACKUP_DIR.tar.gz"
        ;;
    generate-cert)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 generate-cert <common_name> [organization]"
            exit 1
        fi
        
        echo "Generating certificate for $2..."
        log_action "Generating certificate for: $2"
        source $VENV_PATH/bin/activate
        python3 << PYTHON_EOF
import sys
sys.path.append('/opt/cert-server/web')
try:
    from app import generate_key_and_csr, sign_certificate, init_db
    import sqlite3
    
    init_db()
    key_pem, csr_pem = generate_key_and_csr('$2', '${3:-Generated Certificate}')
    cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
    
    conn = sqlite3.connect('/opt/cert-server/config/certificates.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
    conn.commit()
    conn.close()
    
    print(f"✓ Certificate generated successfully")
    print(f"  Serial Number: {serial}")
    print(f"  Common Name: $2")
    print(f"  Access via: https://$(hostname -I | awk '{print $1}'):8443/certificate/{serial}")
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
PYTHON_EOF
        ;;
    health)
        echo "=== Certificate Server Health Check ==="
        
        # Check services
        services=("cert-server" "nginx")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                echo "  ✓ $service: Running"
            else
                echo "  ✗ $service: Not running"
            fi
        done
        
        # Check ports
        ports=("8080" "8443")
        for port in "${ports[@]}"; do
            if nc -z localhost "$port" 2>/dev/null; then
                echo "  ✓ Port $port: Open"
            else
                echo "  ✗ Port $port: Closed"
            fi
        done
        
        # Check web interface
        if curl -k -s "https://localhost:8443/health" >/dev/null 2>&1; then
            echo "  ✓ Web Interface: Accessible"
        else
            echo "  ✗ Web Interface: Not accessible"
        fi
        
        # Check API
        if curl -k -s "https://localhost:8443/api/ca_cert" | grep -q "ca_certificate"; then
            echo "  ✓ API: Functional"
        else
            echo "  ✗ API: Not responding"
        fi
        ;;
    *)
        echo "Certificate Server Management Tool"
        echo ""
        echo "Usage: $0 {command}"
        echo ""
        echo "Commands:"
        echo "  start                    Start all services"
        echo "  stop                     Stop all services" 
        echo "  restart                  Restart all services"
        echo "  status                   Show detailed status"
        echo "  health                   Run health check"
        echo "  logs                     Follow application logs"
        echo "  backup                   Create backup"
        echo "  generate-cert <cn> [org] Generate certificate via CLI"
        echo ""
        echo "Web Interface: https://$(hostname -I | awk '{print $1}'):8443"
        echo "API Endpoint:  https://$(hostname -I | awk '{print $1}'):8443/api"
        exit 1
        ;;
esac
EOF

    chmod +x /opt/cert-server/manage.sh
    ln -sf /opt/cert-server/manage.sh /usr/local/bin/cert-server

    # Create API client script
    cat > /opt/cert-server/api-client.sh << 'EOF'
#!/bin/bash

# Certificate Server API Client
SERVER_URL="${CERT_SERVER_URL:-https://localhost:8443}"
API_BASE="$SERVER_URL/api"

case "$1" in
    submit-csr)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 submit-csr <csr_file_path>"
            exit 1
        fi
        
        if [[ ! -f "$2" ]]; then
            echo "CSR file not found: $2"
            exit 1
        fi
        
        CSR_DATA=$(cat "$2")
        
        curl -k -X POST "$API_BASE/submit_csr" \
             -H "Content-Type: application/json" \
             -d "{\"csr\": \"$(echo "$CSR_DATA" | sed 's/$/\\n/' | tr -d '\n')\", \"auto_approve\": true}" \
             | jq .
        ;;
        
    submit-csr-b64)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 submit-csr-b64 <base64_encoded_csr>"
            exit 1
        fi
        
        curl -k -X POST "$API_BASE/submit_csr" \
             -H "Content-Type: application/json" \
             -d "{\"csr\": \"$2\", \"auto_approve\": true}" \
             | jq .
        ;;
        
    get-ca-cert)
        curl -k -X GET "$API_BASE/ca_cert" | jq -r .ca_certificate
        ;;
        
    *)
        echo "Certificate Server API Client"
        echo "Usage: $0 {submit-csr|submit-csr-b64|get-ca-cert}"
        echo ""
        echo "Examples:"
        echo "  $0 submit-csr /path/to/request.csr"
        echo "  $0 submit-csr-b64 LS0tLS1CRUdJTi..."
        echo "  $0 get-ca-cert > ca.pem"
        exit 1
        ;;
esac
EOF

    chmod +x /opt/cert-server/api-client.sh

    echo "Initializing Database and Starting Services..."
    cd /opt/cert-server/web
    source ../venv/bin/activate
    python3 -c "from app import init_db; init_db()"

    systemctl start cert-server
    systemctl start nginx
    
    # Wait for services to start
    sleep 3

    # Create MOTD
    cat > /etc/motd << EOF
   ____          _   _  __ _           _         ____                           
  / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
 | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
 | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
  \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   

Enhanced Certificate Server - LXC Container

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
API Endpoint:  https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT/api
Username:      $WEB_ADMIN_USER
Password:      $WEB_ADMIN_PASS

Management:    cert-server {start|stop|restart|status|logs|backup}

Enhanced Features:
✓ Automatic certificate approval via web interface
✓ Base64 CSR import with auto-approval  
✓ Private key export for server-generated certificates
✓ Certificate bundle downloads (cert + key)
✓ Duplicate request prevention on refresh
✓ REST API for programmatic access

EOF

    # Save credentials to file for easy access
    cat > /root/cert-server-credentials.txt << EOF
Certificate Server Access Information
====================================

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
Username: $WEB_ADMIN_USER
Password: $WEB_ADMIN_PASS

API Endpoint: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT/api

Management Commands:
- cert-server start|stop|restart|status
- cert-server health
- cert-server logs  
- cert-server backup
- cert-server generate-cert <common_name> [org]

CA Certificate Location: /opt/cert-server/ca/ca-cert.pem
Database Location: /opt/cert-server/config/certificates.db

IMPORTANT: Save this password information!
EOF
    
    chmod 600 /root/cert-server-credentials.txt

    echo "Cleaning up..."
    $STD apt-get -y autoremove
    $STD apt-get -y autoclean

    echo "Certificate Server installation completed!"
}

function install_script() {
    ARCH_CHECK
    PVE_CHECK
    
    header_info
    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "SETTINGS" --yesno "\nUse Default Settings?" --no-button Advanced 10 58); then
        default_settings
    else
        advanced_settings
    fi
    
    msg_info "Validating Storage"
    TEMPLATE_STORAGE=$(pvesh get /storage --output-format json | jq -r '.[] | select(.content | contains("vztmpl")) | .storage' | head -1)
    STORAGE_MENU=()
    MSG_MAX_LENGTH=0
    while read -r line; do
        TAG=$(echo $line | awk '{print $1}')
        TYPE=$(echo $line | awk '{printf "%-10s", $2}')
        FREE=$(echo $line | numfmt --field 4-6 --from-unit=K --to=iec --format %.2f | awk '{printf( "%9sB", $6)}')
        ITEM="  Type: $TYPE Free: $FREE "
        OFFSET=2
        if [[ $((${#ITEM} + $OFFSET)) -gt ${MSG_MAX_LENGTH:-} ]]; then
            MSG_MAX_LENGTH=$((${#ITEM} + $OFFSET))
        fi
        STORAGE_MENU+=("$TAG" "$ITEM" "OFF")
    done < <(pvesm status -content rootdir | awk 'NR>1')
    
    VALID=$(pvesm status -content rootdir | awk 'NR>1')
    if [ -z "$VALID" ]; then
        msg_error "Unable to detect a valid storage location."
        exit 1
    elif [ $((${#STORAGE_MENU[@]}/3)) -eq 1 ]; then
        STORAGE=${STORAGE_MENU[0]}
    else
        while [ -z "${STORAGE:+x}" ]; do
            STORAGE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "STORAGE LOCATION" --radiolist "\nSelect the storage location:" $((${#STORAGE_MENU[@]}/3+9)) $MSG_MAX_LENGTH 6 "${STORAGE_MENU[@]}" 3>&1 1>&2 2>&3) || exit
        done
    fi
    msg_ok "Using ${CL}${BL}$STORAGE${CL} ${GN}for Storage Location."
    msg_ok "Container ID is ${CL}${BL}$var_container${CL}."
    
    msg_info "Getting URL for Latest ${APP} Disk Image"
    if [ "$var_os" == "ubuntu" ]; then
        IMAGE="${var_os}-${var_version}-standard_${var_version}.0-1_amd64.tar.zst"
        if [[ ! -f $TEMPLATE_STORAGE:vztmpl/$IMAGE ]]; then
            pveam download $TEMPLATE_STORAGE $IMAGE >/dev/null 2>&1
        fi
    else
        IMAGE="${var_os}-${var_version}-standard_${var_version}.0-1_amd64.tar.zst"
        if [[ ! -f $TEMPLATE_STORAGE:vztmpl/$IMAGE ]]; then
            pveam download $TEMPLATE_STORAGE "${var_os}-${var_version}-standard" >/dev/null 2>&1
        fi
    fi
    msg_ok "Downloaded ${CL}${BL}$IMAGE${CL}"

    msg_info "Creating LXC Container"
    DISK_REF="$STORAGE:$var_disk"
    TEMPLATE_REF="$TEMPLATE_STORAGE:vztmpl/$IMAGE"
    
    # Build PCT options
    PCT_OPTIONS="
      -features nesting=$var_nesting
      -hostname $var_hostname
      -tags $var_tags
      -net0 name=eth0,bridge=$var_bridge,ip=$var_ip$var_gate$var_ipv6$var_mtu$var_mac$var_vlan
      -onboot 1
      -cores $var_cpu
      -memory $var_ram
      -unprivileged $var_unprivileged
      $var_dns
      $var_ns
    "
    
    pct create $var_container $TEMPLATE_REF $PCT_OPTIONS -rootfs $DISK_REF $var_password >/dev/null 2>&1

    # Configure container for certificate server
    LXC_CONFIG=/etc/pve/lxc/${var_container}.conf
    if [ "$var_unprivileged" == "1" ]; then
        cat >>$LXC_CONFIG <<EOF

# Certificate Server specific configurations
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
lxc.mount.auto: "proc:rw sys:rw"
EOF
    fi
    msg_ok "LXC Container $var_container Created"

    msg_info "Starting LXC Container"
    pct start $var_container
    msg_ok "Started LXC Container"

    msg_info "Setting up Container OS"
    pct exec $var_container -- bash -c "apt-get update && apt-get -y upgrade"
    msg_ok "Set up Container OS"

    msg_info "Installing Certificate Server"
    # Export environment variables to container and run installation
    pct exec $var_container -- bash -c "
        export CERT_SERVER_PORT='$CERT_SERVER_PORT'
        export CERT_SERVER_HTTP_PORT='$CERT_SERVER_HTTP_PORT'
        export VLAN_ID='$VLAN_ID'
        export VLAN_INTERFACE='$VLAN_INTERFACE'
        export WEB_ADMIN_USER='$WEB_ADMIN_USER'
        export WEB_ADMIN_PASS='$WEB_ADMIN_PASS'
        export CA_COUNTRY='${CA_COUNTRY:-US}'
        export CA_STATE='${CA_STATE:-State}'
        export CA_CITY='${CA_CITY:-City}'
        export CA_ORG='${CA_ORG:-Organization}'
        export CA_OU='${CA_OU:-IT Department}'
        export CA_CN='${CA_CN:-Certificate Authority}'
        export CA_EMAIL='${CA_EMAIL:-ca@example.com}'
        export CERT_VALIDITY_DAYS='${CERT_VALIDITY_DAYS:-3650}'
        
        $(declare -f install_certificate_server); install_certificate_server
    " || exit
    msg_ok "Installed Certificate Server"

    msg_info "Creating Container Summary"
    pct exec $var_container -- bash -c "cat > /root/container-info.txt << EOF
Enhanced Certificate Server LXC Container
=========================================

Container ID: $var_container
Hostname: $var_hostname
IP Address: \$(hostname -I | awk '{print \$1}')

Access Information:
- Web Interface: https://\$(hostname -I | awk '{print \$1}'):$CERT_SERVER_PORT
- Username: $WEB_ADMIN_USER
- Password: $WEB_ADMIN_PASS

Management Commands:
- cert-server start|stop|restart|status
- cert-server health
- cert-server logs
- cert-server backup
- cert-server generate-cert <common_name> [org]

API Endpoint: https://\$(hostname -I | awk '{print \$1}'):$CERT_SERVER_PORT/api

Enhanced Features:
✓ Automatic certificate approval via web interface
✓ Base64 CSR import with auto-approval
✓ Private key export for server-generated certificates
✓ Certificate bundle downloads (cert + key)
✓ Duplicate request prevention on refresh
✓ REST API for programmatic access
$([ -n \"$VLAN_ID\" ] && echo \"✓ VLAN support: VLAN $VLAN_ID on $VLAN_INTERFACE\")

Important Files:
- CA Certificate: /opt/cert-server/ca/ca-cert.pem
- Database: /opt/cert-server/config/certificates.db
- Logs: /opt/cert-server/logs/

SAVE THIS INFORMATION!
EOF"
    msg_ok "Created Container Summary"

    msg_info "Cleaning up"
    pct exec $var_container -- bash -c "apt-get -y autoremove && apt-get -y autoclean"
    msg_ok "Cleaned"

    # Get container IP for final display
    IP=$(pct exec $var_container -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null)
    
    msg_info "Completed Successfully!\n"
    echo -e "${APP} LXC Container has been created successfully!"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    ACCESS INFORMATION${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "🌐 Web Interface: ${YW}https://${IP}:${CERT_SERVER_PORT}${CL}"
    echo -e "🔑 Username:      ${YW}${WEB_ADMIN_USER}${CL}"
    echo -e "🔒 Password:      ${YW}${WEB_ADMIN_PASS}${CL}"
    echo -e "🚀 API Endpoint:  ${YW}https://${IP}:${CERT_SERVER_PORT}/api${CL}"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    CONTAINER DETAILS${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "📦 Container ID:  ${YW}${var_container}${CL}"
    echo -e "🖥️  Hostname:      ${YW}${var_hostname}${CL}"
    echo -e "💾 Disk Size:     ${YW}${var_disk}GB${CL}"
    echo -e "🖥️  CPU Cores:     ${YW}${var_cpu}${CL}"
    echo -e "🧠 RAM:           ${YW}${var_ram}MB${CL}"
    echo -e "🌐 IP Address:    ${YW}${IP}${CL}"
    if [[ -n "$VLAN_ID" ]]; then
        echo -e "🏷️  VLAN Config:   ${YW}VLAN ${VLAN_ID} on ${VLAN_INTERFACE}${CL}"
    fi
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    ENHANCED FEATURES${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "✅ ${GN}Automatic certificate approval via web interface${CL}"
    echo -e "✅ ${GN}Base64 CSR import with auto-approval${CL}"
    echo -e "✅ ${GN}Private key export for server-generated certificates${CL}"
    echo -e "✅ ${GN}Certificate bundle downloads (cert + key)${CL}"
    echo -e "✅ ${GN}Duplicate request prevention on page refresh${CL}"
    echo -e "✅ ${GN}REST API for programmatic certificate management${CL}"
    echo -e "✅ ${GN}Health monitoring and management tools${CL}"
    echo -e "✅ ${GN}Secure SSL/TLS configuration with modern ciphers${CL}"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    MANAGEMENT COMMANDS${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "🔧 Container Management:"
    echo -e "   ${YW}pct start ${var_container}${CL}     - Start container"
    echo -e "   ${YW}pct stop ${var_container}${CL}      - Stop container"
    echo -e "   ${YW}pct enter ${var_container}${CL}     - Enter container shell"
    echo -e ""
    echo -e "🔧 Certificate Server Management (inside container):"
    echo -e "   ${YW}cert-server start|stop|restart|status${CL}"
    echo -e "   ${YW}cert-server health${CL}                   - Health check"
    echo -e "   ${YW}cert-server logs${CL}                     - View logs"
    echo -e "   ${YW}cert-server backup${CL}                   - Create backup"
    echo -e "   ${YW}cert-server generate-cert <cn> [org]${CL}  - CLI certificate generation"
    echo -e ""
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "${GN}                    API EXAMPLES${CL}"
    echo -e "${BL}═══════════════════════════════════════════════════════════════${CL}"
    echo -e "📋 Get CA Certificate:"
    echo -e "   ${YW}curl -k https://${IP}:${CERT_SERVER_PORT}/api/ca_cert${CL}"
    echo -e ""
    echo -e "📋 Submit CSR for Auto-Approval:"
    echo -e "   ${YW}curl -k -X POST https://${IP}:${CERT_SERVER_PORT}/api/submit_csr \\${CL}"
    echo -e "   ${YW}     -H \"Content-Type: application/json\" \\${CL}"
    echo -e "   ${YW}     -d '{\"csr\": \"<your_csr_here>\", \"auto_approve\": true}'${CL}"
    echo -e ""
    echo -e "${RD}⚠️  IMPORTANT NOTES:${CL}"
    echo -e "• Save the admin password above - it cannot be recovered!"
    echo -e "• Container info is saved in: ${YW}/root/container-info.txt${CL}"
    echo -e "• CA certificate is located at: ${YW}/opt/cert-server/ca/ca-cert.pem${CL}"
    echo -e "• Database is located at: ${YW}/opt/cert-server/config/certificates.db${CL}"
    echo -e ""
    echo -e "${GN}🎉 Your Enhanced Certificate Server LXC Container is ready!${CL}\n"
}

function update_script() {
    header_info
    if [[ ! -d /var/lib/lxc/$1 ]] && [[ ! -d /etc/pve/lxc/$1.conf ]]; then
        echo -e "No LXC container with ID '$1' exists."
        echo -e "Available containers:"
        pct list
        exit 1
    fi

    if ! pct status $1 &>/dev/null; then
        echo -e "${RD}Container $1 does not exist!${CL}"
        exit 1
    fi

    echo -e "${BL}Updating Certificate Server in Container $1${CL}"
    
    # Check if container is running
    if [[ $(pct status $1) == "status: stopped" ]]; then
        echo -e "${YW}Starting container $1...${CL}"
        pct start $1
        sleep 5
    fi
    
    msg_info "Updating Certificate Server"
    pct exec $1 -- bash -c "
        if [[ -f /usr/local/bin/cert-server ]]; then
            # Update system packages
            apt-get update >/dev/null 2>&1
            apt-get -y upgrade >/dev/null 2>&1
            
            # Update Python packages
            cd /opt/cert-server
            source venv/bin/activate
            pip install --upgrade flask flask-httpauth cryptography pyopenssl >/dev/null 2>&1
            
            # Restart services
            systemctl restart cert-server
            systemctl restart nginx
            
            echo 'Certificate Server updated successfully!'
        else
            echo 'Certificate Server not found in this container!'
            exit 1
        fi
    "
    msg_ok "Updated Certificate Server"
    
    IP=$(pct exec $1 -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null)
    echo -e "\n${GN}✅ Update completed successfully!${CL}"
    echo -e "🌐 Access: ${BL}https://${IP}:8443${CL}"
}

# Main execution
if command -v pveversion >/dev/null 2>&1; then
    if [[ ! -z "$1" ]] && [[ "$1" == "update" ]] && [[ ! -z "$2" ]]; then
        update_script $2
    elif [[ ! -z "$1" ]] && [[ "$1" == "update" ]]; then
        echo -e "${RD}Error: Container ID required for update${CL}"
        echo -e "Usage: $0 update <container_id>"
        echo -e "Example: $0 update 100"
        exit 1
    else
        install_script
    fi
else
    echo -e "${RD}This script is designed to run on Proxmox VE${CL}"
    echo -e "For standalone installations, please use the standalone deployment script."
    exit 1
fi#!/usr/bin/env bash

# Copyright (c) 2021-2025 Enhanced Certificate Server LXC
# Author: Enhanced by Claude, based on tteck methodology
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: Enhanced Certificate Server with Auto-Approval and VLAN Support

# This script creates a Proxmox LXC container for the Enhanced Certificate Server

# App Default Values
APP="Certificate Server"
var_tags="certificate;ssl;tls;ca;security"
var_cpu="2"
var_ram="2048"
var_disk="8"
var_os="debian"
var_version="12"
var_unprivileged="1"

# Color definitions
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="\\033[1m\\033[91m[\\033[1m\\033[96m⌚\\033[1m\\033[91m]\\033[1m\\033[36m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Variables
VERBOSE="no"
SSH_ROOT="yes"
CTID=""
PCT_OSTYPE="$var_os"
PCT_OSVERSION="$var_version"
PCT_DISK_SIZE="$var_disk"
PCT_OPTIONS=""
TEMPLATE_STORAGE="local"
MSG_MAX_LENGTH=0
STORAGE_MENU=()

# Set Temp Dir
if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC" --yesno "This will create a New ${APP} LXC. Proceed?" 10 58); then
    :
else
    clear
    echo -e "⚠ User exited script \n"
    exit
fi

function header_info() {
    clear
    cat <<"EOF"
    ____          _   _  __ _           _         ____                           
   / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
  | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
  | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
   \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   
                                                                                
EOF
    echo -e "                Enhanced ${APP} LXC Container"
    echo ""
}

function msg_info() {
    local msg="$1"
    echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
    local msg="$1"
    echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function PVE_CHECK() {
    if [ $(pgrep -c -f pve-firewall) != 0 ]; then
        if [ -e /etc/proxmox-release ]; then
            if [ "$(pveversion | cut -d'/' -f2 | cut -d'.' -f1)" -lt 7 ]; then
                echo -e "${CROSS} This script requires Proxmox VE 7.0 or higher"
                echo -e "Exiting..."
                sleep 3
                exit 1
            fi
        fi
    fi
}

function ARCH_CHECK() {
    if [ "$(dpkg --print-architecture)" != "amd64" ]; then
        echo -e "\n ${CROSS} This script will not work with PiMox! \n"
        echo -e "Exiting..."
        sleep 3
        exit 1
    fi
}

function exit-script() {
    clear
    echo -e "⚠ User exited script \n"
    exit 1
}

function default_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    # Default settings
    var_container="$CTID"
    var_hostname="cert-server"
    var_disk="$var_disk"
    var_cpu="$var_cpu"
    var_ram="$var_ram"
    var_bridge="vmbr0"
    var_ip="dhcp"
    var_gate=""
    var_ipv6=""
    var_mtu=""
    var_dns=""
    var_ns=""
    var_mac=""
    var_vlan=""
    var_ssh="yes"
    var_verbose="no"
    var_unprivileged="$var_unprivileged"
    var_nesting="1"
    var_password=""
    
    # Certificate Server specific defaults
    CERT_SERVER_PORT="8443"
    CERT_SERVER_HTTP_PORT="8080"
    WEB_ADMIN_USER="admin"
    WEB_ADMIN_PASS="$(openssl rand -base64 12)"
    VLAN_ID=""
    VLAN_INTERFACE=""
    
    clear
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL} ${RD}NO DEVICE PASSTHROUGH${CL}"
    echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
    echo -e "${DGN}Using Container ID: ${BGN}$CTID${CL}"
    echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
    echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
    echo -e "${DGN}Allocated Cores ${BGN}$var_cpu${CL}"
    echo -e "${DGN}Allocated Ram ${BGN}$var_ram${CL}"
    echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
    echo -e "${DGN}Using Static IP: ${BGN}$var_ip${CL}"
    echo -e "${DGN}Using Gateway: ${BGN}$var_gate${CL}"
    echo -e "${DGN}Disable IPv6: ${BGN}$var_ipv6${CL}"
    echo -e "${DGN}Using Interface MTU Size: ${BGN}$var_mtu${CL}"
    echo -e "${DGN}Using DNS Search Domain: ${BGN}$var_dns${CL}"
    echo -e "${DGN}Using DNS Server Address: ${BGN}$var_ns${CL}"
    echo -e "${DGN}Using MAC Address: ${BGN}$var_mac${CL}"
    echo -e "${DGN}Using VLAN Tag: ${BGN}$var_vlan${CL}"
    echo -e "${DGN}Enable Root SSH Access: ${BGN}yes${CL}"
    echo -e "${DGN}Enable Verbose Mode: ${BGN}no${CL}"
    echo -e "${DGN}Certificate Server HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    echo -e "${DGN}Certificate Server Admin User: ${BGN}$WEB_ADMIN_USER${CL}"
    echo -e "${BL}Creating a ${APP} LXC using the above default settings${CL}"
}

function advanced_settings() {
    # Get next available container ID
    CTID=$(pvesh get /cluster/nextid)
    
    clear
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    echo -e "${YW}Type Advanced, or Press [ENTER] for Default.${CL}"
    echo ""
    sleep 1

    case $(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER TYPE" --menu "\nChoose Type" 10 58 2 \
        "1" "Unprivileged (Recommended)" \
        "0" "Privileged" 3>&2 2>&1 1>&3) in
    1) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    0) var_unprivileged="0"; echo -e "${DGN}Using Container Type: ${BGN}Privileged${CL}" ;;
    *) var_unprivileged="1"; echo -e "${DGN}Using Container Type: ${BGN}Unprivileged${CL}" ;;
    esac

    if PW=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "PASSWORD" --passwordbox "\nSet Root Password (needed for root ssh access)" 9 58 3>&2 2>&1 1>&3); then
        if [[ ! -z "$PW" ]]; then
            var_password="-password $PW"
            echo -e "${DGN}Using Root Password: ${BGN}$PW${CL}"
        else
            var_password=""
            echo -e "${DGN}Using Root Password: ${BGN}Automatic Login${CL}"
        fi
    else
        exit-script
    fi

    if CT_ID=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CONTAINER ID" --inputbox "\nSet Container ID" 9 58 $CTID 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_ID" ]]; then
            var_container="$CTID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        else
            var_container="$CT_ID"
            echo -e "${DGN}Using Container ID: ${BGN}$var_container${CL}"
        fi
    else
        exit-script
    fi

    if CT_NAME=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HOSTNAME" --inputbox "\nSet Hostname" 9 58 "cert-server" 3>&2 2>&1 1>&3); then
        if [[ -z "$CT_NAME" ]]; then
            var_hostname="cert-server"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        else
            var_hostname="$CT_NAME"
            echo -e "${DGN}Using Hostname: ${BGN}$var_hostname${CL}"
        fi
    else
        exit-script
    fi

    if DISK_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DISK SIZE" --inputbox "\nSet Disk Size in GB" 9 58 $var_disk 3>&2 2>&1 1>&3); then
        if [[ -z "$DISK_SIZE" ]]; then
            var_disk="$var_disk"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        else
            var_disk="$DISK_SIZE"
            echo -e "${DGN}Using Disk Size: ${BGN}$var_disk${CL}${DGN}GB${CL}"
        fi
    else
        exit-script
    fi

    if CORE_COUNT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CORES" --inputbox "\nAllocate CPU Cores" 9 58 $var_cpu 3>&2 2>&1 1>&3); then
        if [[ -z "$CORE_COUNT" ]]; then
            var_cpu="$var_cpu"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        else
            var_cpu="$CORE_COUNT"
            echo -e "${DGN}Allocated Cores: ${BGN}$var_cpu${CL}"
        fi
    else
        exit-script
    fi

    if RAM_SIZE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "RAM" --inputbox "\nAllocate RAM in MB" 9 58 $var_ram 3>&2 2>&1 1>&3); then
        if [[ -z "$RAM_SIZE" ]]; then
            var_ram="$var_ram"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        else
            var_ram="$RAM_SIZE"
            echo -e "${DGN}Allocated RAM: ${BGN}$var_ram${CL}"
        fi
    else
        exit-script
    fi

    if BRG=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "BRIDGE" --inputbox "\nSet a Bridge" 9 58 "vmbr0" 3>&2 2>&1 1>&3); then
        if [[ -z "$BRG" ]]; then
            var_bridge="vmbr0"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        else
            var_bridge="$BRG"
            echo -e "${DGN}Using Bridge: ${BGN}$var_bridge${CL}"
        fi
    else
        exit-script
    fi

    if NET=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "IP ADDRESS" --inputbox "\nSet a Static IPv4 CIDR Address(/24)" 9 58 dhcp 3>&2 2>&1 1>&3); then
        if [[ "$NET" == "dhcp" ]]; then
            var_ip="dhcp"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        else
            var_ip="$NET"
            echo -e "${DGN}Using IP Address: ${BGN}$var_ip${CL}"
        fi
    else
        exit-script
    fi

    if GATE1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "GATEWAY" --inputbox "\nSet a Gateway IP (mandatory if Static IP was used)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$GATE1" ]]; then
            var_gate=""
            echo -e "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
        else
            var_gate=",gw=$GATE1"
            echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
        fi
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "IPv6" --yesno "\nDisable IPv6?" 9 58); then
        var_ipv6=""
        echo -e "${DGN}Disable IPv6: ${BGN}Yes${CL}"
    else
        var_ipv6=",ip6=dhcp"
        echo -e "${DGN}Disable IPv6: ${BGN}No${CL}"
    fi

    if MTU1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MTU SIZE" --inputbox "\nSet Interface MTU Size (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MTU1" ]]; then
            var_mtu=""
            echo -e "${DGN}Using Interface MTU Size: ${BGN}Default${CL}"
        else
            var_mtu=",mtu=$MTU1"
            echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU1${CL}"
        fi
    else
        exit-script
    fi

    if SD=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SEARCH DOMAIN" --inputbox "\nSet DNS Search Domain (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$SD" ]]; then
            SX=host
            var_dns=""
            echo -e "${DGN}Using DNS Search Domain: ${BGN}Host${CL}"
        else
            SX=$SD
            var_dns="-searchdomain $SD"
            echo -e "${DGN}Using DNS Search Domain: ${BGN}$SD${CL}"
        fi
    else
        exit-script
    fi

    if NX=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "DNS SERVER IP" --inputbox "\nSet DNS Server IP (leave blank for HOST)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$NX" ]]; then
            var_ns=""
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}Host${CL}"
        else
            var_ns="-nameserver $NX"
            echo -e "${DGN}Using DNS Server IP Address: ${BGN}$NX${CL}"
        fi
    else
        exit-script
    fi

    if MAC1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "MAC ADDRESS" --inputbox "\nSet MAC Address(leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$MAC1" ]]; then
            var_mac=""
            echo -e "${DGN}Using MAC Address: ${BGN}Default${CL}"
        else
            var_mac=",hwaddr=$MAC1"
            echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
        fi
    else
        exit-script
    fi

    if VLAN1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN TAG" --inputbox "\nSet VLAN Tag (leave blank for default)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$VLAN1" ]]; then
            var_vlan=""
            echo -e "${DGN}Using VLAN Tag: ${BGN}Default${CL}"
        else
            var_vlan=",tag=$VLAN1"
            echo -e "${DGN}Using VLAN Tag: ${BGN}$VLAN1${CL}"
        fi
    else
        exit-script
    fi

    # Certificate Server specific configurations
    if CS_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "CERTIFICATE SERVER PORT" --inputbox "\nSet HTTPS Port (default: 8443)" 9 58 "8443" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_PORT" ]]; then
            CERT_SERVER_PORT="8443"
        else
            CERT_SERVER_PORT="$CS_PORT"
        fi
        echo -e "${DGN}Using HTTPS Port: ${BGN}$CERT_SERVER_PORT${CL}"
    else
        exit-script
    fi

    if CS_HTTP_PORT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "HTTP PORT" --inputbox "\nSet HTTP Port (default: 8080)" 9 58 "8080" 3>&2 2>&1 1>&3); then
        if [[ -z "$CS_HTTP_PORT" ]]; then
            CERT_SERVER_HTTP_PORT="8080"
        else
            CERT_SERVER_HTTP_PORT="$CS_HTTP_PORT"
        fi
        echo -e "${DGN}Using HTTP Port: ${BGN}$CERT_SERVER_HTTP_PORT${CL}"
    else
        exit-script
    fi

    if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN CONFIGURATION" --yesno "\nConfigure VLAN support inside container?" 9 58); then
        if VLAN_ID_INPUT=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN ID" --inputbox "\nEnter VLAN ID" 9 58 3>&2 2>&1 1>&3); then
            if [[ ! -z "$VLAN_ID_INPUT" ]]; then
                VLAN_ID="$VLAN_ID_INPUT"
                if VLAN_IFACE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "VLAN INTERFACE" --inputbox "\nEnter parent interface (e.g., eth0)" 9 58 "eth0" 3>&2 2>&1 1>&3); then
                    VLAN_INTERFACE="$VLAN_IFACE"
                    echo -e "${DGN}VLAN Configuration: ${BGN}ID=$VLAN_ID Interface=$VLAN_INTERFACE${CL}"
                fi
            fi
        fi
    fi

    if ADM_USER=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN USERNAME" --inputbox "\nSet admin username (default: admin)" 9 58 "admin" 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_USER" ]]; then
            WEB_ADMIN_USER="admin"
        else
            WEB_ADMIN_USER="$ADM_USER"
        fi
        echo -e "${DGN}Using Admin Username: ${BGN}$WEB_ADMIN_USER${CL}"
    else
        exit-script
    fi

    if ADM_PASS=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADMIN PASSWORD" --passwordbox "\nSet admin password (leave blank for auto-generated)" 9 58 3>&2 2>&1 1>&3); then
        if [[ -z "$ADM_PASS" ]]; then
            WEB_ADMIN_PASS="$(openssl rand -base64 12)"
            echo -e "${DGN}Using Admin Password: ${BGN}Auto-generated${CL}"
        else
            WEB_ADMIN_PASS="$ADM_PASS"
            echo -e "${DGN}Using Admin Password: ${BGN}Custom${CL}"
        fi
    else
        exit-script
    fi

    var_ssh="yes"
    var_verbose="no"
    var_nesting="1"

    echo -e "${BL}Creating a ${APP} LXC using the above advanced settings${CL}"
}

function install_certificate_server() {
    # Set STD based on VERBOSE
    if [[ "$VERBOSE" == "yes" ]]; then
        STD=""
    else
        STD="silent"
    fi
    silent() { "$@" > /dev/null 2>&1; }

    # Network check
    RESOLVEDIP=$(getent hosts github.com | awk '{ print $1 }')
    if [[ -z "$RESOLVEDIP" ]]; then
        echo "No Network!"
        exit 1
    fi

    echo "Installing Dependencies..."
    $STD apt-get update
    $STD apt-get install -y \
      curl \
      sudo \
      mc \
      gnupg \
      apt-transport-https \
      software-properties-common \
      openssl \
      nginx \
      python3 \
      python3-pip \
      python3-venv \
      sqlite3 \
      wget \
      jq \
      bridge-utils \
      vlan \
      ufw \
      net-tools \
      netcat-openbsd

    # Configuration variables with defaults
    CERT_SERVER_PORT=${CERT_SERVER_PORT:-8443}
    CERT_SERVER_HTTP_PORT=${CERT_SERVER_HTTP_PORT:-8080}
    VLAN_ID=${VLAN_ID:-""}
    VLAN_INTERFACE=${VLAN_INTERFACE:-""}
    CA_COUNTRY=${CA_COUNTRY:-"US"}
    CA_STATE=${CA_STATE:-"State"}
    CA_CITY=${CA_CITY:-"City"}
    CA_ORG=${CA_ORG:-"Organization"}
    CA_OU=${CA_OU:-"IT Department"}
    CA_CN=${CA_CN:-"Certificate Authority"}
    CA_EMAIL=${CA_EMAIL:-"ca@example.com"}
    CERT_VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-3650}
    WEB_ADMIN_USER=${WEB_ADMIN_USER:-"admin"}
    WEB_ADMIN_PASS=${WEB_ADMIN_PASS:-"$(openssl rand -base64 12)"}

    # VLAN Configuration if specified
    if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
        echo "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}..."
        
        # Load 8021q module
        modprobe 8021q
        echo "8021q" >> /etc/modules
        
        # Create VLAN interface configuration
        cat > /etc/systemd/network/10-vlan.netdev << EOF
[NetDev]
Name=$VLAN_INTERFACE.$VLAN_ID
Kind=vlan

[VLAN]
Id=$VLAN_ID
EOF

        cat > /etc/systemd/network/20-vlan.network << EOF
[Match]
Name=$VLAN_INTERFACE.$VLAN_ID

[Network]
DHCP=yes
IPForward=yes
EOF
        
        systemctl restart systemd-networkd
    fi

    echo "Setting up Certificate Server Directory Structure..."
    mkdir -p /opt/cert-server/{ca,certs,keys,csr,config,web,logs,backups}
    mkdir -p /opt/cert-server/web/{static,templates}
    chmod 755 /opt/cert-server
    chmod 700 /opt/cert-server/{ca,keys}
    chmod 755 /opt/cert-server/logs

    echo "Creating Certificate Authority..."
    cd /opt/cert-server/ca

    # Create CA private key
    openssl genrsa -out ca-key.pem 4096
    chmod 600 ca-key.pem

    # Create CA certificate
    cat > ca.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $CA_CN
emailAddress = $CA_EMAIL

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign
EOF

    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca-cert.pem -config ca.conf
    chmod 644 ca-cert.pem

    # Create serial number file
    echo 1000 > serial
    touch index.txt

    echo "Setting up Python Virtual Environment..."
    cd /opt/cert-server
    python3 -m venv venv
    source venv/bin/activate
    pip install flask flask-httpauth cryptography pyopenssl

    echo "Creating Enhanced Certificate Server Web Application..."
    cat > /opt/cert-server/web/app.py << 'EOF'
#!/usr/bin/env python3

import os
import sys
import json
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
import tempfile
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

# Configuration
CA_DIR = '/opt/cert-server/ca'
CERT_DIR = '/opt/cert-server/certs'
KEY_DIR = '/opt/cert-server/keys'
CSR_DIR = '/opt/cert-server/csr'
DB_PATH = '/opt/cert-server/config/certificates.db'

# Authentication
users = {
    os.environ.get('WEB_ADMIN_USER', 'admin'): os.environ.get('WEB_ADMIN_PASS', 'changeme')
}

@auth.verify_password
def verify_password(username, password):
    return users.get(username) == password

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            csr_data TEXT,
            cert_data TEXT,
            key_data TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_date TIMESTAMP,
            expires_date TIMESTAMP,
            auto_approved BOOLEAN DEFAULT 0,
            request_hash TEXT UNIQUE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_hash TEXT UNIQUE NOT NULL,
            submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_ca_key_cert():
    with open(os.path.join(CA_DIR, 'ca-key.pem'), 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_serial_number():
    with open(os.path.join(CA_DIR, 'serial'), 'r') as f:
        serial = int(f.read().strip())
    
    with open(os.path.join(CA_DIR, 'serial'), 'w') as f:
        f.write(str(serial + 1))
    
    return serial

def generate_request_hash(data):
    """Generate hash to prevent duplicate requests"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_certificate(csr_data, auto_approve=True):
    try:
        ca_key, ca_cert = load_ca_key_cert()
        csr = x509.load_pem_x509_csr(csr_data.encode())
        
        # Extract common name from CSR
        common_name = None
        for attribute in csr.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                common_name = attribute.value
                break
        
        if not common_name:
            raise ValueError("No common name found in CSR")
        
        # Generate request hash to prevent duplicates
        request_hash = generate_request_hash(csr_data + common_name)
        
        # Check for existing request
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM certificates WHERE request_hash = ?', (request_hash,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Duplicate request detected - certificate already exists")
        
        # Generate serial number
        serial = generate_serial_number()
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_encipherment=True,
                digital_signature=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # Store in database with request hash
        cursor.execute('''
            INSERT INTO certificates 
            (common_name, serial_number, status, csr_data, cert_data, approved_date, expires_date, auto_approved, request_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            common_name,
            str(serial),
            'approved' if auto_approve else 'pending',
            csr_data,
            cert_pem,
            datetime.utcnow() if auto_approve else None,
            cert.not_valid_after,
            auto_approve,
            request_hash
        ))
        conn.commit()
        conn.close()
        
        return cert_pem, str(serial)
        
    except Exception as e:
        raise Exception(f"Certificate signing failed: {str(e)}")

def generate_key_and_csr(common_name, organization='', country='US'):
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Generated Certificate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    
    # Convert to PEM
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    
    return key_pem, csr_pem

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request', methods=['GET', 'POST'])
def request_certificate():
    if request.method == 'POST':
        try:
            if 'csr_data' in request.form:
                # Handle uploaded CSR
                csr_data = request.form['csr_data']
                auto_approve = request.form.get('auto_approve', 'off') == 'on'
                
                # Detect and decode Base64 if needed
                try:
                    decoded_csr = base64.b64decode(csr_data).decode()
                    if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                        csr_data = decoded_csr
                except:
                    pass  # Not base64 or not valid, use as-is
                
                cert_pem, serial = sign_certificate(csr_data, auto_approve)
                
                flash(f'Certificate {"approved" if auto_approve else "submitted"} with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
            else:
                # Generate new certificate
                common_name = request.form['common_name']
                organization = request.form.get('organization', '')
                country = request.form.get('country', 'US')
                
                key_pem, csr_pem = generate_key_and_csr(common_name, organization, country)
                cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
                
                # Store the private key for generated certificates
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
                conn.commit()
                conn.close()
                
                flash(f'Certificate generated and approved with serial number: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('request.html')

@app.route('/certificate/<serial>')
def view_certificate(serial):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        flash('Certificate not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('certificate.html', cert=cert_data)

@app.route('/download/<serial>/<file_type>')
def download_certificate(serial, file_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_number = ?', (serial,))
    cert_data = cursor.fetchone()
    conn.close()
    
    if not cert_data:
        return "Certificate not found", 404
    
    if file_type == 'cert':
        content = cert_data[5]  # cert_data
        filename = f'certificate_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'key' and cert_data[6]:  # key_data exists
        content = cert_data[6]
        filename = f'private_key_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'csr':
        content = cert_data[4]  # csr_data
        filename = f'csr_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'bundle':
        # Create certificate bundle with key if available
        bundle_content = cert_data[5]  # cert_data
        if cert_data[6]:  # key_data
            bundle_content += "\n" + cert_data[6]
        content = bundle_content
        filename = f'certificate_bundle_{serial}.pem'
        mimetype = 'application/x-pem-file'
    else:
        return "Invalid file type", 400
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    return send_file(temp_file_path, as_attachment=True, download_name=filename, mimetype=mimetype)

@app.route('/certificates')
def list_certificates():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates ORDER BY created_date DESC')
    certificates = cursor.fetchall()
    conn.close()
    
    return render_template('certificates.html', certificates=certificates)

@app.route('/api/submit_csr', methods=['POST'])
def api_submit_csr():
    try:
        data = request.json
        csr_data = data.get('csr')
        auto_approve = data.get('auto_approve', True)
        
        if not csr_data:
            return jsonify({'error': 'CSR data is required'}), 400
        
        # Decode base64 if needed
        try:
            decoded_csr = base64.b64decode(csr_data).decode()
            if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                csr_data = decoded_csr
        except:
            pass  # Not base64 encoded or not valid
        
        cert_pem, serial = sign_certificate(csr_data, auto_approve)
        
        return jsonify({
            'success': True,
            'serial': serial,
            'certificate': cert_pem,
            'status': 'approved' if auto_approve else 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ca_cert')
def api_ca_cert():
    try:
        with open(os.path.join(CA_DIR, 'ca-cert.pem'), 'r') as f:
            ca_cert = f.read()
        return jsonify({'ca_certificate': ca_cert})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('CERT_SERVER_HTTP_PORT', 8080)), debug=False)
EOF

    chmod +x /opt/cert-server/web/app.py

    echo "Creating Web Templates..."
    mkdir -p /opt/cert-server/web/{templates,static}

    # Create base template
    cat > /opt/cert-server/web/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Certificate Server{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="fas fa-certificate"></i> Certificate Server
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="{{ url_for('index') }}">Home</a>
                <a class="nav-link" href="{{ url_for('request_certificate') }}">Request Certificate</a>
                <a class="nav-link" href="{{ url_for('list_certificates') }}">View Certificates</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

    # Create index template
    cat > /opt/cert-server/web/templates/index.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="jumbotron bg-light p-5 rounded">
            <h1 class="display-4"><i class="fas fa-certificate text-primary"></i> Certificate Server</h1>
            <p class="lead">Generate and manage SSL/TLS certificates with automatic approval.</p>
            <hr class="my-4">
            <p>Enhanced features:</p>
            <ul>
                <li>✅ Automatic certificate approval for web interface requests</li>
                <li>✅ Base64 encoded CSR import with auto-approval</li>
                <li>✅ Private key export for server-generated certificates</li>
                <li>✅ Certificate bundle downloads</li>
                <li>✅ Duplicate request prevention</li>
                <li>✅ REST API for automation</li>
            </ul>
            <a class="btn btn-primary btn-lg" href="{{ url_for('request_certificate') }}" role="button">
                <i class="fas fa-plus"></i> Request Certificate
            </a>
            <a class="btn btn-secondary btn-lg" href="{{ url_for('list_certificates') }}" role="button">
                <i class="fas fa-list"></i> View Certificates
            </a>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create request template
    cat > /opt/cert-server/web/templates/request.html << 'EOF'
{% extends "base.html" %}

{% block title %}Request Certificate - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <h2><i class="fas fa-plus-circle"></i> Request Certificate</h2>
        
        <ul class="nav nav-tabs" id="requestTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="generate-tab" data-bs-toggle="tab" data-bs-target="#generate" type="button" role="tab">
                    <i class="fas fa-magic"></i> Generate New Certificate
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="upload-tab" data-bs-toggle="tab" data-bs-target="#upload" type="button" role="tab">
                    <i class="fas fa-upload"></i> Upload CSR
                </button>
            </li>
        </ul>
        
        <div class="tab-content mt-3" id="requestTabsContent">
            <!-- Generate New Certificate Tab -->
            <div class="tab-pane fade show active" id="generate" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Generate New Certificate</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="common_name" class="form-label">Common Name (CN) *</label>
                                <input type="text" class="form-control" id="common_name" name="common_name" required>
                                <div class="form-text">e.g., www.example.com or *.example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="organization" class="form-label">Organization</label>
                                <input type="text" class="form-control" id="organization" name="organization">
                            </div>
                            <div class="mb-3">
                                <label for="country" class="form-label">Country</label>
                                <input type="text" class="form-control" id="country" name="country" value="US" maxlength="2">
                                <div class="form-text">2-letter country code</div>
                            </div>
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-certificate"></i> Generate & Approve Certificate
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Upload CSR Tab -->
            <div class="tab-pane fade" id="upload" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Upload Certificate Signing Request</h5>
                        <form method="POST" onsubmit="return handleSubmit(this)">
                            <div class="mb-3">
                                <label for="csr_data" class="form-label">CSR Data *</label>
                                <textarea class="form-control" id="csr_data" name="csr_data" rows="10" required placeholder="Paste your PEM encoded CSR or Base64 encoded CSR here"></textarea>
                                <div class="form-text">Supports both PEM format and Base64 encoded CSRs</div>
                            </div>
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="auto_approve" name="auto_approve" checked>
                                <label class="form-check-label" for="auto_approve">
                                    Automatically approve certificate
                                </label>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload"></i> Submit CSR
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Prevent duplicate submissions
const submittedForms = new Set();

function generateFormHash(form) {
    const formData = new FormData(form);
    const data = Array.from(formData.entries()).map(([k, v]) => `${k}:${v}`).join('|');
    return btoa(data).replace(/[^a-zA-Z0-9]/g, '');
}

function handleSubmit(form) {
    const formHash = generateFormHash(form);
    
    if (submittedForms.has(formHash)) {
        alert('This certificate request has already been submitted. Please check the certificates list.');
        return false;
    }
    
    submittedForms.add(formHash);
    
    // Disable submit button
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    }
    
    return true;
}
</script>
{% endblock %}
EOF

    # Create certificate view template
    cat > /opt/cert-server/web/templates/certificate.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificate {{ cert[2] }} - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-10 mx-auto">
        <h2><i class="fas fa-certificate"></i> Certificate Details</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Certificate Information</h5>
                        <table class="table table-borderless">
                            <tr>
                                <td><strong>Common Name:</strong></td>
                                <td>{{ cert[1] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Serial Number:</strong></td>
                                <td>{{ cert[2] }}</td>
                            </tr>
                            <tr>
                                <td><strong>Status:</strong></td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                    {% if cert[10] %}
                                        <span class="badge bg-info ms-1">Auto-Approved</span>
                                    {% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Created:</strong></td>
                                <td>{{ cert[7] }}</td>
                            </tr>
                            {% if cert[8] %}
                            <tr>
                                <td><strong>Approved:</strong></td>
                                <td>{{ cert[8] }}</td>
                            </tr>
                            {% endif %}
                            <tr>
                                <td><strong>Expires:</strong></td>
                                <td>{{ cert[9] }}</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h5>Downloads</h5>
                        <div class="d-grid gap-2">
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='cert') }}" 
                               class="btn btn-primary">
                                <i class="fas fa-download"></i> Download Certificate
                            </a>
                            {% if cert[4] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='csr') }}" 
                               class="btn btn-secondary">
                                <i class="fas fa-download"></i> Download CSR
                            </a>
                            {% endif %}
                            {% if cert[6] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='key') }}" 
                               class="btn btn-warning">
                                <i class="fas fa-key"></i> Download Private Key
                            </a>
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='bundle') }}" 
                               class="btn btn-success">
                                <i class="fas fa-file-archive"></i> Download Bundle (Cert + Key)
                            </a>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                {% if cert[5] %}
                <hr>
                <h5>Certificate Data</h5>
                <pre class="bg-light p-3 small"><code>{{ cert[5] }}</code></pre>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create certificates list template
    cat > /opt/cert-server/web/templates/certificates.html << 'EOF'
{% extends "base.html" %}

{% block title %}Certificates - Certificate Server{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h2><i class="fas fa-list"></i> Certificates</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Common Name</th>
                                <th>Serial Number</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Auto-Approved</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for cert in certificates %}
                            <tr>
                                <td>{{ cert[1] }}</td>
                                <td>{{ cert[2] }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if cert[3] == 'approved' else 'warning' }}">
                                        {{ cert[3].title() }}
                                    </span>
                                </td>
                                <td>{{ cert[7] }}</td>
                                <td>{{ cert[9] }}</td>
                                <td>
                                    {% if cert[10] %}
                                        <i class="fas fa-check text-success"></i>
                                    {% else %}
                                        <i class="fas fa-times text-muted"></i>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="{{ url_for('view_certificate', serial=cert[2]) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    echo "Creating Systemd Service..."
    cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Enhanced Certificate Server with Auto-Approval
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cert-server/web
Environment=PATH=/opt/cert-server/venv/bin
Environment=WEB_ADMIN_USER=$WEB_ADMIN_USER
Environment=WEB_ADMIN_PASS=$WEB_ADMIN_PASS
Environment=CERT_SERVER_HTTP_PORT=$CERT_SERVER_HTTP_PORT
ExecStart=/opt/cert-server/venv/bin/python app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cert-server

    echo "Configuring Nginx Reverse Proxy with SSL..."
    
    # Generate web server certificate for HTTPS
    cd /opt/cert-server/ca
    openssl genrsa -out web-server-key.pem 2048
    chmod 600 web-server-key.pem
    
    cat > web-server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
CN = $(hostname -f)

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $(hostname -f)
DNS.2 = $(hostname -s)
DNS.3 = localhost
IP.1 = $(hostname -I | awk '{print $1}' 2>/dev/null || echo '127.0.0.1')
IP.2 = 127.0.0.1
EOF
    
    openssl req -new -key web-server-key.pem -out web-server.csr -config web-server.conf
    openssl x509 -req -in web-server.csr -CA ca-cert.pem -CAkey ca-key.pem -out web-server.pem -days 365 -extensions v3_req -extfile web-server.conf
    chmod 644 web-server.pem

    cat > /etc/nginx/sites-available/cert-server << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name:$CERT_SERVER_PORT\$request_uri;
}

# HTTPS Certificate Server
server {
    listen $CERT_SERVER_PORT ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /opt/cert-server/ca/web-server.pem;
    ssl_certificate_key /opt/cert-server/ca/web-server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=web:10m rate=30r/m;
    
    # Main application
    location / {
        limit_req zone=web burst=5 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
    
    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=api burst=3 nodelay;
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host

#!/usr/bin/env bash

# Enhanced Certificate Server LXC Container Creation Script
# Author: Iain Reid
# Version: 1.1 - Refactored for proper CA certificate creation order
# License: MIT
#
# This script creates a Proxmox LXC container with an enhanced certificate server
# featuring automatic approval, web interface, and REST API

set -euo pipefail

# Color definitions
RD='\033[0;31m'
GN='\033[0;32m'
YW='\033[1;33m'
BL='\033[0;34m'
MG='\033[0;35m'
CY='\033[0;36m'
WH='\033[1;37m'
CL='\033[0m'
DGN='\033[1;30m'
BGN='\033[4;92m'

# Global variables
APP="CertificateServer"
CTID=""
STORAGE="local-lvm"
TEMPLATE_STORAGE="local"
VERBOSE="no"
SSH_ROOT="yes"
TEMPLATE_FILE=""

# Default values
DEFAULT_CTID="220"
DEFAULT_HOSTNAME="cert-server"
DEFAULT_DISK="8"
DEFAULT_CORES="2"
DEFAULT_RAM="2048"
DEFAULT_PASSWORD=""
DEFAULT_UNPRIVILEGED="1"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_IP="dhcp"
DEFAULT_GATEWAY=""

# Certificate Server specific defaults
CERT_SERVER_PORT="8443"
CERT_SERVER_HTTP_PORT="8080"
WEB_ADMIN_USER="admin"
WEB_ADMIN_PASS=""
VLAN_ID=""
VLAN_INTERFACE=""

# Functions
function header_info() {
    cat <<"EOF"
   ____          _   _  __ _           _         ____                           
  / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
 | |   / _ \ '__| __| | |_| |/ __/ _` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
 | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
  \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   

Enhanced Certificate Server LXC Installer
EOF
}

function msg_info() {
    echo -e "${BL}[INFO]${CL} $1"
}

function msg_ok() {
    echo -e "${GN}[OK]${CL} $1"
}

function msg_error() {
    echo -e "${RD}[ERROR]${CL} $1"
    exit 1
}

function msg_warn() {
    echo -e "${YW}[WARN]${CL} $1"
}

function pve_check() {
    if ! command -v pveversion >/dev/null 2>&1; then
        msg_error "This script requires Proxmox VE"
    fi
    
    PVE_VERSION=$(pveversion | grep -o 'pve-manager/[0-9]*' | cut -d'/' -f2)
    if [ "$PVE_VERSION" -lt 7 ]; then
        msg_error "This script requires Proxmox VE 7.0 or higher"
    fi
}

function arch_check() {
    if [ "$(dpkg --print-architecture)" != "amd64" ]; then
        msg_error "This script only supports amd64 architecture"
    fi
}

function get_next_available_ctid() {
    local start_id=200
    local max_id=999
    
    for ((id=$start_id; id<=$max_id; id++)); do
        if ! pct status $id >/dev/null 2>&1; then
            echo $id
            return
        fi
    done
    
    echo "999"
}

function validate_ctid() {
    local ctid=$1
    
    if ! [[ "$ctid" =~ ^[0-9]+$ ]] || [ "$ctid" -lt 100 ] || [ "$ctid" -gt 999999 ]; then
        msg_error "Invalid Container ID: $ctid (must be 100-999999)"
    fi
    
    if pct status "$ctid" >/dev/null 2>&1; then
        msg_error "Container $ctid already exists"
    fi
}

function get_storage_options() {
    pvesm status -content rootdir | awk 'NR>1 {print $1}' | head -10
}

function validate_storage() {
    local storage=$1
    
    if ! pvesm status | grep -q "^$storage "; then
        msg_error "Storage '$storage' not found"
    fi
    
    if ! pvesm status -content rootdir | grep -q "^$storage "; then
        msg_error "Storage '$storage' does not support container root directories"
    fi
}

function interactive_config() {
    clear
    header_info
    echo ""
    echo -e "${YW}Certificate Server LXC Configuration${CL}"
    echo ""

    # Container ID
    while true; do
        read -p "Container ID [$DEFAULT_CTID]: " CTID
        CTID=${CTID:-$DEFAULT_CTID}
        
        if pct status "$CTID" >/dev/null 2>&1; then
            echo -e "${YW}Warning: Container $CTID already exists.${CL}"
            read -p "Use next available ID ($(get_next_available_ctid))? (y/N): " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                CTID=$(get_next_available_ctid)
                break
            fi
        else
            validate_ctid "$CTID"
            break
        fi
    done

    # Hostname
    read -p "Container Hostname [$DEFAULT_HOSTNAME]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$DEFAULT_HOSTNAME}

    # Container type
    read -p "Privileged container? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        UNPRIVILEGED="0"
    else
        UNPRIVILEGED="1"
    fi

    # Resources
    read -p "CPU Cores [$DEFAULT_CORES]: " CORES
    CORES=${CORES:-$DEFAULT_CORES}

    read -p "RAM (MB) [$DEFAULT_RAM]: " RAM
    RAM=${RAM:-$DEFAULT_RAM}

    read -p "Disk Size (GB) [$DEFAULT_DISK]: " DISK
    DISK=${DISK:-$DEFAULT_DISK}

    # Network
    read -p "Use DHCP? (Y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        IP_CONFIG="dhcp"
        GATEWAY=""
    else
        read -p "IP Address (CIDR, e.g., 192.168.1.100/24): " IP_CONFIG
        read -p "Gateway IP: " GATEWAY
    fi

    # Storage
    echo "Available storage pools:"
    get_storage_options | while read storage; do
        echo "  - $storage"
    done
    read -p "Storage pool [$STORAGE]: " STORAGE_INPUT
    STORAGE=${STORAGE_INPUT:-$STORAGE}
    validate_storage "$STORAGE"

    # Certificate Server specific
    read -p "HTTPS Port [$CERT_SERVER_PORT]: " PORT_INPUT
    CERT_SERVER_PORT=${PORT_INPUT:-$CERT_SERVER_PORT}

    read -p "Admin username [$WEB_ADMIN_USER]: " USER_INPUT
    WEB_ADMIN_USER=${USER_INPUT:-$WEB_ADMIN_USER}

    read -s -p "Admin password (empty for auto-generated): " WEB_ADMIN_PASS
    echo ""
    if [ -z "$WEB_ADMIN_PASS" ]; then
        WEB_ADMIN_PASS=$(openssl rand -base64 12)
    fi

    # Root password
    read -s -p "Root password (empty for random): " ROOT_PASSWORD
    echo ""
    if [ -z "$ROOT_PASSWORD" ]; then
        ROOT_PASSWORD=$(openssl rand -base64 16)
    fi

    # VLAN configuration
    read -p "Configure VLAN? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "VLAN ID: " VLAN_ID
        read -p "VLAN Interface [eth0]: " VLAN_INTERFACE
        VLAN_INTERFACE=${VLAN_INTERFACE:-eth0}
    fi

    # Summary
    echo ""
    echo -e "${BL}Configuration Summary:${CL}"
    echo "  Container ID: $CTID"
    echo "  Hostname: $HOSTNAME"
    echo "  Type: $([ "$UNPRIVILEGED" = "1" ] && echo "Unprivileged" || echo "Privileged")"
    echo "  Resources: ${CORES} cores, ${RAM}MB RAM, ${DISK}GB disk"
    echo "  Network: $IP_CONFIG $([ -n "$GATEWAY" ] && echo "via $GATEWAY")"
    echo "  Storage: $STORAGE"
    echo "  HTTPS Port: $CERT_SERVER_PORT"
    echo "  Admin User: $WEB_ADMIN_USER"
    if [ -n "$VLAN_ID" ]; then
        echo "  VLAN: $VLAN_ID on $VLAN_INTERFACE"
    fi
    echo ""

    read -p "Proceed with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
}

function download_template() {
    local os_type="debian"
    local os_version="12"
    local template_pattern="${os_type}-${os_version}-standard"
    
    msg_info "Checking for LXC template: $template_pattern"
    
    # Check for existing template
    TEMPLATE_FILE=$(pveam list "$TEMPLATE_STORAGE" | grep "$template_pattern" | grep -v "^NAME" | awk '{print $1}' | sed "s|.*vztmpl/||" | head -1)
    
    if [ -z "$TEMPLATE_FILE" ]; then
        msg_info "Template not found locally, downloading: $template_pattern"
        
        # Get available templates from remote
        AVAILABLE_TEMPLATE=$(pveam available | grep "$template_pattern" | awk '{print $2}' | head -1)
        
        if [ -z "$AVAILABLE_TEMPLATE" ]; then
            msg_error "No $template_pattern template available for download"
        fi
        
        msg_info "Downloading template: $AVAILABLE_TEMPLATE"
        if ! pveam download "$TEMPLATE_STORAGE" "$AVAILABLE_TEMPLATE"; then
            msg_error "Failed to download template: $AVAILABLE_TEMPLATE"
        fi
        
        # Get the downloaded template filename
        sleep 2
        TEMPLATE_FILE=$(pveam list "$TEMPLATE_STORAGE" | grep "$template_pattern" | grep -v "^NAME" | awk '{print $1}' | sed "s|.*vztmpl/||" | head -1)
    fi
    
    if [ -z "$TEMPLATE_FILE" ]; then
        msg_error "Template file not found after download attempt"
    fi
    
    msg_ok "Template ready: $TEMPLATE_FILE"
}

function create_container() {
    msg_info "Creating LXC Container $CTID"

    # Build network configuration
    if [ "$IP_CONFIG" = "dhcp" ]; then
        NET_CONFIG="name=eth0,bridge=$DEFAULT_BRIDGE,ip=dhcp"
    else
        NET_CONFIG="name=eth0,bridge=$DEFAULT_BRIDGE,ip=$IP_CONFIG"
        if [ -n "$GATEWAY" ]; then
            NET_CONFIG="$NET_CONFIG,gw=$GATEWAY"
        fi
    fi

    # Create container
    TEMPLATE_PATH="$TEMPLATE_STORAGE:vztmpl/$TEMPLATE_FILE"
    
    if ! pct create "$CTID" "$TEMPLATE_PATH" \
        --hostname "$HOSTNAME" \
        --cores "$CORES" \
        --memory "$RAM" \
        --rootfs "$STORAGE:$DISK" \
        --net0 "$NET_CONFIG" \
        --ostype debian \
        --password "$ROOT_PASSWORD" \
        --unprivileged "$UNPRIVILEGED" \
        --features nesting=1 \
        --onboot 1; then
        
        msg_error "Failed to create container $CTID"
    fi

    msg_ok "LXC Container $CTID created successfully"
}

function start_container() {
    msg_info "Starting LXC Container $CTID"
    
    if ! pct start "$CTID"; then
        msg_error "Failed to start container $CTID"
    fi
    
    # Wait for container to be ready
    msg_info "Waiting for container to initialize..."
    sleep 10
    
    # Test container connectivity
    local retry_count=0
    local max_retries=5
    
    while [ $retry_count -lt $max_retries ]; do
        if pct exec "$CTID" -- echo "Container ready" >/dev/null 2>&1; then
            msg_ok "Container $CTID started and ready"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        msg_info "Waiting for container... (attempt $retry_count/$max_retries)"
        sleep 5
    done
    
    msg_error "Container $CTID not responding after $max_retries attempts"
}

function install_certificate_server() {
    msg_info "Installing Certificate Server in container $CTID"

    # Create installation script - Part 1: System setup and CA creation
    cat > /tmp/cert-server-install-part1.sh << 'INSTALL_SCRIPT_PART1'
#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Update system
apt-get update -y
apt-get upgrade -y

# Install dependencies
apt-get install -y curl
apt-get install -y sudo
apt-get install -y gnupg
apt-get install -y apt-transport-https
apt-get install -y software-properties-common
apt-get install -y openssl
apt-get install -y nginx
apt-get install -y python3
apt-get install -y python3-pip
apt-get install -y python3-venv
apt-get install -y sqlite3
apt-get install -y wget
apt-get install -y jq
apt-get install -y bridge-utils
apt-get install -y vlan
apt-get install -y ufw
apt-get install -y net-tools
apt-get install -y netcat-openbsd

# Configuration variables from environment
CERT_SERVER_PORT="${CERT_SERVER_PORT:-8443}"
CERT_SERVER_HTTP_PORT="${CERT_SERVER_HTTP_PORT:-8080}"
VLAN_ID="${VLAN_ID:-}"
VLAN_INTERFACE="${VLAN_INTERFACE:-}"
CA_COUNTRY="${CA_COUNTRY:-GB}"
CA_STATE="${CA_STATE:-Hampshire}"
CA_CITY="${CA_CITY:-Farnborough}"
CA_ORG="${CA_ORG:-DXC Technology}"
CA_OU="${CA_OU:-EntServ D S}"
CA_CN="${CA_CN:-Certificate Authority}"
CA_EMAIL="${CA_EMAIL:-ca@aip.dxc.com}"
CERT_VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-3650}"
WEB_ADMIN_USER="${WEB_ADMIN_USER:-admin}"
WEB_ADMIN_PASS="${WEB_ADMIN_PASS:-changeme}"

# VLAN Configuration if specified
if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
    echo "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}"
    
    modprobe 8021q
    echo "8021q" >> /etc/modules
    
    cat > /etc/systemd/network/10-vlan.netdev << EOF
[NetDev]
Name=${VLAN_INTERFACE}.${VLAN_ID}
Kind=vlan

[VLAN]
Id=${VLAN_ID}
EOF

    cat > /etc/systemd/network/20-vlan.network << EOF
[Match]
Name=${VLAN_INTERFACE}.${VLAN_ID}

[Network]
DHCP=yes
IPForward=yes
EOF
    
    systemctl restart systemd-networkd
fi

# Create directory structure
mkdir -p /opt/cert-server/ca
mkdir -p /opt/cert-server/certs
mkdir -p /opt/cert-server/keys
mkdir -p /opt/cert-server/csr
mkdir -p /opt/cert-server/config
mkdir -p /opt/cert-server/web
mkdir -p /opt/cert-server/logs
mkdir -p /opt/cert-server/backups
mkdir -p /opt/cert-server/web/static
mkdir -p /opt/cert-server/web/templates
chmod 755 /opt/cert-server
chmod 700 /opt/cert-server/ca
chmod 700 /opt/cert-server/keys

# CRITICAL: Create Certificate Authority FIRST
echo "Creating Certificate Authority..."
cd /opt/cert-server/ca

# Generate CA private key
openssl genrsa -out ca-key.pem 4096
chmod 600 ca-key.pem

# Create CA configuration
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

# Generate CA certificate
openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca-cert.pem -config ca.conf
chmod 644 ca-cert.pem

# Initialize CA database
echo 1000 > serial
touch index.txt

echo "CA Certificate created successfully"

# Now create the web server certificate (AFTER CA is created)
echo "Creating web server certificate..."
openssl genrsa -out web-server-key.pem 2048
chmod 600 web-server-key.pem

# Create web server certificate configuration
cat > web-server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ${CA_COUNTRY}
ST = ${CA_STATE}
L = ${CA_CITY}
O = ${CA_ORG}
OU = ${CA_OU}
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

# Generate web server CSR
openssl req -new -key web-server-key.pem -out web-server.csr -config web-server.conf

# Sign web server certificate with CA
openssl x509 -req -in web-server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -out web-server.pem -days 365 -extensions v3_req -extfile web-server.conf
chmod 644 web-server.pem

echo "Web server certificate created successfully"

# Export environment variables for part 2
cat > /opt/cert-server/config/env.sh << EOF
export CERT_SERVER_PORT="$CERT_SERVER_PORT"
export CERT_SERVER_HTTP_PORT="$CERT_SERVER_HTTP_PORT"
export WEB_ADMIN_USER="$WEB_ADMIN_USER"
export WEB_ADMIN_PASS="$WEB_ADMIN_PASS"
EOF

echo "Part 1 installation completed"
INSTALL_SCRIPT_PART1

    # Push and execute part 1
    pct push "$CTID" /tmp/cert-server-install-part1.sh /root/install-part1.sh
    pct exec "$CTID" -- bash -c "
        export CERT_SERVER_PORT='$CERT_SERVER_PORT'
        export CERT_SERVER_HTTP_PORT='$CERT_SERVER_HTTP_PORT'
        export WEB_ADMIN_USER='$WEB_ADMIN_USER'
        export WEB_ADMIN_PASS='$WEB_ADMIN_PASS'
        export VLAN_ID='$VLAN_ID'
        export VLAN_INTERFACE='$VLAN_INTERFACE'
        chmod +x /root/install-part1.sh
        /root/install-part1.sh
    "
    
    msg_ok "CA Certificate and web server certificate created"

    # Create installation script - Part 2: Python application
    cat > /tmp/cert-server-install-part2.sh << 'INSTALL_SCRIPT_PART2'
#!/bin/bash
set -e

# Load environment variables
source /opt/cert-server/config/env.sh

# Set up Python environment
cd /opt/cert-server
python3 -m venv venv
source venv/bin/activate
pip install flask flask-httpauth cryptography pyopenssl

# Create Flask application
cat > /opt/cert-server/web/app.py << 'PYTHON_APP'
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
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_certificate(csr_data, auto_approve=True):
    try:
        ca_key, ca_cert = load_ca_key_cert()
        csr = x509.load_pem_x509_csr(csr_data.encode())
        
        # Extract common name
        common_name = None
        for attribute in csr.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                common_name = attribute.value
                break
        
        if not common_name:
            raise ValueError("No common name found in CSR")
        
        # Check for duplicates
        request_hash = generate_request_hash(csr_data + common_name)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM certificates WHERE request_hash = ?', (request_hash,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Duplicate request detected")
        
        # Generate certificate
        serial = generate_serial_number()
        
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
        
        # Store in database
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
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Generated Certificate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    
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
                csr_data = request.form['csr_data']
                auto_approve = request.form.get('auto_approve', 'off') == 'on'
                
                # Handle Base64 CSR
                try:
                    decoded_csr = base64.b64decode(csr_data).decode()
                    if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                        csr_data = decoded_csr
                except:
                    pass
                
                cert_pem, serial = sign_certificate(csr_data, auto_approve)
                flash(f'Certificate {"approved" if auto_approve else "submitted"} with serial: {serial}', 'success')
                return redirect(url_for('view_certificate', serial=serial))
                
            else:
                # Generate new certificate
                common_name = request.form['common_name']
                organization = request.form.get('organization', '')
                country = request.form.get('country', 'US')
                
                key_pem, csr_pem = generate_key_and_csr(common_name, organization, country)
                cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
                
                # Store private key
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
                conn.commit()
                conn.close()
                
                flash(f'Certificate generated with serial: {serial}', 'success')
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
        content = cert_data[5]
        filename = f'certificate_{serial}.pem'
    elif file_type == 'key' and cert_data[6]:
        content = cert_data[6]
        filename = f'private_key_{serial}.pem'
    elif file_type == 'csr':
        content = cert_data[4]
        filename = f'csr_{serial}.pem'
    elif file_type == 'bundle':
        content = cert_data[5]
        if cert_data[6]:
            content += "\n" + cert_data[6]
        filename = f'certificate_bundle_{serial}.pem'
    else:
        return "Invalid file type", 400
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    return send_file(temp_file_path, as_attachment=True, download_name=filename)

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
        
        # Handle Base64
        try:
            decoded_csr = base64.b64decode(csr_data).decode()
            if '-----BEGIN CERTIFICATE REQUEST-----' in decoded_csr:
                csr_data = decoded_csr
        except:
            pass
        
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
PYTHON_APP

chmod +x /opt/cert-server/web/app.py

echo "Part 2 installation completed"
INSTALL_SCRIPT_PART2

    # Push and execute part 2
    pct push "$CTID" /tmp/cert-server-install-part2.sh /root/install-part2.sh
    pct exec "$CTID" -- bash -c "
        chmod +x /root/install-part2.sh
        /root/install-part2.sh
    "
    
    msg_ok "Python application installed"

    # Create installation script - Part 3: Web templates
    cat > /tmp/cert-server-install-part3.sh << 'INSTALL_SCRIPT_PART3'
#!/bin/bash
set -e

# Load environment variables
source /opt/cert-server/config/env.sh

# Create web templates
mkdir -p /opt/cert-server/web/templates

# Base template
cat > /opt/cert-server/web/templates/base.html << 'BASE_TEMPLATE'
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
BASE_TEMPLATE

# Index template
cat > /opt/cert-server/web/templates/index.html << 'INDEX_TEMPLATE'
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
                <li>✅ Automatic certificate approval</li>
                <li>✅ Base64 encoded CSR import</li>
                <li>✅ Private key export</li>
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
INDEX_TEMPLATE

# Request template
cat > /opt/cert-server/web/templates/request.html << 'REQUEST_TEMPLATE'
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
            <div class="tab-pane fade show active" id="generate" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Generate New Certificate</h5>
                        <form method="POST">
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
                            </div>
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-certificate"></i> Generate & Approve Certificate
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="tab-pane fade" id="upload" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Upload Certificate Signing Request</h5>
                        <form method="POST">
                            <div class="mb-3">
                                <label for="csr_data" class="form-label">CSR Data *</label>
                                <textarea class="form-control" id="csr_data" name="csr_data" rows="10" required placeholder="Paste your PEM encoded CSR or Base64 encoded CSR here"></textarea>
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
{% endblock %}
REQUEST_TEMPLATE

# Certificate view template
cat > /opt/cert-server/web/templates/certificate.html << 'CERT_TEMPLATE'
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
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Created:</strong></td>
                                <td>{{ cert[7] }}</td>
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
                            {% if cert[6] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='key') }}" 
                               class="btn btn-warning">
                                <i class="fas fa-key"></i> Download Private Key
                            </a>
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='bundle') }}" 
                               class="btn btn-success">
                                <i class="fas fa-file-archive"></i> Download Bundle
                            </a>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
CERT_TEMPLATE

# Certificates list template
cat > /opt/cert-server/web/templates/certificates.html << 'CERTS_TEMPLATE'
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
CERTS_TEMPLATE

echo "Part 3 installation completed"
INSTALL_SCRIPT_PART3

    # Push and execute part 3
    pct push "$CTID" /tmp/cert-server-install-part3.sh /root/install-part3.sh
    pct exec "$CTID" -- bash -c "
        chmod +x /root/install-part3.sh
        /root/install-part3.sh
    "
    
    msg_ok "Web templates created"

    # Create installation script - Part 4: Services and Nginx
    cat > /tmp/cert-server-install-part4.sh << 'INSTALL_SCRIPT_PART4'
#!/bin/bash
set -e

# Load environment variables
source /opt/cert-server/config/env.sh

# Create systemd service
cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Enhanced Certificate Server
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

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cert-server

# Configure Nginx (CA and web server certs already exist)
cat > /etc/nginx/sites-available/cert-server << EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name:$CERT_SERVER_PORT\$request_uri;
}

server {
    listen $CERT_SERVER_PORT ssl http2;
    server_name _;
    
    ssl_certificate /opt/cert-server/ca/web-server.pem;
    ssl_certificate_key /opt/cert-server/ca/web-server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Content-Type application/json;
    }
    
    location /health {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        access_log off;
    }
}
EOF

ln -sf /etc/nginx/sites-available/cert-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable nginx

# Create management script
cat > /opt/cert-server/manage.sh << 'MGMT_SCRIPT'
#!/bin/bash

case "$1" in
    start)
        echo "Starting Certificate Server services..."
        systemctl start cert-server
        systemctl start nginx
        echo "✓ Certificate Server started"
        ;;
    stop)
        echo "Stopping Certificate Server services..."
        systemctl stop cert-server
        systemctl stop nginx
        echo "✓ Certificate Server stopped"
        ;;
    restart)
        echo "Restarting Certificate Server services..."
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
        ;;
    logs)
        echo "Certificate Server Logs (Ctrl+C to exit):"
        journalctl -u cert-server -f --no-pager
        ;;
    *)
        echo "Certificate Server Management Tool"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Web Interface: https://$(hostname -I | awk '{print $1}'):8443"
        echo "API Endpoint:  https://$(hostname -I | awk '{print $1}'):8443/api"
        ;;
esac
MGMT_SCRIPT

chmod +x /opt/cert-server/manage.sh
ln -sf /opt/cert-server/manage.sh /usr/local/bin/cert-server

# Initialize database and start services
cd /opt/cert-server/web
source ../venv/bin/activate
python3 -c "from app import init_db; init_db()"

systemctl start cert-server
systemctl start nginx

# Create MOTD
cat > /etc/motd << EOF
   ____          _   _  __ _           _         ____                           
  / ___|___ _ __| |_(_)/ _(_) ___ __ _| |_ ___  / ___|  ___ _ ____   _____ _ __ 
 | |   / _ \ '__| __| | |_| |/ __/ _\` | __/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
 | |__|  __/ |  | |_| |  _| | (_| (_| | ||  __/  ___) |  __/ |   \ V /  __/ |   
  \____\___|_|   \__|_|_| |_|\___\__,_|\__\___| |____/ \___|_|    \_/ \___|_|   

Enhanced Certificate Server - LXC Container

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
Username:      $WEB_ADMIN_USER
Password:      $WEB_ADMIN_PASS

Management:    cert-server {start|stop|restart|status|logs}

EOF

# Save credentials
cat > /root/cert-server-credentials.txt << EOF
Certificate Server Access Information
====================================

Web Interface: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT
Username: $WEB_ADMIN_USER
Password: $WEB_ADMIN_PASS

API Endpoint: https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT/api

Management Commands:
- cert-server start|stop|restart|status|logs

CA Certificate: /opt/cert-server/ca/ca-cert.pem
Database: /opt/cert-server/config/certificates.db

IMPORTANT: Save this password information!
EOF

chmod 600 /root/cert-server-credentials.txt

# Cleanup
apt-get -y autoremove
apt-get -y autoclean

echo "Certificate Server installation completed successfully!"
INSTALL_SCRIPT_PART4

    # Push and execute part 4
    pct push "$CTID" /tmp/cert-server-install-part4.sh /root/install-part4.sh
    pct exec "$CTID" -- bash -c "
        chmod +x /root/install-part4.sh
        /root/install-part4.sh
    "
    
    # Clean up temporary files
    rm -f /tmp/cert-server-install-part*.sh
    
    msg_ok "Certificate Server installed successfully"
}

function display_completion() {
    # Get container IP
    CONTAINER_IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}' 2>/dev/null || echo "DHCP-IP")
    
    clear
    header_info
    echo ""
    echo -e "${GN}Certificate Server LXC Container Created Successfully!${CL}"
    echo ""
    echo -e "${BL}Container Information:${CL}"
    echo -e "  Container ID: ${GN}$CTID${CL}"
    echo -e "  Hostname: ${GN}$HOSTNAME${CL}"
    echo -e "  IP Address: ${GN}$CONTAINER_IP${CL}"
    echo -e "  Type: ${GN}$([ "$UNPRIVILEGED" = "1" ] && echo "Unprivileged" || echo "Privileged")${CL}"
    echo ""
    echo -e "${BL}Certificate Server Access:${CL}"
    echo -e "  Web Interface: ${GN}https://$CONTAINER_IP:$CERT_SERVER_PORT${CL}"
    echo -e "  API Endpoint: ${GN}https://$CONTAINER_IP:$CERT_SERVER_PORT/api${CL}"
    echo -e "  Username: ${GN}$WEB_ADMIN_USER${CL}"
    echo -e "  Password: ${GN}$WEB_ADMIN_PASS${CL}"
    echo ""
    echo -e "${BL}Management:${CL}"
    echo -e "  Enter Container: ${GN}pct enter $CTID${CL}"
    echo -e "  Service Control: ${GN}cert-server {start|stop|restart|status}${CL}"
    echo -e "  View Logs: ${GN}cert-server logs${CL}"
    echo ""
    echo -e "${BL}Enhanced Features:${CL}"
    echo -e "  ✅ Automatic certificate approval via web interface"
    echo -e "  ✅ Base64 CSR import with auto-approval"
    echo -e "  ✅ Private key export for generated certificates"
    echo -e "  ✅ Certificate bundle downloads (cert + key)"
    echo -e "  ✅ Duplicate request prevention"
    echo -e "  ✅ REST API for automation"
    if [ -n "$VLAN_ID" ]; then
        echo -e "  ✅ VLAN support: ${GN}VLAN $VLAN_ID on $VLAN_INTERFACE${CL}"
    fi
    echo ""
    echo -e "${YW}Root Password: $ROOT_PASSWORD${CL}"
    echo -e "${YW}Credentials saved in: ${GN}/root/cert-server-credentials.txt${CL} (inside container)"
    echo ""
}

function main() {
    clear
    header_info
    echo ""
    
    # Check system requirements
    pve_check
    arch_check
    
    # Interactive configuration
    interactive_config
    
    # Download template
    download_template
    
    # Create and configure container
    create_container
    start_container
    
    # Install certificate server (now properly ordered)
    install_certificate_server
    
    # Display completion information
    display_completion
}

# Run main function
main "$@"
                
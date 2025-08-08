#!/usr/bin/env bash

# Enhanced Certificate Server Installation Script
# Based on community-scripts methodology with extended functionality
# Copyright (c) 2025
# License: MIT
# Source: Enhanced Certificate Authority Server

# ============================================
# PART 1: Core Setup and Functions
# ============================================

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function definitions
msg_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

msg_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

msg_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

msg_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Error handling
catch_errors() {
    set -Eeuo pipefail
    trap 'error_handler $? $LINENO' ERR
}

error_handler() {
    local exit_code=$1
    local line_number=$2
    msg_error "An error occurred on line $line_number with exit code $exit_code"
    cleanup_on_error
    exit $exit_code
}

cleanup_on_error() {
    msg_info "Cleaning up after error..."
    # Add cleanup tasks here
}

# Network configuration
setup_network() {
    msg_info "Configuring network settings"
    
    # Check if running in container or VM
    if [ -f /.dockerenv ] || [ -f /run/systemd/container ]; then
        CONTAINER_ENV=true
    else
        CONTAINER_ENV=false
    fi
    
    # VLAN configuration option
    if [ "${USE_VLAN:-false}" = "true" ]; then
        configure_vlan
    fi
    
    # IPv6 configuration
    if [ "${DISABLE_IPV6:-false}" = "true" ]; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p
    fi
    
    msg_ok "Network configuration completed"
}

configure_vlan() {
    msg_info "Configuring VLAN support"
    
    # Install VLAN packages
    apt-get install -y vlan
    
    # Load 8021q module
    modprobe 8021q
    echo "8021q" >> /etc/modules
    
    # Get VLAN configuration from environment or prompt
    VLAN_ID="${VLAN_ID:-100}"
    VLAN_INTERFACE="${VLAN_INTERFACE:-eth0}"
    VLAN_IP="${VLAN_IP:-}"
    VLAN_NETMASK="${VLAN_NETMASK:-255.255.255.0}"
    VLAN_GATEWAY="${VLAN_GATEWAY:-}"
    
    # Create VLAN interface configuration
    cat > /etc/network/interfaces.d/vlan${VLAN_ID} <<EOF
auto ${VLAN_INTERFACE}.${VLAN_ID}
iface ${VLAN_INTERFACE}.${VLAN_ID} inet static
    address ${VLAN_IP}
    netmask ${VLAN_NETMASK}
    gateway ${VLAN_GATEWAY}
    vlan-raw-device ${VLAN_INTERFACE}
EOF
    
    # Bring up VLAN interface
    ifup ${VLAN_INTERFACE}.${VLAN_ID} || true
    
    msg_ok "VLAN ${VLAN_ID} configured on ${VLAN_INTERFACE}"
}

# System update and base package installation
update_system() {
    msg_info "Updating system packages"
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get upgrade -y
    
    msg_ok "System packages updated"
}

# apt-get install software-properties-common -y
install_dependencies() {
    msg_info "Installing base dependencies"
    
    apt-get install curl -y
    apt-get install wget -y
    apt-get install gnupg -y
    apt-get install lsb-release -y
    apt-get install ca-certificates -y
    apt-get install apt-transport-https -y
    apt-get install openssl -y
    apt-get install nginx -y
    apt-get install python3 -y
    apt-get install python3-pip -y
    apt-get install python3-venv -y
    apt-get install git -y
    apt-get install sudo -y
    apt-get install systemd -y
    apt-get install build-essential -y
    apt-get install libssl-dev -y
    apt-get install libffi-dev -y
    apt-get install python3-dev -y
    
    msg_ok "Base dependencies installed"
}

# Certificate Authority Setup
setup_ca_structure() {
    msg_info "Setting up Certificate Authority structure"
    
    # Define CA directory structure
    CA_ROOT="/opt/certificate-server"
    CA_DIR="${CA_ROOT}/ca"
    CA_PRIVATE="${CA_DIR}/private"
    CA_CERTS="${CA_DIR}/certs"
    CA_NEWCERTS="${CA_DIR}/newcerts"
    CA_CRL="${CA_DIR}/crl"
    CA_CSR="${CA_DIR}/csr"
    CA_REQUESTS="${CA_DIR}/requests"
    CA_EXPORTS="${CA_DIR}/exports"
    
    # Create directory structure
    mkdir -p ${CA_PRIVATE}
    mkdir -p ${CA_CERTS}
    mkdir -p ${CA_NEWCERTS}
    mkdir -p ${CA_CRL}
    mkdir -p ${CA_CSR}
    mkdir -p ${CA_REQUESTS}
    mkdir -p ${CA_EXPORTS}
    
    # Set appropriate permissions
    chmod 700 ${CA_PRIVATE}
    chmod 755 ${CA_CERTS}
    chmod 755 ${CA_NEWCERTS}
    chmod 755 ${CA_CRL}
    chmod 755 ${CA_CSR}
    chmod 755 ${CA_REQUESTS}
    chmod 755 ${CA_EXPORTS}
    
    # Initialize CA database
    touch ${CA_DIR}/index.txt
    echo "1000" > ${CA_DIR}/serial
    echo "1000" > ${CA_DIR}/crlnumber
    
    msg_ok "CA structure created"
}

create_openssl_config() {
    msg_info "Creating OpenSSL configuration"
    
    cat > ${CA_DIR}/openssl.cnf <<'EOF'
# OpenSSL CA configuration file

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /opt/certificate-server/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose
email_in_dn       = no
unique_subject    = no

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
countryName                     = US
stateOrProvinceName             = State
localityName                    = City
0.organizationName              = Organization
organizationalUnitName          = Certificate Authority
commonName                      = CA Root Certificate
emailAddress                    = ca@example.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF
    
    msg_ok "OpenSSL configuration created"
}

generate_ca_certificate() {
    msg_info "Generating CA root certificate"
    
    # Generate CA private key
    openssl genrsa -aes256 \
        -out ${CA_PRIVATE}/ca.key.pem \
        -passout pass:${CA_PASSWORD:-changeme} \
        4096
    
    chmod 400 ${CA_PRIVATE}/ca.key.pem
    
    # Generate CA certificate
    openssl req -config ${CA_DIR}/openssl.cnf \
        -key ${CA_PRIVATE}/ca.key.pem \
        -new -x509 -days 7300 -sha256 -extensions v3_ca \
        -out ${CA_CERTS}/ca.cert.pem \
        -passin pass:${CA_PASSWORD:-changeme}
    
    chmod 444 ${CA_CERTS}/ca.cert.pem
    
    # Verify CA certificate
    openssl x509 -noout -text -in ${CA_CERTS}/ca.cert.pem
    
    msg_ok "CA root certificate generated"
}

# Web Interface Setup
setup_web_interface() {
    msg_info "Setting up web interface"
    
    # Create web directory
    WEB_ROOT="${CA_ROOT}/web"
    mkdir -p ${WEB_ROOT}/static
    mkdir -p ${WEB_ROOT}/templates
    mkdir -p ${WEB_ROOT}/api
    
    # Create Python virtual environment
    python3 -m venv ${CA_ROOT}/venv
    source ${CA_ROOT}/venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install flask flask-cors flask-socketio cryptography pyOpenSSL gunicorn
    
    # Create main Flask application
    create_flask_app
    
    # Create web templates
    create_web_templates
    
    # Create static files
    create_static_files
    
    # Configure Nginx
    configure_nginx
    
    msg_ok "Web interface setup completed"
}

# Continue in Part 2...
# ============================================
# PART 2: Flask Application and Web Components
# ============================================

create_flask_app() {
    cat > ${WEB_ROOT}/app.py <<'PYTHON_APP'
#!/usr/bin/env python3

import os
import sys
import json
import base64
import hashlib
import datetime
import subprocess
import tempfile
import threading
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import OpenSSL

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['CA_DIR'] = '/opt/certificate-server/ca'
app.config['CA_PASSWORD'] = os.environ.get('CA_PASSWORD', 'changeme')
app.config['AUTO_APPROVE'] = True
app.config['SESSION_TYPE'] = 'filesystem'

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Track processed requests to prevent duplicates
processed_requests = {}
request_lock = threading.Lock()

def get_request_hash(request_data):
    """Generate hash of request to detect duplicates"""
    data_str = json.dumps(request_data, sort_keys=True)
    return hashlib.sha256(data_str.encode()).hexdigest()

def is_duplicate_request(request_hash):
    """Check if request was recently processed"""
    with request_lock:
        current_time = datetime.datetime.now()
        # Clean old entries (older than 5 minutes)
        expired = [h for h, t in processed_requests.items() 
                  if (current_time - t).seconds > 300]
        for h in expired:
            del processed_requests[h]
        
        # Check if this request was recently processed
        if request_hash in processed_requests:
            return True
        
        processed_requests[request_hash] = current_time
        return False

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """Get CA status"""
    try:
        ca_cert_path = os.path.join(app.config['CA_DIR'], 'certs', 'ca.cert.pem')
        with open(ca_cert_path, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
        status = {
            'ca_active': True,
            'ca_subject': cert.subject.rfc4514_string(),
            'ca_issuer': cert.issuer.rfc4514_string(),
            'valid_from': cert.not_valid_before_utc.isoformat(),
            'valid_to': cert.not_valid_after_utc.isoformat(),
            'serial_number': str(cert.serial_number),
            'auto_approve': app.config['AUTO_APPROVE']
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/certificate/request', methods=['POST'])
def request_certificate():
    """Handle certificate requests"""
    try:
        data = request.json
        request_type = data.get('type', 'server')
        
        # Check for duplicate request
        request_hash = get_request_hash(data)
        if is_duplicate_request(request_hash):
            return jsonify({'error': 'Duplicate request detected. Please wait before retrying.'}), 429
        
        if data.get('csr_base64'):
            # Handle Base64 encoded CSR
            result = process_base64_csr(data['csr_base64'], request_type, data)
        else:
            # Generate new certificate request
            result = generate_certificate_request(data, request_type)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def process_base64_csr(csr_base64, request_type, data):
    """Process Base64 encoded CSR with auto-approval"""
    try:
        # Decode CSR
        csr_pem = base64.b64decode(csr_base64).decode('utf-8')
        
        # Save CSR to file
        csr_filename = f"request_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csr"
        csr_path = os.path.join(app.config['CA_DIR'], 'requests', csr_filename)
        
        with open(csr_path, 'w') as f:
            f.write(csr_pem)
        
        # Auto-approve if enabled
        if app.config['AUTO_APPROVE']:
            cert_path = sign_certificate_request(csr_path, request_type, data.get('days', 365))
            
            with open(cert_path, 'r') as f:
                cert_pem = f.read()
            
            return {
                'status': 'approved',
                'certificate': cert_pem,
                'csr_file': csr_filename
            }
        else:
            return {
                'status': 'pending',
                'csr_file': csr_filename,
                'message': 'Certificate request pending approval'
            }
    except Exception as e:
        raise Exception(f"Failed to process CSR: {str(e)}")

def generate_certificate_request(data, request_type):
    """Generate new certificate request with key"""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(data.get('key_size', 2048)),
            backend=default_backend()
        )
        
        # Build subject
        subject_components = []
        if data.get('country'):
            subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, data['country']))
        if data.get('state'):
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data['state']))
        if data.get('locality'):
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, data['locality']))
        if data.get('organization'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, data['organization']))
        if data.get('organizational_unit'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data['organizational_unit']))
        subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, data['common_name']))
        
        subject = x509.Name(subject_components)
        
        # Create CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add extensions for server certificates
        if request_type == 'server':
            san_list = []
            if data.get('san_dns'):
                for dns in data['san_dns'].split(','):
                    san_list.append(x509.DNSName(dns.strip()))
            if data.get('san_ip'):
                for ip in data['san_ip'].split(','):
                    san_list.append(x509.IPAddress(ipaddress.ip_address(ip.strip())))
            
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
        
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        # Save private key
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"private_key_{timestamp}.pem"
        key_path = os.path.join(app.config['CA_DIR'], 'private', key_filename)
        
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save CSR
        csr_filename = f"request_{timestamp}.csr"
        csr_path = os.path.join(app.config['CA_DIR'], 'requests', csr_filename)
        
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        
        # Auto-approve for server certificates if enabled
        if request_type == 'server' and app.config['AUTO_APPROVE']:
            cert_path = sign_certificate_request(csr_path, request_type, data.get('days', 365))
            
            with open(cert_path, 'r') as f:
                cert_pem = f.read()
            
            with open(key_path, 'r') as f:
                key_pem = f.read()
            
            # Create export bundle
            export_filename = f"export_{timestamp}.zip"
            export_path = create_certificate_bundle(cert_pem, key_pem, export_filename)
            
            return {
                'status': 'approved',
                'certificate': cert_pem,
                'private_key': key_pem,
                'csr_file': csr_filename,
                'key_file': key_filename,
                'export_file': export_filename
            }
        else:
            return {
                'status': 'pending',
                'csr_file': csr_filename,
                'key_file': key_filename,
                'message': 'Certificate request pending approval'
            }
            
    except Exception as e:
        raise Exception(f"Failed to generate certificate request: {str(e)}")

def sign_certificate_request(csr_path, cert_type, days):
    """Sign a certificate request"""
    try:
        cert_filename = f"cert_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pem"
        cert_path = os.path.join(app.config['CA_DIR'], 'newcerts', cert_filename)
        
        # Determine extensions based on certificate type
        if cert_type == 'server':
            extensions = 'server_cert'
        elif cert_type == 'client':
            extensions = 'usr_cert'
        else:
            extensions = 'v3_ca'
        
        # Sign the certificate
        cmd = [
            'openssl', 'ca',
            '-config', os.path.join(app.config['CA_DIR'], 'openssl.cnf'),
            '-extensions', extensions,
            '-days', str(days),
            '-notext',
            '-md', 'sha256',
            '-in', csr_path,
            '-out', cert_path,
            '-batch',
            '-passin', f'pass:{app.config["CA_PASSWORD"]}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Certificate signing failed: {result.stderr}")
        
        return cert_path
    except Exception as e:
        raise Exception(f"Failed to sign certificate: {str(e)}")

def create_certificate_bundle(cert_pem, key_pem, filename):
    """Create a ZIP bundle with certificate and key"""
    import zipfile
    
    export_path = os.path.join(app.config['CA_DIR'], 'exports', filename)
    
    with zipfile.ZipFile(export_path, 'w') as zf:
        zf.writestr('certificate.pem', cert_pem)
        zf.writestr('private_key.pem', key_pem)
        
        # Add CA certificate
        ca_cert_path = os.path.join(app.config['CA_DIR'], 'certs', 'ca.cert.pem')
        with open(ca_cert_path, 'r') as f:
            zf.writestr('ca_certificate.pem', f.read())
        
        # Add combined PEM
        combined = cert_pem + '\n' + key_pem
        zf.writestr('combined.pem', combined)
    
    return export_path

@app.route('/api/certificates/list')
def list_certificates():
    """List all certificates"""
    try:
        certificates = []
        newcerts_dir = os.path.join(app.config['CA_DIR'], 'newcerts')
        
        for cert_file in os.listdir(newcerts_dir):
            if cert_file.endswith('.pem'):
                cert_path = os.path.join(newcerts_dir, cert_file)
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    
                certificates.append({
                    'filename': cert_file,
                    'subject': cert.subject.rfc4514_string(),
                    'serial_number': str(cert.serial_number),
                    'valid_from': cert.not_valid_before_utc.isoformat(),
                    'valid_to': cert.not_valid_after_utc.isoformat()
                })
        
        return jsonify(certificates)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/certificate/revoke', methods=['POST'])
def revoke_certificate():
    """Revoke a certificate"""
    try:
        data = request.json
        cert_file = data.get('certificate_file')
        reason = data.get('reason', 'unspecified')
        
        cert_path = os.path.join(app.config['CA_DIR'], 'newcerts', cert_file)
        
        cmd = [
            'openssl', 'ca',
            '-config', os.path.join(app.config['CA_DIR'], 'openssl.cnf'),
            '-revoke', cert_path,
            '-crl_reason', reason,
            '-passin', f'pass:{app.config["CA_PASSWORD"]}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Certificate revocation failed: {result.stderr}")
        
        # Generate new CRL
        generate_crl()
        
        return jsonify({'status': 'revoked', 'certificate': cert_file})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_crl():
    """Generate Certificate Revocation List"""
    try:
        crl_path = os.path.join(app.config['CA_DIR'], 'crl', 'ca.crl.pem')
        
        cmd = [
            'openssl', 'ca',
            '-config', os.path.join(app.config['CA_DIR'], 'openssl.cnf'),
            '-gencrl',
            '-out', crl_path,
            '-passin', f'pass:{app.config["CA_PASSWORD"]}'
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
    except Exception as e:
        raise Exception(f"Failed to generate CRL: {str(e)}")

@app.route('/api/certificate/download/<path:filename>')
def download_certificate(filename):
    """Download certificate or export bundle"""
    try:
        # Check which directory contains the file
        paths_to_check = [
            os.path.join(app.config['CA_DIR'], 'exports', filename),
            os.path.join(app.config['CA_DIR'], 'newcerts', filename),
            os.path.join(app.config['CA_DIR'], 'certs', filename)
        ]
        
        for path in paths_to_check:
            if os.path.exists(path):
                return send_file(path, as_attachment=True)
        
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'data': 'Connected to Certificate Server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
PYTHON_APP

    chmod +x ${WEB_ROOT}/app.py
    msg_ok "Flask application created"
}

# ============================================
# PART 3: Web Templates and Static Files
# ============================================

create_web_templates() {
    msg_info "Creating web interface templates"
    
    # Create base template
    cat > ${WEB_ROOT}/templates/base.html <<'HTML_BASE'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate Authority Server - {% block title %}{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">
                <i class="fas fa-certificate"></i>
                <span>Certificate Authority Server</span>
            </div>
            <ul class="nav-menu">
                <li><a href="/" class="nav-link">Dashboard</a></li>
                <li><a href="#request" class="nav-link">Request Certificate</a></li>
                <li><a href="#manage" class="nav-link">Manage</a></li>
                <li><a href="#settings" class="nav-link">Settings</a></li>
            </ul>
        </div>
    </nav>
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                        <button class="alert-close">&times;</button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <footer class="footer">
        <p>&copy; 2025 Certificate Authority Server. All rights reserved.</p>
    </footer>
    
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
HTML_BASE

    # Create index/dashboard template
    cat > ${WEB_ROOT}/templates/index.html <<'HTML_INDEX'
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}

{% block content %}
<div class="dashboard">
    <h1>Certificate Authority Dashboard</h1>
    
    <div class="status-panel" id="ca-status">
        <h2><i class="fas fa-info-circle"></i> CA Status</h2>
        <div class="status-content">
            <div class="status-item">
                <span class="status-label">Status:</span>
                <span class="status-value" id="ca-active">Loading...</span>
            </div>
            <div class="status-item">
                <span class="status-label">Subject:</span>
                <span class="status-value" id="ca-subject">-</span>
            </div>
            <div class="status-item">
                <span class="status-label">Valid Until:</span>
                <span class="status-value" id="ca-validity">-</span>
            </div>
            <div class="status-item">
                <span class="status-label">Auto-Approval:</span>
                <span class="status-value" id="auto-approve">-</span>
            </div>
        </div>
    </div>
    
    <div class="grid-container">
        <div class="card">
            <h2><i class="fas fa-plus-circle"></i> Request Certificate</h2>
            <form id="cert-request-form" class="cert-form">
                <div class="form-section">
                    <h3>Certificate Type</h3>
                    <div class="radio-group">
                        <label>
                            <input type="radio" name="cert_type" value="server" checked>
                            <span>Server Certificate</span>
                        </label>
                        <label>
                            <input type="radio" name="cert_type" value="client">
                            <span>Client Certificate</span>
                        </label>
                    </div>
                </div>
                
                <div class="form-section">
                    <h3>Request Method</h3>
                    <div class="tab-buttons">
                        <button type="button" class="tab-btn active" data-tab="generate">Generate New</button>
                        <button type="button" class="tab-btn" data-tab="import">Import CSR</button>
                    </div>
                    
                    <div class="tab-content active" id="generate-tab">
                        <div class="form-group">
                            <label for="common_name">Common Name (CN) *</label>
                            <input type="text" id="common_name" name="common_name" required placeholder="example.com">
                        </div>
                        
                        <div class="form-group">
                            <label for="organization">Organization (O)</label>
                            <input type="text" id="organization" name="organization" placeholder="ACME Corp">
                        </div>
                        
                        <div class="form-group">
                            <label for="organizational_unit">Organizational Unit (OU)</label>
                            <input type="text" id="organizational_unit" name="organizational_unit" placeholder="IT Department">
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="locality">Locality (L)</label>
                                <input type="text" id="locality" name="locality" placeholder="San Francisco">
                            </div>
                            
                            <div class="form-group">
                                <label for="state">State (ST)</label>
                                <input type="text" id="state" name="state" placeholder="California">
                            </div>
                            
                            <div class="form-group">
                                <label for="country">Country (C)</label>
                                <input type="text" id="country" name="country" placeholder="US" maxlength="2">
                            </div>
                        </div>
                        
                        <div class="form-group server-only">
                            <label for="san_dns">Subject Alternative Names (DNS)</label>
                            <input type="text" id="san_dns" name="san_dns" placeholder="www.example.com, *.example.com">
                            <small>Comma-separated list of DNS names</small>
                        </div>
                        
                        <div class="form-group server-only">
                            <label for="san_ip">Subject Alternative Names (IP)</label>
                            <input type="text" id="san_ip" name="san_ip" placeholder="192.168.1.1, 10.0.0.1">
                            <small>Comma-separated list of IP addresses</small>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="key_size">Key Size</label>
                                <select id="key_size" name="key_size">
                                    <option value="2048" selected>2048 bits</option>
                                    <option value="4096">4096 bits</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="days">Validity (Days)</label>
                                <input type="number" id="days" name="days" value="365" min="1" max="3650">
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-content" id="import-tab">
                        <div class="form-group">
                            <label for="csr_base64">Certificate Signing Request (Base64 PEM)</label>
                            <textarea id="csr_base64" name="csr_base64" rows="10" placeholder="-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----"></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="import_days">Validity (Days)</label>
                            <input type="number" id="import_days" name="import_days" value="365" min="1" max="3650">
                        </div>
                    </div>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-certificate"></i> Request Certificate
                    </button>
                    <button type="reset" class="btn btn-secondary">
                        <i class="fas fa-undo"></i> Reset
                    </button>
                </div>
            </form>
            
            <div id="request-result" class="result-panel" style="display:none;">
                <h3>Certificate Request Result</h3>
                <div class="result-content"></div>
            </div>
        </div>
        
        <div class="card">
            <h2><i class="fas fa-list"></i> Recent Certificates</h2>
            <div id="cert-list" class="cert-list">
                <div class="loading">Loading certificates...</div>
            </div>
        </div>
    </div>
    
    <div class="card" id="manage">
        <h2><i class="fas fa-tasks"></i> Certificate Management</h2>
        <div class="management-tools">
            <button class="btn btn-warning" onclick="refreshCertList()">
                <i class="fas fa-sync"></i> Refresh List
            </button>
            <button class="btn btn-info" onclick="downloadCACert()">
                <i class="fas fa-download"></i> Download CA Certificate
            </button>
            <button class="btn btn-danger" onclick="showRevokeDialog()">
                <i class="fas fa-ban"></i> Revoke Certificate
            </button>
        </div>
    </div>
</div>

<!-- Revoke Dialog -->
<div id="revoke-dialog" class="modal">
    <div class="modal-content">
        <span class="close">&times;</span>
        <h2>Revoke Certificate</h2>
        <form id="revoke-form">
            <div class="form-group">
                <label for="revoke-cert">Select Certificate</label>
                <select id="revoke-cert" name="certificate_file" required></select>
            </div>
            <div class="form-group">
                <label for="revoke-reason">Reason</label>
                <select id="revoke-reason" name="reason">
                    <option value="unspecified">Unspecified</option>
                    <option value="keyCompromise">Key Compromise</option>
                    <option value="CACompromise">CA Compromise</option>
                    <option value="affiliationChanged">Affiliation Changed</option>
                    <option value="superseded">Superseded</option>
                    <option value="cessationOfOperation">Cessation of Operation</option>
                </select>
            </div>
            <div class="form-actions">
                <button type="submit" class="btn btn-danger">Revoke</button>
                <button type="button" class="btn btn-secondary" onclick="closeRevokeDialog()">Cancel</button>
            </div>
        </form>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    // Initialize WebSocket connection
    const socket = io();
    
    socket.on('connected', function(data) {
        console.log('WebSocket connected:', data);
    });
    
    // Load CA status on page load
    $(document).ready(function() {
        loadCAStatus();
        loadCertificateList();
        setupFormHandlers();
    });
</script>
{% endblock %}
HTML_INDEX

    msg_ok "Web templates created"
}

create_static_files() {
    msg_info "Creating static files"
    
    # Create CSS
    mkdir -p ${WEB_ROOT}/static/css
    cat > ${WEB_ROOT}/static/css/style.css <<'CSS_STYLE'
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --bg-color: #ecf0f1;
    --card-bg: #ffffff;
    --text-color: #2c3e50;
    --border-color: #bdc3c7;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background-color: var(--bg-color);
    color: var(--text-color);
    line-height: 1.6;
}

.navbar {
    background-color: var(--primary-color);
    color: white;
    padding: 1rem 0;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.nav-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-brand {
    font-size: 1.5rem;
    font-weight: bold;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.nav-menu {
    list-style: none;
    display: flex;
    gap: 2rem;
}

.nav-link {
    color: white;
    text-decoration: none;
    transition: opacity 0.3s;
}

.nav-link:hover {
    opacity: 0.8;
}

.container {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
}

.dashboard h1 {
    margin-bottom: 2rem;
    color: var(--primary-color);
}

.status-panel {
    background: var(--card-bg);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.status-panel h2 {
    margin-bottom: 1rem;
    color: var(--primary-color);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.status-content {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
}

.status-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem;
    background: var(--bg-color);
    border-radius: 4px;
}

.status-label {
    font-weight: 600;
}

.status-value {
    color: var(--secondary-color);
}

.grid-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
    gap: 2rem;
    margin-bottom: 2rem;
}

.card {
    background: var(--card-bg);
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.card h2 {
    margin-bottom: 1.5rem;
    color: var(--primary-color);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.cert-form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.form-section {
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1.5rem;
}

.form-section h3 {
    margin-bottom: 1rem;
    color: var(--primary-color);
    font-size: 1.1rem;
}

.radio-group {
    display: flex;
    gap: 1.5rem;
}

.radio-group label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
}

.tab-buttons {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
}

.tab-btn {
    flex: 1;
    padding: 0.75rem;
    background: var(--bg-color);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.3s;
}

.tab-btn.active {
    background: var(--secondary-color);
    color: white;
    border-color: var(--secondary-color);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.form-group label {
    font-weight: 600;
    color: var(--text-color);
}

.form-group input,
.form-group select,
.form-group textarea {
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 1rem;
    transition: border-color 0.3s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
    outline: none;
    border-color: var(--secondary-color);
}

.form-group small {
    color: #7f8c8d;
    font-size: 0.875rem;
}

.form-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
}

.form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.btn {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: all 0.3s;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn-primary {
    background: var(--secondary-color);
    color: white;
}

.btn-primary:hover {
    background: #2980b9;
}

.btn-secondary {
    background: var(--border-color);
    color: var(--text-color);
}

.btn-secondary:hover {
    background: #95a5a6;
}

.btn-success {
    background: var(--success-color);
    color: white;
}

.btn-warning {
    background: var(--warning-color);
    color: white;
}

.btn-danger {
    background: var(--danger-color);
    color: white;
}

.btn-info {
    background: var(--secondary-color);
    color: white;
}

.alert {
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.alert-success {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.alert-error {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.alert-close {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
}

.result-panel {
    margin-top: 2rem;
    padding: 1.5rem;
    background: var(--bg-color);
    border-radius: 4px;
    border: 1px solid var(--border-color);
}

.result-panel h3 {
    margin-bottom: 1rem;
    color: var(--primary-color);
}

.cert-list {
    max-height: 400px;
    overflow-y: auto;
}

.cert-item {
    padding: 1rem;
    background: var(--bg-color);
    border-radius: 4px;
    margin-bottom: 0.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.cert-info {
    flex: 1;
}

.cert-actions {
    display: flex;
    gap: 0.5rem;
}

.loading {
    text-align: center;
    padding: 2rem;
    color: var(--border-color);
}

.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
}

.modal-content {
    background-color: var(--card-bg);
    margin: 10% auto;
    padding: 2rem;
    border-radius: 8px;
    width: 500px;
    max-width: 90%;
}

.close {
    float: right;
    font-size: 2rem;
    font-weight: bold;
    cursor: pointer;
}

.close:hover {
    color: var(--danger-color);
}

.footer {
    background: var(--primary-color);
    color: white;
    text-align: center;
    padding: 1rem;
    margin-top: 3rem;
}

.management-tools {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
}

@media (max-width: 768px) {
    .grid-container {
        grid-template-columns: 1fr;
    }
    
    .nav-menu {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .form-row {
        grid-template-columns: 1fr;
    }
}
CSS_STYLE

    # Create JavaScript
    mkdir -p ${WEB_ROOT}/static/js
    cat > ${WEB_ROOT}/static/js/main.js <<'JS_MAIN'
// Request tracking to prevent duplicates
let lastRequestHash = null;
let isProcessing = false;

// Calculate hash of request data
function calculateRequestHash(data) {
    const str = JSON.stringify(data);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString();
}

// Load CA status
function loadCAStatus() {
    $.ajax({
        url: '/api/status',
        method: 'GET',
        success: function(data) {
            $('#ca-active').html('<span class="badge badge-success">Active</span>');
            $('#ca-subject').text(data.ca_subject);
            $('#ca-validity').text(new Date(data.valid_to).toLocaleDateString());
            $('#auto-approve').html(data.auto_approve ? 
                '<span class="badge badge-success">Enabled</span>' : 
                '<span class="badge badge-warning">Disabled</span>');
        },
        error: function() {
            $('#ca-active').html('<span class="badge badge-danger">Error</span>');
        }
    });
}

// Load certificate list
function loadCertificateList() {
    $.ajax({
        url: '/api/certificates/list',
        method: 'GET',
        success: function(data) {
            const listContainer = $('#cert-list');
            if (data.length === 0) {
                listContainer.html('<div class="empty">No certificates issued yet</div>');
                return;
            }
            
            let html = '';
            data.forEach(function(cert) {
                html += `
                    <div class="cert-item">
                        <div class="cert-info">
                            <strong>${cert.subject}</strong><br>
                            <small>Serial: ${cert.serial_number}</small><br>
                            <small>Valid: ${new Date(cert.valid_from).toLocaleDateString()} - ${new Date(cert.valid_to).toLocaleDateString()}</small>
                        </div>
                        <div class="cert-actions">
                            <button class="btn btn-sm btn-info" onclick="downloadCert('${cert.filename}')">
                                <i class="fas fa-download"></i>
                            </button>
                        </div>
                    </div>
                `;
            });
            listContainer.html(html);
            
            // Update revoke dialog options
            const revokeSelect = $('#revoke-cert');
            revokeSelect.empty();
            data.forEach(function(cert) {
                revokeSelect.append(`<option value="${cert.filename}">${cert.subject}</option>`);
            });
        },
        error: function() {
            $('#cert-list').html('<div class="error">Failed to load certificates</div>');
        }
    });
}

// Setup form handlers
function setupFormHandlers() {
    // Tab switching
    $('.tab-btn').click(function() {
        const tab = $(this).data('tab');
        $('.tab-btn').removeClass('active');
        $(this).addClass('active');
        $('.tab-content').removeClass('active');
        $(`#${tab}-tab`).addClass('active');
    });
    
    // Certificate type change
    $('input[name="cert_type"]').change(function() {
        if ($(this).val() === 'server') {
            $('.server-only').show();
        } else {
            $('.server-only').hide();
        }
    });
    
    // Form submission
    $('#cert-request-form').submit(function(e) {
        e.preventDefault();
        
        if (isProcessing) {
            alert('Please wait for the current request to complete');
            return;
        }
        
        const activeTab = $('.tab-content.active').attr('id');
        const formData = {};
        
        // Collect form data based on active tab
        if (activeTab === 'generate-tab') {
            formData.type = $('input[name="cert_type"]:checked').val();
            formData.common_name = $('#common_name').val();
            formData.organization = $('#organization').val();
            formData.organizational_unit = $('#organizational_unit').val();
            formData.locality = $('#locality').val();
            formData.state = $('#state').val();
            formData.country = $('#country').val();
            formData.san_dns = $('#san_dns').val();
            formData.san_ip = $('#san_ip').val();
            formData.key_size = $('#key_size').val();
            formData.days = $('#days').val();
        } else {
            formData.type = $('input[name="cert_type"]:checked').val();
            formData.csr_base64 = $('#csr_base64').val();
            formData.days = $('#import_days').val();
        }
        
        // Check for duplicate request
        const requestHash = calculateRequestHash(formData);
        if (requestHash === lastRequestHash) {
            alert('This appears to be a duplicate request. Please modify your request or wait before retrying.');
            return;
        }
        
        isProcessing = true;
        lastRequestHash = requestHash;
        
        // Submit request
        $.ajax({
            url: '/api/certificate/request',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(formData),
            success: function(response) {
                displayResult(response);
                loadCertificateList();
                isProcessing = false;
            },
            error: function(xhr) {
                const error = xhr.responseJSON ? xhr.responseJSON.error : 'Request failed';
                displayError(error);
                isProcessing = false;
                
                // Clear hash if it was a duplicate error
                if (xhr.status === 429) {
                    lastRequestHash = null;
                }
            }
        });
    });
    
    // Revoke form
    $('#revoke-form').submit(function(e) {
        e.preventDefault();
        
        if (!confirm('Are you sure you want to revoke this certificate?')) {
            return;
        }
        
        const formData = {
            certificate_file: $('#revoke-cert').val(),
            reason: $('#revoke-reason').val()
        };
        
        $.ajax({
            url: '/api/certificate/revoke',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(formData),
            success: function(response) {
                alert('Certificate revoked successfully');
                closeRevokeDialog();
                loadCertificateList();
            },
            error: function(xhr) {
                alert('Failed to revoke certificate: ' + (xhr.responseJSON ? xhr.responseJSON.error : 'Unknown error'));
            }
        });
    });
    
    // Alert close buttons
    $(document).on('click', '.alert-close', function() {
        $(this).parent('.alert').fadeOut();
    });
}

// Display result
function displayResult(response) {
    let html = '';
    
    if (response.status === 'approved') {
        html = `
            <div class="alert alert-success">
                <strong>Certificate Approved!</strong>
            </div>
            <div class="result-details">
                <h4>Certificate Details:</h4>
                <pre>${response.certificate}</pre>
                ${response.private_key ? `
                    <h4>Private Key:</h4>
                    <pre>${response.private_key}</pre>
                ` : ''}
                <div class="result-actions">
                    ${response.export_file ? `
                        <a href="/api/certificate/download/${response.export_file}" class="btn btn-primary">
                            <i class="fas fa-download"></i> Download Bundle
                        </a>
                    ` : ''}
                </div>
            </div>
        `;
    } else {
        html = `
            <div class="alert alert-warning">
                <strong>Certificate Pending Approval</strong>
                <p>${response.message}</p>
            </div>
        `;
    }
    
    $('#request-result').html(html).show();
}

function displayError(error) {
    const html = `
        <div class="alert alert-error">
            <strong>Error:</strong> ${error}
        </div>
    `;
    $('#request-result').html(html).show();
}

// Download functions
function downloadCert(filename) {
    window.location.href = `/api/certificate/download/${filename}`;
}

function downloadCACert() {
    window.location.href = '/api/certificate/download/ca.cert.pem';
}

// Refresh certificate list
function refreshCertList() {
    loadCertificateList();
}

// Revoke dialog
function showRevokeDialog() {
    $('#revoke-dialog').show();
}

function closeRevokeDialog() {
    $('#revoke-dialog').hide();
}

// Modal close on click outside
$(window).click(function(event) {
    if ($(event.target).hasClass('modal')) {
        $('.modal').hide();
    }
});

// Close button handler
$('.close').click(function() {
    $(this).closest('.modal').hide();
});
JS_MAIN

    msg_ok "Static files created"
}

# ============================================
# PART 4: Nginx Configuration and Services
# ============================================

configure_nginx() {
    msg_info "Configuring Nginx web server"
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/cert-server <<'NGINX_CONF'
server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /opt/certificate-server/ca/certs/server.cert.pem;
    ssl_certificate_key /opt/certificate-server/ca/private/server.key.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Proxy settings
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
    
    # Static files
    location /static {
        alias /opt/certificate-server/web/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Certificate downloads
    location /downloads {
        alias /opt/certificate-server/ca/exports;
        autoindex off;
    }
    
    # CRL distribution point
    location /crl {
        alias /opt/certificate-server/ca/crl;
        add_header Content-Type "application/pkix-crl";
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=cert_req:10m rate=10r/m;
    location /api/certificate/request {
        limit_req zone=cert_req burst=5 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX_CONF

    # Generate self-signed certificate for Nginx
    generate_nginx_certificate
    
    # Enable site
    ln -sf /etc/nginx/sites-available/cert-server /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and reload Nginx
    nginx -t
    systemctl restart nginx
    
    msg_ok "Nginx configured"
}

generate_nginx_certificate() {
    msg_info "Generating Nginx SSL certificate"
    
    # Generate server private key
    openssl genrsa -out ${CA_PRIVATE}/server.key.pem 2048
    chmod 400 ${CA_PRIVATE}/server.key.pem
    
    # Generate certificate request
    openssl req -new \
        -key ${CA_PRIVATE}/server.key.pem \
        -out ${CA_CSR}/server.csr \
        -subj "/C=US/ST=State/L=City/O=Certificate Server/CN=$(hostname -f)"
    
    # Create extensions file for server certificate
    cat > ${CA_DIR}/server_ext.cnf <<EOF
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Certificate Server SSL Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $(hostname)
DNS.3 = $(hostname -f)
DNS.4 = *.local
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF

    # Sign the certificate
    openssl ca -config ${CA_DIR}/openssl.cnf \
        -extensions server_cert \
        -extfile ${CA_DIR}/server_ext.cnf \
        -days 3650 \
        -notext \
        -md sha256 \
        -in ${CA_CSR}/server.csr \
        -out ${CA_CERTS}/server.cert.pem \
        -batch \
        -passin pass:${CA_PASSWORD:-changeme}
    
    chmod 444 ${CA_CERTS}/server.cert.pem
    
    msg_ok "Nginx SSL certificate generated"
}

# Systemd Services Setup
create_systemd_services() {
    msg_info "Creating systemd services"
    
    # Create Flask app service
    cat > /etc/systemd/system/cert-server.service <<'SYSTEMD_SERVICE'
[Unit]
Description=Certificate Server Web Application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/certificate-server/web
Environment="PATH=/opt/certificate-server/venv/bin"
Environment="FLASK_SECRET_KEY=change-this-secret-key-in-production"
Environment="CA_PASSWORD=changeme"
ExecStart=/opt/certificate-server/venv/bin/gunicorn --worker-class eventlet -w 1 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

    # Create certificate renewal service
    cat > /etc/systemd/system/cert-renewal.service <<'RENEWAL_SERVICE'
[Unit]
Description=Certificate Renewal Check
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/certificate-server/scripts/check-renewals.sh
User=root
RENEWAL_SERVICE

    # Create certificate renewal timer
    cat > /etc/systemd/system/cert-renewal.timer <<'RENEWAL_TIMER'
[Unit]
Description=Daily Certificate Renewal Check
Requires=cert-renewal.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
RENEWAL_TIMER

    # Create CRL update service
    cat > /etc/systemd/system/crl-update.service <<'CRL_SERVICE'
[Unit]
Description=Update Certificate Revocation List
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/certificate-server/scripts/update-crl.sh
User=root
CRL_SERVICE

    # Create CRL update timer
    cat > /etc/systemd/system/crl-update.timer <<'CRL_TIMER'
[Unit]
Description=Weekly CRL Update
Requires=crl-update.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
CRL_TIMER

    # Set permissions
    chown -R www-data:www-data ${CA_ROOT}/web
    chown -R root:root ${CA_DIR}
    chmod -R 755 ${CA_DIR}
    chmod 700 ${CA_PRIVATE}
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start services
    systemctl enable cert-server.service
    systemctl enable cert-renewal.timer
    systemctl enable crl-update.timer
    systemctl start cert-server.service
    systemctl start cert-renewal.timer
    systemctl start crl-update.timer
    
    msg_ok "Systemd services created and started"
}

# Helper Scripts
create_helper_scripts() {
    msg_info "Creating helper scripts"
    
    mkdir -p ${CA_ROOT}/scripts
    
    # Certificate renewal check script
    cat > ${CA_ROOT}/scripts/check-renewals.sh <<'RENEWAL_SCRIPT'
#!/bin/bash

CA_DIR="/opt/certificate-server/ca"
DAYS_WARNING=30
ADMIN_EMAIL="admin@example.com"

# Check certificate expiration
check_expiry() {
    local cert=$1
    local days_left=$(openssl x509 -in "$cert" -checkend $((DAYS_WARNING * 86400)) 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        local subject=$(openssl x509 -in "$cert" -noout -subject)
        local expiry=$(openssl x509 -in "$cert" -noout -enddate)
        echo "Warning: Certificate expiring soon - $subject - $expiry"
        # Send notification (implement email/webhook notification here)
    fi
}

# Check all certificates
for cert in ${CA_DIR}/newcerts/*.pem; do
    [ -f "$cert" ] && check_expiry "$cert"
done

# Check CA certificate
check_expiry "${CA_DIR}/certs/ca.cert.pem"
RENEWAL_SCRIPT

    # CRL update script
    cat > ${CA_ROOT}/scripts/update-crl.sh <<'CRL_SCRIPT'
#!/bin/bash

CA_DIR="/opt/certificate-server/ca"
CA_PASSWORD="${CA_PASSWORD:-changeme}"

# Generate new CRL
openssl ca -config ${CA_DIR}/openssl.cnf \
    -gencrl \
    -out ${CA_DIR}/crl/ca.crl.pem \
    -passin pass:${CA_PASSWORD}

# Convert to DER format
openssl crl -in ${CA_DIR}/crl/ca.crl.pem \
    -outform DER \
    -out ${CA_DIR}/crl/ca.crl

echo "CRL updated at $(date)"
CRL_SCRIPT

    # Backup script
    cat > ${CA_ROOT}/scripts/backup.sh <<'BACKUP_SCRIPT'
#!/bin/bash

CA_ROOT="/opt/certificate-server"
BACKUP_DIR="/var/backups/cert-server"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/cert-server-backup-${TIMESTAMP}.tar.gz"

# Create backup directory
mkdir -p ${BACKUP_DIR}

# Create backup
tar czf ${BACKUP_FILE} \
    --exclude="${CA_ROOT}/venv" \
    --exclude="${CA_ROOT}/ca/private/*" \
    ${CA_ROOT}

# Encrypt private keys separately
tar czf ${BACKUP_FILE}.keys \
    ${CA_ROOT}/ca/private \
    && openssl enc -aes256 -salt \
    -in ${BACKUP_FILE}.keys \
    -out ${BACKUP_FILE}.keys.enc \
    -pass pass:${BACKUP_PASSWORD:-changeme} \
    && rm ${BACKUP_FILE}.keys

# Keep only last 30 backups
find ${BACKUP_DIR} -name "cert-server-backup-*.tar.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}"
BACKUP_SCRIPT

    # Make scripts executable
    chmod +x ${CA_ROOT}/scripts/*.sh
    
    msg_ok "Helper scripts created"
}

# Environment Configuration
create_env_config() {
    msg_info "Creating environment configuration"
    
    cat > ${CA_ROOT}/.env <<'ENV_CONFIG'
# Certificate Server Configuration
CA_ROOT="/opt/certificate-server"
CA_DIR="${CA_ROOT}/ca"
CA_PASSWORD="changeme"
FLASK_SECRET_KEY="change-this-secret-key-in-production"
AUTO_APPROVE="true"
SERVER_NAME="cert-server.local"

# VLAN Configuration (optional)
USE_VLAN="false"
VLAN_ID="100"
VLAN_INTERFACE="eth0"
VLAN_IP=""
VLAN_NETMASK="255.255.255.0"
VLAN_GATEWAY=""

# Backup Configuration
BACKUP_PASSWORD="changeme"
BACKUP_RETENTION_DAYS="30"

# Email Notifications
SMTP_SERVER="smtp.example.com"
SMTP_PORT="587"
SMTP_USER="notifications@example.com"
SMTP_PASSWORD="changeme"
ADMIN_EMAIL="admin@example.com"
ENV_CONFIG

    # Source environment in profile
    echo "source ${CA_ROOT}/.env" >> /etc/profile.d/cert-server.sh
    
    msg_ok "Environment configuration created"
}

# MOTD and Customization
setup_motd() {
    msg_info "Setting up MOTD"
    
    cat > /etc/motd <<'MOTD'
 ╔═══════════════════════════════════════════════════════════════╗
 ║                   Certificate Authority Server                  ║
 ╠═══════════════════════════════════════════════════════════════╣
 ║  Web Interface: https://your-server-ip                         ║
 ║  API Endpoint:  https://your-server-ip/api                     ║
 ║  CA Directory:  /opt/certificate-server/ca                     ║
 ║                                                                 ║
 ║  Commands:                                                      ║
 ║  - systemctl status cert-server    # Check service status      ║
 ║  - journalctl -u cert-server -f    # View logs                 ║
 ║  - /opt/certificate-server/scripts/backup.sh  # Run backup     ║
 ║                                                                 ║
 ║  Documentation: https://github.com/your-repo/cert-server       ║
 ╚═══════════════════════════════════════════════════════════════╝
MOTD

    # Disable default MOTD parts
    chmod -x /etc/update-motd.d/* 2>/dev/null || true
    
    msg_ok "MOTD configured"
}

# Finalization
finalize_installation() {
    msg_info "Finalizing installation"
    
    # Set up log rotation
    cat > /etc/logrotate.d/cert-server <<'LOGROTATE'
/var/log/cert-server/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload cert-server >/dev/null 2>&1 || true
    endscript
}
LOGROTATE

    # Create log directory
    mkdir -p /var/log/cert-server
    chown www-data:www-data /var/log/cert-server
    
    # Final permissions check
    find ${CA_ROOT} -type d -exec chmod 755 {} \;
    find ${CA_ROOT} -type f -exec chmod 644 {} \;
    chmod 700 ${CA_PRIVATE}
    find ${CA_PRIVATE} -type f -exec chmod 600 {} \;
    chmod +x ${CA_ROOT}/scripts/*.sh
    chmod +x ${WEB_ROOT}/app.py
    
    # Display summary
    clear
    msg_ok "Certificate Server Installation Complete!"
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo " Installation Summary"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo " Web Interface:    https://$(hostname -I | awk '{print $1}')"
    echo " Default Password: changeme (change in ${CA_ROOT}/.env)"
    echo " CA Certificate:   ${CA_CERTS}/ca.cert.pem"
    echo " Service Status:   systemctl status cert-server"
    echo ""
    echo " Features Enabled:"
    echo " ✓ Auto-approval for Base64 CSRs"
    echo " ✓ Server certificate auto-approval"
    echo " ✓ Private key export with certificates"
    echo " ✓ Duplicate request prevention"
    echo " ✓ VLAN support (configurable)"
    echo " ✓ WebSocket real-time updates"
    echo " ✓ Rate limiting protection"
    echo ""
    echo " Next Steps:"
    echo " 1. Change default passwords in ${CA_ROOT}/.env"
    echo " 2. Update CA certificate details if needed"
    echo " 3. Configure email notifications"
    echo " 4. Set up regular backups"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
}

# Main Installation Function
main() {
    msg_info "Starting Enhanced Certificate Server Installation"
    
    catch_errors
    setup_network
    update_system
    install_dependencies
    setup_ca_structure
    create_openssl_config
    generate_ca_certificate
    setup_web_interface
    configure_nginx
    create_systemd_services
    create_helper_scripts
    create_env_config
    setup_motd
    finalize_installation
    
    msg_ok "Installation completed successfully!"
}

# Run main function
main "$@"

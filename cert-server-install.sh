#!/usr/bin/env bash

# Copyright (c) 2025 Enhanced Certificate Server
# Author: Iain Reid
# License: MIT
# Source: Enhanced Certificate Server with VLAN support and auto-approval

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

# Configuration variables
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

msg_info "Installing Dependencies"
$STD apt-get install -y \
  apt-transport-https \
  software-properties-common \
  openssl \
  nginx \
  python3 \
  python3-pip \
  python3-venv \
  sqlite3 \
  curl \
  wget \
  jq \
  bridge-utils \
  vlan
msg_ok "Installed Dependencies"

# VLAN Configuration
if [[ -n "$VLAN_ID" && -n "$VLAN_INTERFACE" ]]; then
    msg_info "Configuring VLAN ${VLAN_ID} on interface ${VLAN_INTERFACE}"
    
    # Load 8021q module
    modprobe 8021q
    echo "8021q" >> /etc/modules
    
    # Create VLAN interface
    vconfig add $VLAN_INTERFACE $VLAN_ID
    
    # Configure network interface for VLAN
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
    msg_ok "Configured VLAN ${VLAN_ID}"
fi

msg_info "Setting up Certificate Server Directory Structure"
mkdir -p /opt/cert-server/{ca,certs,keys,csr,config,web,logs}
mkdir -p /opt/cert-server/web/{static,templates}
chmod 755 /opt/cert-server
chmod 700 /opt/cert-server/{ca,keys}
msg_ok "Created Directory Structure"

msg_info "Creating Certificate Authority"
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

msg_ok "Created Certificate Authority"

msg_info "Setting up Python Virtual Environment"
cd /opt/cert-server
python3 -m venv venv
source venv/bin/activate
pip install flask flask-httpauth cryptography pyopenssl sqlite3
msg_ok "Set up Python Environment"

msg_info "Creating Certificate Server Web Application"
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
            auto_approved BOOLEAN DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_data TEXT NOT NULL,
            submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed BOOLEAN DEFAULT 0
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
        
        # Store in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO certificates 
            (common_name, serial_number, status, csr_data, cert_data, approved_date, expires_date, auto_approved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            common_name,
            str(serial),
            'approved' if auto_approve else 'pending',
            csr_data,
            cert_pem,
            datetime.utcnow() if auto_approve else None,
            cert.not_valid_after,
            auto_approve
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
        content = cert_data[7]  # cert_data
        filename = f'certificate_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'key' and cert_data[8]:  # key_data exists
        content = cert_data[8]
        filename = f'private_key_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'csr':
        content = cert_data[6]  # csr_data
        filename = f'csr_{serial}.pem'
        mimetype = 'application/x-pem-file'
    elif file_type == 'bundle':
        # Create certificate bundle with key if available
        bundle_content = cert_data[7]  # cert_data
        if cert_data[8]:  # key_data
            bundle_content += "\n" + cert_data[8]
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
            csr_data = decoded_csr
        except:
            pass  # Not base64 encoded
        
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

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('CERT_SERVER_HTTP_PORT', 8080)), debug=False)
EOF

chmod +x /opt/cert-server/web/app.py
msg_ok "Created Web Application"

msg_info "Creating Web Templates"
mkdir -p /opt/cert-server/web/templates

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

cat > /opt/cert-server/web/templates/index.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="jumbotron bg-light p-5 rounded">
            <h1 class="display-4"><i class="fas fa-certificate text-primary"></i> Certificate Server</h1>
            <p class="lead">Generate and manage SSL/TLS certificates with automatic approval.</p>
            <hr class="my-4">
            <p>This certificate server provides automated certificate generation and management with support for:</p>
            <ul>
                <li>Automatic certificate approval for web interface requests</li>
                <li>Base64 encoded CSR import with auto-approval</li>
                <li>Private key export for server-generated certificates</li>
                <li>Certificate bundle downloads</li>
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

<div class="row mt-4">
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-upload text-success"></i> Import CSR</h5>
                <p class="card-text">Upload a Certificate Signing Request for automatic approval.</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-magic text-warning"></i> Generate Certificate</h5>
                <p class="card-text">Generate a new certificate with private key automatically.</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-download text-info"></i> Download Bundle</h5>
                <p class="card-text">Download certificate with private key in one bundle.</p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

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
                        <form method="POST">
                            <div class="mb-3">
                                <label for="csr_data" class="form-label">CSR Data *</label>
                                <textarea class="form-control" id="csr_data" name="csr_data" rows="10" required></textarea>
                                <div class="form-text">Paste your PEM encoded CSR or Base64 encoded CSR here</div>
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
EOF

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
                                    {% if cert[11] %}
                                        <span class="badge bg-info ms-1">Auto-Approved</span>
                                    {% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Created:</strong></td>
                                <td>{{ cert[8] }}</td>
                            </tr>
                            {% if cert[9] %}
                            <tr>
                                <td><strong>Approved:</strong></td>
                                <td>{{ cert[9] }}</td>
                            </tr>
                            {% endif %}
                            <tr>
                                <td><strong>Expires:</strong></td>
                                <td>{{ cert[10] }}</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h5>Downloads</h5>
                        <div class="d-grid gap-2">
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
                
                {% if cert[7] %}
                <hr>
                <h5>Certificate Data</h5>
                <pre class="bg-light p-3 small"><code>{{ cert[7] }}</code></pre>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

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
                                <td>{{ cert[8] }}</td>
                                <td>{{ cert[10] }}</td>
                                <td>
                                    {% if cert[11] %}
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

msg_ok "Created Web Templates"

msg_info "Creating Systemd Service"
cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Certificate Server
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
msg_ok "Created Systemd Service"

msg_info "Configuring Nginx Reverse Proxy"
cat > /etc/nginx/sites-available/cert-server << EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $CERT_SERVER_PORT ssl;
    server_name _;
    
    ssl_certificate /opt/cert-server/ca/ca-cert.pem;
    ssl_certificate_key /opt/cert-server/ca/ca-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # API endpoints for certificate operations
    location /api/ {
        proxy_pass http://127.0.0.1:$CERT_SERVER_HTTP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Content-Type application/json;
    }
}
EOF

ln -sf /etc/nginx/sites-available/cert-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable nginx
msg_ok "Configured Nginx"

msg_info "Creating Management Scripts"
cat > /opt/cert-server/manage.sh << 'EOF'
#!/bin/bash

CERT_SERVER_DIR="/opt/cert-server"
VENV_PATH="$CERT_SERVER_DIR/venv"

case "$1" in
    start)
        echo "Starting Certificate Server..."
        systemctl start cert-server
        systemctl start nginx
        echo "Certificate Server started"
        ;;
    stop)
        echo "Stopping Certificate Server..."
        systemctl stop cert-server
        systemctl stop nginx
        echo "Certificate Server stopped"
        ;;
    restart)
        echo "Restarting Certificate Server..."
        systemctl restart cert-server
        systemctl restart nginx
        echo "Certificate Server restarted"
        ;;
    status)
        echo "Certificate Server Status:"
        systemctl status cert-server --no-pager -l
        echo ""
        echo "Nginx Status:"
        systemctl status nginx --no-pager -l
        ;;
    logs)
        journalctl -u cert-server -f
        ;;
    backup)
        BACKUP_DIR="/opt/cert-server-backup-$(date +%Y%m%d_%H%M%S)"
        echo "Creating backup in $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        cp -r $CERT_SERVER_DIR/ca "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/config "$BACKUP_DIR/"
        cp -r $CERT_SERVER_DIR/certs "$BACKUP_DIR/" 2>/dev/null || true
        cp -r $CERT_SERVER_DIR/keys "$BACKUP_DIR/" 2>/dev/null || true
        tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
        rm -rf "$BACKUP_DIR"
        echo "Backup created: $BACKUP_DIR.tar.gz"
        ;;
    clean-duplicates)
        echo "Cleaning duplicate certificate entries..."
        source $VENV_PATH/bin/activate
        python3 << 'PYTHON_EOF'
import sqlite3
import os

DB_PATH = '/opt/cert-server/config/certificates.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Remove duplicate certificates based on common_name, keeping the latest
cursor.execute('''
    DELETE FROM certificates 
    WHERE id NOT IN (
        SELECT MIN(id) 
        FROM certificates 
        GROUP BY common_name, serial_number
    )
''')

affected = cursor.rowcount
conn.commit()
conn.close()
print(f"Removed {affected} duplicate entries")
PYTHON_EOF
        ;;
    generate-cert)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 generate-cert <common_name> <organization>"
            exit 1
        fi
        echo "Generating certificate for $2..."
        source $VENV_PATH/bin/activate
        python3 << PYTHON_EOF
import sys
sys.path.append('/opt/cert-server/web')
from app import generate_key_and_csr, sign_certificate, init_db
import sqlite3

try:
    init_db()
    key_pem, csr_pem = generate_key_and_csr('$2', '$3')
    cert_pem, serial = sign_certificate(csr_pem, auto_approve=True)
    
    # Store the private key
    conn = sqlite3.connect('/opt/cert-server/config/certificates.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE certificates SET key_data = ? WHERE serial_number = ?', (key_pem, serial))
    conn.commit()
    conn.close()
    
    print(f"Certificate generated with serial: {serial}")
    print(f"Access via web interface or download directly")
except Exception as e:
    print(f"Error: {e}")
PYTHON_EOF
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|backup|clean-duplicates|generate-cert}"
        exit 1
        ;;
esac
EOF

chmod +x /opt/cert-server/manage.sh
ln -sf /opt/cert-server/manage.sh /usr/local/bin/cert-server
msg_ok "Created Management Scripts"

msg_info "Creating API Client Script"
cat > /opt/cert-server/api-client.sh << 'EOF'
#!/bin/bash

# Certificate Server API Client
# Usage examples:
#   ./api-client.sh submit-csr /path/to/csr.pem
#   ./api-client.sh get-ca-cert
#   ./api-client.sh submit-csr-b64 <base64_encoded_csr>

SERVER_URL="${CERT_SERVER_URL:-https://localhost:8443}"
API_BASE="$SERVER_URL/api"

case "$1" in
    submit-csr)
        if [ -z "$2" ]; then
            echo "Usage: $0 submit-csr <csr_file_path>"
            exit 1
        fi
        
        if [ ! -f "$2" ]; then
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
        if [ -z "$2" ]; then
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
        
    test)
        echo "Testing API endpoints..."
        echo "Getting CA Certificate:"
        curl -k -s "$API_BASE/ca_cert" | jq -r .ca_certificate | head -5
        echo "API test completed"
        ;;
        
    *)
        echo "Certificate Server API Client"
        echo "Usage: $0 {submit-csr|submit-csr-b64|get-ca-cert|test}"
        echo ""
        echo "Environment Variables:"
        echo "  CERT_SERVER_URL - Server URL (default: https://localhost:8443)"
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
msg_ok "Created API Client"

msg_info "Setting up Database and Starting Services"
cd /opt/cert-server/web
source ../venv/bin/activate
python3 -c "from app import init_db; init_db()"

systemctl start cert-server
systemctl start nginx
msg_ok "Started Services"

motd_ssh
customize

msg_info "Cleaning up"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"

# Display setup information
echo -e "\n${GN}Certificate Server Installation Complete!${CL}\n"
echo -e "Web Interface: ${BL}https://$(hostname -I | awk '{print $1}'):$CERT_SERVER_PORT${CL}"
echo -e "Username: ${YW}$WEB_ADMIN_USER${CL}"
echo -e "Password: ${YW}$WEB_ADMIN_PASS${CL}"
echo -e ""
echo -e "Management Commands:"
echo -e "  ${BL}cert-server start${CL}     - Start services"
echo -e "  ${BL}cert-server stop${CL}      - Stop services" 
echo -e "  ${BL}cert-server restart${CL}   - Restart services"
echo -e "  ${BL}cert-server status${CL}    - Check status"
echo -e "  ${BL}cert-server logs${CL}      - View logs"
echo -e "  ${BL}cert-server backup${CL}    - Create backup"
echo -e ""
echo -e "API Endpoints:"
echo -e "  ${BL}POST /api/submit_csr${CL}  - Submit CSR for auto-approval"
echo -e "  ${BL}GET /api/ca_cert${CL}      - Get CA certificate"
echo -e ""
if [[ -n "$VLAN_ID" ]]; then
echo -e "VLAN Configuration:"
echo -e "  ${BL}VLAN ID: $VLAN_ID${CL}"
echo -e "  ${BL}Interface: $VLAN_INTERFACE.$VLAN_ID${CL}"
echo -e ""
fi
echo -e "Features:"
echo -e "  ${GN}✓${CL} Automatic certificate approval via web interface"
echo -e "  ${GN}✓${CL} Base64 CSR import with auto-approval"
echo -e "  ${GN}✓${CL} Private key export for server-generated certificates"
echo -e "  ${GN}✓${CL} Certificate bundle downloads (cert + key)"
echo -e "  ${GN}✓${CL} REST API for programmatic access"
echo -e "  ${GN}✓${CL} VLAN support for network segmentation"
echo -e "  ${GN}✓${CL} Duplicate prevention on manual refresh"', serial=cert[2], file_type='cert') }}" 
                               class="btn btn-primary">
                                <i class="fas fa-download"></i> Download Certificate
                            </a>
                            {% if cert[6] %}
                            <a href="{{ url_for('download_certificate', serial=cert[2], file_type='csr') }}" 
                               class="btn btn-secondary">
                                <i class="fas fa-download"></i> Download CSR
                            </a>
                            {% endif %}
                            {% if cert[8] %}
                            <a href="{{ url_for('download_certificate
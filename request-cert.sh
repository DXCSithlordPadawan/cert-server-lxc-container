#!/usr/bin/env bash

#####################################################################################################################################################################
# Certificate Request Submission Script for Certificate Server
# Author: Generated for Iain Reid's Certificate Server
# Created: 12 Aug 2025
# Tested: 12 Aug 2025
# Purpose: Submit certificate requests to the CA server at defined in the Configuration Section at line 17
# Usage Generate a new certificate with specific SANs: ./request-cert.sh -n "dc1.aip.dxc.com" -s "dc.aip.dxc.com,dc1,dc1.aip" -i "192.168.0.110,100.85.64.116"
# Usage Existing CSR: ./request-cert.sh -f existing.csr
# Usage Vith V3.req: ./request-cert.sh -c v3.req --insecure
# Usage Test connection to server: ./request-cert.sh --test --insecure
# Usage With custom validity period and key size: ./request-cert.sh -n "app.aip.dxc.com" -d 730 -k 4096
# License: MIT
#####################################################################################################################################################################

set -euo pipefail

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CERT_SERVER="${CERT_SERVER:-192.168.0.122}"
CERT_SERVER_PORT="${CERT_SERVER_PORT:-8443}"
CERT_SERVER_URL="https://${CERT_SERVER}:${CERT_SERVER_PORT}"

# API Endpoints (matching create-cert-server-lxc.sh implementation)
API_SUBMIT_CSR="${CERT_SERVER_URL}/api/submit_csr"
API_CA_CERT="${CERT_SERVER_URL}/api/ca_cert"
API_HEALTH="${CERT_SERVER_URL}/health"

# Default values from v3.req
DEFAULT_COUNTRY="GB"
DEFAULT_STATE="Hampshire"
DEFAULT_LOCALITY="Farnborough"
DEFAULT_ORG="DXC Technology"
DEFAULT_OU="EntServ D S"
DEFAULT_CN="cert-server.aip.dxc.com"
DEFAULT_KEY_SIZE="2048"
DEFAULT_DAYS="365"

# Script variables
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OUTPUT_DIR="${SCRIPT_DIR}/certificates"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERBOSE=false
DEBUG=false
USE_EXISTING_CSR=false
CSR_FILE=""
CONFIG_FILE=""
AUTO_APPROVE=true
INSECURE=true  # Default to true for self-signed certificates

# Function definitions
msg_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

msg_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

msg_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

msg_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

msg_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${YELLOW}[DEBUG]${NC} $1"
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Submit certificate requests to Certificate Server at ${CERT_SERVER}:${CERT_SERVER_PORT}

OPTIONS:
    -h, --help              Show this help message
    -c, --config FILE       Use OpenSSL config file (like v3.req)
    -f, --csr FILE          Submit existing CSR file
    -n, --common-name CN    Common Name for the certificate
    -o, --output DIR        Output directory (default: ./certificates)
    -d, --days DAYS         Certificate validity in days (default: 365)
    -k, --key-size SIZE     Key size in bits (default: 2048)
    -s, --san DOMAINS       Additional SANs (comma-separated)
    -i, --san-ip IPS        Additional IP SANs (comma-separated)
    --server HOST           Certificate server hostname/IP
    --port PORT             Certificate server port
    --no-auto-approve       Disable auto-approval
    -v, --verbose           Verbose output
    --debug                 Debug output
    -t, --test              Test connection to server
    --secure                Verify SSL certificate (default: skip for self-signed)

EXAMPLES:
    # Generate and submit new certificate request
    $0 -n "www.example.com" -s "example.com,*.example.com"
    
    # Submit using v3.req config
    $0 -c v3.req
    
    # Submit existing CSR file
    $0 -f existing.csr
    
    # Test connection first
    $0 --test
    
    # Debug connection issues
    $0 --test --debug

EOF
}

test_connection() {
    msg_info "Testing connection to Certificate Server at ${CERT_SERVER_URL}..."
    
    # Build curl options
    local curl_opts="-w \n%{http_code} -o /dev/null"
    if [ "$INSECURE" = true ]; then
        curl_opts="${curl_opts} -k"
        msg_debug "Skipping SSL certificate verification"
    fi
    if [ "$VERBOSE" = true ] || [ "$DEBUG" = true ]; then
        curl_opts="${curl_opts} -v"
    else
        curl_opts="${curl_opts} -s"
    fi
    
    # Test health endpoint
    msg_debug "Testing health endpoint: ${API_HEALTH}"
    local http_code=$(curl ${curl_opts} "${API_HEALTH}" 2>&1 | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        msg_ok "Successfully connected to Certificate Server"
        
        # Get health status
        local curl_opts_json="-s"
        [ "$INSECURE" = true ] && curl_opts_json="${curl_opts_json} -k"
        
        local health=$(curl ${curl_opts_json} "${API_HEALTH}" 2>/dev/null)
        if [ -n "$health" ]; then
            echo -e "${BLUE}Server Status:${NC}"
            echo "$health" | python3 -m json.tool 2>/dev/null || echo "$health"
        fi
        
        # Test CA certificate endpoint
        msg_debug "Testing CA certificate endpoint..."
        local ca_response=$(curl ${curl_opts_json} "${API_CA_CERT}" 2>/dev/null)
        if echo "$ca_response" | grep -q "ca_certificate"; then
            msg_ok "CA certificate endpoint accessible"
        else
            msg_warn "CA certificate endpoint may not be accessible"
        fi
        
    else
        msg_error "Failed to connect to Certificate Server (HTTP code: ${http_code:-none})"
        msg_info "Try running with --debug for more information"
        if [ "$INSECURE" = false ]; then
            msg_info "If using self-signed certificates, the --secure flag is not needed (insecure is default)"
        fi
    fi
}

create_openssl_config() {
    local config_file="$1"
    local cn="${2:-$DEFAULT_CN}"
    local san_dns="${3:-}"
    local san_ip="${4:-}"
    
    msg_debug "Creating OpenSSL config file: $config_file"
    
    cat > "$config_file" << EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
countryName = ${COUNTRY:-$DEFAULT_COUNTRY}
stateOrProvinceName = ${STATE:-$DEFAULT_STATE}
localityName = ${LOCALITY:-$DEFAULT_LOCALITY}
organizationName = ${ORGANIZATION:-$DEFAULT_ORG}
organizationalUnitName = ${OU:-$DEFAULT_OU}
commonName = ${cn}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${cn}
EOF

    # Add additional SANs
    local dns_counter=2
    if [ -n "$san_dns" ]; then
        IFS=',' read -ra SANS <<< "$san_dns"
        for san in "${SANS[@]}"; do
            san=$(echo "$san" | xargs)  # Trim whitespace
            echo "DNS.${dns_counter} = ${san}" >> "$config_file"
            msg_debug "Added DNS.${dns_counter} = ${san}"
            ((dns_counter++))
        done
    fi
    
    # Add IP SANs
    local ip_counter=1
    if [ -n "$san_ip" ]; then
        IFS=',' read -ra IPS <<< "$san_ip"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)  # Trim whitespace
            echo "IP.${ip_counter} = ${ip}" >> "$config_file"
            msg_debug "Added IP.${ip_counter} = ${ip}"
            ((ip_counter++))
        done
    fi
    
    if [ "$DEBUG" = true ]; then
        msg_debug "Config file contents:"
        cat "$config_file"
    fi
}

generate_csr() {
    local key_file="$1"
    local csr_file="$2"
    local config_file="$3"
    
    msg_info "Generating private key (${KEY_SIZE:-$DEFAULT_KEY_SIZE} bits)..."
    openssl genrsa -out "$key_file" ${KEY_SIZE:-$DEFAULT_KEY_SIZE} 2>/dev/null
    
    if [ ! -f "$key_file" ]; then
        msg_error "Failed to generate private key"
    fi
    
    msg_info "Generating Certificate Signing Request..."
    if ! openssl req -new -key "$key_file" -out "$csr_file" -config "$config_file" 2>/dev/null; then
        msg_error "Failed to generate CSR. Check the configuration file."
    fi
    
    if [ ! -f "$csr_file" ]; then
        msg_error "CSR file was not created"
    fi
    
    if [ "$VERBOSE" = true ] || [ "$DEBUG" = true ]; then
        msg_info "CSR Details:"
        openssl req -in "$csr_file" -noout -text | head -30
    fi
    
    msg_ok "CSR generated successfully: $csr_file"
}

submit_csr_to_server() {
    local csr_file="$1"
    local response_file="$2"
    
    if [ ! -f "$csr_file" ]; then
        msg_error "CSR file not found: $csr_file"
    fi
    
    msg_info "Reading CSR from file..."
    local csr_content=$(cat "$csr_file")
    
    if [ -z "$csr_content" ]; then
        msg_error "CSR file is empty"
    fi
    
    msg_debug "CSR content length: $(echo "$csr_content" | wc -c) bytes"
    
    # The server expects the CSR in PEM format directly, not Base64 encoded
    # Based on the server code, it will handle Base64 encoding internally if needed
    
    msg_info "Submitting CSR to Certificate Server..."
    msg_debug "Endpoint: ${API_SUBMIT_CSR}"
    
    # Prepare JSON payload
    local json_payload=$(cat <<EOF
{
    "csr": "${csr_content//$'\n'/\\n}",
    "auto_approve": ${AUTO_APPROVE,,}
}
EOF
)
    
    if [ "$DEBUG" = true ]; then
        msg_debug "JSON payload (first 200 chars):"
        echo "${json_payload:0:200}..."
    fi
    
    # Build curl command
    local curl_opts="-X POST -H \"Content-Type: application/json\""
    if [ "$INSECURE" = true ]; then
        curl_opts="${curl_opts} -k"
    fi
    if [ "$VERBOSE" = true ] || [ "$DEBUG" = true ]; then
        curl_opts="${curl_opts} -v"
    else
        curl_opts="${curl_opts} -s"
    fi
    
    # Submit request
    local response=$(eval "curl ${curl_opts} -d '${json_payload}' '${API_SUBMIT_CSR}'" 2>&1)
    
    echo "$response" > "$response_file"
    
    if [ "$DEBUG" = true ]; then
        msg_debug "Server response:"
        echo "$response"
    fi
    
    # Check response
    if echo "$response" | grep -q '"success":\s*true'; then
        if echo "$response" | grep -q '"status":\s*"approved"'; then
            msg_ok "Certificate request approved!"
        else
            msg_warn "Certificate request submitted, pending approval"
        fi
        return 0
    elif echo "$response" | grep -q '"error"'; then
        local error=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error', 'Unknown error'))" 2>/dev/null || echo "$response")
        msg_error "Server error: $error"
    else
        msg_error "Unexpected response from server. Check $response_file for details."
    fi
}

extract_certificate() {
    local response_file="$1"
    local cert_file="$2"
    
    msg_info "Extracting certificate from response..."
    
    # Try to extract certificate from JSON response
    if python3 << EOF
import json
try:
    with open('$response_file', 'r') as f:
        data = json.load(f)
        cert = data.get('certificate', '')
        if cert:
            with open('$cert_file', 'w') as cf:
                cf.write(cert)
            exit(0)
except:
    pass
exit(1)
EOF
    then
        if [ -s "$cert_file" ]; then
            msg_ok "Certificate saved to: $cert_file"
            
            if [ "$VERBOSE" = true ]; then
                msg_info "Certificate details:"
                openssl x509 -in "$cert_file" -noout -subject -dates
            fi
            return 0
        fi
    fi
    
    msg_warn "Could not extract certificate from response"
    return 1
}

download_ca_certificate() {
    local ca_cert_file="$1"
    
    msg_info "Downloading CA certificate..."
    
    local curl_opts="-s"
    if [ "$INSECURE" = true ]; then
        curl_opts="${curl_opts} -k"
    fi
    
    local response=$(curl ${curl_opts} "${API_CA_CERT}" 2>/dev/null)
    
    if python3 << EOF
import json
try:
    data = json.loads('''$response''')
    ca_cert = data.get('ca_certificate', '')
    if ca_cert:
        with open('$ca_cert_file', 'w') as f:
            f.write(ca_cert)
        exit(0)
except:
    pass
exit(1)
EOF
    then
        if [ -s "$ca_cert_file" ]; then
            msg_ok "CA certificate saved to: $ca_cert_file"
            return 0
        fi
    fi
    
    msg_warn "Could not download CA certificate"
    return 1
}

create_bundle() {
    local key_file="$1"
    local cert_file="$2"
    local ca_cert_file="$3"
    local bundle_file="$4"
    
    msg_info "Creating certificate bundle..."
    
    # Create PEM bundle
    cat "$cert_file" > "$bundle_file"
    [ -f "$ca_cert_file" ] && cat "$ca_cert_file" >> "$bundle_file"
    cat "$key_file" >> "$bundle_file"
    
    msg_ok "Bundle created: $bundle_file"
}

process_v3_req_config() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        msg_error "Configuration file not found: $config_file"
    fi
    
    msg_info "Processing v3.req configuration file..."
    msg_debug "Config file: $config_file"
    
    # Use the config file directly for OpenSSL
    # The file already has the correct format
    cp "$config_file" "${OUTPUT_DIR}/config_${TIMESTAMP}.cnf"
    
    msg_ok "Configuration file prepared"
}

# Main function
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -f|--csr)
                USE_EXISTING_CSR=true
                CSR_FILE="$2"
                shift 2
                ;;
            -n|--common-name)
                COMMON_NAME="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--days)
                DAYS="$2"
                shift 2
                ;;
            -k|--key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            -s|--san)
                SAN_DNS="$2"
                shift 2
                ;;
            -i|--san-ip)
                SAN_IP="$2"
                shift 2
                ;;
            --server)
                CERT_SERVER="$2"
                CERT_SERVER_URL="https://${CERT_SERVER}:${CERT_SERVER_PORT}"
                API_SUBMIT_CSR="${CERT_SERVER_URL}/api/submit_csr"
                API_CA_CERT="${CERT_SERVER_URL}/api/ca_cert"
                API_HEALTH="${CERT_SERVER_URL}/health"
                shift 2
                ;;
            --port)
                CERT_SERVER_PORT="$2"
                CERT_SERVER_URL="https://${CERT_SERVER}:${CERT_SERVER_PORT}"
                API_SUBMIT_CSR="${CERT_SERVER_URL}/api/submit_csr"
                API_CA_CERT="${CERT_SERVER_URL}/api/ca_cert"
                API_HEALTH="${CERT_SERVER_URL}/health"
                shift 2
                ;;
            --no-auto-approve)
                AUTO_APPROVE=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --debug)
                DEBUG=true
                VERBOSE=true
                shift
                ;;
            -t|--test)
                test_connection
                exit 0
                ;;
            --secure)
                INSECURE=false
                shift
                ;;
            *)
                msg_error "Unknown option: $1"
                ;;
        esac
    done
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Process based on input method
    if [ "$USE_EXISTING_CSR" = true ]; then
        # Submit existing CSR
        if [ ! -f "$CSR_FILE" ]; then
            msg_error "CSR file not found: $CSR_FILE"
        fi
        
        msg_info "Using existing CSR: $CSR_FILE"
        local response_file="${OUTPUT_DIR}/response_${TIMESTAMP}.json"
        local cert_file="${OUTPUT_DIR}/certificate_${TIMESTAMP}.pem"
        
        submit_csr_to_server "$CSR_FILE" "$response_file"
        extract_certificate "$response_file" "$cert_file"
        
    elif [ -n "$CONFIG_FILE" ]; then
        # Process v3.req style config
        process_v3_req_config "$CONFIG_FILE"
        
        local key_file="${OUTPUT_DIR}/private_key_${TIMESTAMP}.pem"
        local csr_file="${OUTPUT_DIR}/request_${TIMESTAMP}.csr"
        local config_file="${OUTPUT_DIR}/config_${TIMESTAMP}.cnf"
        local response_file="${OUTPUT_DIR}/response_${TIMESTAMP}.json"
        local cert_file="${OUTPUT_DIR}/certificate_${TIMESTAMP}.pem"
        local ca_cert_file="${OUTPUT_DIR}/ca_certificate.pem"
        local bundle_file="${OUTPUT_DIR}/bundle_${TIMESTAMP}.pem"
        
        # Generate CSR using the config file
        generate_csr "$key_file" "$csr_file" "$CONFIG_FILE"
        submit_csr_to_server "$csr_file" "$response_file"
        
        if extract_certificate "$response_file" "$cert_file"; then
            download_ca_certificate "$ca_cert_file"
            create_bundle "$key_file" "$cert_file" "$ca_cert_file" "$bundle_file"
        fi
        
    else
        # Generate new certificate request
        if [ -z "${COMMON_NAME:-}" ]; then
            msg_error "Common Name required. Use -n option or -c for config file"
        fi
        
        local key_file="${OUTPUT_DIR}/private_key_${TIMESTAMP}.pem"
        local csr_file="${OUTPUT_DIR}/request_${TIMESTAMP}.csr"
        local config_file="${OUTPUT_DIR}/config_${TIMESTAMP}.cnf"
        local response_file="${OUTPUT_DIR}/response_${TIMESTAMP}.json"
        local cert_file="${OUTPUT_DIR}/certificate_${TIMESTAMP}.pem"
        local ca_cert_file="${OUTPUT_DIR}/ca_certificate.pem"
        local bundle_file="${OUTPUT_DIR}/bundle_${TIMESTAMP}.pem"
        
        create_openssl_config "$config_file" "$COMMON_NAME" "${SAN_DNS:-}" "${SAN_IP:-}"
        generate_csr "$key_file" "$csr_file" "$config_file"
        submit_csr_to_server "$csr_file" "$response_file"
        
        if extract_certificate "$response_file" "$cert_file"; then
            download_ca_certificate "$ca_cert_file"
            create_bundle "$key_file" "$cert_file" "$ca_cert_file" "$bundle_file"
        fi
    fi
    
    # Summary
    echo ""
    msg_ok "Certificate request process completed!"
    echo -e "${BLUE}Output files in: ${OUTPUT_DIR}${NC}"
    ls -la "$OUTPUT_DIR"/*_${TIMESTAMP}* 2>/dev/null || true
}

# Check dependencies
check_dependencies() {
    local deps=("openssl" "curl" "python3")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            msg_error "Required dependency not found: $dep"
        fi
    done
}

# Run main
check_dependencies

# Show current configuration if debug
if [ "$DEBUG" = true ]; then
    msg_debug "Configuration:"
    msg_debug "  Server: ${CERT_SERVER}"
    msg_debug "  Port: ${CERT_SERVER_PORT}"
    msg_debug "  URL: ${CERT_SERVER_URL}"
    msg_debug "  Insecure: ${INSECURE}"
fi

main "$@"
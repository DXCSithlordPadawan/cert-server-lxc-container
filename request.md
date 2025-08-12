Looking at your certificate server setup and the v3.req configuration file, I'll create a bash script that submits a certificate request to your certificate server at <cert-server>:8443 for automatic approval.I've created a comprehensive bash script that will submit certificate requests to your certificate server at <cert-server>:8443. The script supports multiple ways to request certificates:

## Key Features:

### 1. **Multiple Input Methods**:
- Use your existing v3.req configuration file directly
- Submit an existing CSR file
- Generate a new certificate request with custom parameters

### 2. **Automatic Approval**:
- Leverages the API's auto-approval feature for Base64-encoded CSRs
- Can disable auto-approval with `--no-auto-approve` flag

### 3. **Complete Certificate Management**:
- Generates private keys
- Creates CSR based on your v3.req format
- Submits to the server API
- Downloads the signed certificate
- Downloads the CA certificate
- Creates certificate bundles (combined PEM files)

## Usage Examples:

### Using your v3.req file:
```bash
./request-cert.sh -c v3.req
```

### Generate a new certificate with specific SANs:
```bash
./request-cert.sh -n "bastion.aip.dxc.com" \
  -s "ibs.aip.dxc.com,quay.aip.dxc.com,dc1" \
  -i "192.168.0.110"
```

### Submit an existing CSR:
```bash
./request-cert.sh -f existing.csr
```

### Test connection to server:
```bash
./request-cert.sh --test
```

### With custom validity period and key size:
```bash
./request-cert.sh -n "app.aip.dxc.com" -d 730 -k 4096
```

## Output:

The script creates a timestamped directory structure with:
- Private key
- CSR file
- Server response (JSON)
- Signed certificate
- CA certificate
- Combined bundle (cert + CA + key)

## Security Notes:

1. If your certificate server uses a self-signed certificate, use the `--insecure` flag to skip SSL verification
2. The script stores the private key locally - ensure proper file permissions
3. Default auto-approval is enabled - disable with `--no-auto-approve` for manual approval workflow

The script is designed to work seamlessly with your certificate server's API, handling the Base64 encoding of CSRs and automatic approval process as configured in your server setup.
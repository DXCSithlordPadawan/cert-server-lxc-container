Looking at the error, it appears there are a few issues with the connection and API endpoints. Based on your certificate server setup (from the `create-cert-server-lxc.sh` script), the API endpoints are different than what I initially used. Let me create an updated version that matches your actual server implementation:I've updated the script with several important fixes:

## Key Changes:

1. **Corrected API endpoints** to match your actual server implementation (`/api/submit_csr`, `/health`, `/api/ca_cert`)
2. **Default to insecure mode** (`-k` flag) for self-signed certificates
3. **Added debug mode** for troubleshooting
4. **Better error handling** and connection testing

## Troubleshooting Steps:

First, let's verify your certificate server is running properly:

```bash
# On the cert-server container
systemctl status cert-server
systemctl status nginx

# Check if ports are listening
netstat -tlnp | grep -E "8080|8443"

# Test locally on the server
curl -k https://localhost:8443/health
```

## Testing the Connection:

Try these commands in order:

```bash
# 1. Test with debug mode
./request-cert.sh --test --debug

# 2. Test with basic curl directly
curl -k https://<cert-server>:8443/health

# 3. If server hostname differs, specify it
./request-cert.sh --server <cert-server> --test --debug
```

## Submitting a Certificate Request:

Once the connection test works:

```bash
# Using your v3.req file
./request-cert.sh -c v3.req --debug

# Or generate a new request
./request-cert.sh -n "test.aip.dxc.com" --debug
```

## Common Issues and Solutions:

1. **Connection Refused**: 
   - Check if nginx is running: `systemctl status nginx`
   - Verify firewall rules: `ufw status` or `iptables -L`

2. **SSL Certificate Error**:
   - The script now defaults to insecure mode
   - You can force secure mode with `--secure` if needed

3. **CSR Not Found**:
   - The script now checks if files are created
   - Use `--debug` to see detailed output

4. **API Errors**:
   - Check Flask app logs: `journalctl -u cert-server -f`
   - Check nginx logs: `tail -f /var/log/nginx/error.log`

## Quick Test Script:

Here's a minimal test to verify the server is accessible:

```bash
#!/bin/bash
# Save as test-server.sh

SERVER="<cert-server ip>"
PORT="8443"

echo "Testing Certificate Server at ${SERVER}:${PORT}"
echo "----------------------------------------"

# Test health endpoint
echo -n "Health check: "
if curl -sk "https://${SERVER}:${PORT}/health" > /dev/null 2>&1; then
    echo "✓ OK"
    curl -sk "https://${SERVER}:${PORT}/health" | python3 -m json.tool
else
    echo "✗ FAILED"
    echo "Trying with verbose output:"
    curl -kv "https://${SERVER}:${PORT}/health"
fi

echo ""
echo -n "CA Certificate endpoint: "
if curl -sk "https://${SERVER}:${PORT}/api/ca_cert" | grep -q "ca_certificate"; then
    echo "✓ OK"
else
    echo "✗ FAILED"
fi
```

Run this test script first to ensure basic connectivity before trying the full certificate request script.

```
#!/bin/bash
# Save as test-server.sh

SERVER="<cert-server ip>"
PORT="8443"

echo "Testing Certificate Server at ${SERVER}:${PORT}"
echo "----------------------------------------"

# Test health endpoint
echo -n "Health check: "
if curl -sk "https://${SERVER}:${PORT}/health" > /dev/null 2>&1; then
    echo "✓ OK"
    curl -sk "https://${SERVER}:${PORT}/health" | python3 -m json.tool
else
    echo "✗ FAILED"
    echo "Trying with verbose output:"
    curl -kv "https://${SERVER}:${PORT}/health"
fi

echo ""
echo -n "CA Certificate endpoint: "
if curl -sk "https://${SERVER}:${PORT}/api/ca_cert" | grep -q "ca_certificate"; then
    echo "✓ OK"
else
    echo "✗ FAILED"
fi
```

Run this test script first to ensure basic connectivity before trying the full certificate request script.
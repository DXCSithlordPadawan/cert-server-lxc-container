# cert-server-lxc-container
Certificate Server on a Proxmox LXC Container

## 📋 **Complete Script Set**

### 1. **Enhanced Certificate Server Installation Script** 
- Includes all certificate server functionality with modern enhancements
- Full VLAN support for network segmentation

### 2. **Advanced Configuration Script**
- Post-installation configuration and fine-tuning
- Health monitoring and automated backup setup
- Enhanced security configurations

### 3. **Complete Deployment Script**
- All-in-one installation and configuration
- Interactive prompts and comprehensive error handling
- Production-ready deployment

## 🚀 **Key Features Implemented**

### ✅ **Your Requested Enhancements:**
- **Automatic certificate approval** via web interface
- **Base64 CSR import** with auto-approval capability
- **Private key export** for server-generated certificates
- **Certificate bundle downloads** (cert + key in one file)
- **Duplicate prevention** - stops certificate creation on manual refresh
- **VLAN support** for network segmentation

### ✅ **Additional Production Features:**
- **REST API** with comprehensive documentation
- **Health monitoring** with automated checks every 5 minutes
- **Automated daily backups** with retention management
- **UFW firewall** protection with minimal required ports
- **Rate limiting** on API and web endpoints
- **Security headers** and modern TLS configuration
- **Comprehensive management tools** via CLI

## 🛠️ **Installation & Usage**

### Quick Start:
```bash
# Basic installation
./cert-server-deploy.sh

# With VLAN configuration
./cert-server-deploy.sh --vlan-id 100 --vlan-interface eth0 --vlan-ip 192.168.100.10

# Custom admin credentials
./cert-server-deploy.sh --admin-user certadmin --admin-pass mypassword
```

### Management:
```bash
cert-server start|stop|restart|status
cert-server health              # Comprehensive health check
cert-server backup              # Manual backup
cert-server generate-cert example.com "My Org"
```

### API Usage:
```bash
# Get CA certificate
curl -k https://your-server:8443/api/ca_cert

# Submit CSR for auto-approval
curl -k -X POST https://your-server:8443/api/submit_csr \
  -H "Content-Type: application/json" \
  -d '{"csr": "your_csr_here", "auto_approve": true}'
```

## 🔒 **Security Features**

- **Modern TLS** with TLS 1.2/1.3 only
- **Rate limiting** to prevent abuse
- **Security headers** (HSTS, X-Frame-Options, etc.)
- **UFW firewall** with minimal attack surface
- **Random admin passwords** generated at installation
- **Request tracking** to prevent duplicates

## 📊 **Monitoring & Maintenance**

- **Automated health checks** every 5 minutes
- **Daily backups** with configurable retention
- **Comprehensive logging** with logrotate integration
- **Real-time status monitoring**
- **Disk space and service monitoring**

The scripts follow the tteck methodology you referenced, with proper error handling, colored output, and container-friendly installation. They're production-ready and include all the enhanced features you requested, plus additional enterprise-grade capabilities for reliability and security.

Would you like me to explain any specific part of the implementation or add any additional features?

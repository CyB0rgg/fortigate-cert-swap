# FortiGate Certificate Swap

**High-performance Go binary for automated FortiGate certificate management with revolutionary automatic intermediate CA handling.**

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/CyB0rgg/fortigate-cert-swap)](https://github.com/CyB0rgg/fortigate-cert-swap/releases)

## 🚀 Features

- **🔥 Ultra-Fast Performance**: 0.026s startup time (13.4x faster than Python)
- **📦 Zero Dependencies**: Single native binary, no runtime requirements
- **🔗 Automatic Intermediate CA Management**: World's first solution to FortiGate's certificate chain limitation
- **🎯 Multi-Service Binding**: GUI, SSL-VPN, FTM, and SSL inspection support
- **🛡️ Production Ready**: Comprehensive error handling and validation
- **🌐 Cross-Platform**: Native binaries for Linux, macOS, Windows
- **⚡ Lightning Builds**: 30-second compilation vs 5+ minutes for alternatives

## 🛠️ Installation

### Pre-built Binaries (Recommended)

```bash
# Linux x64
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-linux-amd64
chmod +x fortigate-cert-swap-linux-amd64
sudo mv fortigate-cert-swap-linux-amd64 /usr/local/bin/fortigate-cert-swap

# Linux ARM64
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-linux-arm64
chmod +x fortigate-cert-swap-linux-arm64
sudo mv fortigate-cert-swap-linux-arm64 /usr/local/bin/fortigate-cert-swap

# macOS ARM64 (M1/M2/M3/M4)
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-darwin-arm64
chmod +x fortigate-cert-swap-darwin-arm64
sudo mv fortigate-cert-swap-darwin-arm64 /usr/local/bin/fortigate-cert-swap

# macOS Intel
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-darwin-amd64
chmod +x fortigate-cert-swap-darwin-amd64
sudo mv fortigate-cert-swap-darwin-amd64 /usr/local/bin/fortigate-cert-swap

# Windows x64
# Download fortigate-cert-swap-windows-amd64.exe from releases
```

### Build from Source

```bash
git clone https://github.com/CyB0rgg/fortigate-cert-swap.git
cd fortigate-cert-swap
go build -ldflags="-s -w" -o fortigate-cert-swap main.go
```

## 🎯 Quick Start

```bash
# Check version
fortigate-cert-swap --version

# Standard mode - GUI/SSL-VPN/FTM binding with automatic intermediate CA management
fortigate-cert-swap --config fortigate.yaml --cert /path/to/cert.pem --key /path/to/key.pem

# Certificate-only mode - SSL inspection certificates
fortigate-cert-swap --cert-only --cert /path/to/cert.pem --key /path/to/key.pem --config fortigate.yaml

# SSL inspection certificate mode - automated profile rebinding
fortigate-cert-swap --ssl-inspection-cert --cert /path/to/cert.pem --key /path/to/key.pem --config fortigate.yaml
```

## 🔗 Revolutionary: Automatic Intermediate CA Management

### The Problem FortiGate Has
- **Incomplete Certificate Chains**: FortiGate presents certificates without intermediate CAs
- **SSL Labs Warnings**: Missing intermediate certificate warnings
- **Validation Failures**: curl requires `--insecure` flag due to incomplete chains
- **Manual Uploads**: Administrators must manually upload intermediate CAs

### Our Solution
- ✅ **Automatic Detection**: Extracts intermediate CAs from certificate chains
- ✅ **Smart Upload**: Only uploads missing intermediate CAs to avoid duplicates  
- ✅ **Complete Chains**: Ensures SSL Labs and curl validation without `--insecure`
- ✅ **Zero Configuration**: Works automatically with full certificate chains

```bash
# Console output shows automatic intermediate CA processing:
# [*] Certificate chain analysis: Found 1 intermediate CA to process
# [*] Intermediate CA 'R11' not found in FortiGate CA store
# [*] Successfully uploaded intermediate CA certificate 'R11' to FortiGate CA store
# [*] Complete certificate chain validation: curl test successful without --insecure
```

## 📋 Usage Examples

### Standard Certificate Deployment
```bash
# Deploy certificate with GUI/SSL-VPN/FTM binding
fortigate-cert-swap --host fortigate.example.com --port 443 --token YOUR_TOKEN \
  --cert /path/to/fullchain.pem --key /path/to/private.key
```

### SSL Inspection Certificates
```bash
# Deploy SSL inspection certificate with automatic profile rebinding
fortigate-cert-swap --ssl-inspection-cert \
  --cert /path/to/fullchain.pem --key /path/to/private.key \
  --host fortigate.example.com --port 443 --token YOUR_TOKEN --prune
```

### Configuration File Usage
```bash
# Use YAML configuration file
fortigate-cert-swap --config fortigate.yaml --cert /path/to/cert.pem --key /path/to/key.pem
```

**Example `fortigate.yaml`:**
```yaml
host: fortigate.example.com
port: 443
token: "your-api-token"
insecure: false
auto_intermediate_ca: true
timeout_connect: 5
timeout_read: 30
```

### Service Rebinding Only
```bash
# Rebind existing certificate to services without uploading new certificate
fortigate-cert-swap --rebind gui,sslvpn,ftm --config fortigate.yaml
```

## 🔧 Command Line Options

```
USAGE:
  fortigate-cert-swap [OPTIONS]

DESCRIPTION:
  Automated FortiGate certificate deployment with revolutionary intermediate CA management.
  Supports multiple operation modes: standard binding, certificate-only upload,
  SSL inspection certificate deployment, and custom service rebinding.

REQUIRED OPTIONS:
  --host HOST                FortiGate host/IP address
  --token TOKEN              FortiGate API token
  --cert CERT_FILE           Path to certificate file (PEM format)
  --key KEY_FILE             Path to private key file (PEM format)

OPTIONAL ARGUMENTS:
  --config CONFIG_FILE       Path to YAML configuration file
  --port PORT                FortiGate HTTPS port (default: 443)
  --name NAME                Certificate name override
  --vdom VDOM                VDOM name (default: global)
  --insecure                 Skip TLS certificate verification
  --dry-run                  Show what would be done without making changes
  --prune                    Remove unused certificates
  --timeout-connect SEC      Connection timeout (default: 5)
  --timeout-read SEC         Read timeout (default: 30)
  --log LOG_FILE             Log file path
  --log-level LEVEL          Log level: standard|debug (default: standard)
  --rebind SERVICES          Rebind services: gui,sslvpn,ftm (default: all)
  --cert-only                Upload certificate only, no binding
  --ssl-inspection-cert      SSL inspection certificate mode
  --auto-intermediate-ca     Automatic intermediate CA management (default: true)
  --version                  Show version information
  --help                     Show this help message

OPERATION MODES:
  [*] Standard               Standard mode: Upload certificate and bind to GUI/SSL-VPN/FTM
  [*] Cert-only              Certificate-only: Upload certificate without service binding
  [*] SSL Inspection         SSL inspection: Deploy certificate for SSL inspection profiles
  [*] Rebind                 Custom rebind: Bind certificate to specific services only

REVOLUTIONARY FEATURES:
  [*] Auto CA Management     World's first automatic intermediate CA management
  [*] Chain Processing       Intelligent certificate chain processing
  [*] Smart SSL Rebinding    Domain-aware SSL inspection profile rebinding
  [*] Safe Pruning           Enhanced certificate pruning with safety checks
```

## 🔒 FortiGate API Setup

Before using the tool, create a FortiGate REST API user with appropriate permissions.

### Quick Setup (Testing)
1. **System** → **Administrators** → **Create New** → **REST API Admin**
2. **Name**: `cert-swap-api`
3. **Admin Profile**: `prof_admin` (full access)
4. **Trusted Hosts**: Configure allowed source IPs
5. **Generate Token**: Copy the token immediately (shown only once)

### Production Setup (Minimal Permissions)
Create a custom admin profile with only required permissions using the FortiGate CLI:

```bash
# Create custom admin profile with minimal required permissions
config system accprofile
    edit "REST_API_ADMIN"
        set sysgrp custom
        set fwgrp custom
        set vpngrp read-write
        config sysgrp-permission
            set cfg read-write
        end
        config fwgrp-permission
            set others read-write
        end
    next
end

# Create API user with the custom profile
config system api-user
    edit "auto-cert-updater"
        set api-key <auto-generated-via-gui>
        set accprofile "REST_API_ADMIN"
    next
end
```

**Required API Endpoints:**
- `vpn.certificate/local` - Upload, update, and manage local certificates
- `vpn.certificate/ca` - Upload and manage CA certificates (for intermediate CA management)
- `system/global` - Bind certificates to GUI admin interface
- `vpn.ssl/settings` - Bind certificates to SSL-VPN
- `system/ftm-push` - Bind certificates to FTM push notifications
- `firewall/ssl-ssh-profile` - Manage SSL inspection profiles (if using SSL inspection)

**Note:** The API key must be generated through the GUI after creating the user via CLI.

**See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed API setup instructions.**

## 🚀 Performance Comparison

| Metric | Go Binary | Python Original |
|--------|-----------|-----------------|
| **Startup Time** | 0.026s | 0.348s |
| **Binary Size** | 6.5MB | 2.1MB (script) |
| **Build Time** | 30s | N/A |
| **Dependencies** | Zero | Python + libraries |
| **Performance** | **13.4x faster** | Baseline |

## 🔄 ACME.sh Integration

Perfect for automated certificate renewal with ACME.sh deploy hooks:

```bash
#!/bin/bash
# /etc/acme.sh/deploy/fortigate.sh

fortigate-cert-swap \
  --cert "$CERT_PATH" \
  --key "$KEY_PATH" \
  --host "$FORTI_HOST" \
  --port "$FORTI_PORT" \
  --token "$FORTI_TOKEN"
```

## 📊 SSL Inspection Features

- **Domain-based Discovery**: Automatically finds SSL inspection profiles by certificate domain
- **Multi-profile Support**: Handles multiple profiles using the same certificate
- **Automatic Rebinding**: Transfers profiles from old to new certificates
- **Standard Naming**: Uses domain-expiry format (e.g., `example.com-20251114`)
- **Optional Pruning**: Deletes old certificates after successful rebinding

## 🛡️ Security Features

- **Secure Token Handling**: API tokens never logged or exposed
- **TLS Verification**: Full certificate chain validation by default
- **Minimal Permissions**: Works with restricted API user accounts
- **Audit Trail**: Comprehensive logging of all operations
- **Dry-run Mode**: Test operations without making changes

## 📚 Documentation

- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Complete production deployment guide
- **[examples/](examples/)** - Configuration file examples
- **[RELEASE_NOTES.md](RELEASE_NOTES.md)** - Version history and changes

## 🧪 Testing

```bash
# Test with dry-run mode
fortigate-cert-swap --dry-run --config fortigate.yaml --cert test.pem --key test.key

# Expected output:
# [*] Loading certificate and key files...
# [*] Certificate chain summary:
#     [leaf] example.com - expires 2025-11-12 (87 days)
#     [ca-1] Let's Encrypt Authority X3 - expires 2030-01-29 (1626 days)
# [*] Effective configuration:
#     host: fortigate.example.com
#     port: 443
#     vdom: GLOBAL
#     insecure: false
#     dry_run: true
#     prune: false
#     timeout_connect: 5s
#     timeout_read: 30s
# [*] Planned certificate name: example.com-20251112
# [*] Planned intermediate CA: Lets-Encrypt-Authority-X3 (CN: Let's Encrypt Authority X3)
# [*] Target store: GLOBAL
# [*] Processing automatic intermediate CA management...
# [*] Intermediate CA already exists: Lets-Encrypt-Authority-X3 (installed by user)
# [*] Uploading certificate: example.com-20251112
# DRY RUN: would POST vpn.certificate/local name=example.com-20251112 store=GLOBAL
# [*] Standard mode: binding certificate to services
# ✓ Successfully bound certificate to gui
# ✓ Successfully bound certificate to sslvpn
# ✓ Successfully bound certificate to ftm
# ✓ Operation completed successfully
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/CyB0rgg/fortigate-cert-swap/issues)
- **Documentation**: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Examples**: [examples/](examples/) directory

---

**Copyright (c) 2025 CyB0rgg <dev@bluco.re>**
**Licensed under the MIT License**
**Built with ❤️ in Go for maximum performance and reliability.**

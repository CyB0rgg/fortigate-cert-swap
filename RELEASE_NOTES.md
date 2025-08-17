# Release Notes - v2.0.0

## 🚀 Complete Go Rewrite with 13.4x Performance Improvement

This release completely rewrites the FortiGate Certificate Swap tool in Go, delivering dramatic performance improvements while maintaining 100% functional parity with the Python implementation.

### ⚡ Performance Improvements

- **13.4x Faster Startup**: 0.026s vs 0.348s (Python)
- **Native Binary**: Single 6.5MB executable with zero dependencies
- **Cross-Platform**: Linux (x64/ARM64), macOS (Intel/M1/M2/M3/M4), Windows (x64)
- **Instant Deployment**: No Python installation required

### 🔧 Technical Changes

#### **New Binary Distribution**
```bash
# Available binaries:
fortigate-cert-swap-linux-amd64      # Linux x86_64
fortigate-cert-swap-linux-arm64      # Linux ARM64
fortigate-cert-swap-darwin-amd64     # macOS Intel
fortigate-cert-swap-darwin-arm64     # macOS Apple Silicon (M1/M2/M3/M4)
fortigate-cert-swap-windows-amd64.exe # Windows x64
```

#### **Command Line Changes**
- **Removed**: `-C` short flag (use `--config` instead)
- **Renamed**: `--ssl-inspection-certificate` → `--ssl-inspection-cert`
- **All other flags**: Unchanged

#### **Updated Help Format**
```
USAGE:
  fortigate-cert-swap [OPTIONS]

REQUIRED OPTIONS:
  --host HOST                FortiGate host/IP address
  --token TOKEN              FortiGate API token
  --cert CERT_FILE           Path to certificate file (PEM format)
  --key KEY_FILE             Path to private key file (PEM format)

OPERATION MODES:
  [*] Standard               Standard mode: Upload certificate and bind to GUI/SSL-VPN/FTM
  [*] Cert-only              Certificate-only: Upload certificate without service binding
  [*] SSL Inspection         SSL inspection: Deploy certificate for SSL inspection profiles
  [*] Rebind                 Custom rebind: Bind certificate to specific services only
```

### 📦 Installation

#### **Binary Installation (Recommended)**
```bash
# Linux x64
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-linux-amd64
chmod +x fortigate-cert-swap-linux-amd64
sudo mv fortigate-cert-swap-linux-amd64 /usr/local/bin/fortigate-cert-swap

# macOS ARM64 (M1/M2/M3/M4)
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest/download/fortigate-cert-swap-darwin-arm64
chmod +x fortigate-cert-swap-darwin-arm64
sudo mv fortigate-cert-swap-darwin-arm64 /usr/local/bin/fortigate-cert-swap
```

#### **Build from Source**
```bash
git clone https://github.com/CyB0rgg/fortigate-cert-swap.git
cd fortigate-cert-swap
go build -ldflags="-s -w" -o fortigate-cert-swap main.go
```

### 🔄 Migration Guide

#### **Update Commands**
```bash
# OLD (Python)
python3 forti_cert_swap.py -C config.yaml --cert cert.pem --key key.pem

# NEW (Go)
fortigate-cert-swap --config config.yaml --cert cert.pem --key key.pem
```

#### **Update Scripts**
- Replace `python3 forti_cert_swap.py` with `fortigate-cert-swap`
- Change `-C` to `--config`
- Change `--ssl-inspection-certificate` to `--ssl-inspection-cert`
- All YAML configuration files work unchanged

### ✅ Preserved Features

- **100% Functional Parity**: All Python features preserved
- **Automatic Intermediate CA Management**: World's first FortiGate certificate chain solution
- **All Operation Modes**: Standard, cert-only, SSL inspection, custom rebinding
- **Configuration Files**: All existing YAML configs work unchanged
- **Environment Variables**: Complete environment variable support
- **JSON Output**: Identical output format
- **Console Messages**: 100% parity with Python version

### 🧪 Testing

```bash
# Test with dry-run mode
fortigate-cert-swap --dry-run --config fortigate.yaml --cert test.pem --key test.key

# Expected output:
# [*] DRY RUN: would POST vpn.certificate/local name=test-cert store=GLOBAL
# [*] DRY RUN: would PUT system/global
# [*] DRY RUN: would PUT vpn.ssl/settings
# [*] DRY RUN: would PUT system/ftm-push
```

### ⚠️ Breaking Changes

- **Command Line**: Minor flag changes (see migration guide)
- **Binary Name**: Changed from `forti_cert_swap.py` to `fortigate-cert-swap`
- **Dependencies**: Python no longer required

### 📋 Requirements

- **None**: Single native binary with zero dependencies
- **Supported Platforms**: Linux, macOS, Windows
- **FortiGate API**: Same API requirements as Python version

---

**Copyright (c) 2025 CyB0rgg <dev@bluco.re>**  
**Licensed under the MIT License**
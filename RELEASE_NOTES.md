# Release Notes - v1.10.0

## 🎉 Major Release: SSL Inspection Certificate Management

This is a significant release that adds comprehensive SSL inspection certificate management capabilities to the FortiGate Certificate Swap utility, enabling automated certificate renewal workflows for SSL inspection scenarios.

### 🚀 Key Highlights

- **Two new SSL inspection certificate modes** for different use cases
- **Automated SSL inspection profile rebinding** with domain-based discovery
- **FortiGate duplicate content limitation handling** with comprehensive workarounds
- **Production-tested SSL inspection workflows** with real FortiGate configurations
- **Comprehensive documentation** of limitations and best practices

### ✨ New Features

#### 🔒 Certificate-Only Mode (`--cert-only`)
- **Simple Certificate Upload**: Upload/update certificates without any service bindings
- **Perfect for SSL Inspection**: Designed specifically for SSL inspection certificate scenarios
- **No Service Disruption**: Updates certificates without affecting GUI, SSL-VPN, or FTM bindings

#### 🎯 SSL Inspection Certificate Mode (`--ssl-inspection-certificate`)
- **Automated SSL Inspection Workflow**: Complete certificate renewal with automatic profile rebinding
- **Domain-Based Discovery**: Finds SSL inspection profiles by matching certificate domains
- **Multi-Profile Support**: Handles multiple SSL inspection profiles using the same certificate
- **Standard Naming**: Uses domain-expiry date naming scheme (e.g., `kiroshi.group-20251114`)
- **Optional Pruning**: Delete old SSL inspection certificates after successful rebinding

#### 🧠 Advanced SSL Inspection Features
- **Hybrid Domain Matching**: Text-based extraction + certificate parsing fallback
- **Profile Discovery**: Maps certificates to SSL inspection profiles across firewall/ssl-ssh-profile configurations
- **Automatic Rebinding**: Seamlessly transfers SSL inspection profiles from old to new certificates
- **Case-Insensitive Matching**: Handles domain variations (`BluCore.io` matches `kiroshi.group`)

### 🔧 Technical Improvements

#### Enhanced Certificate Operations
- **SSL Inspection Profile Mapping**: Complete discovery of certificate-to-profile relationships
- **Domain Extraction Logic**: Robust extraction from certificate names, CN, and SAN fields
- **Certificate Content Validation**: Prevents FortiGate duplicate content conflicts
- **Mutually Exclusive Modes**: Proper argument validation prevents conflicting operations

#### Improved Error Handling
- **FortiGate Limitation Awareness**: Handles duplicate certificate content restrictions
- **Detailed Logging**: Enhanced logging for SSL inspection operations
- **Recovery Guidance**: Clear error messages with actionable solutions

### 🐛 Critical Fixes

#### Certificate Naming Issue Resolution
- **Root Cause**: Using `--name` parameter overrode automatic expiry-based naming
- **Impact**: Caused FortiGate duplicate content errors during testing
- **Solution**: Documented proper usage patterns and automatic naming behavior
- **Workaround**: Always use fresh certificate content for SSL inspection renewals

#### Mode Clarification
- **`--rebind` Mode**: Now clearly documented to only affect GUI/SSL-VPN/FTM services
- **SSL Inspection Separation**: SSL inspection profiles require dedicated `--ssl-inspection-certificate` mode

### ⚠️ Important Limitations & Workarounds

#### FortiGate Certificate Duplicate Content Limitation
**Limitation**: FortiGate prevents uploading certificates with identical content but different names.

**Workarounds**:
- **For `--ssl-inspection-certificate`**: Always use fresh certificate content (renewed certificates)
- **For `--cert-only`**: Do NOT use `--name` parameter - let system auto-generate names
- **For Testing**: Ensure certificate content is actually different, not just the intended name

### 📋 Usage Examples

#### Certificate-Only Mode
```bash
# Simple certificate upload without service bindings
python3 forti_cert_swap.py --cert-only --cert fullchain.cer --key private.key -C fortigate.yaml
```

#### SSL Inspection Certificate Mode
```bash
# Automated SSL inspection certificate renewal with rebinding
python3 forti_cert_swap.py --ssl-inspection-certificate --cert fullchain.cer --key private.key --host fortigate.kiroshi.group --port 8443 --token TOKEN --insecure

# With pruning of old certificates
python3 forti_cert_swap.py --ssl-inspection-certificate --cert fullchain.cer --key private.key --prune -C ssl-inspection-certificate.yaml
```

#### Rebind Mode (GUI/SSL-VPN/FTM Only)
```bash
# Rebinds GUI, SSL-VPN, and FTM services only (NOT SSL inspection profiles)
python3 forti_cert_swap.py --rebind certificate-name-20251114 -C fortigate.yaml
```

### 🧪 Testing Results

✅ **Certificate Naming**: Fixed to generate `kiroshi.group-20251114` based on certificate expiry  
✅ **SSL Inspection Discovery**: Successfully found and mapped 2 SSL inspection profiles  
✅ **Certificate Upload**: Created new certificate in GLOBAL store (HTTP 200)  
✅ **Profile Rebinding**: Successfully rebound both profiles from `kiroshi.group-20251001` to `kiroshi.group-20251114`  
✅ **No Failures**: All operations completed without errors  

### 🔄 Backward Compatibility

- **✅ Console output unchanged** - existing scripts continue to work
- **✅ Configuration format preserved** - existing YAML configs work without changes  
- **✅ Command-line interface maintained** - all existing parameters work as before
- **✅ Default behavior unchanged** - standard certificate upload and binding workflow preserved

### 🎯 Production Ready

This release makes the tool suitable for SSL inspection certificate management with:
- Automated SSL inspection profile discovery and rebinding
- Comprehensive error handling for FortiGate limitations
- Battle-tested workflows with real FortiGate configurations
- Detailed documentation of limitations and workarounds

### 📦 Installation

```bash
# Download the script
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/download/v1.10.0/forti_cert_swap.py

# Make executable
chmod +x forti_cert_swap.py

# Install dependencies
pip3 install cryptography requests pyyaml
```

### 📚 Documentation Updates

- **README.md**: Added SSL inspection certificate management section with examples
- **CHANGELOG.md**: Comprehensive v1.10.0 feature documentation
- **DEPLOYMENT_GUIDE.md**: SSL inspection deployment patterns and best practices

**⚠️ Breaking Changes**: None - fully backward compatible  
**🏷️ Recommended for**: SSL inspection certificate management, automated certificate renewal  
**📋 Requirements**: Python 3.8+, cryptography, requests, pyyaml (optional)
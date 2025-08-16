# 🔒 fortigate-cert-swap

A utility to **upload and rotate TLS certificates** on a FortiGate device, with **automatic intermediate CA management** and flexible operation modes:

**Full Service Binding Mode** (default):
- 🖥️ **GUI** (`system global admin-server-cert`)
- 🔐 **SSL-VPN** (`vpn.ssl settings servercert`)
- 📱 **FTM Push** (`system ftm-push server-cert`)

**Certificate-Only Mode** (`--cert-only`):
- 📄 **General Certificate Upload** - Upload/update any certificate without changing service bindings
- 🔒 **SSL Inspection Support** - Perfect for SSL inspection certificates
- 🎯 **Standard Naming** - Uses standard certificate naming scheme (domain-YYYYMMDD)

**SSL Inspection Certificate Mode** (`--ssl-inspection-certificate`):
- 🔄 **Automated SSL Inspection** - Upload with standard naming and automatically rebind SSL inspection profiles
- 🎯 **Domain Matching** - Finds and rebinds SSL inspection profiles based on certificate domain
- 🧹 **Optional Pruning** - Delete old SSL inspection certificates after successful rebinding

**Rebind-Only Mode** (`--rebind`):
- 🔄 **GUI/SSL-VPN/FTM Rebinding** - Bind GUI, SSL-VPN, and FTM services to existing certificates without upload
- ⚠️ **Note**: Does NOT rebind SSL inspection profiles - use `--ssl-inspection-certificate` for SSL inspection certificate management

Supports YAML configuration, dry-run mode, pruning older certificates, and comprehensive file logging.

---

## 🚀 Features

- 📄 **YAML config** (`-C/--config`) merged with CLI options (CLI takes precedence).
- 🏷️ **Automatic naming** derived from **CN + expiry date** (e.g., `fortigate.kiroshi.group-20251108`), or override with `--name`.
- 🌐 **GLOBAL vs VDOM** store selection (`--vdom` omitted defaults to GLOBAL).
- 👀 **Dry-run** mode to preview changes without making them.
- 🧹 **Prune** older certificates with the same base name **only if they are not bound to any services**.
- 🔄 **Rebind-only** mode to bind GUI/SSL-VPN/FTM services to an **existing** certificate without upload (`--rebind`) - does NOT affect SSL inspection profiles.
- 🔒 **Certificate-only** mode to upload/update any certificate without service bindings (`--cert-only`) - perfect for SSL inspection or general certificate management.
- 🎯 **SSL inspection certificate** mode with automated profile rebinding (`--ssl-inspection-certificate`).
- 🧠 **Smart SSL inspection** detection with domain-based matching and certificate name preservation.
- 🔄 **Hybrid domain matching** using both text-based and certificate parsing approaches.
- 🔁 **Retries** for safe idempotency (avoids POST/500 retry loops).
- 📜 **Optional logging** to file (`--log`, `--log-level {standard|debug}`).
- 🛡️ **Friendly TLS hints** when verification fails (suggests `--insecure` or fixing intermediates).
- 🔗 **Automatic intermediate CA management** - First tool to solve FortiGate's certificate chain design limitation.
- 🤖 **Dual certificate store management** - Automatically manages both local certificates and CA certificates.
- ✅ **Complete certificate chain validation** - Ensures SSL Labs and curl validation without `--insecure` flags.

---

## 🛠️ Requirements

- Python 3.8+
- Modules:
  - `cryptography`
  - `requests`
  - `pyyaml` (only if using `-C/--config`)

### Install on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y python3-cryptography python3-requests python3-yaml
```

### Or via pip

```bash
pip3 install cryptography requests pyyaml
```

---

## ⚙️ Example Configuration (`fortigate.yaml`)

```yaml
# FortiGate connection & behavior
host: fortigate.kiroshi.group
port: 8443
token: "REPLACE_WITH_YOUR_API_TOKEN"
# vdom: "root"        # omit for GLOBAL store
insecure: true        # system CA store used when false (default: false)
dry_run: false
prune: true

# Automatic intermediate CA management (NEW in v1.11.0)
auto_intermediate_ca: true  # automatically upload missing intermediate CAs (default: true)

# timeouts (seconds)
timeout_connect: 5
timeout_read: 30

# Optional file logging (plain, scrubbed)
log: "~/logs/forti_cert_swap-deploy.log"
log_level: "debug"    # standard | debug
```

---

## 💡 Basic Usage

### Upload & bind from existing key and certificate chain:

```bash
forti_cert_swap.py -C fortigate.yaml --cert /path/fullchain.pem --key /path/privkey.pem
```

### Rebind GUI/SSL-VPN/FTM services only (no upload), using an existing certificate name on FortiGate:

```bash
# Rebinds GUI, SSL-VPN, and FTM services only (NOT SSL inspection profiles)
forti_cert_swap.py -C fortigate.yaml --rebind fortigate.kiroshi.group-20251108
```

### Certificate-only mode (upload any certificate without service bindings):

```bash
# Upload certificate without binding to any services (useful for SSL inspection or general certificate management)
forti_cert_swap.py -C fortigate.yaml --cert-only --cert /path/fullchain.pem --key /path/privkey.pem

# With pruning (only deletes certificates not bound to any services)
forti_cert_swap.py -C fortigate.yaml --cert-only --cert /path/fullchain.pem --key /path/privkey.pem --prune
```

### SSL inspection certificate mode (automated rebinding):

```bash
# Upload with standard naming and automatically rebind SSL inspection profiles
forti_cert_swap.py --ssl-inspection-certificate --cert /path/fullchain.pem --key /path/privkey.pem -C ssl-inspection-certificate.yaml

# With pruning of old SSL inspection certificates
forti_cert_swap.py --ssl-inspection-certificate --cert /path/fullchain.pem --key /path/privkey.pem --prune -C ssl-inspection-certificate.yaml
```

### Dry-run mode:

```bash
forti_cert_swap.py -C fortigate.yaml --dry-run
```

### TLS verification issues:

If the FortiGate does not present full intermediates, verification can fail. Either add missing intermediates to the FortiGate or run with `--insecure` temporarily.

---

## 🔗 Automatic Intermediate CA Management (NEW in v1.11.0)

### 🚀 **WORLD'S FIRST: FortiGate Certificate Chain Solution**

This tool is the **first and only solution** to automatically solve FortiGate's fundamental certificate chain design limitation. FortiGate has an architectural inconsistency where:

- **Local Certificate Store** (`vpn.certificate/local`): Stores leaf certificates only
- **CA Certificate Store** (`vpn.certificate/ca`): Stores intermediate and root CAs separately
- **Chain Presentation**: FortiGate combines certificates from both stores when presenting SSL certificates

**The Problem**: Without intermediate CAs in the CA store, FortiGate presents incomplete certificate chains, causing:
- ❌ SSL Labs warnings about missing intermediate certificates
- ❌ curl validation failures requiring `--insecure` flag
- ❌ Browser warnings and trust issues
- ❌ Manual intermediate CA upload requirements

**Our Revolutionary Solution**: Automatic intermediate CA management that:
- ✅ **Extracts intermediate CAs** from certificate chains using cryptography library
- ✅ **Detects missing CAs** by comparing with FortiGate's existing CA store
- ✅ **Automatically uploads** missing intermediate CAs with proper naming
- ✅ **Enables SSL inspection trust** for uploaded intermediate CAs
- ✅ **Provides complete certificate chains** for SSL Labs and curl validation
- ✅ **Works seamlessly** with all certificate operation modes

### 🤖 **Intelligent CA Management Features**

#### **Automatic Detection and Upload**
```bash
# Automatic intermediate CA management (default behavior)
forti_cert_swap.py --cert fullchain.pem --key private.key -C fortigate.yaml

# Console output shows intermediate CA operations:
# [*] Certificate chain analysis: Found 1 intermediate CA to process
# [*] Intermediate CA 'R11' not found in FortiGate CA store
# [*] Successfully uploaded intermediate CA certificate 'R11' to FortiGate CA store
# [*] Complete certificate chain validation: curl test successful without --insecure
```

#### **Smart Deduplication**
```bash
# On subsequent runs, detects existing intermediate CAs:
# [*] Certificate chain analysis: Found 1 intermediate CA to process
# [*] Intermediate CA 'R11' already exists in FortiGate CA store (installed by user)
# [*] Skipping intermediate CA upload - certificate already present
```

#### **Manual Control Options**
```bash
# Disable automatic intermediate CA management
forti_cert_swap.py --cert fullchain.pem --key private.key --no-auto-intermediate-ca -C fortigate.yaml

# Enable automatic intermediate CA management (explicit)
forti_cert_swap.py --cert fullchain.pem --key private.key --auto-intermediate-ca -C fortigate.yaml
```

#### **Configuration File Control**
```yaml
# Enable automatic intermediate CA management (default)
auto_intermediate_ca: true

# Disable automatic intermediate CA management
auto_intermediate_ca: false
```

### 🔍 **Technical Implementation**

#### **Certificate Chain Processing**
- **Chain Parsing**: Extracts and validates complete certificate chains
- **Immediate Issuer Extraction**: Identifies direct issuing CAs (not root CAs)
- **Content Comparison**: Binary certificate comparison to prevent duplicates
- **Sanitized Naming**: Generates clean CA certificate names from Common Name

#### **FortiGate Integration**
- **CA Store Management**: Automatically manages FortiGate's CA certificate store
- **SSL Inspection Trust**: Enables `ssl-inspection-trusted` for uploaded CAs
- **Factory CA Awareness**: Distinguishes between user-installed and factory CAs
- **Dual Store Architecture**: Seamlessly coordinates local and CA certificate stores

### 🎯 **Production Benefits**

#### **Before v1.11.0**
- ❌ Manual intermediate CA uploads required
- ❌ Incomplete certificate chains in SSL inspection
- ❌ SSL Labs warnings about missing certificates
- ❌ curl validation required `--insecure` flag

#### **After v1.11.0**
- ✅ Automatic intermediate CA management
- ✅ Complete certificate chains automatically
- ✅ SSL Labs validation passes without warnings
- ✅ curl validation works without `--insecure` flag

### 🏆 **Industry Impact**

This release establishes our tool as the **definitive solution** for FortiGate certificate management by being the **first and only tool** to automatically address FortiGate's certificate chain design limitation. No other tool provides this level of automated certificate chain management for FortiGate devices.

---

## 🔒 SSL Inspection Certificate Management

FortiGate SSL inspection requires certificates to be bound to SSL inspection profiles. This tool provides two approaches:

### Certificate-Only Mode (`--cert-only`)
- **Simple Upload**: Upload/update certificates without any service bindings
- **Standard Naming**: Uses standard certificate naming scheme (domain-YYYYMMDD)
- **Manual Control**: No automatic profile rebinding - certificates are simply uploaded
- **Use Case**: When you want to upload certificates for any purpose without affecting service bindings

```bash
# Simple certificate upload without service bindings (for SSL inspection)
forti_cert_swap.py --cert-only --cert /path/fullchain.pem --key /path/privkey.pem -C fortigate.yaml
```

### SSL Inspection Certificate Mode (`--ssl-inspection-certificate`)
- **Standard Naming**: Uses standard naming scheme (domain-YYYYMMDD)
- **Automatic Rebinding**: Finds SSL inspection profiles by domain and rebinds them to new certificate
- **Multi-Profile Support**: Handles multiple SSL inspection profiles using the same domain
- **Optional Pruning**: Can delete old SSL inspection certificates after successful rebinding
- **Use Case**: Complete automated SSL inspection certificate renewal workflow

```bash
# Automated SSL inspection certificate swap with rebinding
forti_cert_swap.py --ssl-inspection-certificate --cert /path/fullchain.pem --key /path/privkey.pem --prune -C ssl-inspection-certificate.yaml
```

### Domain Matching Logic
Both modes use hybrid domain matching:
1. **Text-based matching**: Fast extraction from certificate names (e.g., `kiroshi.group-20251114` → `kiroshi.group`)
2. **Certificate parsing**: Fallback to fetching and parsing actual certificates from FortiGate
3. **Case-insensitive**: Handles domain name variations (`BluCore.io` matches `kiroshi.group`)

### ⚠️ FortiGate Certificate Upload/Swap Limitations

#### 1. Duplicate Content Prevention
**Important**: FortiGate prevents uploading certificates with identical content but different names. This can cause issues during certificate renewals.

**Limitation**: If you try to upload a new certificate with the same content as an existing certificate (but with a different name), FortiGate will reject the upload with a duplicate content error.

**Workaround**:
- **For `--ssl-inspection-certificate` mode**: Always use fresh certificate content (renewed certificates) to avoid conflicts
- **For `--cert-only` mode**: Do NOT use the `--name` parameter - let the system auto-generate names based on certificate expiry dates
- **Testing**: When testing, ensure certificate content is actually different, not just the intended name

**Example of the issue**:
```bash
# This will fail if certificate content is identical to existing cert
python3 forti_cert_swap.py --ssl-inspection-certificate --cert fullchain.cer --key private.key --name kiroshi.group-20251001

# This works correctly - auto-generates name from certificate expiry
python3 forti_cert_swap.py --ssl-inspection-certificate --cert fullchain.cer --key private.key
```

#### 2. Certificate Pruning Safety
**Important**: The `--prune` option only deletes certificates that are **not bound to any services**.

**Service Binding Checks**: Before deleting any certificate, the system verifies it's not bound to:
- **GUI** admin interface (`system/global`)
- **SSL-VPN** (`vpn.ssl/settings`)
- **FTM** push notifications (`system/ftm-push`)
- **SSL inspection profiles** (`firewall/ssl-ssh-profile`)

**Safety Features**:
- Certificates bound to any service are automatically skipped
- Detailed logging shows why certificates were skipped
- Only certificates with older expiry dates are considered for deletion
- Only certificates with the same base domain are considered

**Example pruning behavior**:
```bash
# Safe pruning - only deletes unbound certificates with same domain and older expiry
python3 forti_cert_swap.py --cert-only --cert /path/fullchain.pem --key /path/privkey.pem --prune

# Output shows what was pruned vs skipped:
# [*] Pruned 1 old certificate(s): kiroshi.group-20251001
# [!] Skipped 20 certificate(s) during pruning
```

#### 3. SSL Inspection Profile Limitations
**Important**: SSL inspection profiles can only be rebound using the `--ssl-inspection-certificate` mode.

**Limitation**: The `--rebind` mode does NOT affect SSL inspection profiles - it only rebinds GUI, SSL-VPN, and FTM services.

**Correct Usage**:
```bash
# For GUI/SSL-VPN/FTM rebinding only
python3 forti_cert_swap.py --rebind existing-cert-name

# For SSL inspection profile rebinding
python3 forti_cert_swap.py --ssl-inspection-certificate --cert /path/fullchain.pem --key /path/privkey.pem
```

#### 4. Certificate Store Scope
**Important**: Certificate operations are scoped to either GLOBAL or VDOM stores.

**Limitation**: Certificates in GLOBAL store cannot be used by VDOM services and vice versa.

**Configuration**:
```bash
# GLOBAL store (default)
python3 forti_cert_swap.py --cert /path/fullchain.pem --key /path/privkey.pem

# VDOM store
python3 forti_cert_swap.py --vdom root --cert /path/fullchain.pem --key /path/privkey.pem
```

---

## 📋 Logging

- Enable logging with `--log /path/to/file.log`.
- Set verbosity with `--log-level {standard|debug}` (default: `standard`).

---

## 🧪 Testing

The project includes a comprehensive test suite with 39 unit tests covering all major functionality:

```bash
# Run all tests
python3 test_forti_cert_swap.py

# Run with verbose output
python3 test_forti_cert_swap.py -v

# Run specific test class
python3 -m unittest test_forti_cert_swap.TestCertificateProcessor -v
```

### Test Coverage
- ✅ Configuration validation and merging
- ✅ Certificate processing and validation
- ✅ Enhanced logging with scrubbing
- ✅ FortiGate API client functionality
- ✅ Certificate operations (upload, bind, prune)
- ✅ Error handling and edge cases
- ✅ Integration scenarios

---

## 📜 License

MIT © CyB0rgg <dev@bluco.re>

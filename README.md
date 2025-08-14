# 🔒 fortigate-cert-swap

A utility to **upload and rotate TLS certificates** on a FortiGate device, binding them to:

- 🖥️ **GUI** (`system global admin-server-cert`)
- 🔐 **SSL-VPN** (`vpn.ssl settings servercert`)
- 📱 **FTM Push** (`system ftm-push server-cert`)

Supports YAML configuration, dry-run mode, pruning older certificates, rebind-only mode, and file logging.

---

## 🚀 Features

- 📄 **YAML config** (`-C/--config`) merged with CLI options (CLI takes precedence).
- 🏷️ **Automatic naming** derived from **CN + expiry date** (e.g., `fortigate.kiroshi.group-20251108`), or override with `--name`.
- 🌐 **GLOBAL vs VDOM** store selection (`--vdom` omitted defaults to GLOBAL).
- 👀 **Dry-run** mode to preview changes without making them.
- 🧹 **Prune** older certificates with the same base name **after successful bindings**.
- 🔄 **Rebind-only** mode to bind GUI/SSL-VPN/FTM to an **existing** certificate without upload (`--rebind`).
- 🔁 **Retries** for safe idempotency (avoids POST/500 retry loops).
- 📜 **Optional logging** to file (`--log`, `--log-level {standard|debug}`).
- 🛡️ **Friendly TLS hints** when verification fails (suggests `--insecure` or fixing intermediates).

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

### Rebind only (no upload), using an existing certificate name on FortiGate:

```bash
forti_cert_swap.py -C fortigate.yaml --rebind fortigate.kiroshi.group-20251108
```

### Dry-run mode:

```bash
forti_cert_swap.py -C fortigate.yaml --dry-run
```

### TLS verification issues:

If the FortiGate does not present full intermediates, verification can fail. Either add missing intermediates to the FortiGate or run with `--insecure` temporarily.

---

## 📋 Logging

- Enable logging with `--log /path/to/file.log`.
- Set verbosity with `--log-level {standard|debug}` (default: `standard`).

---

## 🧪 Testing

The project includes a comprehensive test suite with 37 unit tests covering all major functionality:

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

# fortigate-cert-swap

Utility to upload/rotate a TLS certificate on a FortiGate and bind it to:
- GUI (`system global admin-server-cert`)
- SSL‑VPN (`vpn.ssl settings servercert`)
- FTM Push (`system ftm-push server-cert`)

It supports YAML config, dry‑run, pruning of older certs, rebind‑only mode, and file logging.

> Version: **v1.8.0**
> License: **MIT**

## Features
- **YAML config** (`-C/--config`) merged with CLI (CLI wins).
- **Automatic name** derived from **CN + expiry date** (e.g., `fortigate.kiroshi.group-20251108`) or override with `--name`.
- **GLOBAL vs VDOM** store selection (`--vdom` omitted ⇒ GLOBAL).
- **Dry-run** mode to preview changes.
- **Prune** older certs with the same base name **after successful bindings**.
- **Rebind-only**: bind GUI/SSL‑VPN/FTM to an **existing** certificate name without upload (`--rebind`).
- **Retries** for safe idempotency (no POST/500 retry loops).
- **Optional logging** to file (`--log`, `--log-level {standard|debug}`).
- **Friendly TLS hints** when verification fails (suggest `--insecure` or fixing intermediates).

## Requirements
- Python 3.8+
- Modules:
  - `cryptography`
  - `requests`
  - `pyyaml` (only if using `-C/--config`)

Install on Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y python3-cryptography python3-requests python3-yaml
```

Or via pip:
```bash
pip3 install cryptography requests pyyaml
```

## Example config (fortigate.yaml)

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

## Basic usage
Upload & bind from an existing key/chain:
```bash
forti_cert_swap.py -C fortigate.yaml --cert /path/fullchain.pem --key /path/privkey.pem
```

Rebind only (no upload), using an existing cert already present on the FortiGate:
```bash
forti_cert_swap.py -C fortigate.yaml --rebind fortigate.kiroshi.group-20251108
```

Dry‑run:
```bash
forti_cert_swap.py -C fortigate.yaml --dry-run
```

TLS verify issues:
- If the FortiGate does not present full intermediates, verification can fail. Either add missing intermediates to FortiGate, or run with `--insecure` temporarily.

## Logging
- Enable with `--log /path/file.log`.
- Verbosity via `--log-level {standard|debug}` (default: `standard`).

## License
MIT © CyB0rgg @ Kiroshi.Group, Jarvis @ Kiroshi.Group

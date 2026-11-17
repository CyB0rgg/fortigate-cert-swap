# Release Notes - v2.0.2

## 🐛 Bug-fix release - failed deployments no longer report success

Fixes GitHub issue #1 ("Global store http 404 error"). If the FortiGate REST API rejects the certificate upload - typically because the configured port is not the admin HTTPS port (`admin-sport`), or the API user lacks permissions - v2.0.1 printed `Created certificate … (HTTP 404)`, tried to bind services (which failed), printed `Operation completed successfully` and exited 0. acme.sh therefore reported `Success` while nothing had changed on the FortiGate.

### Fixed
- Upload failure (non-200 on both `POST` and `PUT` of `vpn.certificate/local`) now aborts with exit code 1 before any service is touched.
- Any failed service binding in standard mode now ends the run with exit code 1 and an explicit `Operation failed` line.
- Every failed API call now prints the HTTP status, the FortiGate `error` / `cli_error` fields, and a hint for the usual cause (`404`: wrong port / not the REST API; `401`: API key; `403`: `accprofile`, trusted hosts, or a VDOM forced on a non-VDOM unit).

### Added
- Unit tests (`go test ./...`) for the failure description helper.

### Verified
- Reproduced issue #1 against a server answering 404 to every request: v2.0.1 reports success and exits 0, v2.0.2 aborts with `Certificate upload failed: HTTP 404 - … check admin-sport …` and exit 1.
- Normal deployment re-run against FortiOS 7.4.11 (no-vdom, `scope=global`) unchanged.

---

# Release Notes - v2.0.1

## 🎨 UX Improvements Patch Release

This patch release resolves all console output formatting inconsistencies discovered after v2.0.0, delivering a truly professional terminal experience.

### Fixed Issues
- **Fixed duplicate CA certificate display**: Eliminated duplicate "[*] Installing CA certificate" messages
- **Fixed 29 inconsistent status indicators**: All `fmt.Printf` calls now use unified formatting system
- **Fixed certificate chain summary headers**: Consistent bold white formatting for all headers
- **Fixed effective configuration headers**: Professional formatting for configuration summaries
- **Fixed CA certificate creation indicators**: Changed improper `[*]` to `[✓]` for completed operations
- **Fixed SSL inspection profile rebinding indicators**: Changed improper `[*]` to `[✓]` for completed operations
- **Fixed import formatting**: Removed unprofessional empty line in imports section

### Unified Status Indicator System
- `[*]` - Ongoing operations (bold white)
- `[✓]` - Successful completions (bold white)
- `[!]` - Warnings (bold white)
- `[✗]` - Errors (bold white)

### Technical Details
- **29 formatting fixes**: Every status indicator now uses consistent `printInfo()`, `printSuccess()`, `printWarning()`, `printError()` functions
- **Professional code quality**: Clean import structure and consistent formatting throughout
- **Zero functional changes**: All fixes are purely cosmetic UX improvements

### Installation
Download the latest binaries from the [releases page](https://github.com/CyB0rgg/fortigate-cert-swap/releases/latest).

---

**Copyright (c) 2025 CyB0rgg <dev@bluco.re>**  
**Licensed under the MIT License**
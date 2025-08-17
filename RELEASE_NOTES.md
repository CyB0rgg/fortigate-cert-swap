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
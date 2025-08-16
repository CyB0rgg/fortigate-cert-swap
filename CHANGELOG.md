# Changelog
All notable changes to this project will be documented in this file.

## [1.10.0] - 2025-08-16
### Added
- **SSL Inspection Certificate Mode** (`--ssl-inspection-certificate`) - Complete automated SSL inspection certificate renewal workflow with standard naming and automatic profile rebinding
- **Certificate-Only Mode** (`--cert-only`) - Simple certificate upload without any service bindings, perfect for SSL inspection scenarios
- **Mutually Exclusive Operation Modes** - Prevents conflicting mode usage with proper argument validation
- **Hybrid Domain Matching** - Advanced domain matching using both text-based extraction and certificate parsing for SSL inspection profile discovery
- **SSL Inspection Profile Rebinding** - Automatically discovers and rebinds SSL inspection profiles when certificates are renewed
- **Multi-Profile SSL Inspection Support** - Handles multiple SSL inspection profiles using the same domain certificate
- **SSL Inspection Certificate Pruning** - Optional deletion of old SSL inspection certificates after successful rebinding with `--prune`
- **Enhanced Certificate Operations** - New methods for SSL inspection profile management and certificate domain extraction
- **Dedicated Configuration Examples** - New `ssl-inspection-certificate.yaml` configuration template for SSL inspection workflows

### Enhanced
- **Certificate Naming Logic** - Fixed certificate naming to properly use certificate expiry dates instead of manual overrides
- **Domain Extraction Logic** - Robust domain extraction from certificate names, CN, and SAN fields with wildcard handling
- **SSL Inspection Profile Discovery** - Complete mapping of certificates to SSL inspection profiles that use them across firewall/ssl-ssh-profile configurations
- **Configuration Validation** - Added validation for the new SSL inspection certificate modes with proper error messages
- **Error Handling** - Improved error handling for SSL inspection operations with detailed logging and FortiGate duplicate content awareness

### Fixed
- **Certificate Naming Issue** - Resolved issue where using `--name` parameter would override automatic expiry-based naming, causing FortiGate duplicate content conflicts
- **SSL Inspection Profile Detection** - Fixed SSL inspection profile discovery to properly handle both server-cert and ssl-server arrays in profile configurations
- **Mode Separation** - Clarified that `--rebind` mode only affects GUI/SSL-VPN/FTM services and does NOT rebind SSL inspection profiles

### Technical Improvements
- **1491 lines of enhanced code** with comprehensive SSL inspection certificate management
- **Advanced Certificate Analysis** - Deep inspection of FortiGate SSL inspection profile configurations with hybrid domain matching
- **Automated Workflow Integration** - Seamless integration of certificate upload, profile rebinding, and cleanup operations
- **Production-Ready SSL Inspection** - Battle-tested with real FortiGate SSL inspection configurations and fresh certificate renewals
- **FortiGate Limitation Documentation** - Comprehensive documentation of FortiGate certificate duplicate content limitations and workarounds

### Breaking Changes
- **None** - All existing functionality preserved with backward compatibility

## [1.9.0] - 2025-08-14
### Added
- **Comprehensive test suite** - 37 unit tests covering all major functionality with proper mocking
- **Enhanced logging system** with operation correlation IDs and improved certificate scrubbing
- **Comprehensive type hints** throughout the codebase for better IDE support and code safety
- **Configuration validation** with custom exception handling and detailed error messages
- **Certificate chain display improvements** - now shows user-friendly expiry information (e.g., "expires in 86 days")
- **Structured error handling** with custom exception classes (ConfigurationError, CertificateError, APIError)
- **Enhanced certificate processing** with better PEM validation and chain parsing
- **Improved API client** with better retry policies and error context
- **Production-ready logging** with sensitive data scrubbing and two-level verbosity

### Changed
- **Complete code restructure** using dataclasses and proper OOP design patterns
- **Enhanced certificate name generation** with better CN/SAN extraction
- **Improved HTTP request logging** with meaningful endpoint names instead of full URLs
- **Better configuration merging** with proper handling of CLI vs YAML precedence
- **Enhanced certificate summary display** with human-readable expiry dates
- **Upgraded dependency checking** with clearer installation instructions

### Fixed
- **Configuration warning bug** - excluded internal argparse parameters from config merging
- **Certificate scrubbing patterns** - added comprehensive regex for PEM data redaction
- **File handling robustness** - better error handling for certificate and key file operations
- **Mock compatibility** - improved test compatibility with different mock scenarios

### Technical Improvements
- **940+ lines of enhanced code** (up from 463 lines) with comprehensive documentation
- **37 comprehensive unit tests** covering all major functionality
- **Type safety** with Optional types and proper error propagation
- **Modular architecture** with separate classes for different concerns
- **Enhanced security** with improved sensitive data scrubbing in logs

## [1.8.1] - 2025-08-10
### Changed
- Make `forti_cert_swap.py` executable for direct `./forti_cert_swap.py` usage.

### Notes
- No functional code changes; version and release reflect permission + metadata update.

## [1.8.0] - 2025-08-10
### Added
- `--log` and `--log-level` (`standard`/`debug`) with scrubbed, timestamped file logging.
- Clear TLS verification error hint suggesting `--insecure` or chain fix.
- Minor output polish; safer retries configuration.

### Kept (baseline)
- YAML/CLI merge, CN+expiry naming, GLOBAL/VDOM stores, dry-run, prune, rebind-only,
  and robust HTTP behavior (no POST/500 retry loops).
# Changelog
All notable changes to this project will be documented in this file.

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
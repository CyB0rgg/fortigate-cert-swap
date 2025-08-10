# Changelog

All notable changes to this project will be documented in this file.

## [1.8.0] - 2025-08-10
### Added
- `--log` and `--log-level` (`standard`/`debug`) with scrubbed, timestamped file logging.
- Clear TLS verification error hint suggesting `--insecure` or chain fix.
- Minor output polish; safer retries configuration.

### Kept (baseline)
- YAML/CLI merge, CN+expiry naming, GLOBAL/VDOM stores, dry-run, prune, rebind-only,
  and robust HTTP behavior (no POST/500 retry loops).


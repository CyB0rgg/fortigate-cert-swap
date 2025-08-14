# Release Notes - v1.9.0

## 🎉 Major Release: Production-Ready Enhancement

This is a significant release that transforms the FortiGate Certificate Swap utility into a production-ready tool with comprehensive improvements across all areas.

### 🚀 Key Highlights

- **940+ lines of enhanced code** with comprehensive type hints and documentation
- **37 comprehensive unit tests** ensuring reliability and maintainability
- **Enhanced logging system** with operation correlation and sensitive data scrubbing
- **Structured error handling** with custom exception classes
- **Production-ready architecture** using modern Python patterns

### ✨ New Features

- **🆔 Operation Correlation IDs**: Track operations across log entries for better debugging
- **📅 Enhanced Certificate Display**: Human-readable expiry information (e.g., "expires in 86 days")
- **🔒 Comprehensive Type Safety**: Full type hints throughout the codebase
- **✅ Configuration Validation**: Detailed validation with helpful error messages
- **🔧 Improved Certificate Processing**: Better PEM validation and chain parsing
- **🌐 Enhanced API Client**: Better retry policies and error context
- **🧪 Comprehensive Test Suite**: 37 unit tests covering all major functionality

### 🔧 Technical Improvements

- **🏗️ Modular Architecture**: Separate classes for different concerns (Config, Logger, CertificateProcessor, etc.)
- **📊 Dataclass Configuration**: Type-safe configuration with automatic validation
- **🛡️ Enhanced Security**: Comprehensive sensitive data scrubbing in logs
- **💬 Better Error Messages**: Clear, actionable error messages with context
- **📈 Improved Test Coverage**: 37 tests covering all major functionality

### 🐛 Bug Fixes

- Fixed configuration warning bug with internal argparse parameters
- Enhanced certificate scrubbing patterns for better security
- Improved file handling robustness
- Better mock compatibility for testing

### 📈 Performance & Reliability

- More efficient HTTP request handling
- Better retry policies for network operations
- Improved certificate chain processing
- Enhanced error recovery mechanisms

### 🔄 Backward Compatibility

- **✅ Console output unchanged** - existing scripts continue to work
- **✅ Configuration format preserved** - existing YAML configs work without changes
- **✅ Command-line interface maintained** - all existing parameters work as before

### 🎯 Production Ready

This release makes the tool suitable for production environments with:
- Comprehensive logging for audit trails
- Robust error handling for automated deployments
- Type safety for better IDE support and fewer runtime errors
- Extensive test coverage for confidence in deployments

### 🧪 Testing

Run the comprehensive test suite:
```bash
# Run all 37 tests
python3 test_forti_cert_swap.py

# Run with verbose output
python3 test_forti_cert_swap.py -v
```

### 📦 Installation

```bash
# Download the script
wget https://github.com/CyB0rgg/fortigate-cert-swap/releases/download/v1.9.0/forti_cert_swap.py

# Make executable
chmod +x forti_cert_swap.py

# Install dependencies
pip3 install cryptography requests pyyaml
```

**⚠️ Breaking Changes**: None - fully backward compatible  
**🏷️ Recommended for**: Production deployments, automated certificate management  
**📋 Requirements**: Python 3.8+, cryptography, requests, pyyaml (optional)
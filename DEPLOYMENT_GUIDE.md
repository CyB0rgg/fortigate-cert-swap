# FortiGate Certificate Swap - Production Deployment Guide

This guide provides comprehensive instructions for deploying the improved FortiGate certificate swap script in production environments.

## 📋 Quick Start

### 1. **Choose Your Version**
- [`forti_cert_swap.py`](forti_cert_swap.py) - Production-ready with enhanced error handling, validation, and maintainability

### 2. **Install Dependencies**
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y python3-cryptography python3-requests python3-yaml

# Or via pip
pip3 install cryptography requests pyyaml
```

### 3. **Basic Usage**
```bash
# Standard mode - GUI/SSL-VPN/FTM binding
python3 forti_cert_swap.py -C fortigate.yaml --cert /path/to/cert.pem --key /path/to/key.pem

# Certificate-only mode - SSL inspection
python3 forti_cert_swap.py --cert-only --cert /path/to/cert.pem --key /path/to/key.pem -C fortigate.yaml

# SSL inspection certificate mode - automated rebinding
python3 forti_cert_swap.py --ssl-inspection-certificate --cert /path/to/cert.pem --key /path/to/key.pem -C ssl-inspection-certificate.yaml

# Rebind GUI/SSL-VPN/FTM services only
python3 forti_cert_swap.py --rebind existing-cert-name -C fortigate.yaml
```

## 🔒 SSL Inspection Certificate Management

### Certificate-Only Mode (`--cert-only`)
Perfect for SSL inspection scenarios where you need to upload certificates without affecting service bindings:

```bash
# Simple certificate upload for SSL inspection
python3 forti_cert_swap.py --cert-only --cert /path/to/cert.pem --key /path/to/key.pem -C fortigate.yaml
```

**Use Cases**:
- SSL inspection certificate updates
- Certificate content refresh without service disruption
- Manual certificate management workflows

### SSL Inspection Certificate Mode (`--ssl-inspection-certificate`)
Complete automated SSL inspection certificate renewal workflow:

```bash
# Automated SSL inspection certificate renewal
python3 forti_cert_swap.py --ssl-inspection-certificate --cert /path/to/cert.pem --key /path/to/key.pem --host fortigate.kiroshi.group --port 8443 --token TOKEN --insecure

# With pruning of old certificates
python3 forti_cert_swap.py --ssl-inspection-certificate --cert /path/to/cert.pem --key /path/to/key.pem --prune -C ssl-inspection-certificate.yaml
```

**Features**:
- **Domain-based discovery**: Finds SSL inspection profiles by certificate domain
- **Automatic rebinding**: Transfers profiles from old to new certificates
- **Multi-profile support**: Handles multiple profiles using the same certificate
- **Standard naming**: Uses domain-expiry format (e.g., `kiroshi.group-20251114`)
- **Optional pruning**: Deletes old certificates after successful rebinding

### ⚠️ FortiGate Certificate Duplicate Content Limitation

**Important**: FortiGate prevents uploading certificates with identical content but different names.

**Workarounds**:
- **For `--ssl-inspection-certificate`**: Always use fresh certificate content (renewed certificates)
- **For `--cert-only`**: Do NOT use `--name` parameter - let system auto-generate names
- **For testing**: Ensure certificate content is actually different

**Example**:
```bash
# INCORRECT - will fail with duplicate content
python3 forti_cert_swap.py --ssl-inspection-certificate --cert cert.pem --key key.pem --name old-cert-name

# CORRECT - auto-generates name from certificate expiry
python3 forti_cert_swap.py --ssl-inspection-certificate --cert cert.pem --key key.pem
```

## 🚀 Production Enhancements

### Enhanced Logging
The current version includes comprehensive logging with operation correlation:

```
2025-08-14 06:05:19 UTC INFO     [26e2d92c] Starting upload operation for certificate 'kiroshi.group-20251029' on forti.kiroshi.group
2025-08-14 06:05:19 UTC WARNING  [26e2d92c] HTTP POST vpn.certificate/local -> 500 (FortiGate error: -5)
2025-08-14 06:05:19 UTC INFO     [26e2d92c] All bindings successful: GUI✓ | SSL-VPN✓ | FTM✓
```

### Key Improvements:
- **Operation Correlation**: Each operation gets a unique ID for tracking
- **Concise HTTP Logs**: Simplified endpoint logging with error context
- **Summarized Results**: Certificate lists and binding results are condensed
- **Performance Metrics**: Built-in timing and success rate tracking

## 🔧 Configuration Management

### Environment Variables
Set these environment variables for production deployment:

```bash
# Required
export FORTI_CERT_HOST=your-fortigate.example.com
export FORTI_CERT_PORT=8443
export FORTI_CERT_TOKEN=your-api-token

# Optional
export FORTI_CERT_VDOM=root                    # For VDOM deployments
export FORTI_CERT_INSECURE=false               # Set to true only if needed
export FORTI_CERT_DRY_RUN=false                # Set to true for testing
export FORTI_CERT_PRUNE=true                   # Auto-cleanup old certificates
export FORTI_CERT_TIMEOUT_CONNECT=10           # Connection timeout
export FORTI_CERT_TIMEOUT_READ=60              # Read timeout
export FORTI_CERT_LOG_LEVEL=standard           # standard or debug
export FORTI_CERT_LOG_FILE=/var/log/forti_cert_swap.log
```

### Configuration Validation
Use the production enhancements to validate your configuration:

```python
# Configuration validation is built into the main script
python3 forti_cert_swap.py --dry-run -C your-config.yaml --cert test.pem --key test.key
```

## 📊 Monitoring & Metrics

### Built-in Metrics
The improved version includes comprehensive metrics collection:

```python
# Metrics are logged automatically with operation correlation IDs
# Check log files for performance and success rate information
tail -f /var/log/forti_cert_swap.log | grep -E "(INFO|ERROR|WARN)"
```

### Log Analysis
Analyze your existing logs to identify issues:

```python
# Log analysis can be done with standard tools
grep -c "ERROR" /var/log/forti_cert_swap.log
grep -c "INFO.*successful" /var/log/forti_cert_swap.log
```

## 🧪 Testing

### Unit Tests
The project includes a comprehensive test suite with 37 unit tests covering all major functionality:

```bash
# Run all tests
python3 test_forti_cert_swap.py

# Run with verbose output
python3 test_forti_cert_swap.py -v

# Run specific test class
python3 -m unittest test_forti_cert_swap.TestCertificateProcessor -v
```

**Test Coverage:**
- Configuration validation and merging
- Certificate processing and validation
- Enhanced logging with sensitive data scrubbing
- FortiGate API client functionality
- Certificate operations (upload, bind, prune)
- Error handling and edge cases
- Integration scenarios

### Integration Testing
Use the integration testing framework:

```python
# Use dry-run mode for integration testing
python3 forti_cert_swap.py --dry-run -C test-config.yaml --cert test.pem --key test.key
```

### Pre-deployment Validation
Validate your deployment environment:

```python
# Environment validation is built into the script
# Run with --dry-run to validate configuration and connectivity
python3 forti_cert_swap.py --dry-run -C production-config.yaml --cert test.pem --key test.key
```

## 🔒 Security Best Practices

### 1. **API Token Management**
- Use dedicated service accounts with minimal permissions
- Rotate tokens regularly
- Store tokens in secure credential management systems
- Never commit tokens to version control

### 2. **TLS Configuration**
- Use proper CA certificates instead of `--insecure`
- Validate certificate chains
- Monitor certificate expiration dates

### 3. **File Permissions**
```bash
# Secure certificate files
chmod 600 /path/to/private.key
chmod 644 /path/to/certificate.pem

# Secure log files
chmod 640 /var/log/forti_cert_swap.log
chown root:adm /var/log/forti_cert_swap.log
```

### 4. **Network Security**
- Use dedicated management networks
- Implement firewall rules for FortiGate API access
- Consider VPN or bastion hosts for remote access

## 📈 Performance Optimization

### 1. **Connection Pooling**
The improved version includes connection pooling:
- Reuses HTTP connections
- Configurable pool sizes
- Automatic retry logic

### 2. **Timeout Configuration**
Optimize timeouts for your environment:
```yaml
# For fast local networks
timeout_connect: 3
timeout_read: 15

# For slower/remote connections
timeout_connect: 10
timeout_read: 60
```

### 3. **Batch Operations**
For multiple certificates, consider:
- Running operations in parallel (with caution)
- Using dry-run mode for validation
- Implementing circuit breakers for error handling

## 🚨 Error Handling & Recovery

### Common Issues and Solutions

#### 1. **HTTP 500 Errors**
**Cause**: Certificate already exists or FortiGate internal error
**Solution**: The script automatically retries with PUT (update) operation

#### 2. **TLS Verification Failures**
**Cause**: Incomplete certificate chain on FortiGate
**Solutions**:
- Add intermediate certificates to FortiGate
- Use `--insecure` temporarily (not recommended for production)
- Update system CA bundle

#### 3. **Timeout Errors**
**Cause**: Network latency or FortiGate load
**Solutions**:
- Increase timeout values
- Check network connectivity
- Monitor FortiGate CPU/memory usage

#### 4. **Permission Errors**
**Cause**: Insufficient API token permissions
**Solutions**:
- Verify token has certificate management permissions
- Check VDOM access rights
- Ensure token hasn't expired

### Recovery Procedures

#### Failed Certificate Upload
```bash
# Check current certificates
python3 forti_cert_swap.py --rebind existing-cert-name --dry-run

# Rollback to previous certificate (GUI/SSL-VPN/FTM only)
python3 forti_cert_swap.py --rebind previous-cert-name
```

#### Failed SSL Inspection Certificate Operations
```bash
# Check SSL inspection profiles and certificates
python3 forti_cert_swap.py --ssl-inspection-certificate --cert current.pem --key current.key --dry-run

# Manual SSL inspection profile rebinding (if needed)
# Use FortiGate GUI: Security Profiles > SSL/SSH Inspection > [Profile] > Server Certificate
```

#### Failed Service Bindings
```bash
# Rebind GUI/SSL-VPN/FTM services to existing certificate
python3 forti_cert_swap.py --rebind cert-name-20251108

# Check binding status via FortiGate CLI
# GUI: show system global | grep admin-server-cert
# SSL-VPN: show vpn ssl settings | grep servercert
# FTM: show system ftm-push | grep server-cert
```

#### SSL Inspection Profile Issues
```bash
# Verify SSL inspection profile mappings
# FortiGate CLI: show firewall ssl-ssh-profile [profile-name]
# Look for server-cert array entries

# Check certificate domain matching
# Ensure certificate CN/SAN matches expected domain
```

## 📋 Deployment Checklist

### Pre-deployment
- [ ] Dependencies installed and tested
- [ ] Configuration validated
- [ ] API token permissions verified
- [ ] Network connectivity confirmed
- [ ] Backup procedures in place
- [ ] Monitoring configured
- [ ] Test certificates available
- [ ] SSL inspection profiles identified (if using SSL inspection modes)
- [ ] Certificate domain matching verified
- [ ] FortiGate duplicate content limitations understood

### Deployment
- [ ] Deploy in dry-run mode first
- [ ] Validate certificate chain
- [ ] Test with non-critical certificate
- [ ] Monitor logs during deployment
- [ ] Verify all bindings successful
- [ ] Test FortiGate services (GUI, SSL-VPN)
- [ ] Verify SSL inspection profile rebinding (if applicable)
- [ ] Test SSL inspection functionality
- [ ] Confirm certificate naming follows expected pattern

### Post-deployment
- [ ] Monitor error rates
- [ ] Verify certificate rotation
- [ ] Test rollback procedures
- [ ] Update documentation
- [ ] Schedule regular maintenance
- [ ] Review and rotate API tokens
- [ ] Validate SSL inspection certificate workflows
- [ ] Document SSL inspection profile mappings
- [ ] Test certificate renewal automation

## 🔄 Automation & Scheduling

### Cron Job Example
```bash
# /etc/cron.d/forti-cert-swap
# Renew certificates daily at 2 AM
0 2 * * * root /usr/local/bin/forti_cert_swap.py -C /etc/fortigate/config.yaml --cert /etc/ssl/certs/current.pem --key /etc/ssl/private/current.key >> /var/log/forti_cert_swap.log 2>&1
```

### Systemd Service
```ini
# /etc/systemd/system/forti-cert-swap.service
[Unit]
Description=FortiGate Certificate Swap
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/forti_cert_swap.py -C /etc/fortigate/config.yaml --cert /etc/ssl/certs/current.pem --key /etc/ssl/private/current.key
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Integration with Let's Encrypt
```bash
#!/bin/bash
# /etc/letsencrypt/renewal-hooks/deploy/fortigate-deploy.sh

# This script runs after successful Let's Encrypt renewal
CERT_PATH="/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/yourdomain.com/privkey.pem"

# Deploy to FortiGate
/usr/local/bin/forti_cert_swap.py \
    -C /etc/fortigate/config.yaml \
    --cert "$CERT_PATH" \
    --key "$KEY_PATH" \
    --log /var/log/forti_cert_swap.log

# Check exit code
if [ $? -eq 0 ]; then
    logger "FortiGate certificate deployment successful"
else
    logger "FortiGate certificate deployment failed"
    exit 1
fi
```

## 📞 Support & Troubleshooting

### Debug Mode
Enable debug logging for troubleshooting:
```bash
export FORTI_CERT_LOG_LEVEL=debug
python3 forti_cert_swap.py --log-level debug ...
```

### Common Log Patterns
- `HTTP 500`: Certificate conflict, will retry with PUT
- `TLS verification failed`: Certificate chain issue
- `Connection timeout`: Network or FortiGate performance issue
- `All bindings successful`: Operation completed successfully

### Getting Help
1. Check the comprehensive test suite for examples
2. Review log analysis suggestions
3. Use the deployment validator for environment issues
4. Enable debug logging for detailed troubleshooting

---

## 📚 Additional Resources

- [FortiGate REST API Documentation](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/954635/rest-api-administrator)
- [Certificate Management Best Practices](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/954635/certificate-management)
- [Python Cryptography Library](https://cryptography.io/en/latest/)

---

*This deployment guide is based on analysis of your production logs and includes specific improvements for your use case.*
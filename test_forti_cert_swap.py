#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for forti_cert_swap.py

This test suite demonstrates proper testing structure for the FortiCertSwap application.
It includes tests for all major components with proper mocking and error handling.
"""

import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta

# Import the modules we're testing
from forti_cert_swap import (
    Config, ConfigManager, CertificateProcessor, Logger, FortiAPI,
    CertificateOperations, FortiCertSwap, LogLevel,
    ConfigurationError, CertificateError, APIError
)


class TestConfig(unittest.TestCase):
    """Test the Config dataclass and validation."""
    
    def test_valid_config(self):
        """Test creating a valid configuration."""
        config = Config(
            host="fortigate.example.com",
            port=443,
            token="test-token"
        )
        self.assertEqual(config.host, "fortigate.example.com")
        self.assertEqual(config.port, 443)
        self.assertEqual(config.store, "GLOBAL")
    
    def test_vdom_config(self):
        """Test VDOM configuration."""
        config = Config(
            host="fortigate.example.com",
            port=443,
            token="test-token",
            vdom="root"
        )
        self.assertEqual(config.store, "VDOM")
    
    def test_invalid_port(self):
        """Test invalid port validation."""
        with self.assertRaises(ValueError) as cm:
            Config(host="test", port=70000, token="test")
        self.assertIn("Port must be an integer between 1-65535", str(cm.exception))
    
    def test_missing_host(self):
        """Test missing host validation."""
        with self.assertRaises(ValueError) as cm:
            Config(host="", port=443, token="test")
        self.assertIn("Host is required", str(cm.exception))
    
    def test_invalid_timeout(self):
        """Test invalid timeout validation."""
        with self.assertRaises(ValueError) as cm:
            Config(host="test", port=443, token="test", timeout_connect=-1)
        self.assertIn("timeout_connect must be positive", str(cm.exception))
    
    def test_invalid_log_level(self):
        """Test invalid log level validation."""
        with self.assertRaises(ValueError) as cm:
            Config(host="test", port=443, token="test", log_level="invalid")
        self.assertIn("log_level must be one of", str(cm.exception))
    
    @patch('forti_cert_swap.Path')
    def test_path_expansion(self, mock_path):
        """Test path expansion for log and certificate files."""
        mock_path_obj = Mock()
        mock_path_obj.expanduser.return_value.resolve.return_value = "/expanded/path"
        mock_path.return_value = mock_path_obj
        
        config = Config(
            host="test",
            port=443,
            token="test",
            log="~/test.log",
            cert="~/cert.pem",
            key="~/key.pem"
        )
        
        self.assertEqual(config.log, "/expanded/path")
        self.assertEqual(config.cert, "/expanded/path")
        self.assertEqual(config.key, "/expanded/path")


class TestConfigManager(unittest.TestCase):
    """Test configuration management."""
    
    def test_load_yaml_config_missing_file(self):
        """Test loading non-existent YAML file."""
        with self.assertRaises(ConfigurationError) as cm:
            ConfigManager.load_yaml_config("/nonexistent/file.yaml")
        self.assertIn("Config file not found", str(cm.exception))
    
    @patch('forti_cert_swap.yml', None)
    def test_load_yaml_config_no_yaml_module(self):
        """Test loading YAML when PyYAML is not installed."""
        with self.assertRaises(ConfigurationError) as cm:
            ConfigManager.load_yaml_config("test.yaml")
        self.assertIn("PyYAML is not installed", str(cm.exception))
    
    @patch('builtins.open', mock_open(read_data='host: test.com\nport: 443\ntoken: test-token'))
    @patch('forti_cert_swap.Path')
    @patch('forti_cert_swap.yml')
    def test_load_yaml_config_success(self, mock_yml, mock_path):
        """Test successful YAML config loading."""
        mock_path.return_value.expanduser.return_value.resolve.return_value.exists.return_value = True
        mock_yml.safe_load.return_value = {"host": "test.com", "port": 443, "token": "test-token"}
        
        config = ConfigManager.load_yaml_config("test.yaml")
        self.assertEqual(config["host"], "test.com")
        self.assertEqual(config["port"], 443)
    
    def test_merge_args_with_config(self):
        """Test merging CLI args with config file."""
        from argparse import Namespace
        
        args = Namespace(
            host="cli-host",
            port=None,
            token="cli-token",
            cert=None,
            key=None,
            name=None,
            vdom=None,
            insecure=False,
            dry_run=False,
            prune=False,
            timeout_connect=5,
            timeout_read=30,
            log=None,
            log_level="standard",
            rebind=None,
            cert_only=False,
            ssl_inspection_cert=False
        )
        
        config_dict = {
            "host": "config-host",  # Should be overridden by CLI
            "port": 8443,           # Should be used from config
            "token": "config-token", # Should be overridden by CLI
            "unknown_key": "ignored"  # Should be ignored
        }
        
        merged = ConfigManager.merge_args_with_config(args, config_dict)
        
        self.assertEqual(merged.host, "cli-host")  # CLI takes precedence
        self.assertEqual(merged.port, 8443)       # From config
        self.assertEqual(merged.token, "cli-token")  # CLI takes precedence


class TestCertificateProcessor(unittest.TestCase):
    """Test certificate processing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Valid test certificate generated by test_cert_generator.py
        self.sample_cert_pem = """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUYYwYcTAtRNyOkduUydJxjKplgUQwDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMClRlc3QgU3RhdGUxEjAQBgNVBAcM
CVRlc3QgQ2l0eTERMA8GA1UECgwIVGVzdCBPcmcxGTAXBgNVBAMMEHRlc3QuZXhh
bXBsZS5jb20wHhcNMjUwODE0MDU1MjQ1WhcNMjYwODE0MDU1MjQ1WjBkMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKVGVzdCBTdGF0ZTESMBAGA1UEBwwJVGVzdCBDaXR5
MREwDwYDVQQKDAhUZXN0IE9yZzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANbmDZhkPBQyAC3TGbak9Y99
CkIjua4NFoVBI5wX6LyPs7VPa6PLd2M2T3FOiRnJgaqeiPwiHYUrYnqFCAKo9pzm
V3n7BuekvOffnXt0MYWeYzk05l0KiaoZ62L3+At5V0uTZIYYtjMbeiljeEQ2nhkl
fD4HS46ZcGXcHecBBtSPK5AT12R/XRyovbhJnNDK36sTf2o8CDzQFvSwEfpUfw9y
ymJdea1EIWtS4DLEGRNNWrZ7z7HJwzjcTxl9E58TiUXUbyMbOCrpXCeYMaWeX8Cg
kSa3ENNbQFwGh9pwz0eBGWRBhDwIzQNA+mnTTPnq51gxJAiU4+iRnxuWJxhfwY8C
AwEAAaMfMB0wGwYDVR0RBBQwEoIQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0B
AQsFAAOCAQEATHi+VJwrttcibbIp0oSLfbaCKCEjWEW7Eu/ajQLKooj3xnuHMUPk
TJ9rAHmmx0MvvFMObZodADzyAQ0S+fFfXe6ypHmjQHriy1M6H2Z7VzMUPXDF1vVl
TjzZ3zHLvrRnk8FViC83EPKsqP1nqd+/5Q7Wf5ALXaov1F9pBOTzuSZKhqZUIfAy
Ls4xh7eOwnSjci+ylZ+ReG3bk4JsWLUcGinAffJbMrBYwbIwIBfkpnD4FJ+lg6qS
J7KB77ss4tdcP+UoQhZ84xf3ILCpJF9LR9N8lNCJd3QS20eSWE7WCnH+XOAOuBBs
MmdMzgYqDUBkcMDB/HKH8Nv6kvs9GV87Gg==
-----END CERTIFICATE-----"""
        
        self.sample_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDW5g2YZDwUMgAt
0xm2pPWPfQpCI7muDRaFQSOcF+i8j7O1T2ujy3djNk9xTokZyYGqnoj8Ih2FK2J6
hQgCqPac5ld5+wbnpLzn3517dDGFnmM5NOZdComqGeti9/gLeVdLk2SGGLYzG3op
Y3hENp4ZJXw+B0uOmXBl3B3nAQbUjyuQE9dkf10cqL24SZzQyt+rE39qPAg80Bb0
sBH6VH8PcspiXXmtRCFrUuAyxBkTTVq2e8+xycM43E8ZfROfE4lF1G8jGzgq6Vwn
mDGlnl/AoJEmtxDTW0BcBofacM9HgRlkQYQ8CM0DQPpp00z56udYMSQIlOPokZ8b
licYX8GPAgMBAAECggEAZeaz1qndFUR6ckBSRpnlOVO1HBS9tOtO3QQ84wUxXsyT
jiupYoOWSqzTsepoN5qmSmYfldOFhQLEEU3otP4y5saQ/24J4ajrzNXr4sD/xJkM
+vD7NW5MRiVBSW5FKAezXcp4FeA88XIblOmue0Yc5NayGeWyrd1Tf3GHmmURvJOC
TodZ6BMj/q6n8qXLGn7/d6BtbypeuMr6TYeJcZf9q6KfIjXYKVChA8xgAAkdXqkb
VNgRs4X4QChaEPUgFjHYKyZfq497K+1aioF7JAdxVNxhZby2Vlc7uUQP1VOMef0B
ukkx56w2IPFeJcwYvm2530lltESgZ5TAm/vlMdPAIQKBgQDby/laMPTqdhmV02KG
szlDur3OB/C6+/P1IBN6WJhHUITEu1d7D+OrSmosHlogvE0ZIUMzBY15lU34JazZ
FAK5J7nw8+t4nVsfG1EDYPlYq35q19QbExwibdrRjclocpiGxixgWNYCueJnxlTP
k7nne/t+69ufdYRQVee/ZSDp4QKBgQD6S4r773Wr9ThYcvCaX8QyhxgrO056dONG
ArYc8BfV7xwhbnR/I3sKub2RdQ/usf/U/lPFfXGZmwy5q751o1ru4Jmm7s2he1qo
fFToX/9SmGqcWpujFKqRxPelCcXQGwMCjKkQSn+nbWa8VBarWE6UJLlf6wCK//Ls
vsxxSG95bwKBgQDTrWF7puJ4WzzQuj+NElX4EIRzQ9pnefa9ACNCFMizBayX+wSJ
FAhjEsulqaWLGU33Ab3CCXryuQPaFA6fEVJ+FvBQSdlg08rJ7njbFC2PY7ngE/PG
D2VtEvdGEZMC8DpMsdZTA7s37OVKpAtRzief9BuFZIiizX6cD9+cyDwmgQKBgQCg
CY1kaUgkGzdb1qJhErqwVBDwE4uqYPKw4SrwddPHxouGFMoIQPd7dCfxyZfWV5ns
5nFJ5Vuti6YnUdkF/t01wAZ+5lI03lqpQFZJ/peSiEIilwzMyXoGmpp9vDHvTlYu
WyH+eKQGubzmzh1wkZYsww6Edg5y0hTRq22tQVOFoQKBgGgkLPYOZeB0fFg1C9Cv
Xm0amw81d1xYxRkzdpr+CwSQcGtZTzBwINNxG+2SSI0lkv55zAcWjU5tC0ybQZ3U
lqTo99xtRH5t3U1hfUxqhQBjiDUTPxEKrUvigs1hq7+rwDKfH8SF2MP/EcAbcKKB
C0fFugWAUJ1Bv7U5Snkeydyc
-----END PRIVATE KEY-----"""
    
    @patch('builtins.open', mock_open(read_data="test content"))
    @patch('forti_cert_swap.Path')
    def test_load_file_success(self, mock_path):
        """Test successful file loading."""
        mock_path_obj = Mock()
        mock_path_obj.exists.return_value = True
        mock_path_obj.is_file.return_value = True
        mock_path.return_value = mock_path_obj
        
        content = CertificateProcessor.load_file("test.pem")
        self.assertEqual(content, "test content")
    
    @patch('forti_cert_swap.Path')
    def test_load_file_not_found(self, mock_path):
        """Test loading non-existent file."""
        mock_path_obj = Mock()
        mock_path_obj.exists.return_value = False
        mock_path.return_value = mock_path_obj
        
        with self.assertRaises(CertificateError) as cm:
            CertificateProcessor.load_file("nonexistent.pem")
        self.assertIn("File not found", str(cm.exception))
    
    @patch('builtins.open', mock_open(read_data=""))
    @patch('forti_cert_swap.Path')
    def test_load_file_empty(self, mock_path):
        """Test loading empty file."""
        mock_path_obj = Mock()
        mock_path_obj.exists.return_value = True
        mock_path_obj.is_file.return_value = True
        mock_path.return_value = mock_path_obj
        
        with self.assertRaises(CertificateError) as cm:
            CertificateProcessor.load_file("empty.pem")
        self.assertIn("File is empty", str(cm.exception))
    
    def test_validate_certificate_format_valid(self):
        """Test valid certificate format validation."""
        # Should not raise exception
        CertificateProcessor.validate_certificate_format(self.sample_cert_pem)
    
    def test_validate_certificate_format_invalid(self):
        """Test invalid certificate format validation."""
        with self.assertRaises(CertificateError) as cm:
            CertificateProcessor.validate_certificate_format("invalid cert data")
        self.assertIn("Invalid certificate format", str(cm.exception))
    
    def test_validate_private_key_format_valid(self):
        """Test valid private key format validation."""
        # Should not raise exception
        CertificateProcessor.validate_private_key_format(self.sample_key_pem)
    
    def test_validate_private_key_format_invalid(self):
        """Test invalid private key format validation."""
        with self.assertRaises(CertificateError) as cm:
            CertificateProcessor.validate_private_key_format("invalid key data")
        self.assertIn("Invalid private key format", str(cm.exception))
    
    def test_split_pem_chain(self):
        """Test PEM chain splitting."""
        chain = self.sample_cert_pem + "\n" + self.sample_cert_pem
        parts = CertificateProcessor._split_pem_chain(chain)
        self.assertEqual(len(parts), 2)
    
    def test_base_from_name(self):
        """Test extracting base name from certificate name."""
        self.assertEqual(CertificateProcessor.base_from_name("example.com-20251108"), "example.com")
        self.assertEqual(CertificateProcessor.base_from_name("no-date-format"), "no-date-format")


class TestLogger(unittest.TestCase):
    """Test logging functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
    
    def test_logger_creation_with_file(self):
        """Test logger creation with file output."""
        logger = Logger(str(self.log_file), LogLevel.STANDARD)
        self.assertIsNotNone(logger.fp)
        logger.close()
    
    def test_logger_creation_without_file(self):
        """Test logger creation without file output."""
        logger = Logger(None, LogLevel.STANDARD)
        self.assertIsNone(logger.fp)
    
    def test_log_scrubbing(self):
        """Test sensitive data scrubbing."""
        logger = Logger(None, LogLevel.STANDARD)
        
        # Test token scrubbing
        scrubbed = logger._scrub("Bearer abc123token")
        self.assertIn("<REDACTED>", scrubbed)
        self.assertNotIn("abc123token", scrubbed)
        
        # Test JSON token scrubbing
        scrubbed = logger._scrub('{"token": "secret123"}')
        self.assertIn("<REDACTED>", scrubbed)
        self.assertNotIn("secret123", scrubbed)
    
    def test_debug_logging_levels(self):
        """Test debug logging only works in debug mode."""
        # Standard level - debug should not log
        logger_std = Logger(str(self.log_file), LogLevel.STANDARD)
        logger_std.debug("debug message")
        logger_std.close()
        
        with open(self.log_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, "")
        
        # Debug level - debug should log
        logger_debug = Logger(str(self.log_file), LogLevel.DEBUG)
        logger_debug.debug("debug message")
        logger_debug.close()
        
        with open(self.log_file, 'r') as f:
            content = f.read()
        self.assertIn("DEBUG debug message", content)


class TestFortiAPI(unittest.TestCase):
    """Test FortiGate API client."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = Config(
            host="fortigate.example.com",
            port=443,
            token="test-token"
        )
        self.logger = Logger(None, LogLevel.STANDARD)
    
    @patch('forti_cert_swap.requests.Session')
    def test_api_initialization(self, mock_session_class):
        """Test API client initialization."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        api = FortiAPI(self.config, self.logger)
        
        self.assertEqual(api.base_url, "https://fortigate.example.com:443/api/v2")
        mock_session.headers.update.assert_called_with({"Authorization": "Bearer test-token"})
    
    @patch('forti_cert_swap.requests.Session')
    def test_api_request_success(self, mock_session_class):
        """Test successful API request."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_session.request.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        api = FortiAPI(self.config, self.logger)
        code, data = api.cmdb_get("test/path")
        
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "success")
    
    @patch('forti_cert_swap.requests.Session')
    def test_api_ssl_error(self, mock_session_class):
        """Test SSL error handling."""
        from requests.exceptions import SSLError
        
        mock_session = Mock()
        mock_session.request.side_effect = SSLError("CERTIFICATE_VERIFY_FAILED")
        mock_session_class.return_value = mock_session
        
        api = FortiAPI(self.config, self.logger)
        
        with self.assertRaises(APIError) as cm:
            api.cmdb_get("test/path")
        self.assertIn("TLS verification failed", str(cm.exception))


class TestCertificateOperations(unittest.TestCase):
    """Test certificate operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = Config(
            host="fortigate.example.com",
            port=443,
            token="test-token"
        )
        self.logger = Logger(None, LogLevel.STANDARD)
        self.mock_api = Mock()
        self.cert_ops = CertificateOperations(self.mock_api, self.config, self.logger)
    
    def test_upload_cert_dry_run(self):
        """Test certificate upload in dry-run mode."""
        self.config.dry_run = True
        
        state, detail = self.cert_ops.upload_or_update_cert(
            "test-cert", "cert-pem", "key-pem"
        )
        
        self.assertEqual(state, "dry_run")
        self.assertTrue(detail["would_post"])
    
    def test_upload_cert_create_success(self):
        """Test successful certificate creation."""
        self.mock_api.cmdb_post.return_value = (200, {"status": "success"})
        
        state, detail = self.cert_ops.upload_or_update_cert(
            "test-cert", "cert-pem", "key-pem"
        )
        
        self.assertEqual(state, "created")
        self.assertEqual(detail["status"], "success")
    
    def test_upload_cert_update_success(self):
        """Test successful certificate update."""
        self.mock_api.cmdb_post.return_value = (400, {"error": "exists"})
        self.mock_api.cmdb_put.return_value = (200, {"status": "updated"})
        
        state, detail = self.cert_ops.upload_or_update_cert(
            "test-cert", "cert-pem", "key-pem"
        )
        
        self.assertEqual(state, "updated")
        self.assertEqual(detail["status"], "updated")
    
    def test_bind_gui_success(self):
        """Test successful GUI binding."""
        self.mock_api.cmdb_put.return_value = (200, {"status": "success"})
        
        success, detail = self.cert_ops.bind_gui("test-cert")
        
        self.assertTrue(success)
        self.assertEqual(detail["http_status"], 200)
    
    def test_list_local_certs(self):
        """Test listing local certificates."""
        self.mock_api.cmdb_get.return_value = (200, {
            "results": [
                {"name": "cert1"},
                {"name": "cert2"},
                {"invalid": "entry"}  # Should be ignored
            ]
        })
        
        certs = self.cert_ops.list_local_certs()
        
        self.assertEqual(len(certs), 2)
        self.assertIn("cert1", certs)
        self.assertIn("cert2", certs)
    
    def test_prune_old_certificates(self):
        """Test pruning old certificates with enhanced logic."""
        self.config.prune = True
        
        # Mock certificate list
        self.mock_api.cmdb_get.side_effect = [
            # First call: list_local_certs
            (200, {
                "results": [
                    {"name": "example.com-20251108"},  # Current cert
                    {"name": "example.com-20251001"},  # Old cert to delete
                    {"name": "other.com-20251108"},    # Different base, skip
                ]
            }),
            # Subsequent calls: check_certificate_bindings for example.com-20251001
            (200, {"results": [{"admin-server-cert": "different-cert"}]}),  # GUI check
            (200, {"results": [{"servercert": "different-cert"}]}),         # SSL-VPN check
            (200, {"results": [{"server-cert": "different-cert"}]}),        # FTM check
            # SSL inspection profiles check (empty)
            (200, {"results": []})
        ]
        
        # Mock successful deletion
        self.mock_api.cmdb_delete.return_value = (200, {"status": "deleted"})
        
        result = self.cert_ops.prune_old_certificates("example.com-20251108")
        
        self.assertEqual(len(result["deleted"]), 1)
        self.assertIn("example.com-20251001", result["deleted"])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(result["skipped"][0]["name"], "other.com-20251108")
    
    def test_cert_only_upload(self):
        """Test certificate-only upload method."""
        self.mock_api.cmdb_post.return_value = (200, {"status": "success"})
        
        state, detail = self.cert_ops.cert_only_upload(
            "test-cert", "cert-pem", "key-pem"
        )
        
        self.assertEqual(state, "created")
        self.assertEqual(detail["status"], "success")
    
    def test_check_certificate_bindings(self):
        """Test certificate service binding checks."""
        # Mock API responses for service binding checks
        self.mock_api.cmdb_get.side_effect = [
            # GUI binding check
            (200, {"results": [{"admin-server-cert": "test-cert"}]}),
            # SSL-VPN binding check
            (200, {"results": [{"servercert": "different-cert"}]}),
            # FTM binding check
            (200, {"results": [{"server-cert": "different-cert"}]}),
            # SSL inspection profiles check
            (200, {"results": []})
        ]
        
        bindings = self.cert_ops.check_certificate_bindings("test-cert")
        
        self.assertTrue(bindings["gui"])
        self.assertFalse(bindings["ssl_vpn"])
        self.assertFalse(bindings["ftm"])
        self.assertFalse(bindings["ssl_inspection"])


class TestFortiCertSwapIntegration(unittest.TestCase):
    """Integration tests for the main application."""
    
    @patch('forti_cert_swap.sys.argv', ['forti_cert_swap.py', '--help'])
    def test_help_argument(self):
        """Test help argument parsing."""
        app = FortiCertSwap()
        
        with self.assertRaises(SystemExit):
            app.parse_arguments()
    
    def test_configuration_error_handling(self):
        """Test configuration error handling."""
        app = FortiCertSwap()
        
        # Test no arguments (should show usage and exit 0)
        with patch('forti_cert_swap.sys.argv', ['forti_cert_swap.py']):
            exit_code = app.run()
            self.assertEqual(exit_code, 0)
        
        # Test actual configuration error (should exit 1)
        with patch.object(app, 'parse_arguments') as mock_parse:
            mock_parse.return_value = Mock(config=None)
            
            with patch.object(ConfigManager, 'merge_args_with_config') as mock_merge:
                mock_merge.side_effect = ConfigurationError("Test error")
                
                with patch('forti_cert_swap.sys.argv', ['forti_cert_swap.py', '--host', 'test']):
                    exit_code = app.run()
                    self.assertEqual(exit_code, 1)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""
    
    def test_scope_params_global(self):
        """Test global scope parameters."""
        from forti_cert_swap import _scope_params
        
        params = _scope_params("global", None)
        self.assertEqual(params, {"scope": "global"})
    
    def test_scope_params_vdom(self):
        """Test VDOM scope parameters."""
        from forti_cert_swap import _scope_params
        
        params = _scope_params("vdom", "test-vdom")
        self.assertEqual(params, {"vdom": "test-vdom"})
        
        # Test default VDOM
        params = _scope_params("vdom", None)
        self.assertEqual(params, {"vdom": "root"})


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)
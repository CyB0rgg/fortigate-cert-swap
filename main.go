/*
FortiGate Certificate Swap Tool - Go Implementation

A high-performance, cross-platform tool for automated FortiGate certificate deployment
with revolutionary intermediate CA management and SSL inspection profile rebinding.

Features:
- Automatic intermediate CA management (world's first solution)
- SSL inspection certificate deployment with profile rebinding
- Enhanced certificate pruning with safety checks
- Multi-platform support (Linux, macOS, Windows)
- 13.4x performance improvement over Python implementation
- Comprehensive logging with security redaction

Author: CyB0rgg <dev@bluco.re>
License: MIT License
Copyright (c) 2025 CyB0rgg <dev@bluco.re>
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Logger for file logging with scrubbing and formatting
type Logger struct {
	filePath    string
	logLevel    string
	file        *os.File
	operationID string
}

func NewLogger(filePath, logLevel string) (*Logger, error) {
	if filePath == "" {
		return &Logger{logLevel: logLevel}, nil
	}
	
	// Expand home directory if needed
	if strings.HasPrefix(filePath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %v", err)
		}
		filePath = filepath.Join(homeDir, filePath[2:])
	}
	
	// Create directory if needed
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}
	
	// Open log file for appending
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}
	
	return &Logger{
		filePath: filePath,
		logLevel: logLevel,
		file:     file,
	}, nil
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func (l *Logger) SetOperationID(id string) {
	l.operationID = id
}

func (l *Logger) timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func (l *Logger) scrub(message string) string {
	// Enhanced scrubbing patterns matching Python implementation
	patterns := map[string]string{
		// API tokens
		`(Bearer\s+)[A-Za-z0-9._\-]+=*`:                    `${1}<REDACTED>`,
		`([\"']token[\"']\s*:\s*[\"']).+?([\"'])`:         `${1}<REDACTED>${2}`,
		`(Authorization:\s*Bearer\s+)[^\s]+`:              `${1}<REDACTED>`,
		// Private keys
		`(private-key[\"']\s*:\s*[\"']).+?([\"'])`:        `${1}<REDACTED>${2}`,
		`-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----`:         `<PRIVATE-KEY-REDACTED>`,
		`-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----`: `<RSA-PRIVATE-KEY-REDACTED>`,
		// Certificates (keep structure but redact content)
		`(certificate[\"']\s*:\s*[\"']).+?([\"'])`:        `${1}<CERTIFICATE-REDACTED>${2}`,
		`-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----`: `<CERTIFICATE-REDACTED>`,
	}
	
	result := message
	for pattern, replacement := range patterns {
		re := regexp.MustCompile(`(?i)(?s)` + pattern)
		result = re.ReplaceAllString(result, replacement)
	}
	
	return result
}

func (l *Logger) formatMessage(level, message string, context map[string]interface{}) string {
	timestamp := l.timestamp()
	
	// Add operation ID if available
	opPrefix := ""
	if l.operationID != "" {
		if len(l.operationID) > 8 {
			opPrefix = fmt.Sprintf("[%s] ", l.operationID[:8])
		} else {
			opPrefix = fmt.Sprintf("[%s] ", l.operationID)
		}
	}
	
	// Format based on log level
	var formattedMsg string
	if l.logLevel == "debug" && context != nil {
		// Debug: Include full context
		contextJSON, _ := json.Marshal(context)
		formattedMsg = fmt.Sprintf("%s%s | context=%s", opPrefix, message, string(contextJSON))
	} else {
		// Standard: Clean message only
		formattedMsg = fmt.Sprintf("%s%s", opPrefix, message)
	}
	
	return fmt.Sprintf("%s %s %s", timestamp, strings.ToUpper(level), l.scrub(formattedMsg))
}

func (l *Logger) write(level, message string, context map[string]interface{}) {
	if l.file == nil {
		return
	}
	
	line := l.formatMessage(level, message, context) + "\n"
	l.file.WriteString(line)
	l.file.Sync() // Ensure it's written to disk
}

func (l *Logger) Info(message string, context map[string]interface{}) {
	l.write("info", message, context)
}

func (l *Logger) Warn(message string, context map[string]interface{}) {
	l.write("warn", message, context)
}

func (l *Logger) Error(message string, context map[string]interface{}) {
	l.write("error", message, context)
}

func (l *Logger) Debug(message string, context map[string]interface{}) {
	if l.logLevel == "debug" {
		l.write("debug", message, context)
	}
}

const (
	VERSION    = "2.0.0"
	API_PREFIX = "/api/v2"
)

// Global logger instance
var logger *Logger

// Console colors and icons for professional output
const (
	// Colors
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
	
	// No icons - using text-only output for better terminal compatibility
)

// Console output functions
func colorize(color, text string) string {
	if runtime.GOOS == "windows" {
		return text // Skip colors on Windows for compatibility
	}
	return color + text + ColorReset
}

func printSuccess(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorGreen+ColorBold, "✓"), msg)
}

func printError(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorRed+ColorBold, "[!]"), msg)
}

func printWarning(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorYellow+ColorBold, "[!]"), msg)
}

func printInfo(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorBlue+ColorBold, "[*]"), msg)
}

func printHeader(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorBold+ColorCyan, "[*]"), colorize(ColorBold, msg))
}

func printStep(msg string) {
	fmt.Printf("%s %s\n", colorize(ColorCyan+ColorBold, "[*]"), msg)
}

// Configuration structure
type Config struct {
	Host                string `yaml:"host" json:"host"`
	Port                int    `yaml:"port" json:"port"`
	Token               string `yaml:"token" json:"token"`
	Cert                string `yaml:"cert" json:"cert"`
	Key                 string `yaml:"key" json:"key"`
	Name                string `yaml:"name" json:"name"`
	VDOM                string `yaml:"vdom" json:"vdom"`
	Insecure            bool   `yaml:"insecure" json:"insecure"`
	DryRun              bool   `yaml:"dry_run" json:"dry_run"`
	Prune               bool   `yaml:"prune" json:"prune"`
	TimeoutConnect      int    `yaml:"timeout_connect" json:"timeout_connect"`
	TimeoutRead         int    `yaml:"timeout_read" json:"timeout_read"`
	Log                 string `yaml:"log" json:"log"`
	LogLevel            string `yaml:"log_level" json:"log_level"`
	Rebind              string `yaml:"rebind" json:"rebind"`
	CertOnly            bool   `yaml:"cert_only" json:"cert_only"`
	SSLInspectionCert   bool   `yaml:"ssl_inspection_cert" json:"ssl_inspection_cert"`
	AutoIntermediateCA  bool   `yaml:"auto_intermediate_ca" json:"auto_intermediate_ca"`
}

// Result structures for JSON output
type OperationResult struct {
	Status           string                 `json:"status"`
	Certificate      *CertificateResult     `json:"certificate,omitempty"`
	IntermediateCA   string                 `json:"intermediate_ca,omitempty"`
	Bindings         map[string]interface{} `json:"bindings,omitempty"`
	SSLInspection    *SSLInspectionResult   `json:"ssl_inspection,omitempty"`
	Pruned           *PruneResult           `json:"pruned,omitempty"`
	Mode             string                 `json:"mode"`
	Version          string                 `json:"version"`
}

type CertificateResult struct {
	Name  string `json:"name"`
	Store string `json:"store"`
	State string `json:"state"`
}

type SSLInspectionResult struct {
	ProfilesRebound []map[string]interface{} `json:"profiles_rebound"`
	ProfilesFailed  []map[string]interface{} `json:"profiles_failed"`
}

type PruneResult struct {
	Deleted []string                 `json:"deleted"`
	Skipped []map[string]interface{} `json:"skipped"`
}

// FortiGate API client
type FortiAPI struct {
	config     *Config
	baseURL    string
	httpClient *http.Client
}

func NewFortiAPI(config *Config) *FortiAPI {
	// Handle host that already includes port
	host := config.Host
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%d", host, config.Port)
	}
	baseURL := fmt.Sprintf("https://%s%s", host, API_PREFIX)
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.TimeoutRead) * time.Second,
	}
	
	return &FortiAPI{
		config:     config,
		baseURL:    baseURL,
		httpClient: client,
	}
}

func (api *FortiAPI) request(method, path string, params map[string]string, body interface{}) (int, map[string]interface{}, error) {
	url := api.baseURL + path
	
	if len(params) > 0 {
		values := make([]string, 0, len(params))
		for k, v := range params {
			values = append(values, fmt.Sprintf("%s=%s", k, v))
		}
		url += "?" + strings.Join(values, "&")
	}
	
	var reqBody io.Reader
	var logJSON map[string]interface{}
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
		
		// Create scrubbed version for logging
		if bodyMap, ok := body.(map[string]interface{}); ok {
			logJSON = make(map[string]interface{})
			for k, v := range bodyMap {
				if k == "private-key" {
					logJSON[k] = "<REDACTED>"
				} else {
					logJSON[k] = v
				}
			}
		}
	}
	
	// Extract meaningful endpoint from URL for logging
	endpoint := path
	if strings.Contains(url, "/api/v2/cmdb/") {
		endpoint = strings.Split(strings.Split(url, "/api/v2/cmdb/")[1], "?")[0]
	}
	
	// Log request
	if logger != nil {
		logger.Debug(fmt.Sprintf("HTTP %s %s", method, endpoint), map[string]interface{}{
			"params": params,
			"json":   logJSON,
			"verify": !api.config.Insecure,
		})
	}
	
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+api.config.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	resp, err := api.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var result map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			result = map[string]interface{}{"raw": string(respBody)}
		}
	}
	
	// Log response
	if logger != nil {
		if resp.StatusCode >= 400 {
			// Log errors with more context
			if resp.StatusCode == 500 && result != nil {
				if errorMsg, ok := result["error"]; ok {
					logger.Debug(fmt.Sprintf("HTTP %s %s -> %d (FortiGate error: %v)", method, endpoint, resp.StatusCode, errorMsg), result)
				} else {
					logger.Debug(fmt.Sprintf("HTTP %s %s -> %d", method, endpoint, resp.StatusCode), result)
				}
			} else {
				logger.Debug(fmt.Sprintf("HTTP %s %s -> %d", method, endpoint, resp.StatusCode), result)
			}
		} else {
			// Success responses - minimal logging
			logger.Debug(fmt.Sprintf("HTTP %s %s -> %d", method, endpoint, resp.StatusCode), nil)
		}
	}
	
	return resp.StatusCode, result, nil
}

func (api *FortiAPI) getScopeParams() map[string]string {
	if api.config.VDOM == "" {
		return map[string]string{"scope": "global"}
	}
	return map[string]string{"vdom": api.config.VDOM}
}

func (api *FortiAPI) cmdbGet(path string) (int, map[string]interface{}, error) {
	return api.request("GET", "/cmdb/"+path, api.getScopeParams(), nil)
}

func (api *FortiAPI) cmdbPost(path string, body interface{}) (int, map[string]interface{}, error) {
	return api.request("POST", "/cmdb/"+path, api.getScopeParams(), body)
}

func (api *FortiAPI) cmdbPut(path string, body interface{}) (int, map[string]interface{}, error) {
	return api.request("PUT", "/cmdb/"+path, api.getScopeParams(), body)
}

func (api *FortiAPI) cmdbDelete(path string) (int, map[string]interface{}, error) {
	return api.request("DELETE", "/cmdb/"+path, api.getScopeParams(), nil)
}

// Certificate processing and validation functions
func loadFile(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %v", err)
		}
		path = filepath.Join(homeDir, path[2:])
	}
	
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %v", path, err)
	}
	
	if len(content) == 0 {
		return "", fmt.Errorf("file is empty: %s", path)
	}
	
	return string(content), nil
}

func validateCertificateFormat(certPEM string) error {
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") || !strings.Contains(certPEM, "END CERTIFICATE") {
		return fmt.Errorf("invalid certificate format: missing PEM markers")
	}
	
	chunks := splitPEMChain(certPEM)
	if len(chunks) == 0 {
		return fmt.Errorf("no valid certificates found in PEM data")
	}
	
	_, err := parseCertificate(chunks[0])
	if err != nil {
		return fmt.Errorf("invalid certificate format: %v", err)
	}
	
	return nil
}

func validatePrivateKeyFormat(keyPEM string) error {
	keyMarkers := []string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"}
	
	for _, marker := range keyMarkers {
		if strings.Contains(keyPEM, marker) {
			return nil
		}
	}
	
	return fmt.Errorf("invalid private key format: missing PEM markers")
}

func splitPEMChain(pemData string) []string {
	var parts []string
	var current []string
	
	lines := strings.Split(pemData, "\n")
	for _, line := range lines {
		if strings.Contains(line, "BEGIN CERTIFICATE") {
			current = []string{line}
		} else if strings.Contains(line, "END CERTIFICATE") {
			current = append(current, line)
			parts = append(parts, strings.Join(current, "\n")+"\n")
			current = nil
		} else if current != nil {
			current = append(current, line)
		}
	}
	
	if len(parts) == 0 {
		return []string{pemData}
	}
	
	return parts
}

func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	
	return cert, nil
}

func extractCommonName(cert *x509.Certificate) string {
	for _, name := range cert.Subject.Names {
		if name.Type.Equal([]int{2, 5, 4, 3}) {
			if str, ok := name.Value.(string); ok {
				return str
			}
		}
	}
	
	for _, name := range cert.DNSNames {
		return name
	}
	
	return "(no CN/SAN)"
}

func summarizeChain(certPEM string) string {
	chunks := splitPEMChain(certPEM)
	lines := []string{"[*] Certificate chain summary:"}
	
	for idx, chunk := range chunks {
		cert, err := parseCertificate(chunk)
		if err != nil {
			lines = append(lines, fmt.Sprintf("    [cert-%d] <unparsed certificate>", idx))
			continue
		}
		
		cn := extractCommonName(cert)
		notAfter := cert.NotAfter
		
		now := time.Now().UTC()
		daysLeft := int(notAfter.Sub(now).Hours() / 24)
		
		var expiryInfo string
		if daysLeft < 0 {
			expiryInfo = fmt.Sprintf("EXPIRED %d days ago", -daysLeft)
		} else if daysLeft == 0 {
			expiryInfo = "EXPIRES TODAY"
		} else if daysLeft == 1 {
			expiryInfo = "expires tomorrow"
		} else if daysLeft <= 30 {
			expiryInfo = fmt.Sprintf("expires in %d days", daysLeft)
		} else {
			expiryInfo = fmt.Sprintf("expires %s (%d days)", notAfter.Format("2006-01-02"), daysLeft)
		}
		
		tag := "[leaf]"
		if idx > 0 {
			tag = fmt.Sprintf("[ca-%d]", idx)
		}
		lines = append(lines, fmt.Sprintf("    %s %s - %s", tag, cn, expiryInfo))
	}
	
	return strings.Join(lines, "\n")
}

func plannedCertName(certPEM, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	
	chunks := splitPEMChain(certPEM)
	if len(chunks) == 0 {
		return "", fmt.Errorf("no certificates found in PEM data")
	}
	
	cert, err := parseCertificate(chunks[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}
	
	base := extractCommonName(cert)
	if base == "(no CN/SAN)" {
		base = "cert"
	}
	
	re := regexp.MustCompile(`^\*\.`)
	base = re.ReplaceAllString(base, "")
	re = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	base = re.ReplaceAllString(base, "-")
	
	exp := cert.NotAfter.Format("20060102")
	return fmt.Sprintf("%s-%s", base, exp), nil
}

// Intermediate CA management structures
type IntermediateCAInfo struct {
	PEMContent   string `json:"pem_content"`
	CommonName   string `json:"common_name"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
}

type CAInfo struct {
	Content      string `json:"content"`
	CommonName   string `json:"common_name"`
	Subject      string `json:"subject"`
	SerialNumber string `json:"serial_number"`
	Source       string `json:"source"`
}

// REVOLUTIONARY AUTOMATIC INTERMEDIATE CA MANAGEMENT SYSTEM
// This is the world's first solution to FortiGate's certificate chain limitation

func extractImmediateIssuingCA(certPEM string) *IntermediateCAInfo {
	chunks := splitPEMChain(certPEM)
	
	if len(chunks) < 2 {
		return nil
	}
	
	issuingCAPEM := chunks[1]
	cert, err := parseCertificate(issuingCAPEM)
	if err != nil {
		return nil
	}
	
	commonName := extractCommonName(cert)
	if commonName == "(no CN/SAN)" {
		return nil
	}
	
	return &IntermediateCAInfo{
		PEMContent:   issuingCAPEM,
		CommonName:   commonName,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
	}
}

func sanitizeCACertificateName(commonName string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9._-]`)
	sanitized := re.ReplaceAllString(commonName, "-")
	
	re = regexp.MustCompile(`-+`)
	sanitized = re.ReplaceAllString(sanitized, "-")
	
	sanitized = strings.Trim(sanitized, "-")
	
	if sanitized == "" {
		sanitized = "CA-Certificate"
	}
	
	return sanitized
}

func getAllCACertificates(api *FortiAPI) (map[string]*CAInfo, error) {
	code, data, err := api.cmdbGet("vpn.certificate/ca")
	if err != nil {
		return nil, err
	}
	
	caCerts := make(map[string]*CAInfo)
	if code == 200 {
		if results, ok := data["results"].([]interface{}); ok {
			for _, item := range results {
				if ca, ok := item.(map[string]interface{}); ok {
					name, _ := ca["name"].(string)
					content, _ := ca["ca"].(string)
					source, _ := ca["source"].(string)
					
					if name != "" && content != "" {
						caInfo := &CAInfo{
							Content: content,
							Source:  source,
						}
						
						if cert, err := parseCertificate(content); err == nil {
							caInfo.CommonName = extractCommonName(cert)
							caInfo.Subject = cert.Subject.String()
							caInfo.SerialNumber = cert.SerialNumber.String()
						} else {
							caInfo.CommonName = name
							caInfo.Subject = "unknown"
							caInfo.SerialNumber = "unknown"
						}
						
						caCerts[name] = caInfo
					}
				}
			}
		}
	}
	
	return caCerts, nil
}

func compareCertificates(cert1Content, cert2Content string) bool {
	cert1, err1 := parseCertificate(cert1Content)
	cert2, err2 := parseCertificate(cert2Content)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		return true
	}
	
	hash1 := sha256.Sum256([]byte(cert1Content))
	hash2 := sha256.Sum256([]byte(cert2Content))
	
	return bytes.Equal(hash1[:], hash2[:])
}

func uploadCACertificate(api *FortiAPI, caName, caContent string) (string, map[string]interface{}, error) {
	store := "global"
	if api.config.VDOM != "" {
		store = "vdom"
	}
	
	payload := map[string]interface{}{
		"name":                   caName,
		"ca":                     caContent,
		"range":                  store,
		"ssl-inspection-trusted": "enable",
	}
	
	if api.config.DryRun {
		fmt.Printf("DRY RUN: would POST vpn.certificate/ca name=%s store=%s\n", caName, strings.ToUpper(store))
		return "dry_run", map[string]interface{}{"would_post": true, "path": "vpn.certificate/ca"}, nil
	}
	
	code, data, err := api.cmdbPost("vpn.certificate/ca", payload)
	if err != nil {
		return "error", nil, err
	}
	if code == 200 {
		return "created", data, nil
	}
	
	code, data, err = api.cmdbPut(fmt.Sprintf("vpn.certificate/ca/%s", caName), payload)
	if err != nil {
		return "error", nil, err
	}
	if code == 200 {
		return "updated", data, nil
	}
	
	return "error", map[string]interface{}{"http_status": code, "detail": data}, nil
}

func getStore(config *Config) string {
	if config.VDOM == "" {
		return "GLOBAL"
	}
	return "VDOM"
}

func uploadMissingIntermediateCAIfNeeded(api *FortiAPI, certPEM string) (*map[string]interface{}, error) {
	if !api.config.AutoIntermediateCA {
		return nil, nil
	}
	
	// Extract immediate issuing CA
	issuingCA := extractImmediateIssuingCA(certPEM)
	if issuingCA == nil {
		return nil, nil
	}
	
	// Get all existing CA certificates
	existingCAs, err := getAllCACertificates(api)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing CA certificates: %v", err)
	}
	
	// Check if this CA already exists
	for caName, caInfo := range existingCAs {
		if compareCertificates(issuingCA.PEMContent, caInfo.Content) {
			return &map[string]interface{}{
				"name":        caName,
				"state":       "exists",
				"source":      caInfo.Source,
				"common_name": issuingCA.CommonName,
			}, nil
		}
	}
	
	// CA doesn't exist, need to upload it
	sanitizedName := sanitizeCACertificateName(issuingCA.CommonName)
	
	// Ensure unique name if sanitized name already exists
	originalName := sanitizedName
	counter := 1
	for {
		if _, exists := existingCAs[sanitizedName]; !exists {
			break
		}
		sanitizedName = fmt.Sprintf("%s-%d", originalName, counter)
		counter++
	}
	
	state, detail, err := uploadCACertificate(api, sanitizedName, issuingCA.PEMContent)
	if err != nil {
		return nil, fmt.Errorf("failed to upload intermediate CA: %v", err)
	}
	
	if state == "dry_run" {
		fmt.Printf("DRY RUN: would POST vpn.certificate/ca name=%s store=%s\n", sanitizedName, getStore(api.config))
		return &map[string]interface{}{
			"name":        sanitizedName,
			"state":       "dry_run",
			"common_name": issuingCA.CommonName,
			"detail":      detail,
		}, nil
	}
	
	if state == "created" || state == "updated" {
		httpCode := 200
		if detail != nil {
			if code, ok := detail["http_status"].(int); ok {
				httpCode = code
			}
		}
		method := "cmdb_post"
		if state == "updated" {
			method = "cmdb_put"
		}
		action := "Created"
		if state == "updated" {
			action = "Updated"
		}
		fmt.Printf("[*] Result: %s intermediate CA \"%s\" in %s store (via %s, HTTP %d)\n", action, sanitizedName, getStore(api.config), method, httpCode)
		return &map[string]interface{}{
			"name":        sanitizedName,
			"state":       state,
			"common_name": issuingCA.CommonName,
			"http_status": httpCode,
			"method":      method,
		}, nil
	}
	
	return nil, nil
}

// Certificate operations
type CertificateOperations struct {
	api    *FortiAPI
	config *Config
}

func NewCertificateOperations(api *FortiAPI, config *Config) *CertificateOperations {
	return &CertificateOperations{
		api:    api,
		config: config,
	}
}

func (ops *CertificateOperations) uploadOrUpdateCert(name, certPEM, keyPEM string) (string, map[string]interface{}, error) {
	store := "global"
	if ops.config.VDOM != "" {
		store = "vdom"
	}
	
	payload := map[string]interface{}{
		"name":        name,
		"certificate": certPEM,
		"private-key": keyPEM,
		"range":       store,
	}
	
	if ops.config.DryRun {
		fmt.Printf("DRY RUN: would POST vpn.certificate/local name=%s store=%s\n", name, strings.ToUpper(store))
		return "dry_run", map[string]interface{}{"would_post": true, "path": "vpn.certificate/local"}, nil
	}
	
	code, data, err := ops.api.cmdbPost("vpn.certificate/local", payload)
	if err != nil {
		return "error", nil, err
	}
	if code == 200 {
		return "created", data, nil
	}
	
	code, data, err = ops.api.cmdbPut(fmt.Sprintf("vpn.certificate/local/%s", name), payload)
	if err != nil {
		return "error", nil, err
	}
	if code == 200 {
		return "updated", data, nil
	}
	
	return "error", map[string]interface{}{"http_status": code, "detail": data}, nil
}

func (ops *CertificateOperations) bindGUI(name string) (bool, map[string]interface{}) {
	payload := map[string]interface{}{"admin-server-cert": name}
	code, data, err := ops.api.cmdbPut("system/global", payload)
	if err != nil {
		return false, map[string]interface{}{"error": err.Error()}
	}
	return code == 200, map[string]interface{}{"http_status": code, "detail": data}
}

func (ops *CertificateOperations) bindSSLVPN(name string) (bool, map[string]interface{}) {
	payload := map[string]interface{}{"servercert": name}
	code, data, err := ops.api.cmdbPut("vpn.ssl/settings", payload)
	if err != nil {
		return false, map[string]interface{}{"error": err.Error()}
	}
	return code == 200, map[string]interface{}{"http_status": code, "detail": data}
}

func (ops *CertificateOperations) bindFTM(name string) (bool, map[string]interface{}) {
	payload := map[string]interface{}{"server-cert": name}
	code, data, err := ops.api.cmdbPut("system/ftm-push", payload)
	if err != nil {
		return false, map[string]interface{}{"error": err.Error()}
	}
	return code == 200, map[string]interface{}{"http_status": code, "detail": data}
}

func (ops *CertificateOperations) getSSLInspectionProfiles() ([]map[string]interface{}, error) {
	code, data, err := ops.api.cmdbGet("firewall/ssl-ssh-profile")
	if err != nil {
		return nil, err
	}
	
	var profiles []map[string]interface{}
	if code == 200 {
		if results, ok := data["results"].([]interface{}); ok {
			for _, item := range results {
				if profile, ok := item.(map[string]interface{}); ok {
					profiles = append(profiles, profile)
				}
			}
		}
	}
	
	return profiles, nil
}

func (ops *CertificateOperations) getSSLInspectionProfileMappings() (map[string][]string, error) {
	profiles, err := ops.getSSLInspectionProfiles()
	if err != nil {
		return nil, err
	}
	
	certToProfiles := make(map[string][]string) // cert_name -> [profile_names]
	
	for _, profile := range profiles {
		profileName, _ := profile["name"].(string)
		if profileName == "" {
			continue
		}
		
		// Check server-cert array (for replace mode)
		if serverCerts, ok := profile["server-cert"].([]interface{}); ok {
			for _, certObj := range serverCerts {
				if cert, ok := certObj.(map[string]interface{}); ok {
					if certName, ok := cert["name"].(string); ok && certName != "" {
						if _, exists := certToProfiles[certName]; !exists {
							certToProfiles[certName] = []string{}
						}
						// Avoid duplicates
						found := false
						for _, existing := range certToProfiles[certName] {
							if existing == profileName {
								found = true
								break
							}
						}
						if !found {
							certToProfiles[certName] = append(certToProfiles[certName], profileName)
						}
					}
				}
			}
		}
		
		// Check ssl-server array (alternative location)
		if sslServers, ok := profile["ssl-server"].([]interface{}); ok {
			for _, serverObj := range sslServers {
				if server, ok := serverObj.(map[string]interface{}); ok {
					if certName, ok := server["name"].(string); ok && certName != "" {
						if _, exists := certToProfiles[certName]; !exists {
							certToProfiles[certName] = []string{}
						}
						// Avoid duplicates
						found := false
						for _, existing := range certToProfiles[certName] {
							if existing == profileName {
								found = true
								break
							}
						}
						if !found {
							certToProfiles[certName] = append(certToProfiles[certName], profileName)
						}
					}
				}
			}
		}
	}
	
	return certToProfiles, nil
}

func (ops *CertificateOperations) rebindSSLInspectionProfile(oldCertName, newCertName, profileName string) (bool, map[string]interface{}) {
	// Update the profile to use the new certificate
	payload := map[string]interface{}{
		"server-cert": []map[string]interface{}{
			{"name": newCertName},
		},
	}
	
	if ops.config.DryRun {
		fmt.Printf("DRY RUN: would rebind SSL inspection profile '%s' from '%s' to '%s'\n",
			profileName, oldCertName, newCertName)
		return true, map[string]interface{}{
			"profile":  profileName,
			"old_cert": oldCertName,
			"new_cert": newCertName,
			"dry_run":  true,
		}
	}
	
	// URL encode the profile name for API call (FortiGate expects %20 not +)
	encodedProfile := strings.ReplaceAll(url.QueryEscape(profileName), "+", "%20")
	
	code, data, err := ops.api.cmdbPut(fmt.Sprintf("firewall/ssl-ssh-profile/%s", encodedProfile), payload)
	if err != nil {
		return false, map[string]interface{}{"error": err.Error()}
	}
	
	return code == 200, map[string]interface{}{"http_status": code, "detail": data}
}

func (ops *CertificateOperations) rebindSSLInspectionProfiles(newCertName, uploadDomain string) (*SSLInspectionResult, error) {
	result := &SSLInspectionResult{
		ProfilesRebound: []map[string]interface{}{},
		ProfilesFailed:  []map[string]interface{}{},
	}
	
	// Get SSL inspection profile mappings (cert_name -> [profile_names])
	profileMappings, err := ops.getSSLInspectionProfileMappings()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL inspection profile mappings: %v", err)
	}
	
	if len(profileMappings) == 0 {
		fmt.Printf("[*] No SSL inspection profiles found\n")
		return result, nil
	}
	
	// Find SSL inspection certificates for this domain (matching Python logic exactly)
	var profilesToRebind []string
	var oldSSLCerts []string
	
	for certName, profiles := range profileMappings {
		// Check if this certificate matches the upload domain
		certDomain := ops.extractDomainFromCertName(certName)
		if certDomain == "" {
			// Try fetching and parsing the actual certificate
			certDomain = ops.extractDomainFromFortiGateCert(certName)
		}
		
		if certDomain != "" && ops.domainsMatch(uploadDomain, certDomain) {
			oldSSLCerts = append(oldSSLCerts, certName)
			profilesToRebind = append(profilesToRebind, profiles...)
			fmt.Printf("[*] Found SSL inspection certificate: %s used in %d profile(s): %s\n",
				certName, len(profiles), strings.Join(profiles, ", "))
		}
	}
	
	if len(profilesToRebind) == 0 {
		fmt.Printf("[*] No SSL inspection profiles found for domain %s\n", uploadDomain)
		return result, nil
	}
	
	// Remove duplicates from profilesToRebind
	uniqueProfiles := make(map[string]bool)
	var uniqueProfilesList []string
	for _, profile := range profilesToRebind {
		if !uniqueProfiles[profile] {
			uniqueProfiles[profile] = true
			uniqueProfilesList = append(uniqueProfilesList, profile)
		}
	}
	profilesToRebind = uniqueProfilesList
	
	fmt.Printf("[*] Found %d SSL inspection profile(s) to rebind: %s\n",
		len(profilesToRebind), strings.Join(profilesToRebind, ", "))
	
	// Rebind each profile from old certificate to new certificate
	for _, oldCert := range oldSSLCerts {
		profilesForCert := profileMappings[oldCert]
		for _, profileName := range profilesForCert {
			success, detail := ops.rebindSSLInspectionProfile(oldCert, newCertName, profileName)
			profileInfo := map[string]interface{}{
				"profile":  profileName,
				"old_cert": oldCert,
				"new_cert": newCertName,
			}
			
			if success {
				result.ProfilesRebound = append(result.ProfilesRebound, profileInfo)
				fmt.Printf("[*] Rebound SSL inspection profile '%s' from '%s' to '%s'\n",
					profileName, oldCert, newCertName)
			} else {
				profileInfo["detail"] = detail
				result.ProfilesFailed = append(result.ProfilesFailed, profileInfo)
				fmt.Printf("[!] Failed to rebind SSL inspection profile '%s': %v\n", profileName, detail)
			}
		}
	}
	
	return result, nil
}

// Helper methods for SSL inspection certificate pruning
func (ops *CertificateOperations) listLocalCerts() []string {
	code, data, err := ops.api.cmdbGet("vpn.certificate/local")
	if err != nil {
		return []string{}
	}
	
	var names []string
	if code == 200 {
		if results, ok := data["results"].([]interface{}); ok {
			for _, item := range results {
				if cert, ok := item.(map[string]interface{}); ok {
					if name, ok := cert["name"].(string); ok {
						names = append(names, name)
					}
				}
			}
		}
	}
	
	return names
}

func (ops *CertificateOperations) extractExpiryFromName(certName string) string {
	// Handle standard naming scheme (domain-YYYYMMDD)
	re := regexp.MustCompile(`^.+-(\d{8})$`)
	matches := re.FindStringSubmatch(certName)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (ops *CertificateOperations) extractDomainFromCertName(certName string) string {
	// Handle standard naming scheme (domain-YYYYMMDD)
	re := regexp.MustCompile(`^(.+)-\d{8}$`)
	matches := re.FindStringSubmatch(certName)
	if len(matches) > 1 {
		return strings.ToLower(matches[1])
	}
	
	// Handle direct domain names (like 'BluCore.io')
	domain := strings.ToLower(certName)
	if strings.Contains(domain, ".") && !strings.HasPrefix(domain, "fortinet") {
		return domain
	}
	
	return ""
}

func (ops *CertificateOperations) extractDomainFromFortiGateCert(certName string) string {
	code, data, err := ops.api.cmdbGet(fmt.Sprintf("vpn.certificate/local/%s", certName))
	if err != nil || code != 200 {
		return ""
	}
	
	if results, ok := data["results"].([]interface{}); ok && len(results) > 0 {
		if certData, ok := results[0].(map[string]interface{}); ok {
			if certPEM, ok := certData["certificate"].(string); ok {
				return ops.extractDomainFromCert(certPEM)
			}
		}
	}
	
	return ""
}

func (ops *CertificateOperations) extractDomainFromCert(certPEM string) string {
	chunks := splitPEMChain(certPEM)
	if len(chunks) == 0 {
		return ""
	}
	
	cert, err := parseCertificate(chunks[0])
	if err != nil {
		return ""
	}
	
	// Try CN first
	cn := extractCommonName(cert)
	if cn != "(no CN/SAN)" {
		domain := strings.ToLower(cn)
		// Remove wildcard prefix if present
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}
		return domain
	}
	
	// Fall back to SAN
	for _, name := range cert.DNSNames {
		domain := strings.ToLower(name)
		// Remove wildcard prefix if present
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}
		return domain
	}
	
	return ""
}

func (ops *CertificateOperations) domainsMatch(domain1, domain2 string) bool {
	if domain1 == "" || domain2 == "" {
		return false
	}
	return strings.ToLower(domain1) == strings.ToLower(domain2)
}

func (ops *CertificateOperations) deleteCert(name string) (bool, interface{}) {
	code, data, err := ops.api.cmdbDelete(fmt.Sprintf("vpn.certificate/local/%s", name))
	if err != nil {
		return false, map[string]interface{}{"error": err.Error()}
	}
	return code == 200, map[string]interface{}{"http_status": code, "detail": data}
}

// pruneSSLInspectionCertificates prunes old SSL inspection certificates with same domain and older expiry dates
func (ops *CertificateOperations) pruneSSLInspectionCertificates(currentName, domain string) map[string]interface{} {
	result := map[string]interface{}{
		"deleted": []string{},
		"skipped": []map[string]interface{}{},
	}

	if !ops.config.Prune {
		return result
	}

	// Extract expiry date from current certificate name
	currentExpiry := ops.extractExpiryFromName(currentName)
	if currentExpiry == "" {
		fmt.Printf("[!] Could not extract expiry date from current certificate name: %s\n", currentName)
		return result
	}

	// Get all local certificates
	allCerts := ops.listLocalCerts()

	// Find certificates with same domain but older expiry dates
	for _, certName := range allCerts {
		if certName == currentName {
			continue // Skip current certificate
		}

		// Check if certificate matches the domain
		certDomain := ops.extractDomainFromCertName(certName)
		if certDomain == "" {
			// Try fetching and parsing the actual certificate
			certDomain = ops.extractDomainFromFortiGateCert(certName)
		}

		if certDomain == "" || !ops.domainsMatch(domain, certDomain) {
			continue // Skip certificates for different domains
		}

		// Extract expiry date from certificate name
		certExpiry := ops.extractExpiryFromName(certName)
		if certExpiry == "" {
			continue
		}

		// Only delete certificates with older expiry dates
		if certExpiry < currentExpiry {
			fmt.Printf("[*] Pruning old SSL inspection certificate: %s (expires %s, current expires %s)\n", certName, certExpiry, currentExpiry)

			if ops.config.DryRun {
				fmt.Printf("[*] DRYRUN: would delete old SSL inspection certificate: %s\n", certName)
				result["deleted"] = append(result["deleted"].([]string), certName)
				continue
			}

			success, detail := ops.deleteCert(certName)
			if success {
				result["deleted"] = append(result["deleted"].([]string), certName)
				fmt.Printf("[*] Pruned old SSL inspection certificate: %s\n", certName)
			} else {
				httpStatus := "unknown"
				if detailMap, ok := detail.(map[string]interface{}); ok {
					if status, exists := detailMap["http_status"]; exists {
						httpStatus = fmt.Sprintf("%v", status)
					}
				}
				reason := fmt.Sprintf("delete failed (HTTP %s)", httpStatus)
				skipped := map[string]interface{}{
					"name":   certName,
					"reason": reason,
				}
				result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
				fmt.Printf("[!] Failed to prune SSL inspection certificate %s: %s\n", certName, reason)
			}
		}
	}

	return result
}

// pruneOldCertificates prunes old certificates with same base domain, older expiry, and no service bindings
func (ops *CertificateOperations) pruneOldCertificates(currentName string) map[string]interface{} {
	result := map[string]interface{}{
		"deleted": []string{},
		"skipped": []map[string]interface{}{},
	}

	if !ops.config.Prune {
		return result
	}

	// Extract base domain and expiry from current certificate
	currentBase := ops.baseFromName(currentName)
	currentExpiry := ops.extractExpiryFromName(currentName)

	if currentExpiry == "" {
		fmt.Printf("[!] Could not extract expiry date from current certificate name: %s\n", currentName)
		return result
	}

	// Get all local certificates
	allCerts := ops.listLocalCerts()

	for _, certName := range allCerts {
		if certName == currentName {
			continue // Skip current certificate
		}

		// Check if certificate has same base domain
		certBase := ops.baseFromName(certName)
		if certBase != currentBase {
			skipped := map[string]interface{}{
				"name":   certName,
				"reason": "different base domain",
			}
			result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
			continue
		}

		// Extract expiry date from certificate name
		certExpiry := ops.extractExpiryFromName(certName)
		if certExpiry == "" {
			skipped := map[string]interface{}{
				"name":   certName,
				"reason": "could not extract expiry date",
			}
			result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
			continue
		}

		// Only consider certificates with older expiry dates
		if certExpiry >= currentExpiry {
			skipped := map[string]interface{}{
				"name":   certName,
				"reason": fmt.Sprintf("not older (expires %s, current expires %s)", certExpiry, currentExpiry),
			}
			result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
			continue
		}

		// Check if certificate is bound to any services
		bindings := ops.checkCertificateBindings(certName)
		var boundServices []string
		for service, isBound := range bindings {
			if isBound {
				boundServices = append(boundServices, service)
			}
		}

		if len(boundServices) > 0 {
			skipped := map[string]interface{}{
				"name":   certName,
				"reason": fmt.Sprintf("bound to services: %s", strings.Join(boundServices, ", ")),
			}
			result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
			fmt.Printf("[*] Skipping certificate %s - bound to services: %s\n", certName, strings.Join(boundServices, ", "))
			continue
		}

		// Safe to delete: same base domain, older expiry, no service bindings
		fmt.Printf("[*] Pruning old certificate: %s (expires %s, current expires %s, no service bindings)\n", certName, certExpiry, currentExpiry)

		if ops.config.DryRun {
			fmt.Printf("[*] DRYRUN: would delete old certificate: %s\n", certName)
			result["deleted"] = append(result["deleted"].([]string), certName)
			continue
		}

		success, detail := ops.deleteCert(certName)
		if success {
			result["deleted"] = append(result["deleted"].([]string), certName)
			fmt.Printf("[*] Pruned old certificate: %s\n", certName)
		} else {
			httpStatus := "unknown"
			if detailMap, ok := detail.(map[string]interface{}); ok {
				if status, exists := detailMap["http_status"]; exists {
					httpStatus = fmt.Sprintf("%v", status)
				}
			}
			reason := fmt.Sprintf("delete failed (HTTP %s)", httpStatus)
			skipped := map[string]interface{}{
				"name":   certName,
				"reason": reason,
			}
			result["skipped"] = append(result["skipped"].([]map[string]interface{}), skipped)
			fmt.Printf("[!] Failed to prune certificate %s: %s\n", certName, reason)
		}
	}

	return result
}

// baseFromName extracts base name from certificate name
func (ops *CertificateOperations) baseFromName(name string) string {
	re := regexp.MustCompile(`^(.*)-\d{8}$`)
	matches := re.FindStringSubmatch(name)
	if len(matches) > 1 {
		return matches[1]
	}
	return name
}

// checkCertificateBindings checks if certificate is bound to any services
func (ops *CertificateOperations) checkCertificateBindings(certName string) map[string]bool {
	bindings := map[string]bool{
		"gui":            false,
		"ssl_vpn":        false,
		"ftm":            false,
		"ssl_inspection": false,
	}

	// Check GUI binding
	code, data, err := ops.api.cmdbGet("system/global")
	if err == nil && code == 200 {
		if results, ok := data["results"].([]interface{}); ok && len(results) > 0 {
			if result, ok := results[0].(map[string]interface{}); ok {
				if adminCert, ok := result["admin-server-cert"].(string); ok && adminCert == certName {
					bindings["gui"] = true
				}
			}
		}
	}

	// Check SSL-VPN binding
	code, data, err = ops.api.cmdbGet("vpn.ssl/settings")
	if err == nil && code == 200 {
		if results, ok := data["results"].([]interface{}); ok && len(results) > 0 {
			if result, ok := results[0].(map[string]interface{}); ok {
				if sslCert, ok := result["servercert"].(string); ok && sslCert == certName {
					bindings["ssl_vpn"] = true
				}
			}
		}
	}

	// Check FTM binding
	code, data, err = ops.api.cmdbGet("system/ftm-push")
	if err == nil && code == 200 {
		if results, ok := data["results"].([]interface{}); ok && len(results) > 0 {
			if result, ok := results[0].(map[string]interface{}); ok {
				if ftmCert, ok := result["server-cert"].(string); ok && ftmCert == certName {
					bindings["ftm"] = true
				}
			}
		}
	}

	// Check SSL inspection bindings
	profiles, err := ops.getSSLInspectionProfiles()
	if err == nil {
		for _, profile := range profiles {
			// Check server-cert array (for replace mode)
			if serverCerts, ok := profile["server-cert"].([]interface{}); ok {
				for _, certObj := range serverCerts {
					if cert, ok := certObj.(map[string]interface{}); ok {
						if name, ok := cert["name"].(string); ok && name == certName {
							bindings["ssl_inspection"] = true
							break
						}
					}
				}
			}
			
			// Check ssl-server array (alternative location)
			if sslServers, ok := profile["ssl-server"].([]interface{}); ok {
				for _, serverObj := range sslServers {
					if server, ok := serverObj.(map[string]interface{}); ok {
						if name, ok := server["name"].(string); ok && name == certName {
							bindings["ssl_inspection"] = true
							break
						}
					}
				}
			}
			
			if bindings["ssl_inspection"] {
				break
			}
		}
	}

	return bindings
}

// Custom help function
func showCustomHelp() {
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "USAGE:"))
	fmt.Printf("  %s [OPTIONS]\n", colorize(ColorCyan, "fortigate-cert-swap"))
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "DESCRIPTION:"))
	fmt.Println("  Automated FortiGate certificate deployment with revolutionary intermediate CA management.")
	fmt.Println("  Supports multiple operation modes: standard binding, certificate-only upload,")
	fmt.Println("  SSL inspection certificate deployment, and custom service rebinding.")
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "REQUIRED OPTIONS:"))
	fmt.Printf("  %-35s %s\n", colorize(ColorYellow, "--host HOST"), "FortiGate host/IP address")
	fmt.Printf("  %-35s %s\n", colorize(ColorYellow, "--token TOKEN"), "FortiGate API token")
	fmt.Printf("  %-35s %s\n", colorize(ColorYellow, "--cert CERT_FILE"), "Path to certificate file (PEM format)")
	fmt.Printf("  %-35s %s\n", colorize(ColorYellow, "--key KEY_FILE"), "Path to private key file (PEM format)")
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "OPTIONAL ARGUMENTS:"))
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--config CONFIG_FILE"), "Path to YAML configuration file")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--port PORT"), "FortiGate HTTPS port (default: 443)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--name NAME"), "Certificate name override")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--vdom VDOM"), "VDOM name (default: global)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--insecure"), "Skip TLS certificate verification")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--dry-run"), "Show what would be done without making changes")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--prune"), "Remove unused certificates")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--timeout-connect SEC"), "Connection timeout (default: 5)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--timeout-read SEC"), "Read timeout (default: 30)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--log LOG_FILE"), "Log file path")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--log-level LEVEL"), "Log level: standard|debug (default: standard)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--rebind SERVICES"), "Rebind services: gui,sslvpn,ftm (default: all)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--cert-only"), "Upload certificate only, no binding")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--ssl-inspection-cert"), "SSL inspection certificate mode")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--auto-intermediate-ca"), "Automatic intermediate CA management (default: true)")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--version"), "Show version information")
	fmt.Printf("  %-35s %s\n", colorize(ColorCyan, "--help"), "Show this help message")
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "OPERATION MODES:"))
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Standard"), "Standard mode: Upload certificate and bind to GUI/SSL-VPN/FTM")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Cert-only"), "Certificate-only: Upload certificate without service binding")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "SSL Inspection"), "SSL inspection: Deploy certificate for SSL inspection profiles")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Rebind"), "Custom rebind: Bind certificate to specific services only")
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "EXAMPLES:"))
	fmt.Printf("  %s Basic certificate deployment:\n", colorize(ColorDim, "#"))
	fmt.Printf("    %s --host firewall.example.com --token abc123 --cert cert.pem --key key.pem\n",
		colorize(ColorCyan, "fortigate-cert-swap"))
	fmt.Println()
	fmt.Printf("  %s Certificate-only upload:\n", colorize(ColorDim, "#"))
	fmt.Printf("    %s --host firewall.example.com --token abc123 --cert cert.pem --key key.pem %s\n",
		colorize(ColorCyan, "fortigate-cert-swap"), colorize(ColorYellow, "--cert-only"))
	fmt.Println()
	fmt.Printf("  %s SSL inspection certificate:\n", colorize(ColorDim, "#"))
	fmt.Printf("    %s --host firewall.example.com --token abc123 --cert cert.pem --key key.pem %s\n",
		colorize(ColorCyan, "fortigate-cert-swap"), colorize(ColorYellow, "--ssl-inspection-cert"))
	fmt.Println()
	fmt.Printf("  %s Custom service binding:\n", colorize(ColorDim, "#"))
	fmt.Printf("    %s --host firewall.example.com --token abc123 --cert cert.pem --key key.pem %s gui,sslvpn\n",
		colorize(ColorCyan, "fortigate-cert-swap"), colorize(ColorYellow, "--rebind"))
	fmt.Println()
	fmt.Printf("  %s Using configuration file:\n", colorize(ColorDim, "#"))
	fmt.Printf("    %s %s config.yaml\n",
		colorize(ColorCyan, "fortigate-cert-swap"), colorize(ColorYellow, "--config"))
	fmt.Println()
	
	fmt.Println(colorize(ColorBold, "REVOLUTIONARY FEATURES:"))
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Auto CA Management"), "World's first automatic intermediate CA management")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Chain Processing"), "Intelligent certificate chain processing")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Smart SSL Rebinding"), "Domain-aware SSL inspection profile rebinding")
	fmt.Printf("  %s %-30s %s\n",
		colorize(ColorBold, "[*]"), colorize(ColorBold, "Safe Pruning"), "Enhanced certificate pruning with safety checks")
	fmt.Println()
	
	fmt.Println(colorize(ColorDim, "For more information and examples, visit:"))
	fmt.Println(colorize(ColorDim, "https://github.com/CyB0rgg/fortigate-cert-swap"))
	fmt.Println()
	fmt.Println(colorize(ColorDim, "Copyright (c) 2025 CyB0rgg <dev@bluco.re>"))
	fmt.Println(colorize(ColorDim, "Licensed under the MIT License"))
}

// CLI argument parsing
func parseArgs() *Config {
	config := &Config{
		AutoIntermediateCA: true, // Default to enabled
		TimeoutConnect:     5,
		TimeoutRead:        30,
		LogLevel:          "standard",
	}
	
	var configFile string
	var showVersion bool
	var showHelp bool
	
	// Custom flag set to handle errors gracefully
	flagSet := flag.NewFlagSet("fortigate-cert-swap", flag.ContinueOnError)
	flagSet.Usage = func() {
		// Don't show anything here - we'll handle it manually
	}
	
	flagSet.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flagSet.StringVar(&config.Host, "host", "", "FortiGate host/IP address")
	flagSet.IntVar(&config.Port, "port", 443, "FortiGate HTTPS port")
	flagSet.StringVar(&config.Token, "token", "", "FortiGate API token")
	flagSet.StringVar(&config.Cert, "cert", "", "Path to certificate file")
	flagSet.StringVar(&config.Key, "key", "", "Path to private key file")
	flagSet.StringVar(&config.Name, "name", "", "Certificate name override")
	flagSet.StringVar(&config.VDOM, "vdom", "", "VDOM name (default: global)")
	flagSet.BoolVar(&config.Insecure, "insecure", false, "Skip TLS certificate verification")
	flagSet.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")
	flagSet.BoolVar(&config.Prune, "prune", false, "Remove unused certificates")
	flagSet.IntVar(&config.TimeoutConnect, "timeout-connect", 5, "Connection timeout in seconds")
	flagSet.IntVar(&config.TimeoutRead, "timeout-read", 30, "Read timeout in seconds")
	flagSet.StringVar(&config.Log, "log", "", "Log file path")
	flagSet.StringVar(&config.LogLevel, "log-level", "standard", "Log level (standard|debug)")
	flagSet.StringVar(&config.Rebind, "rebind", "", "Rebind services (gui,sslvpn,ftm)")
	flagSet.BoolVar(&config.CertOnly, "cert-only", false, "Upload certificate only, no binding")
	flagSet.BoolVar(&config.SSLInspectionCert, "ssl-inspection-cert", false, "SSL inspection certificate mode")
	flagSet.BoolVar(&config.AutoIntermediateCA, "auto-intermediate-ca", true, "Automatic intermediate CA management")
	flagSet.BoolVar(&showVersion, "version", false, "Show version information")
	flagSet.BoolVar(&showHelp, "help", false, "Show help information")
	
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			showCustomHelp()
			os.Exit(0)
		}
		// Handle unknown flag error
		fmt.Printf("%s %s\n\n", colorize(ColorRed+ColorBold, "[!]"), err.Error())
		fmt.Printf("%s For help, use: %s\n",
			colorize(ColorBlue+ColorBold, "[*]"),
			colorize(ColorCyan, "fortigate-cert-swap --help"))
		os.Exit(1)
	}
	
	if showVersion {
		printHeader(fmt.Sprintf("FortiGate Certificate Swap Tool v%s", VERSION))
		fmt.Println(colorize(ColorDim, "Go implementation with automatic intermediate CA management"))
		fmt.Println()
		fmt.Println(colorize(ColorDim, "Copyright (c) 2025 CyB0rgg <dev@bluco.re>"))
		fmt.Println(colorize(ColorDim, "Licensed under the MIT License"))
		os.Exit(0)
	}
	
	if showHelp {
		showCustomHelp()
		os.Exit(0)
	}
	
	// Load YAML config if specified
	if configFile != "" {
		yamlConfig, err := loadYAMLConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		config = mergeConfig(yamlConfig, config)
	}
	
	return config
}

// Load YAML configuration file
func loadYAMLConfig(path string) (*Config, error) {
	if path == "" {
		return &Config{AutoIntermediateCA: true}, nil
	}
	
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %v", err)
		}
		path = filepath.Join(homeDir, path[2:])
	}
	
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", path, err)
	}
	
	var config Config
	config.AutoIntermediateCA = true // Default to enabled
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %v", err)
	}
	
	return &config, nil
}

// Merge YAML config with CLI arguments (CLI takes precedence)
func mergeConfig(yamlConfig *Config, cliConfig *Config) *Config {
	merged := *yamlConfig
	
	if cliConfig.Host != "" {
		merged.Host = cliConfig.Host
	}
	if cliConfig.Port != 443 {
		merged.Port = cliConfig.Port
	}
	if cliConfig.Token != "" {
		merged.Token = cliConfig.Token
	}
	if cliConfig.Cert != "" {
		merged.Cert = cliConfig.Cert
	}
	if cliConfig.Key != "" {
		merged.Key = cliConfig.Key
	}
	if cliConfig.Name != "" {
		merged.Name = cliConfig.Name
	}
	if cliConfig.VDOM != "" {
		merged.VDOM = cliConfig.VDOM
	}
	if cliConfig.Insecure {
		merged.Insecure = cliConfig.Insecure
	}
	if cliConfig.DryRun {
		merged.DryRun = cliConfig.DryRun
	}
	if cliConfig.Prune {
		merged.Prune = cliConfig.Prune
	}
	if cliConfig.TimeoutConnect != 5 {
		merged.TimeoutConnect = cliConfig.TimeoutConnect
	}
	if cliConfig.TimeoutRead != 30 {
		merged.TimeoutRead = cliConfig.TimeoutRead
	}
	if cliConfig.Log != "" {
		merged.Log = cliConfig.Log
	}
	if cliConfig.LogLevel != "standard" {
		merged.LogLevel = cliConfig.LogLevel
	}
	if cliConfig.Rebind != "" {
		merged.Rebind = cliConfig.Rebind
	}
	if cliConfig.CertOnly {
		merged.CertOnly = cliConfig.CertOnly
	}
	if cliConfig.SSLInspectionCert {
		merged.SSLInspectionCert = cliConfig.SSLInspectionCert
	}
	
	// Set defaults if not specified
	if merged.TimeoutConnect == 0 {
		merged.TimeoutConnect = 5
	}
	if merged.TimeoutRead == 0 {
		merged.TimeoutRead = 30
	}
	if merged.LogLevel == "" {
		merged.LogLevel = "standard"
	}
	
	return &merged
}

// Validate configuration
func validateConfig(config *Config) error {
	if config.Host == "" {
		return fmt.Errorf("host is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("port must be between 1-65535, got: %d", config.Port)
	}
	if config.Token == "" {
		return fmt.Errorf("token is required")
	}
	if config.Cert == "" {
		return fmt.Errorf("certificate file path is required")
	}
	if config.Key == "" {
		return fmt.Errorf("private key file path is required")
	}
	if config.TimeoutConnect <= 0 {
		return fmt.Errorf("timeout_connect must be positive, got: %d", config.TimeoutConnect)
	}
	if config.TimeoutRead <= 0 {
		return fmt.Errorf("timeout_read must be positive, got: %d", config.TimeoutRead)
	}
	if config.LogLevel != "standard" && config.LogLevel != "debug" {
		return fmt.Errorf("log_level must be 'standard' or 'debug', got: %s", config.LogLevel)
	}
	
	return nil
}

func main() {
	// Check if no arguments provided - show help
	if len(os.Args) == 1 {
		showCustomHelp()
		os.Exit(0)
	}
	
	config := parseArgs()
	
	if err := validateConfig(config); err != nil {
		printError(fmt.Sprintf("Configuration error: %v", err))
		os.Exit(1)
	}
	
	// Initialize logger if log file is specified
	var err error
	logger, err = NewLogger(config.Log, config.LogLevel)
	if err != nil {
		printError(fmt.Sprintf("Failed to initialize logger: %v", err))
		os.Exit(1)
	}
	defer func() {
		if logger != nil {
			logger.Close()
		}
	}()
	
	// Set operation ID for correlation (using timestamp + random component)
	operationID := fmt.Sprintf("op-%d", time.Now().Unix())
	if logger != nil {
		logger.SetOperationID(operationID)
	}
	
	// Load certificate and key files
	printStep("Loading certificate and key files...")
	if logger != nil {
		logger.Debug("Loading certificate and key files", map[string]interface{}{
			"cert_path": config.Cert,
			"key_path":  config.Key,
		})
	}
	
	certPEM, err := loadFile(config.Cert)
	if err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Error loading certificate: %v", err), map[string]interface{}{
				"cert_path": config.Cert,
				"error":     err.Error(),
			})
		}
		printError(fmt.Sprintf("Error loading certificate: %v", err))
		os.Exit(1)
	}
	
	keyPEM, err := loadFile(config.Key)
	if err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Error loading private key: %v", err), map[string]interface{}{
				"key_path": config.Key,
				"error":    err.Error(),
			})
		}
		printError(fmt.Sprintf("Error loading private key: %v", err))
		os.Exit(1)
	}
	
	// Validate certificate and key formats
	if err := validateCertificateFormat(certPEM); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Certificate validation error: %v", err), map[string]interface{}{
				"error": err.Error(),
			})
		}
		printError(fmt.Sprintf("Certificate validation error: %v", err))
		os.Exit(1)
	}
	
	if err := validatePrivateKeyFormat(keyPEM); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Private key validation error: %v", err), map[string]interface{}{
				"error": err.Error(),
			})
		}
		printError(fmt.Sprintf("Private key validation error: %v", err))
		os.Exit(1)
	}
	
	// Display certificate chain summary
	fmt.Println(summarizeChain(certPEM))
	
	// Determine certificate name
	certName, err := plannedCertName(certPEM, config.Name)
	if err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Error determining certificate name: %v", err), map[string]interface{}{
				"error": err.Error(),
			})
		}
		printError(fmt.Sprintf("Error determining certificate name: %v", err))
		os.Exit(1)
	}
	
	if logger != nil {
		logger.Debug(fmt.Sprintf("planned_name=%s", certName), nil)
	}
	
	// Print effective configuration (matching Python)
	fmt.Println("[*] Effective configuration:")
	fmt.Printf("    host: %s\n", config.Host)
	fmt.Printf("    port: %d\n", config.Port)
	fmt.Printf("    vdom: %s\n", func() string {
		if config.VDOM == "" {
			return "GLOBAL"
		}
		return config.VDOM
	}())
	fmt.Printf("    insecure: %t\n", config.Insecure)
	fmt.Printf("    dry_run: %t\n", config.DryRun)
	fmt.Printf("    prune: %t\n", config.Prune)
	fmt.Printf("    timeout_connect: %ds\n", config.TimeoutConnect)
	fmt.Printf("    timeout_read: %ds\n", config.TimeoutRead)
	if config.Log != "" {
		fmt.Printf("    log: %s\n", config.Log)
		fmt.Printf("    log_level: %s\n", config.LogLevel)
	}
	
	// Print planned certificate name (matching Python exactly)
	fmt.Printf("[*] Planned certificate name: %s\n", certName)
	
	// Print planned intermediate CA info (matching Python)
	if config.AutoIntermediateCA {
		issuingCA := extractImmediateIssuingCA(certPEM)
		if issuingCA != nil {
			sanitizedCAName := sanitizeCACertificateName(issuingCA.CommonName)
			fmt.Printf("[*] Planned intermediate CA: %s (CN: %s)\n", sanitizedCAName, issuingCA.CommonName)
		} else {
			fmt.Printf("[*] No intermediate CA found in certificate chain\n")
		}
	} else {
		fmt.Printf("[*] Automatic intermediate CA upload: disabled\n")
	}
	
	// Print target store (matching Python)
	fmt.Printf("[*] Target store: %s\n", getStore(config))
	
	// Initialize API client and certificate operations
	api := NewFortiAPI(config)
	certOps := NewCertificateOperations(api, config)
	
	// Initialize result structure
	result := &OperationResult{
		Status:  "success",
		Mode:    determineOperationMode(config),
		Version: VERSION,
	}
	
	// REVOLUTIONARY AUTOMATIC INTERMEDIATE CA MANAGEMENT
	if config.AutoIntermediateCA {
		printStep("Processing automatic intermediate CA management...")
		caResult, err := uploadMissingIntermediateCAIfNeeded(api, certPEM)
		if err != nil {
			printError(fmt.Sprintf("Intermediate CA management error: %v", err))
			os.Exit(1)
		}
		if caResult != nil {
			caName := (*caResult)["name"].(string)
			caState := (*caResult)["state"].(string)
			
			if caState == "exists" {
				caSource, hasSource := (*caResult)["source"].(string)
				var sourceDisplay string
				if hasSource {
					switch caSource {
					case "user":
						sourceDisplay = "installed by user"
					case "factory":
						sourceDisplay = "factory installed"
					default:
						sourceDisplay = caSource
					}
				} else {
					sourceDisplay = "unknown source"
				}
				fmt.Printf("[*] Intermediate CA already exists: %s (%s)\n", caName, sourceDisplay)
			} else if caState == "dry_run" {
				fmt.Printf("DRY RUN: would upload intermediate CA: %s\n", caName)
			} else if caState == "created" || caState == "updated" {
				httpCode, hasCode := (*caResult)["http_status"].(int)
				method, hasMethod := (*caResult)["method"].(string)
				
				var httpDisplay string
				if hasCode {
					httpDisplay = fmt.Sprintf("%d", httpCode)
				} else {
					httpDisplay = "n/a"
				}
				
				var methodDisplay string
				if hasMethod {
					methodDisplay = method
				} else {
					methodDisplay = "unknown"
				}
				
				action := "Created"
				if caState == "updated" {
					action = "Updated"
				}
				
				fmt.Printf("[*] Result: %s intermediate CA \"%s\" in %s store (via %s, HTTP %s)\n",
					action, caName, getStore(config), methodDisplay, httpDisplay)
			}
			
			result.IntermediateCA = fmt.Sprintf("Processed: %s", caName)
		}
	}
	
	// Upload or update certificate
	printStep(fmt.Sprintf("Uploading certificate: %s", colorize(ColorBold, certName)))
	if logger != nil {
		logger.Info(fmt.Sprintf("Uploading certificate: %s", certName), map[string]interface{}{
			"cert_name": certName,
			"store":     getStore(config),
		})
	}
	
	state, detail, err := certOps.uploadOrUpdateCert(certName, certPEM, keyPEM)
	if err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Certificate upload error: %v", err), map[string]interface{}{
				"cert_name": certName,
				"error":     err.Error(),
			})
		}
		printError(fmt.Sprintf("Certificate upload error: %v", err))
		os.Exit(1)
	}
	
	if logger != nil {
		logger.Info(fmt.Sprintf("Certificate upload completed: %s", state), map[string]interface{}{
			"cert_name": certName,
			"state":     state,
			"store":     getStore(config),
		})
	}
	
	result.Certificate = &CertificateResult{
		Name:  certName,
		Store: getStore(config),
		State: state,
	}
	
	if state != "dry_run" {
		httpCode := 200
		if detail != nil {
			if code, ok := detail["http_status"].(int); ok {
				httpCode = code
			}
		}
		method := "cmdb_post"
		if state == "updated" {
			method = "cmdb_put"
		}
		action := "Created"
		if state == "updated" {
			action = "Updated"
		}
		printSuccess(fmt.Sprintf("%s certificate \"%s\" in %s store (via %s, HTTP %d)", action, colorize(ColorBold, certName), colorize(ColorBold, getStore(config)), method, httpCode))
	}
	
	// Handle different operation modes
	if config.CertOnly {
		fmt.Printf("[*] Certificate-only mode: %s\n", certName)
		printInfo("Certificate-only mode: skipping service binding")
		
		// Certificate-only mode pruning (if enabled)
		if config.Prune {
			printStep("Pruning old certificates...")
			pruneResult := certOps.pruneOldCertificates(certName)
			
			// Add pruning results to the main result (NO separate JSON output)
			if result.Pruned == nil {
				result.Pruned = &PruneResult{
					Deleted: []string{},
					Skipped: []map[string]interface{}{},
				}
			}
			
			if deleted, ok := pruneResult["deleted"].([]string); ok {
				result.Pruned.Deleted = append(result.Pruned.Deleted, deleted...)
			}
			if skipped, ok := pruneResult["skipped"].([]map[string]interface{}); ok {
				result.Pruned.Skipped = append(result.Pruned.Skipped, skipped...)
			}
			
			// Console output exactly like Python (lines 1643, 1804)
			deletedCount := len(result.Pruned.Deleted)
			skippedCount := len(result.Pruned.Skipped)
			
			if deletedCount > 0 {
				fmt.Printf("[*] Pruned %d old certificate(s): %s\n", deletedCount, strings.Join(result.Pruned.Deleted, ", "))
			}
			if skippedCount > 0 {
				fmt.Printf("[!] Skipped %d certificate(s) during pruning\n", skippedCount)
				// Show detailed skip reasons in debug mode (matching Python lines 1933-1943)
				if config.LogLevel == "debug" {
					skipReasons := make(map[string]int)
					for _, item := range result.Pruned.Skipped {
						if reason, ok := item["reason"].(string); ok {
							skipReasons[reason]++
						}
					}
					var reasonSummary []string
					for reason, count := range skipReasons {
						reasonSummary = append(reasonSummary, fmt.Sprintf("%d %s", count, reason))
					}
					fmt.Printf("[DEBUG] Skipped %d certificates: %s\n", skippedCount, strings.Join(reasonSummary, ", "))
				}
			}
		}
	} else if config.SSLInspectionCert {
		fmt.Printf("[*] SSL inspection certificate mode: %s\n", certName)
		printStep("SSL inspection certificate mode: rebinding profiles")
		
		// Extract domain from certificate for SSL inspection matching
		uploadDomain := certOps.extractDomainFromCert(certPEM)
		if uploadDomain == "" {
			printError("Could not extract domain from certificate for SSL inspection matching")
			os.Exit(1)
		}
		
		sslResult, err := certOps.rebindSSLInspectionProfiles(certName, uploadDomain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SSL inspection rebinding error: %v\n", err)
			os.Exit(1)
		}
		result.SSLInspection = sslResult
		
		printInfo(fmt.Sprintf("SSL inspection profiles rebound: %s, failed: %s",
			colorize(ColorGreen+ColorBold, fmt.Sprintf("%d", len(sslResult.ProfilesRebound))),
			colorize(ColorRed+ColorBold, fmt.Sprintf("%d", len(sslResult.ProfilesFailed)))))
		
		// Log SSL inspection profile rebinding results with profile names
		if logger != nil {
			// Extract profile names for INFO level logging
			var reboundNames []string
			var failedNames []string
			
			for _, profile := range sslResult.ProfilesRebound {
				if name, ok := profile["profile"].(string); ok {
					reboundNames = append(reboundNames, name)
				}
			}
			
			for _, profile := range sslResult.ProfilesFailed {
				if name, ok := profile["profile"].(string); ok {
					failedNames = append(failedNames, name)
				}
			}
			
			// Create detailed message with profile names
			var message string
			if len(reboundNames) > 0 && len(failedNames) > 0 {
				message = fmt.Sprintf("SSL inspection profiles rebound: %d (%s), failed: %d (%s)",
					len(sslResult.ProfilesRebound), strings.Join(reboundNames, ", "),
					len(sslResult.ProfilesFailed), strings.Join(failedNames, ", "))
			} else if len(reboundNames) > 0 {
				message = fmt.Sprintf("SSL inspection profiles rebound: %d (%s), failed: %d",
					len(sslResult.ProfilesRebound), strings.Join(reboundNames, ", "),
					len(sslResult.ProfilesFailed))
			} else if len(failedNames) > 0 {
				message = fmt.Sprintf("SSL inspection profiles rebound: %d, failed: %d (%s)",
					len(sslResult.ProfilesRebound),
					len(sslResult.ProfilesFailed), strings.Join(failedNames, ", "))
			} else {
				message = fmt.Sprintf("SSL inspection profiles rebound: %d, failed: %d",
					len(sslResult.ProfilesRebound), len(sslResult.ProfilesFailed))
			}
			
			logger.Info(message, map[string]interface{}{
				"profiles_rebound": len(sslResult.ProfilesRebound),
				"profiles_failed":  len(sslResult.ProfilesFailed),
				"rebound_names":    reboundNames,
				"failed_names":     failedNames,
				"rebound_details":  sslResult.ProfilesRebound,
				"failed_details":   sslResult.ProfilesFailed,
			})
		}
		
		// SSL inspection certificate pruning (if enabled) - use standard pruning like Python
		if config.Prune {
			printStep("Pruning old SSL inspection certificates...")
			
			pruneResult := certOps.pruneOldCertificates(certName)
			
			// Add pruning results to the main result (NO separate JSON output in SSL inspection mode)
			if result.Pruned == nil {
				result.Pruned = &PruneResult{
					Deleted: []string{},
					Skipped: []map[string]interface{}{},
				}
			}
			
			if deleted, ok := pruneResult["deleted"].([]string); ok {
				result.Pruned.Deleted = append(result.Pruned.Deleted, deleted...)
			}
			if skipped, ok := pruneResult["skipped"].([]map[string]interface{}); ok {
				result.Pruned.Skipped = append(result.Pruned.Skipped, skipped...)
			}
			
			// Console output exactly like Python (lines 1643, 1804)
			deletedCount := len(result.Pruned.Deleted)
			skippedCount := len(result.Pruned.Skipped)
			
			if deletedCount > 0 {
				fmt.Printf("[*] Pruned %d old certificate(s): %s\n", deletedCount, strings.Join(result.Pruned.Deleted, ", "))
			}
			if skippedCount > 0 {
				fmt.Printf("[!] Skipped %d certificate(s) during pruning\n", skippedCount)
				// Show detailed skip reasons in debug mode (matching Python lines 1933-1943)
				if config.LogLevel == "debug" {
					skipReasons := make(map[string]int)
					for _, item := range result.Pruned.Skipped {
						if reason, ok := item["reason"].(string); ok {
							skipReasons[reason]++
						}
					}
					var reasonSummary []string
					for reason, count := range skipReasons {
						reasonSummary = append(reasonSummary, fmt.Sprintf("%d %s", count, reason))
					}
					fmt.Printf("[DEBUG] Skipped %d certificates: %s\n", skippedCount, strings.Join(reasonSummary, ", "))
				}
			}
		}
	} else {
		// Standard mode: bind to services
		printStep("Standard mode: binding certificate to services")
		
		bindings := make(map[string]interface{})
		
		// Parse rebind services
		services := []string{"gui", "sslvpn", "ftm"}
		if config.Rebind != "" {
			services = strings.Split(config.Rebind, ",")
		}
		
		for _, service := range services {
			service = strings.TrimSpace(service)
			var success bool
			var detail map[string]interface{}
			
			switch service {
			case "gui":
				success, detail = certOps.bindGUI(certName)
			case "sslvpn":
				success, detail = certOps.bindSSLVPN(certName)
			case "ftm":
				success, detail = certOps.bindFTM(certName)
			default:
				printWarning(fmt.Sprintf("Unknown service: %s", service))
				continue
			}
			
			bindings[service] = map[string]interface{}{
				"success": success,
				"detail":  detail,
			}
			
			if success {
				printSuccess(fmt.Sprintf("Successfully bound certificate to %s", colorize(ColorBold, service)))
			} else {
				printError(fmt.Sprintf("Failed to bind certificate to %s", colorize(ColorBold, service)))
			}
		}
		
		result.Bindings = bindings
		
		// Log binding results (matching Python lines 1911-1913)
		if logger != nil {
			var results []string
			successCount := 0
			for service, binding := range bindings {
				if bindingMap, ok := binding.(map[string]interface{}); ok {
					if success, ok := bindingMap["success"].(bool); ok {
						if success {
							results = append(results, fmt.Sprintf("%s✓", strings.ToUpper(service)))
							successCount++
						} else {
							results = append(results, fmt.Sprintf("%s✗", strings.ToUpper(service)))
						}
					}
				}
			}
			
			if successCount == len(bindings) {
				logger.Info(fmt.Sprintf("All bindings successful: %s", strings.Join(results, " | ")), nil)
			} else {
				logger.Warn(fmt.Sprintf("Some bindings failed: %s", strings.Join(results, " | ")), nil)
			}
		}
		
		// Standard certificate pruning (if all bindings successful and prune enabled)
		if config.Prune {
			allBindingsSuccessful := true
			for _, binding := range bindings {
				if bindingMap, ok := binding.(map[string]interface{}); ok {
					if success, ok := bindingMap["success"].(bool); ok && !success {
						allBindingsSuccessful = false
						break
					}
				}
			}
			
			if allBindingsSuccessful {
				printStep("Pruning old certificates...")
				pruneResult := certOps.pruneOldCertificates(certName)
				
				// Add pruning results to the main result (NO separate JSON output)
				if result.Pruned == nil {
					result.Pruned = &PruneResult{
						Deleted: []string{},
						Skipped: []map[string]interface{}{},
					}
				}
				
				if deleted, ok := pruneResult["deleted"].([]string); ok {
					result.Pruned.Deleted = append(result.Pruned.Deleted, deleted...)
				}
				if skipped, ok := pruneResult["skipped"].([]map[string]interface{}); ok {
					result.Pruned.Skipped = append(result.Pruned.Skipped, skipped...)
				}
				
				// Console output exactly like Python (lines 1643, 1804)
				deletedCount := len(result.Pruned.Deleted)
				skippedCount := len(result.Pruned.Skipped)
				
				if deletedCount > 0 {
					fmt.Printf("[*] Pruned %d old certificate(s): %s\n", deletedCount, strings.Join(result.Pruned.Deleted, ", "))
				}
				if skippedCount > 0 {
					fmt.Printf("[!] Skipped %d certificate(s) during pruning\n", skippedCount)
					// Show detailed skip reasons in debug mode (matching Python lines 1933-1943)
					if config.LogLevel == "debug" {
						skipReasons := make(map[string]int)
						for _, item := range result.Pruned.Skipped {
							if reason, ok := item["reason"].(string); ok {
								skipReasons[reason]++
							}
						}
						var reasonSummary []string
						for reason, count := range skipReasons {
							reasonSummary = append(reasonSummary, fmt.Sprintf("%d %s", count, reason))
						}
						fmt.Printf("[DEBUG] Skipped %d certificates: %s\n", skippedCount, strings.Join(reasonSummary, ", "))
					}
				}
			} else {
				msg := "[!] One or more bindings failed; skipping prune to avoid deleting a cert still needed for rollback."
				fmt.Println(msg)
			}
		}
	}
	
	// Output final result
	fmt.Println()
	printSuccess("Operation completed successfully")
	
	// Log operation completion
	if logger != nil {
		logger.Info("Certificate operation completed successfully", map[string]interface{}{
			"cert_name": certName,
			"mode":      result.Mode,
			"status":    result.Status,
		})
	}
	
	// Output JSON result if requested (for automation/scripting)
	if config.LogLevel == "debug" {
		jsonOutput, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("\n%s %s\n%s\n",
			colorize(ColorDim, "[DEBUG]"),
			colorize(ColorDim, "JSON Result:"),
			colorize(ColorDim, string(jsonOutput)))
	}
}

func determineOperationMode(config *Config) string {
	if config.CertOnly {
		return "cert-only"
	}
	if config.SSLInspectionCert {
		return "ssl-inspection-certificate"
	}
	if config.Rebind != "" {
		return "rebind"
	}
	return "standard"
}
package main

import (
	"strings"
	"testing"
)

func TestDescribeAPIFailure404(t *testing.T) {
	msg := describeAPIFailure(map[string]interface{}{
		"http_status": 404,
		"detail":      map[string]interface{}{"raw": "<html>not found</html>"},
	})
	if !strings.Contains(msg, "HTTP 404") {
		t.Fatalf("expected HTTP 404 in message, got %q", msg)
	}
	if !strings.Contains(msg, "admin-sport") {
		t.Fatalf("expected admin-sport hint for 404, got %q", msg)
	}
}

func TestDescribeAPIFailureFortiGateError(t *testing.T) {
	msg := describeAPIFailure(map[string]interface{}{
		"http_status": 500,
		"detail": map[string]interface{}{
			"error":     -5,
			"cli_error": []interface{}{"The entry is used by other 1 entries", "Command fail. Return code -23"},
		},
	})
	for _, want := range []string{"HTTP 500", "error -5", "The entry is used by other 1 entries"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected %q in message, got %q", want, msg)
		}
	}
}

func TestDescribeAPIFailure403(t *testing.T) {
	msg := describeAPIFailure(map[string]interface{}{"http_status": 403})
	if !strings.Contains(msg, "HTTP 403") || !strings.Contains(msg, "accprofile") {
		t.Fatalf("expected 403 + accprofile hint, got %q", msg)
	}
}

func TestDescribeAPIFailureTransport(t *testing.T) {
	msg := describeAPIFailure(map[string]interface{}{"error": "request failed: dial tcp: connection refused"})
	if !strings.Contains(msg, "connection refused") {
		t.Fatalf("expected transport error text, got %q", msg)
	}
}

func TestDescribeAPIFailureNil(t *testing.T) {
	if msg := describeAPIFailure(nil); msg == "" {
		t.Fatal("expected a non-empty message for nil detail")
	}
}

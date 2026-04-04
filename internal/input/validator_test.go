package input_test

import (
	"testing"

	"ipcheck/internal/input"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ipStr string
		want  bool
	}{
		// Private IPv4 ranges
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.0.1", true},
		{"192.168.255.254", true},
		// Public IPv4 examples
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.45", false}, // Example documentation IP
		// Loopback and unspecified IPv4
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		// Private IPv6 ranges (unique local)
		{"fc00::1", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", true},
		// Private IPv6 ranges (link-local)
		{"fe80::1", true},
		{"febf:ffff:ffff:ffff::", true},
		// Public IPv6 example
		{"2001:0db8::1", false}, // Example documentation IP
		{"2001:4860:4860::8888", false}, // Google Public DNS
		// Loopback and unspecified IPv6
		{"::1", true},
		{"::", true},
		// Invalid IP strings
		{"not-an-ip", false},
		{"192.168.0", false}, // Incomplete IP
		{"256.0.0.1", false}, // Invalid octet
	}

	for _, tt := range tests {
		got := input.IsPrivateIP(tt.ipStr)
		if got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %t; want %t", tt.ipStr, got, tt.want)
		}
	}
}

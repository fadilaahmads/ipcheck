package models

import (
	"encoding/json"
)

// Enhanced cache result to support both VT and AbuseIPDB
type EnhancedCachedResult struct {
	IP               string          `json:"ip"`
	// VirusTotal data
	VTMaliciousBy    []string        `json:"vt_malicious_by,omitempty"`
	VTSuspiciousBy   []string        `json:"vt_suspicious_by,omitempty"`
	VTLastQueried    int64           `json:"vt_last_queried,omitempty"`
	VTRaw            json.RawMessage `json:"vt_raw,omitempty"`
	// AbuseIPDB data
	AbuseScore       int             `json:"abuse_score,omitempty"`
	AbuseTotalReports int            `json:"abuse_total_reports,omitempty"`
	AbuseIsTor       bool            `json:"abuse_is_tor,omitempty"`
	AbuseCountry     string          `json:"abuse_country,omitempty"`
	AbuseISP          string          `json:"abuse_isp,omitempty"`
	AbuseLastQueried int64           `json:"abuse_last_queried,omitempty"`
	AbuseRaw         json.RawMessage `json:"abuse_raw,omitempty"`
	// Combined assessment
	RiskLevel        string          `json:"risk_level"` // HIGH, MEDIUM, LOW
	ShouldBlock      bool            `json:"should_block"`
	LastUpdated      int64           `json:"last_updated"`
}

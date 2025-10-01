package models

import (
	"encoding/json"
)

type CachedResult struct {
	IP            string   `json:"ip"`
	MaliciousBy   []string `json:"malicious_by,omitempty"`
	SuspiciousBy  []string `json:"suspicious_by,omitempty"`
	LastQueriedAt int64    `json:"last_queried_at"`
	Raw           json.RawMessage `json:"raw,omitempty"`
}

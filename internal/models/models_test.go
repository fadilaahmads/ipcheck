package models_test

import (
	"encoding/json"
	"testing"
	"time"

	"ipcheck/internal/models"
)

func TestAbuseIPDBErrorInitialization(t *testing.T) {
	err := models.AbuseIPDBError{}
	if err.Errors != nil {
		t.Errorf("Expected Errors to be nil, got %v", err.Errors)
	}
}

func TestCheckResponseInitialization(t *testing.T) {
	resp := models.CheckResponse{}
	// Test that nested struct is also initialized to its zero value
	if resp.Data.IPAddress != "" {
		t.Errorf("Expected IPAddress to be empty, got %s", resp.Data.IPAddress)
	}
}

func TestBlacklistResponseInitialization(t *testing.T) {
	resp := models.BlacklistResponse{}
	if resp.Meta.GeneratedAt != "" {
		t.Errorf("Expected GeneratedAt to be empty, got %s", resp.Meta.GeneratedAt)
	}
}

func TestReportsResponseInitialization(t *testing.T) {
	resp := models.ReportsResponse{}
	if resp.Data.Total != 0 {
		t.Errorf("Expected Total to be 0, got %d", resp.Data.Total)
	}
}

func TestCheckBlockResponseInitialization(t *testing.T) {
	resp := models.CheckBlockResponse{}
	if resp.Data.NetworkAddress != "" {
		t.Errorf("Expected NetworkAddress to be empty, got %s", resp.Data.NetworkAddress)
	}
}

func TestAbuseIPDBClientInitialization(t *testing.T) {
	client := models.AbuseIPDBClient{}
	if client.APIKey != "" {
		t.Errorf("Expected APIKey to be empty, got %s", client.APIKey)
	}
	if client.BaseURL != "" {
		t.Errorf("Expected BaseURL to be empty, got %s", client.BaseURL)
	}
	if client.HTTPClient != nil {
		t.Errorf("Expected HTTPClient to be nil, got %v", client.HTTPClient)
	}
}

func TestCliConfigInitialization(t *testing.T) {
	config := models.CliConfig{}
	if config.FileFlag != "" {
		t.Errorf("Expected FileFlag to be empty, got %s", config.FileFlag)
	}
	if config.IntervalFlag != 0 {
		t.Errorf("Expected IntervalFlag to be 0, got %v", config.IntervalFlag)
	}
}

func TestProviderConfigInitialization(t *testing.T) {
	config := models.ProviderConfig{}
	if config.VTAPIKey != "" {
		t.Errorf("Expected VTAPIKey to be empty, got %s", config.VTAPIKey)
	}
	if config.VirustotalApiBaseUrl != "" {
		t.Errorf("Expected VirustotalApiBaseUrl to be empty, got %s", config.VirustotalApiBaseUrl)
	}
}

func TestScanStateInitialization(t *testing.T) {
	state := models.ScanState{}
	if state.RequestDone != 0 {
		t.Errorf("Expected RequestDone to be 0, got %d", state.RequestDone)
	}
	if state.HighRisk != nil {
		t.Errorf("Expected HighRisk to be nil, got %v", state.HighRisk)
	}
}

func TestEnhancedCachedResultJSON(t *testing.T) {
	now := time.Now().Unix()
	original := models.EnhancedCachedResult{
		IP:                "8.8.8.8",
		VTMaliciousBy:     []string{"detection1", "detection2"},
		VTLastQueried:     now,
		VTRaw:             json.RawMessage(`{"vt_data": "some_data"}`),
		AbuseScore:        50,
		AbuseTotalReports: 10,
		AbuseIsTor:        true,
		AbuseCountry:      "US",
		AbuseISP:          "Google",
		AbuseLastQueried:  now,
		AbuseRaw:          json.RawMessage(`{"abuse_data": "other_data"}`),
		RiskLevel:         "MEDIUM",
		ShouldBlock:       true,
		LastUpdated:       now,
	}

	marshaled, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal EnhancedCachedResult: %v", err)
	}

	var unmarshaled models.EnhancedCachedResult
	err = json.Unmarshal(marshaled, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal EnhancedCachedResult: %v", err)
	}

	if original.IP != unmarshaled.IP {
		t.Errorf("Expected IP %s, got %s", original.IP, unmarshaled.IP)
	}
	if len(original.VTMaliciousBy) != len(unmarshaled.VTMaliciousBy) {
		t.Errorf("Expected VTMaliciousBy length %d, got %d", len(original.VTMaliciousBy), len(unmarshaled.VTMaliciousBy))
	}
	if original.VTLastQueried != unmarshaled.VTLastQueried {
		t.Errorf("Expected VTLastQueried %d, got %d", original.VTLastQueried, unmarshaled.VTLastQueried)
	}
	// Note: Deep comparison for json.RawMessage is complex; shallow check for presence
	if len(original.VTRaw) == 0 && len(unmarshaled.VTRaw) != 0 || len(original.VTRaw) != 0 && len(unmarshaled.VTRaw) == 0 {
		t.Errorf("Expected VTRaw presence to match, original: %t, unmarshaled: %t", len(original.VTRaw) > 0, len(unmarshaled.VTRaw) > 0)
	}
	if original.AbuseScore != unmarshaled.AbuseScore {
		t.Errorf("Expected AbuseScore %d, got %d", original.AbuseScore, unmarshaled.AbuseScore)
	}
	if original.AbuseCountry != unmarshaled.AbuseCountry {
		t.Errorf("Expected AbuseCountry %s, got %s", original.AbuseCountry, unmarshaled.AbuseCountry)
	}
	if original.RiskLevel != unmarshaled.RiskLevel {
		t.Errorf("Expected RiskLevel %s, got %s", original.RiskLevel, unmarshaled.RiskLevel)
	}
	if original.ShouldBlock != unmarshaled.ShouldBlock {
		t.Errorf("Expected ShouldBlock %t, got %t", original.ShouldBlock, unmarshaled.ShouldBlock)
	}
	if original.LastUpdated != unmarshaled.LastUpdated {
		t.Errorf("Expected LastUpdated %d, got %d", original.LastUpdated, unmarshaled.LastUpdated)
	}
}

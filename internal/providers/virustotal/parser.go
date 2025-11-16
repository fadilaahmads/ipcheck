package virustotal

import (
	"encoding/json"
	"fmt"
	"time"
	)

// parseAnalysis inspects the JSON response from VT and returns vendor lists
func ParseVTAnalysis(body json.RawMessage) (malicious []string, suspicious []string, err error) {
	// Response structure: data.attributes.last_analysis_results.{vendor}.{category, result}
	// We will decode into a generic map and walk it.
	var root map[string]interface{}
	if err = json.Unmarshal(body, &root); err != nil {
		return nil, nil, err
	}
	data, ok := root["data"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("unexpected vt response: missing data")
	}
	attrs, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("unexpected vt response: missing attributes")
	}
	last, ok := attrs["last_analysis_results"].(map[string]interface{})
	if !ok {
		// no analysis details present
		return nil, nil, nil
	}
	for vendor, v := range last {
		vmap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		category, _ := vmap["category"].(string) // "malicious", "suspicious", "harmless", etc.
		if category == "malicious" {
			malicious = append(malicious, vendor)
		} else if category == "suspicious" {
			suspicious = append(suspicious, vendor)
		}
	}
	return malicious, suspicious, nil
}

func ParseVTAPIQuota(body json.RawMessage) (int, int, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return 0,0, err
	}
	data, ok := root["data"].(map[string]interface{})
	if !ok {
		return 0,0, fmt.Errorf("unexpected response: no data")
	}
	
	// parse total usage 
	totalMap, ok := data["total"].(map[string]interface{})
	if !ok {
		return 0,0, fmt.Errorf("unexpected response: missing total")
	}
	totalVal, ok := totalMap["/api/v3/(ip_addresses)"].(float64)
	if !ok {
		return 0,0, fmt.Errorf("unexpected response: total[ip_addresses] not found or not number")
	}

	// parse today's usage
	todayKey := time.Now().Format("2006-01-02")
	dailyMap, ok := data["daily"].(map[string]interface{})
	if !ok {
		return int(totalVal), 0, fmt.Errorf("unexpected response: missing daily")
	}
	
	var todayVal float64
	if todayEntry, exists := dailyMap[todayKey]; exists {
		if entryMap, ok := todayEntry.(map[string]interface{}); ok {
			if v, ok :=entryMap["/api/v3/(ip_addresses)"].(float64); ok {
				todayVal = v
			}
		}
	}

	return int(totalVal), int(todayVal), nil
}

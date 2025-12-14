package virustotal 

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ipcheck/internal/models"
	)

// queryVT queries VirusTotal v3 for an IP and returns the raw JSON response
func FetchVTIPData(client *http.Client, virustotalApiBaseUrl string, apiKey string, ip string) (json.RawMessage, error) {
	req, err := http.NewRequest("GET", virustotalApiBaseUrl+"ip_addresses/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", apiKey) // VT v3 uses x-apikey header OR Authorization Bearer; using x-apikey is fine
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// 429 handling - caller can inspect resp.StatusCode for rate limit info
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited: %s", string(bodyBytes))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vt returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return json.RawMessage(bodyBytes), nil
}

func CheckVTIPData(client *http.Client, apiKey string, ip string, virustotalApiBaseUrl string, result *models.EnhancedCachedResult) error {	
	fmt.Printf("  → Querying VirusTotal . . . \n")
	vtRaw, err := FetchVTIPData(client, virustotalApiBaseUrl, apiKey, ip)	
	if err != nil {
		return err
	}

	malicious, suspicious, err := ParseVTAnalysis(vtRaw)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	result.VTMaliciousBy = malicious
	result.VTSuspiciousBy = suspicious
	result.VTLastQueried = time.Now().Unix()
	result.VTRaw = vtRaw
	
	fmt.Printf("  ✓ VT: Malicious=%d, Suspicious=%d\n", len(malicious), len(suspicious))
	return nil
}


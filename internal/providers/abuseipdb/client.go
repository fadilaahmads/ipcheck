package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"ipcheck/internal/models"
)

func QueryAbuseIPDB(client *http.Client, abuseipdbApiBaseUrl string, apiKey string, ip string) (*models.AbuseCheckData, error){

	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	
	req, err := http.NewRequest("GET", abuseipdbApiBaseUrl+"/check?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited: %s", string(bodyBytes))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AbuseIPDB returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var checkResp models.AbuseCheckResponse
	if err := json.Unmarshal(bodyBytes, &checkResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &checkResp.Data, nil
}

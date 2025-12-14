package abuseipdb

import (
	"fmt"
	"encoding/json"
	"net/http"
	"time"

	"ipcheck/internal/models"
)

func ParseAbuseIPDBIPData(client *http.Client, apiKey string, ip string, abuseipdbApiBaseUrl string, result *models.EnhancedCachedResult) error {
	fmt.Printf("  → Querying AbuseIPDB...\n")
	abuseData, err := fetchAbuseIPDBIPData(client, abuseipdbApiBaseUrl, apiKey, ip)
	if err != nil {
		return err
	}

	result.AbuseScore = abuseData.AbuseConfidenceScore
	result.AbuseTotalReports = abuseData.TotalReports
	result.AbuseIsTor = abuseData.IsTor
	result.AbuseCountry = abuseData.CountryCode
	result.AbuseISP = abuseData.ISP
	result.AbuseLastQueried = time.Now().Unix()

	rawBytes, err := json.Marshal(abuseData)
	if err != nil {
		return fmt.Errorf("error marshaling AbuseIPDB data: %w", err)
	}
	result.AbuseRaw = json.RawMessage(rawBytes)

	fmt.Printf("  ✓ AbuseIPDB: Score=%d, Reports=%d, Tor=%v\n", 
		abuseData.AbuseConfidenceScore, abuseData.TotalReports, abuseData.IsTor)
	return nil
}

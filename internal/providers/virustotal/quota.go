package virustotal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func FetchVTAPIQuota(client *http.Client, virustotalApiBaseUrl string, apiKey string) (json.RawMessage, error){
	req, err := http.NewRequest("GET", virustotalApiBaseUrl+"users/"+apiKey+"/api_usage", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vt returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return json.RawMessage(bodyBytes), nil
}

func CheckVTAPIQuota(client *http.Client,virustotalApiBaseUrl string, apiKey string) error {
	vtQuota, err := FetchVTAPIQuota(client, virustotalApiBaseUrl, apiKey)
	if err != nil {
		fmt.Errorf("Error checking VirusTotal quota: %v\n", err)	
	}
	vtQuotaTotal, vtQuotaToday, vtQuotaErr := ParseVTAPIQuota(vtQuota)
	if vtQuotaErr != nil {
		fmt.Errorf("Error parsing VirusTotal quota: %v", vtQuotaErr)	
	}
	
	fmt.Printf("[*] Virustotal Today AvailableQuota: %d | Quota Used Today: %d\n", vtQuotaTotal, vtQuotaToday)
	fmt.Println()
	return nil
}

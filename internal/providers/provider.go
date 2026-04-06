package providers

import (
	"fmt"
	"os"

	"ipcheck/internal/input"
	"ipcheck/internal/models"
)

func SetupProviders(providerFlag string, VTAPIBaseUrl string, AbuseIPDBBaseUrl string) (*models.ProviderConfig, error) {
	// Load .env file
	env, _ := input.ParseEnvFile(".env")

	// Get VT API Key (Priority: .env > os.Getenv)
	vtAPIKey := env["VIRUSTOTAL_API_KEY"]
	if vtAPIKey == "" {
		vtAPIKey = os.Getenv("VIRUSTOTAL_API_KEY")
	}

	// Get AbuseIPDB API Key (Priority: .env > os.Getenv)
	abuseipdbAPIKey := env["ABUSEIPDB_API_KEY"]
	if abuseipdbAPIKey == "" {
		abuseipdbAPIKey = os.Getenv("ABUSEIPDB_API_KEY")
	}

	useVT := (providerFlag == "vt" || providerFlag == "both") && vtAPIKey != ""
	useAbuse := (providerFlag == "abuse" || providerFlag == "both")

	if !useVT && !useAbuse {
		return nil, fmt.Errorf("no API keys set. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY")
	}

	return &models.ProviderConfig{
		VTAPIKey: vtAPIKey,
		VirustotalApiBaseUrl: VTAPIBaseUrl,
		AbuseIPDBAPIKey: abuseipdbAPIKey,
		AbuseipdbApiBaseUrl: AbuseIPDBBaseUrl,
		UseVT: useVT,
		UseAbuse: useAbuse,
	}, nil
}

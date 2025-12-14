package orchestrator

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
	
	"ipcheck/internal/assessment"
	"ipcheck/internal/cache"
	"ipcheck/internal/input"
	"ipcheck/internal/models"
	"ipcheck/internal/output"
	"ipcheck/internal/providers/abuseipdb"	
	"ipcheck/internal/providers/virustotal"
)

type ProcessIPSArgs struct {	
	Client *http.Client
	Providers *models.ProviderConfig
	Config *models.CliConfig	
	ThreatCache cache.CacheMap
	VirustotalApiBaseUrl string
	AbuseipdbApibaseUrl string
	Mu *sync.Mutex
}

// ProcessIP queries threat intelligence providers and assess a single IP
func processIP(ip string, processIPConfig *ProcessIPSArgs) (shouldStop bool) {	
	client := processIPConfig.Client
	providers := processIPConfig.Providers
	config := processIPConfig.Config	
	threatCache := processIPConfig.ThreatCache
	virustotalApiBaseUrl := processIPConfig.Providers.VirustotalApiBaseUrl
	abuseipdbApiBaseUrl := processIPConfig.Providers.AbuseipdbApiBaseUrl
	mu := processIPConfig.Mu

	fmt.Printf("[query] %s\n", ip)

	result := models.EnhancedCachedResult{
		IP: ip,
		LastUpdated: time.Now().Unix(),
	}
	// Query VirusTotal
	if providers.UseVT {	
		if err := virustotal.CheckVTIPData(client, providers.VTAPIKey, ip,virustotalApiBaseUrl, &result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Query AbuseIPDB
	if providers.UseAbuse {
		if err := abuseipdb.ParseAbuseIPDBIPData(client, providers.AbuseIPDBAPIKey, ip, abuseipdbApiBaseUrl, &result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}	
	}

	assessment.CalculateRiskLevel(&result)

	// write outputs & update cache
	mu.Lock()
	threatCache[ip] = result
		
	// Categorized and write to files
	if err := output.SaveResultToFile(&result, config.MalFile, config.SuspFile); err != nil {
		fmt.Fprintf(os.Stderr, "   ✗ Error writing output file: %v\n", err)
	}	
	mu.Unlock()

	// Display summary for this IP
	output.DisplaySingleIPSummary(&result)

	return false
}

// ScanIP performs the main scanning loop
func ScanIPs(
	ips []string, 
	client *http.Client, 
	providers *models.ProviderConfig, 
	config *models.CliConfig, 
	threatCache cache.CacheMap,
) *models.ScanState {
	ticker := time.NewTicker(config.IntervalFlag)
	defer ticker.Stop()

	var mu sync.Mutex
	state := &models.ScanState{}

	processIPConfig := ProcessIPSArgs{}
	processIPConfig.Client = client
	processIPConfig.Providers = providers
	processIPConfig.Config = config
	processIPConfig.ThreatCache = threatCache
	processIPConfig.Mu = &mu

	for _, ip := range ips {
		// Skip private IPs 
		if input.IsPrivateIP(ip) {
			fmt.Printf("[skip] private/internal IP: %s\n", ip)
			continue
		}

		// Check daily cap
		if state.RequestDone >= config.DailyFlag {
			fmt.Fprintf(os.Stderr, "\n[!] daily cap reached (%d requests). Stopping.\n", config.DailyFlag)
			break
		}

		// Check cache
		mu.Lock()
		cached, exists := threatCache[ip]
		mu.Unlock()

		if exists {
			cache.HandleCachedResult(ip, cached, state)
			continue
		}

		// Rate limiting (skip wait on first reuqest)
		if state.RequestDone > 0 {
			<-ticker.C 
		}

		// Process IP 
		if shouldStop := processIP(ip, &processIPConfig); shouldStop {
			break
		}
	}

	return state
}

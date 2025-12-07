package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

// Configurable defaults
const (
	defaultInterval  = 15 * time.Second // 4 req / minute => 1 every 15s
	defaultDailyCap  = 50
	cacheFilename    = "threat_intel_cache.json"
	maliciousOutFile = "malicious.txt"
	suspiciousOutFile= "suspicious.txt"	
	virustotalApiBaseUrl = "https://www.virustotal.com/api/v3/"
  abuseipdbApiBaseUrl = "https://api.abuseipdb.com/api/v2"
	)

type Config struct {
	FileFlag string
	IntervalFlag time.Duration
	DailyFlag int
	CacheFlag string
	MalFile string
	SuspFile string
	ProviderFlag string
}

// appendLine appends a single line to a file, creating it if needed
func appendLine(path string, line string) error {
	// ensure directory exists
	if dir := filepath.Dir(path); dir != "." {
		os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func ParseFlags() *models.CliConfig {
	config := &models.CliConfig{}
	flag.StringVar(&config.FileFlag, "file", "", "path to file with IPs (one per line). If empty, reads from stdin")
	flag.DurationVar(&config.IntervalFlag, "interval", defaultInterval, "interval between requests. default 15s -> 4 req/min")
	flag.IntVar(&config.DailyFlag, "daily", defaultDailyCap, "daily request cap (per run). default Virustotal: 500")
	flag.StringVar(&config.CacheFlag, "cache", cacheFilename, "path to cache json file")
	flag.StringVar(&config.MalFile, "mal", maliciousOutFile, "malicious output file")
	flag.StringVar(&config.SuspFile, "susp", suspiciousOutFile, "suspicious output file")
	flag.StringVar(&config.ProviderFlag, "provider", "both", "threat intel provider: vt, abuse, or both")
	flag.Parse()
	return config
}	

func SetupProviders(providerFlag string) (*models.ProviderConfig, error) {
	vtAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")
	abuseipdbAPIKey := os.Getenv("ABUSEIPDB_API_KEY")

	useVT := (providerFlag == "vt" || providerFlag == "both") && vtAPIKey != ""
	useAbuse := (providerFlag == "abuse" || providerFlag == "both")

	if !useVT && !useAbuse {
		return nil, fmt.Errorf("no API keys set. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY")
	}

	return &models.ProviderConfig{
		VTAPIKey: vtAPIKey,
		AbuseIPDBAPIKey: abuseipdbAPIKey,
		UseVT: useVT,
		UseAbuse: useAbuse,
	}, nil
}

func CheckVTQuota(client *http.Client, apiKey string) error {
	vtQuota, err := virustotal.CheckVTAPIQuota(client, virustotalApiBaseUrl, apiKey)
	if err != nil {
		fmt.Errorf("Error checking VirusTotal quota: %v\n", err)	
	}
	vtQuotaTotal, vtQuotaToday, vtQuotaErr := virustotal.ParseVTAPIQuota(vtQuota)
	if vtQuotaErr != nil {
		fmt.Errorf("Error parsing VirusTotal quota: %v", vtQuotaErr)	
	}
	
	fmt.Printf("[*] Virustotal Today AvailableQuota: %d | Quota Used Today: %d\n", vtQuotaTotal, vtQuotaToday)
	fmt.Println()
	return nil
}

func HandleCachedResult(ip string, cached models.EnhancedCachedResult, state *models.ScanState)  {
	fmt.Printf("[cache] %s -> Risk: %s, Should Block: %v\n", ip, cached.RiskLevel, cached.ShouldBlock)
	// categorized cached result
	switch cached.RiskLevel {
	case "HIGH":
		state.HighRisk = append(state.HighRisk, ip)
	case "MEDIUM":
		state.MediumRisk = append(state.MediumRisk, ip)
	case "LOW":
		state.LowRisk = append(state.LowRisk, ip)
	}	
}

func ParsingVirustotal(client *http.Client, apiKey string, ip string, result *models.EnhancedCachedResult) error {	
	fmt.Printf("  → Querying VirusTotal . . . \n")
	vtRaw, err := virustotal.QueryVT(client, virustotalApiBaseUrl, apiKey, ip)	
	if err != nil {
		return err
	}

	malicious, suspicious, err := virustotal.ParseVTAnalysis(vtRaw)
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

func ParsingAbuseIPDB(client *http.Client, apiKey string, ip string, result *models.EnhancedCachedResult) error {
	fmt.Printf("  → Querying AbuseIPDB...\n")
	abuseData, err := abuseipdb.QueryAbuseIPDB(client, abuseipdbApiBaseUrl, apiKey, ip)
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

func SaveResultToFile(result *models.EnhancedCachedResult, malFile, suspFile string) error {
	var line string
	var outputFile string

	switch result.RiskLevel {
	case "HIGH":
		line = fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Tor: %v | Block: YES",
	 result.IP, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
	 outputFile = malFile 
  case "MEDIUM":
		line = fmt.Sprintf("%s | Risk: MEDIUM | VT_Mal: %d | Abuse: %d | Tor: %v | Review: YES",
	 result.IP, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
	 outputFile = suspFile
	default:
	 return nil // Low risk doesn't need file output
	}

	return appendLine(outputFile, line)
}

func main() {
	// flags
	config := ParseFlags()
  // Get API keys	
	providers, err := SetupProviders(config.ProviderFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}	

	ips, err := input.ReadLinesFromFileOrStdin(config.FileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read IPs:", err)
		os.Exit(1)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "no valid IPs found")
		os.Exit(1)
	}

	// load cache
	threatCache, err := cache.LoadCache(config.CacheFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load cache:", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 30 * time.Second}
		
	ticker := time.NewTicker(config.IntervalFlag)
	defer ticker.Stop()

	var mu sync.Mutex // protects cache and counters and file writes
	state := &models.ScanState{}
	requestsDone := 0

	// Result tracking
	var highRisk, mediumRisk, lowRisk []string
	output.PrintScanHeader(providers, len(ips))
	
	for _, ip := range ips {
		// Skip private IPs 
		if input.IsPrivateIP(ip) {
			fmt.Printf("[skip] private/internal IP: %s\n", ip)
			continue
		}

		// Check daily cap
		if requestsDone >= config.DailyFlag {
			fmt.Fprintf(os.Stderr, "\n[!] daily cap reached (%d requests). Stopping.\n", config.DailyFlag)
			break
		}

		// skip if cached
		mu.Lock()

		cached, exists := threatCache[ip]
		mu.Unlock()
		if exists {
			HandleCachedResult(ip, cached, state)	
			continue
		}

		// Wait for ticker (rate-limiting). For first iteration, do not wait.
		if requestsDone > 0 {
			<-ticker.C
		}

		fmt.Printf("[query] %s\n", ip)
		result := models.EnhancedCachedResult{
			IP:	ip,
			LastUpdated:	time.Now().Unix(),
		}
		
		// Query VirusTotal
		if providers.UseVT {
			if err := CheckVTQuota(client, providers.VTAPIKey); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := ParsingVirustotal(client, virustotalApiBaseUrl, ip, &result); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		// Query AbuseIPDB
		if providers.UseAbuse {
			err := ParsingAbuseIPDB(client, abuseipdbApiBaseUrl, ip, &result)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}	
		}

		assessment.CalculateRiskLevel(&result)

		// write outputs & update cache
		mu.Lock()
		threatCache[ip] = result
		
		// Categorized and write to files
		if err := SaveResultToFile(&result, config.MalFile, config.SuspFile); err != nil {
			fmt.Fprintf(os.Stderr, "   ✗ Error writing output file: %v\n", err)
		}	
		mu.Unlock()

		// Display summary for this IP
		output.DisplaySingleIPSummary(&result)	
	}

	// ========================================================================
	// Final Summary
	// ========================================================================
	output.DisplaySummaryBanner()
	fmt.Printf("Total IPs Processed: %d\n", len(ips))
	fmt.Printf("API Requests Made:   %d\n\n", requestsDone)

	// High Risk (Block)
	output.PrintHighRiskSummary(highRisk, threatCache)

	// Medium Risk (REVIEW)
	output.PrintMediumRiskSummary(mediumRisk, threatCache)
	
	// Low Risk (CLEAN)
	output.PrintLowRiskSummary(lowRisk)

	// Recommendations
	output.DisplayRecommendationBanner(state, config.MalFile, config.SuspFile)	

	// Export firewall commands (optional feature)
	if len(highRisk) > 0 {
		output.DisplayFirewallCommandBanner()	
		for i, ip := range highRisk {
			if i >= 5 {
				fmt.Printf("... and %d more\n", len(highRisk)-5)
				break
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP\n", ip)
		}
		fmt.Println()
	}

	output.DisplaySingleLine()	
	fmt.Printf("Cache saved to: %s\n", config.CacheFlag)	
	fmt.Println("Scan complete.")

}

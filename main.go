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

func ParsingAbuseIPDB(client *http.Client, apiKey string, ip string, result *models.EnhancedCachedResult) error {
	fmt.Printf("  → Querying AbuseIPDB...\n")
	abuseData, err := abuseipdb.FetchAbuseIPDBIPData(client, abuseipdbApiBaseUrl, apiKey, ip)
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

// ProcessIP queries thrate intelligence providers and assess a single IP
func ProcessIP(
	ip string,
	client *http.Client,
	providers *models.ProviderConfig,
	config *models.CliConfig,
	state *models.ScanState,
	threatCache cache.CacheMap,
	mu *sync.Mutex,
) (shouldStop bool) {
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
		if err := ParsingAbuseIPDB(client, providers.AbuseIPDBAPIKey, ip, &result); err != nil {
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
			HandleCachedResult(ip, cached, state)
			continue
		}

		// Rate limiting (skip wait on first reuqest)
		if state.RequestDone > 0 {
			<-ticker.C 
		}

		// Process IP 
		if shouldStop := ProcessIP(ip, client, providers, config, state, threatCache, &mu); shouldStop {
			break
		}
	}

	return state
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

	// Check VirusTotal quota
	if err := virustotal.CheckVTAPIQuota(client, virustotalApiBaseUrl, providers.VTAPIKey); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Perform Scan
	state := ScanIPs(ips, client, providers, config, threatCache)

	// Final Summary	
	output.DisplaySummaryBanner(state, threatCache, ips, config)	
}

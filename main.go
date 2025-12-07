package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"	
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

// Helper function
func minVal(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func QueryVirustotal(client *http.Client, apiKey string, ip string, result *models.EnhancedCachedResult) error {	
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
			QueryVirustotal(client, virustotalApiBaseUrl, ip, &result)	
		}

		// Query AbuseIPDB
		if providers.UseAbuse {
			fmt.Printf("  → Querying AbuseIPDB...\n")
			abuseData, abuseErr := abuseipdb.QueryAbuseIPDB(client, abuseipdbApiBaseUrl, providers.AbuseIPDBAPIKey, ip)
			requestsDone++

			if abuseErr != nil {
				fmt.Fprintf(os.Stderr, "  ✗ AbuseIPDB error: %v\n", abuseErr)
				if strings.Contains(abuseErr.Error(), "rate limited") {
					mu.Lock()
					fmt.Fprintln(os.Stderr, "[!] AbuseIPDB rate limit hit. Continuing with VT only")
					providers.UseAbuse = false
					mu.Unlock()
				}
			} else {
				result.AbuseScore = abuseData.AbuseConfidenceScore
				result.AbuseTotalReports = abuseData.TotalReports 
				result.AbuseIsTor = abuseData.IsTor 
				result.AbuseCountry = abuseData.CountryCode
				result.AbuseISP = abuseData.ISP
				result.AbuseLastQueried = time.Now().Unix()

				rawBytes, err := json.Marshal(abuseData)
				if err != nil {
					fmt.Println("  ✗ Error parsing abuseipdb datai")
					os.Exit(1)
				}
				result.AbuseRaw = json.RawMessage(rawBytes)

				fmt.Printf("  ✓ AbuseIPDB: Score=%d, Reports=%d, Tor=%v\n", abuseData.AbuseConfidenceScore, abuseData.TotalReports, abuseData.IsTor)
			}
		}

		assessment.CalculateRiskLevel(&result)

		// write outputs & update cache
		mu.Lock()
		threatCache[ip] = result
		
		// Categorized and write to files
		switch result.RiskLevel {
		case "HIGH":
			highRisk = append(highRisk, ip)
			line := fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Tor: %v | Block: YES", ip, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
			if err := appendLine(config.MalFile, line); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Error writing malicious file: %v\n", err)
			}
		case "MEDIUM":
			mediumRisk = append(mediumRisk, ip)
			line := fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Review: YES", ip, len(result.VTMaliciousBy), result.AbuseScore)
			if err := appendLine(config.SuspFile, line); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Error writing suspicious file: %v\n", err)
			}
		default:
			lowRisk = append(lowRisk, ip)
		}

		// Save cache after each IP
		if err := cache.SaveCache(config.CacheFlag, threatCache); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Error saving cache: %v\n", err)
		}
		mu.Unlock()

		// Display summary for this IP
		fmt.Printf("  ▶ Assessment: Risk=%s, Should Block=%v\n", result.RiskLevel, result.ShouldBlock)
		if result.AbuseIsTor {
			fmt.Printf("  ⚠ TOR EXIT NODE DETECTED\n")
		}
		if result.AbuseCountry != "" {
			fmt.Printf("  ℹ Country: %s | ISP: %s\n", result.AbuseCountry, result.AbuseISP)
		}
		fmt.Println()
	}

	// ========================================================================
	// Final Summary
	// ========================================================================
	output.DisplaySummaryBanner()
	fmt.Printf("Total IPs Processed: %d\n", len(ips))
	fmt.Printf("API Requests Made:   %d\n\n", requestsDone)

	// High Risk (Block)
	fmt.Printf("🔴 HIGH RISK (BLOCK): %d\n", len(highRisk))
	if len(highRisk) > 0 {
		output.DisplaySingleLine()	
		for _, ip := range highRisk {
			cached := threatCache[ip]
			fmt.Printf("  • %s\n", ip)
			if len(cached.VTMaliciousBy) > 0 {
				fmt.Printf("    VT Malicious: %v\n", cached.VTMaliciousBy[:minVal(3, len(cached.VTMaliciousBy))])
			}
			fmt.Printf("    AbuseIPDB Score: %d | Reports: %d | Tor: %v\n", cached.AbuseScore, cached.AbuseTotalReports, cached.AbuseIsTor)
		}
	}
	fmt.Println()

	// Medium Risk (REVIEW)
	fmt.Printf("🟡 MEDIUM RISK (REVIEW): %d\n", len(mediumRisk))
	if len(mediumRisk) > 0 {
		output.DisplaySingleLine()	
		for _, ip := range mediumRisk {
			cached := threatCache[ip]
			fmt.Printf("  • %s\n", ip)
			fmt.Printf("    VT: Mal=%d, Susp=%d | AbuseIPDB: %d\n", len(cached.VTMaliciousBy), len(cached.VTSuspiciousBy), cached.AbuseScore)
		}
	}
	fmt.Println()

	// Low Risk (CLEAN)
	fmt.Printf("🟢 LOW RISK (CLEAN): %d\n", len(lowRisk))
	if len(lowRisk) > 0 && len(lowRisk) <= 10 {
		output.DisplaySingleLine()	
		for _, ip := range lowRisk {
			fmt.Printf("  • %s\n", ip)
		}
	}
	fmt.Println()

	// Recommendations
	output.DisplayRecommendationBanner()	
	if len(highRisk) > 0 {
		fmt.Printf("🚨 IMMEDIATE ACTION: Block %d HIGH RISK IPs in firewall\n", len(highRisk))
		fmt.Printf("   See: %s\n", config.MalFile)
	}
	if len(mediumRisk) > 0 {
		fmt.Printf("⚠️  MANUAL REVIEW: Investigate %d MEDIUM RISK IPs\n", len(mediumRisk))
		fmt.Printf("   See: %s\n", config.SuspFile)
	}
	if len(lowRisk) > 0 {
		fmt.Printf("✅ NO ACTION: %d IPs appear clean\n", len(lowRisk))
	}
	fmt.Println()

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

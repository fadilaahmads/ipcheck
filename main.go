package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"	
	"sync"
	"time"

	"ipcheck/models"
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

type cacheMap map[string]models.EnhancedCachedResult

// Helper function
func minVal(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readLines reads lines from a file or stdin and returns deduplicated IPs
func readLinesFromFileOrStdin(filename string) ([]string, error) {
	set := make(map[string]struct{})
	var scanner *bufio.Scanner

	if filename == "" {
		// read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no input provided: supply -file or pipe IPs to stdin")
		}
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Allow comma-separated lists or other common separators
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == ' '
		})
		for _, p := range parts {
			ip := strings.TrimSpace(p)
			// Validate IP
			if net.ParseIP(ip) == nil {
				// skip non-IP tokens silently (or you can log)
				continue
			}
			set[ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	var out []string
	for ip := range set {
		out = append(out, ip)
	}
	return out, nil
}

// loadCache loads vt_cache.json if exists, otherwise returns empty cache
func loadCache(path string) (cacheMap, error) {
	c := make(cacheMap)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if err := dec.Decode(&c); err != nil && err != io.EOF {
		return nil, err
	}
	return c, nil
}

// saveCache writes cache atomically
func saveCache(path string, c cacheMap) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
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

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateBlocks := []*net.IPNet{
		// IPv4 private range
		{IP: net.IPv4(10,0,0,0), Mask: net.CIDRMask(8,32)},
		{IP: net.IPv4(172,16,0,0), Mask: net.CIDRMask(12,32)},
		{IP: net.IPv4(192,168,0,0), Mask: net.CIDRMask(16,32)},
		// IPv6 unique local
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7,128)},
		// IPv6 link-local
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10,128)},
	}

	// Check private ranges
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	
	// also skip loopback and unspecified
	return ip.IsLoopback() || ip.IsUnspecified()
}

// parseAnalysis inspects the JSON response from VT and returns vendor lists
func parseVTAnalysis(body json.RawMessage) (malicious []string, suspicious []string, err error) {
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

func parseVTAPIQuota(body json.RawMessage) (int, int, error) {
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

func checkVTAPIQuota(client *http.Client, apiKey string) (json.RawMessage, error){
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

// queryVT queries VirusTotal v3 for an IP and returns the raw JSON response
func queryVT(client *http.Client, apiKey string, ip string) (json.RawMessage, error) {
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

// ============================================================================
// AbuseIPDB Functions
// ============================================================================

func queryAbuseIPDB(client *http.Client, apiKey string, ip string) (*models.AbuseCheckData, error){

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

// ============================================================================
// Risk Assessment Logic
// ============================================================================

func calculateRiskLevel(result *models.EnhancedCachedResult) {
	// Virustotal score: each malicious vendor = 15 points, suspicious = 5 points
	vtScore := len(result.VTMaliciousBy) * 15
	if len(result.VTSuspiciousBy) > 0 {
		vtScore += len(result.VTSuspiciousBy) * 5 
	}
	if vtScore > 100 {
		vtScore = 100
	}

	// Combined score (weighted average: Virustotal 40%, AbuseIPDB 60%)
	combinedScore := int(float64(vtScore)*0.4 + float64(result.AbuseScore)*0.6)

	// Decission Logic
	switch  {
	case combinedScore >= 75 || result.AbuseIsTor || len(result.VTMaliciousBy) >= 5:
		result.RiskLevel = "HIGH"
		result.ShouldBlock = true
	case combinedScore >= 40 || len(result.VTMaliciousBy) >= 2 || result.AbuseScore >= 50:
		result.RiskLevel = "MEDIUM"
		result.ShouldBlock = false // perlu review manual
	default:
		result.RiskLevel = "LOW"
		result.ShouldBlock = false
	}
}

func main() {
	// flags
	fileFlag := flag.String("file", "", "path to file with IPs (one per line). If empty, reads from stdin")
	intervalFlag := flag.Duration("interval", defaultInterval, "interval between requests. default 15s -> 4 req/min")
	dailyFlag := flag.Int("daily", defaultDailyCap, "daily request cap (per run). default 500")
	cacheFlag := flag.String("cache", cacheFilename, "path to cache json file")
	malFile := flag.String("mal", maliciousOutFile, "malicious output file")
	suspFile := flag.String("susp", suspiciousOutFile, "suspicious output file")
	providerFlag := flag.String("provider", "both", "threat intel provider: vt, abuse, or both")
	flag.Parse()

  // Get API keys	
	vtAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")
	abuseipdbAPIKey := os.Getenv("ABUSEIPDB_API_KEY")

	useVT := (*providerFlag == "vt" || *providerFlag == "both") && vtAPIKey != ""
	useAbuse := (*providerFlag == "abuse" || *providerFlag == "both") && abuseipdbAPIKey != ""

	if !useVT && !useAbuse {
		fmt.Fprintln(os.Stderr, "error: no API keys Set. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY")
		os.Exit(1)
	}

	ips, err := readLinesFromFileOrStdin(*fileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read IPs:", err)
		os.Exit(1)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "no valid IPs found")
		os.Exit(1)
	}

	// load cache
	cache, err := loadCache(*cacheFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load cache:", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 30 * time.Second}
		
	ticker := time.NewTicker(*intervalFlag)
	defer ticker.Stop()

	var mu sync.Mutex // protects cache and counters and file writes
	requestsDone := 0

	// Result tracking
	var highRisk, mediumRisk, lowRisk []string
	fmt.Printf("[*] Starting threat inelligence scan\n")
	fmt.Printf("[*] Providers: VT: %v, AbuseIPDB=%v\n", useVT, useAbuse)
	fmt.Printf("[*] Processing %d IPs\n\n", len(ips))

	for _, ip := range ips {
		// Skip private IPs 
		if isPrivateIP(ip) {
			fmt.Printf("[skip] private/internal IP: %s\n", ip)
			continue
		}

		// Check daily cap
		if requestsDone >= *dailyFlag {
			fmt.Fprintf(os.Stderr, "\n[!] daily cap reached (%d requests). Stopping.\n", *dailyFlag)
			break
		}

		// skip if cached
		mu.Lock()

		cached, exists := cache[ip]
		mu.Unlock()
		if exists {
			fmt.Printf("[cache] %s -> Risk: %s, Should Block: %v\n", ip, cached.RiskLevel, cached.ShouldBlock)
			// categorized cached result
			switch cached.RiskLevel {
			case "HIGH":
				highRisk = append(highRisk, ip)
			case "MEDIUM":
				mediumRisk = append(mediumRisk, ip)
			case "LOW":
				lowRisk = append(lowRisk, ip)
			}
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
		if useVT {
			fmt.Printf("  → Querying VirusTotal . . . \n")
			vtRaw, vtErr := queryVT(client, vtAPIKey, ip)
			requestsDone++
			if vtErr != nil {
				fmt.Fprintf(os.Stderr, "[error] query %s: %v\n", ip, vtErr)
				// If rate-limited by VT, it's best to stop immediately
				if strings.Contains(vtErr.Error(), "rate limited") {
					fmt.Fprintln(os.Stderr, "received rate limit response from VT; stopping further queries")
					break
				}	
			} else {
				malicious, suspicious, parseErr := parseVTAnalysis(vtRaw)
				if parseErr != nil {
					fmt.Fprintf(os.Stderr, "[warn] parse error for %s: %v\n", ip, parseErr)
				} else {
					result.VTMaliciousBy = malicious
					result.VTSuspiciousBy = suspicious
					result.VTLastQueried = time.Now().Unix()
					result.VTRaw = vtRaw
					fmt.Printf("  ✓ VT: Malicious=%d, Suspicious=%d\n", len(malicious), len(suspicious))
				} 
			}	
		}

		// Query AbuseIPDB
		if useAbuse {
			fmt.Printf("  → Querying AbuseIPDB...\n")
			abuseData, abuseErr := queryAbuseIPDB(client, abuseipdbAPIKey, ip)
			requestsDone++

			if abuseErr != nil {
				fmt.Fprintf(os.Stderr, "  ✗ AbuseIPDB error: %v\n", abuseErr)
				if strings.Contains(abuseErr.Error(), "rate limited") {
					fmt.Fprintln(os.Stderr, "[!] AbuseIPDB rate limit hit. Continuing with VT only")
					useAbuse = false
				}
			} else {
				result.AbuseScore = abuseData.AbuseConfidenceScore
				result.AbuseTotalReports = abuseData.TotalReports 
				result.AbuseIsTor = abuseData.IsTor 
				result.AbuseCountry = abuseData.CountryCode
				result.AbuseISP = abuseData.ISP
				result.AbuseLastQueried = time.Now().Unix()

				rawBytes, _ := json.Marshal(abuseData)
				result.AbuseRaw = json.RawMessage(rawBytes)

				fmt.Printf("  ✓ AbuseIPDB: Score=%d, Reports=%d, Tor=%v\n", abuseData.AbuseConfidenceScore, abuseData.TotalReports, abuseData.IsTor)
			}
		}

		// write outputs & update cache
		mu.Lock()
		cache[ip] = result
		
		// Categorized and write to files
		switch result.RiskLevel {
		case "HIGH":
			highRisk = append(highRisk, ip)
			line := fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Tor: %v | Block: YES", ip, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
			if err := appendLine(*malFile, line); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Error writing malicious file: %v\n", err)
			}
		case "MEDIUM":
			mediumRisk = append(mediumRisk, ip)
			line := fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Review: YES", ip, len(result.VTMaliciousBy), result.AbuseScore)
			if err := appendLine(*suspFile, line); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Error writing suspicious file: %v\n", err)
			}
		default:
			lowRisk = append(lowRisk, ip)
		}

		// Save cache after each IP
		if err := saveCache(*cacheFlag, cache); err != nil {
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
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                      THREAT INTELLIGENCE SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Total IPs Processed: %d\n", len(ips))
	fmt.Printf("API Requests Made:   %d\n\n", requestsDone)

	// High Risk (Block)
	fmt.Printf("🔴 HIGH RISK (BLOCK): %d\n", len(highRisk))
	if len(highRisk) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────────")
		for _, ip := range highRisk {
			cached := cache[ip]
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
		fmt.Println("───────────────────────────────────────────────────────────────")
		for _, ip := range mediumRisk {
			cached := cache[ip]
			fmt.Printf("  • %s\n", ip)
			fmt.Printf("    VT: Mal=%d, Susp=%d | AbuseIPDB: %d\n", len(cached.VTMaliciousBy), len(cached.VTSuspiciousBy), cached.AbuseScore)
		}
	}
	fmt.Println()

	// Low Risk (CLEAN)
	fmt.Printf("🟢 LOW RISK (CLEAN): %d\n", len(lowRisk))
	if len(lowRisk) > 0 && len(lowRisk) <= 10 {
		fmt.Println("───────────────────────────────────────────────────────────────")
		for _, ip := range lowRisk {
			fmt.Printf("  • %s\n", ip)
		}
	}
	fmt.Println()

	// Recommendations
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                        RECOMMENDATIONS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	if len(highRisk) > 0 {
		fmt.Printf("🚨 IMMEDIATE ACTION: Block %d HIGH RISK IPs in firewall\n", len(highRisk))
		fmt.Printf("   See: %s\n", *malFile)
	}
	if len(mediumRisk) > 0 {
		fmt.Printf("⚠️  MANUAL REVIEW: Investigate %d MEDIUM RISK IPs\n", len(mediumRisk))
		fmt.Printf("   See: %s\n", *suspFile)
	}
	if len(lowRisk) > 0 {
		fmt.Printf("✅ NO ACTION: %d IPs appear clean\n", len(lowRisk))
	}
	fmt.Println()

	// Export firewall commands (optional feature)
	if len(highRisk) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("Sample Firewall Block Commands:")
		fmt.Println("───────────────────────────────────────────────────────────────")
		for i, ip := range highRisk {
			if i >= 5 {
				fmt.Printf("... and %d more\n", len(highRisk)-5)
				break
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP\n", ip)
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Cache saved to: %s\n", *cacheFlag)
	fmt.Println("Scan complete.")

	}
}

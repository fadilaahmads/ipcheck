package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"	
	"sync"
	"time"
)

// Configurable defaults
const (
	defaultInterval  = 15 * time.Second // 4 req / minute => 1 every 15s
	defaultDailyCap  = 500
	cacheFilename    = "vt_cache.json"
	maliciousOutFile = "malicious.txt"
	suspiciousOutFile= "suspicious.txt"
	apiBaseURL = "https://www.virustotal.com/api/v3/"
	)

// cachedResult stores parsed vendors for an IP and when it was queried
type cachedResult struct {
	IP            string   `json:"ip"`
	MaliciousBy   []string `json:"malicious_by,omitempty"`
	SuspiciousBy  []string `json:"suspicious_by,omitempty"`
	LastQueriedAt int64    `json:"last_queried_at"`
	Raw           json.RawMessage `json:"raw,omitempty"`
}

type cacheMap map[string]cachedResult

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

// parseAnalysis inspects the JSON response from VT and returns vendor lists
func parseAnalysis(body json.RawMessage) (malicious []string, suspicious []string, err error) {
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
	req, err := http.NewRequest("GET", apiBaseURL+"users/"+apiKey+"/api_usage", nil)
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
	req, err := http.NewRequest("GET", apiBaseURL+"ip_addresses/"+ip, nil)
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

func main() {
	// flags
	fileFlag := flag.String("file", "", "path to file with IPs (one per line). If empty, reads from stdin")
	intervalFlag := flag.Duration("interval", defaultInterval, "interval between requests (for rate limiting). default 15s -> 4 req/min")
	dailyFlag := flag.Int("daily", defaultDailyCap, "daily request cap (per run). default 500")
	cacheFlag := flag.String("cache", cacheFilename, "path to cache json file")
	malFile := flag.String("mal", maliciousOutFile, "malicious output file")
	suspFile := flag.String("susp", suspiciousOutFile, "suspicious output file")
	flag.Parse()

	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: VIRUSTOTAL_API_KEY env var not set")
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
	
	//Check Available Virustotal quota
	vtQuota, err := checkVTAPIQuota(client, apiKey)
	quotaTotal, quotaToday, err := parseVTAPIQuota(vtQuota)
	fmt.Printf("[*] Total VirusTotal Quota: %d out of 15k\n", quotaTotal)
	fmt.Printf("[*] Used request: %d / 500 daily\n", quotaToday) 

	ticker := time.NewTicker(*intervalFlag)
	defer ticker.Stop()

	var mu sync.Mutex // protects cache and counters and file writes
	requestsDone := 0

	for _, ip := range ips {
		// Check daily cap
		if requestsDone >= *dailyFlag {
			fmt.Fprintf(os.Stderr, "daily cap reached (%d requests). stopping.\n", *dailyFlag)
			break
		}

		// skip if already cached
		mu.Lock()
		if _, ok := cache[ip]; ok {
			mu.Unlock()
			fmt.Printf("[skip] cached: %s\n", ip)
			continue
		}
		mu.Unlock()

		// Wait for ticker (rate-limiting). For first iteration, do not wait.
		if requestsDone > 0 {
			<-ticker.C
		}

		fmt.Printf("[query] %s\n", ip)
		raw, qerr := queryVT(client, apiKey, ip)
		requestsDone++

		if qerr != nil {
			fmt.Fprintf(os.Stderr, "[error] query %s: %v\n", ip, qerr)
			// If rate-limited by VT, it's best to stop immediately
			if strings.Contains(qerr.Error(), "rate limited") {
				fmt.Fprintln(os.Stderr, "received rate limit response from VT; stopping further queries")
				break
			}
			// continue to next ip on other errors
			continue
		}

		malicious, suspicious, perr := parseAnalysis(raw)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "[warn] parse error for %s: %v\n", ip, perr)
		}

		cr := cachedResult{
			IP:            ip,
			MaliciousBy:   malicious,
			SuspiciousBy:  suspicious,
			LastQueriedAt: time.Now().Unix(),
			Raw:           raw,
		}

		// write outputs & update cache
		mu.Lock()
		cache[ip] = cr	
		// Append to malicious/suspicious files if vendors exist
		if len(malicious) > 0 {
			for _, v := range malicious {
				line := fmt.Sprintf("%s %s", ip, v)
				if err := appendLine(*malFile, line); err != nil {
					fmt.Fprintf(os.Stderr, "[err] writing malicious file: %v\n", err)
				}
			}
		}
		if len(suspicious) > 0 {
			for _, v := range suspicious {
				line := fmt.Sprintf("%s %s", ip, v)
				if err := appendLine(*suspFile, line); err != nil {
					fmt.Fprintf(os.Stderr, "[err] writing suspicious file: %v\n", err)
				}
			}
		}
		// persist cache after every write (safe but slightly slower)
		if err := saveCache(*cacheFlag, cache); err != nil {
			fmt.Fprintf(os.Stderr, "[err] saving cache: %v\n", err)
		}
		mu.Unlock()

		// small info
		if len(malicious) > 0 {
			fmt.Printf("[malicious] %s -> %v\n", ip, malicious)
		} else if len(suspicious) > 0 {
			fmt.Printf("[suspicious] %s -> %v\n", ip, suspicious)
		} else {
			fmt.Printf("[clean] %s\n", ip)
		}
	}

	fmt.Println("done. requests:", requestsDone)
}


package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"	
	"time"
	
	"ipcheck/internal/cache"
	"ipcheck/internal/input"
	"ipcheck/internal/models"
	"ipcheck/internal/orchestrator"
	"ipcheck/internal/output"
	"ipcheck/internal/providers"
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

func main() {
	// flags
	config := ParseFlags()
  // Get API keys	
	providers, err := providers.SetupProviders(config.ProviderFlag, virustotalApiBaseUrl, abuseipdbApiBaseUrl)
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
	state := orchestrator.ScanIPs(ips, client, providers, config, threatCache)

	// Final Summary	
	output.DisplaySummaryBanner(state, threatCache, ips, config)	
}

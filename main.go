package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
	
	// Setup context for graceful shutdown
	ctx, cancel :=  context.WithCancel(context.Background())


	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

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

	doneChan := make(chan *models.ScanState)

	// Perform scan in goroutine
	go func() {
		state := orchestrator.ScanIPs(ctx, ips, client, providers, config, threatCache)
		doneChan <- state
	}()

	// Wait for either completion or interrupt
	var state *models.ScanState
	var interrupted bool

	select {
	case <- sigChan:
		fmt.Fprintf(os.Stderr, "\n\n[!] Interrupt received. Shutting down gracefully...\n")
		interrupted = true
		cancel() // Signal the scanner to stop

		select {
		case state = <- doneChan:
			fmt.Fprintf(os.Stderr, "[*] Scanner stopped cleanly\n")
		case <- time.After(5*time.Second):
			fmt.Fprintf(os.Stderr, "[!] Timeout waiting for scanner to stop\n")
			state = &models.ScanState{} // Create empty state
		}

	case state = <- doneChan:
		// Normal completion
		interrupted = false
	}

	fmt.Fprintf(os.Stderr, "[*] Saving cache...\n")
	if err := cache.SaveCache(config.CacheFlag, threatCache); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to save cache: %v\n", err)
		os.Exit(1)
	}

	// Final Summary
	if interrupted {
		output.DisplayInterruptedSummary(state, threatCache, ips, config)
	} else {
		output.DisplaySummaryBanner(state, threatCache, ips, config)
	}
}

package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
	
	"ipcheck/internal/assessment"
	"ipcheck/internal/input"
	"ipcheck/internal/models"
	"ipcheck/internal/output"
	"ipcheck/internal/providers/abuseipdb"	
	"ipcheck/internal/providers/virustotal"
	"ipcheck/internal/ratelimit"
	"ipcheck/internal/repositories"
)

type ProcessIPSArgs struct {
	Client      *http.Client
	Providers   *models.ProviderConfig
	Config      *models.CliConfig
	Repo        repositories.Repository
}

// ProcessIP queries threat intelligence providers and assess a single IP
func processIP(ctx context.Context, ip string, args *ProcessIPSArgs) (*models.EnhancedCachedResult, error) {
	client := args.Client
	providers := args.Providers
	config := args.Config
	repo := args.Repo

	fmt.Printf("[query] %s\n", ip)

	result := models.EnhancedCachedResult{
		IP:          ip,
		LastUpdated: time.Now().Unix(),
	}
	// Query VirusTotal
	if providers.UseVT {
		if err := virustotal.CheckVTIPData(ctx, client, providers.VTAPIKey, ip, providers.VirustotalApiBaseUrl, &result); err != nil {
			return nil, fmt.Errorf("VirusTotal error for %s: %v", ip, err)
		}
	}

	// Query AbuseIPDB
	if providers.UseAbuse {
		if err := abuseipdb.ParseAbuseIPDBIPData(ctx, client, providers.AbuseIPDBAPIKey, ip, providers.AbuseipdbApiBaseUrl, &result); err != nil {
			return nil, fmt.Errorf("AbuseIPDB error for %s: %v", ip, err)
		}
	}

	assessment.CalculateRiskLevel(&result)

	// write outputs & update repository
	if err := repo.SaveIP(ctx, &result); err != nil {
		fmt.Fprintf(os.Stderr, "   ✗ Error saving result to repository: %v\n", err)
	}

	// Categorized and write to files (keeping this for manual log comparison as requested)
	if err := output.SaveResultToFile(&result, config.MalFile, config.SuspFile); err != nil {
		fmt.Fprintf(os.Stderr, "   ✗ Error writing output file: %v\n", err)
	}

	// Display summary for this IP
	output.DisplaySingleIPSummary(&result)

	return &result, nil
}

// ScanIP performs the main scanning loop
func ScanIPs(
	ctx context.Context,
	ips []string,
	client *http.Client,
	providers *models.ProviderConfig,
	config *models.CliConfig,
	repo repositories.Repository,
	rateLimiter ratelimit.RateLimiter,
) *models.ScanState {
	defer rateLimiter.Stop()

	state := &models.ScanState{}

	processIPConfig := ProcessIPSArgs{
		Client:      client,
		Providers:   providers,
		Config:      config,
		Repo:        repo,
	}

	for _, ip := range ips {
		// Check for cancellation before processing each IP 
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\n[*] Shutdown signal received. Stopping scan...\n")
			return state
		default:
			// Contnue processing
		}

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

		// Check repository (cache)
		cached, exists, err := repo.GetIP(ctx, ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ✗ Error checking repository: %v\n", err)
		}

		if exists {
			fmt.Printf("[cache] %s -> Risk: %s, Should Block: %v\n", ip, cached.RiskLevel, cached.ShouldBlock)
			// Update state for summary
			switch cached.RiskLevel {
			case "HIGH":
				state.HighRisk = append(state.HighRisk, ip)
			case "MEDIUM":
				state.MediumRisk = append(state.MediumRisk, ip)
			case "LOW":
				state.LowRisk = append(state.LowRisk, ip)
			}
			continue
		}

		// Rate limiting (skip wait on first reuqest)
		if state.RequestDone > 0 {
			if err := rateLimiter.Wait(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "\n[*] Shutdown signal received during rate limit wait: %v. Stopping scan...\n", err)
				return state
			}
		}

		state.RequestDone++

		// Process IP 
		result, err := processIP(ctx, ip, &processIPConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ✗ %v\n", err)
			continue // Skip to next IP instead of exiting
		}

		// Update state for summary
		switch result.RiskLevel {
		case "HIGH":
			state.HighRisk = append(state.HighRisk, ip)
		case "MEDIUM":
			state.MediumRisk = append(state.MediumRisk, ip)
		case "LOW":
			state.LowRisk = append(state.LowRisk, ip)
		}
	}

	return state
}

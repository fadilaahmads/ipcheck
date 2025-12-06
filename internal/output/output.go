package output

import (
	"fmt"

	"ipcheck/internal/models"
)

func DisplaySingleLine() {
	fmt.Println("───────────────────────────────────────────────────────────────")
}

func DisplayDoubleLine() {
	fmt.Println("═══════════════════════════════════════════════════════════════")	
}

func DisplayRecommendationBanner() {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                        RECOMMENDATIONS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func DisplaySummaryBanner() {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                      THREAT INTELLIGENCE SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func DisplayFirewallCommandBanner()  {
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("Sample Firewall Block Commands:")
	fmt.Println("───────────────────────────────────────────────────────────────")	
}

func PrintScanHeader(providers *models.ProviderConfig, ipCount int) {
	fmt.Printf("[*] Starting threat inelligence scan\n")
	fmt.Printf("[*] Providers: VT: %v, AbuseIPDB=%v\n", providers.UseVT, providers.UseAbuse)
	fmt.Printf("[*] Processing %d IPs\n", ipCount)
}

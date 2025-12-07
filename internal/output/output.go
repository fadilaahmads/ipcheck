package output

import (
	"fmt"
	
	"ipcheck/internal/cache"
	"ipcheck/internal/models"
	"ipcheck/internal/utils"
)

func DisplaySingleLine() {
	fmt.Println("───────────────────────────────────────────────────────────────")
}

func DisplayDoubleLine() {
	fmt.Println("═══════════════════════════════════════════════════════════════")	
}

func DisplayRecommendationBanner(state *models.ScanState, malFile, suspFile string) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                        RECOMMENDATIONS")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if len(state.HighRisk) > 0 {
		fmt.Printf("🚨 IMMEDIATE ACTION: Block %d HIGH RISK IPs in firewall\n", len(state.HighRisk))
		fmt.Printf("   See: %s\n", malFile)
	}
	if len(state.MediumRisk) > 0 {
		fmt.Printf("⚠️  MANUAL REVIEW: Investigate %d MEDIUM RISK IPs\n", len(state.MediumRisk))
		fmt.Printf("   See: %s\n", suspFile)
	}
	if len(state.LowRisk) > 0 {
		fmt.Printf("✅ NO ACTION: %d IPs appear clean\n", len(state.LowRisk))
	}
	fmt.Println()
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

func DisplaySingleIPSummary(result *models.EnhancedCachedResult)  {
	fmt.Printf("  ▶ Assessment: Risk=%s, Should Block=%v\n", result.RiskLevel, result.ShouldBlock)
	if result.AbuseIsTor {
		fmt.Printf("  ⚠ TOR EXIT NODE DETECTED\n")
	}
	if result.AbuseCountry != "" {
		fmt.Printf("  ℹ Country: %s | ISP: %s\n", result.AbuseCountry, result.AbuseISP)
	}
	fmt.Println()	
}

func PrintHighRiskSummary(highRisk []string, threatCache cache.CacheMap)  {
	fmt.Printf("🔴 HIGH RISK (BLOCK): %d\n", len(highRisk))
	if len(highRisk) == 0 {
		fmt.Println()
		return
	}

	DisplaySingleLine()

	for _, ip := range highRisk {
		cached := threatCache[ip]
		fmt.Printf("  • %s\n", ip)
		if len(cached.VTMaliciousBy) > 0 {
			fmt.Printf("    VT Malicious: %v\n", cached.VTMaliciousBy[:utils.MinVal(3, len(cached.VTMaliciousBy))])
		}
		fmt.Printf("    AbuseIPDB Score: %d | Reports: %d | Tor: %v\n", 
			cached.AbuseScore, cached.AbuseTotalReports, cached.AbuseIsTor)
	}
	fmt.Println()
}

func PrintMediumRiskSummary(mediumRisk []string, threatCache cache.CacheMap) {
	fmt.Printf("🟡 MEDIUM RISK (REVIEW): %d\n", len(mediumRisk))
	if len(mediumRisk) == 0 {
		fmt.Println()
		return
	}

	DisplaySingleLine()

	for _, ip := range mediumRisk {
		cached := threatCache[ip]
		fmt.Printf("  • %s\n", ip)
		fmt.Printf("    VT: Mal=%d, Susp=%d | AbuseIPDB: %d\n", 
			len(cached.VTMaliciousBy), len(cached.VTSuspiciousBy), cached.AbuseScore)
	}
	fmt.Println()
}

func PrintLowRiskSummary(lowRisk []string) {
	fmt.Printf("🟢 LOW RISK (CLEAN): %d\n", len(lowRisk))
	if len(lowRisk) > 0 && len(lowRisk) <= 10 {
		DisplaySingleLine()	
		for _, ip := range lowRisk {
			fmt.Printf("  • %s\n", ip)
		}
	}
	fmt.Println()
}

package output

import (
	"fmt"
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

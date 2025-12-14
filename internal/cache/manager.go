package cache

import (
	"fmt"

	"ipcheck/internal/models"
)

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

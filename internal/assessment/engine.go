package assessment

import (
	"ipcheck/internal/models"
)

// ============================================================================
// Risk Assessment Logic
// ============================================================================

func CalculateRiskLevel(result *models.EnhancedCachedResult) {
	// 1. VT Score Calculation (More aggressive: 20 points per malicious vendor)
	vtScore := len(result.VTMaliciousBy) * 20
	vtScore += len(result.VTSuspiciousBy) * 5
	if vtScore > 100 {
		vtScore = 100
	}

	// 2. AbuseIPDB Volumetric Boost
	// We give a "bonus" to the score based on the raw number of reports.
	// This helps catch high-activity attackers that haven't hit 100% confidence yet.
	reportBonus := 0
	switch {
	case result.AbuseTotalReports >= 500:
		reportBonus = 25
	case result.AbuseTotalReports >= 100:
		reportBonus = 15
	case result.AbuseTotalReports >= 20:
		reportBonus = 5
	}

	// 3. Combined weighted score (VT 60% / Abuse 40%) + Volumetric Bonus
	combinedScore := int(float64(vtScore)*0.6+float64(result.AbuseScore)*0.4) + reportBonus

	// 4. Decision Logic (SOC-Grade Thresholds)
	switch {
	case result.AbuseIsTor:
		// TOR exit nodes are high risk for attacks but not always "malicious"
		// In an attack scenario, they should usually be blocked.
		result.RiskLevel = "HIGH"
		result.ShouldBlock = true

	case combinedScore >= 70 || len(result.VTMaliciousBy) >= 3 || result.AbuseScore >= 80:
		// Trigger HIGH if:
		// - Combined score is high (consensus)
		// - OR 3+ vendors agree (consensus)
		// - OR AbuseIPDB is very confident
		result.RiskLevel = "HIGH"
		result.ShouldBlock = true

	case combinedScore >= 30 || len(result.VTMaliciousBy) >= 1 || result.AbuseTotalReports >= 5:
		// Trigger MEDIUM if there is ANY evidence of suspicious activity
		result.RiskLevel = "MEDIUM"
		result.ShouldBlock = false

	default:
		result.RiskLevel = "LOW"
		result.ShouldBlock = false
	}
}

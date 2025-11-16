package assessment

import (
	"ipcheck/internal/models"
)

// ============================================================================
// Risk Assessment Logic
// ============================================================================

func CalculateRiskLevel(result *models.EnhancedCachedResult) {
	// Virustotal score: each malicious vendor = 15 points, suspicious = 5 points
	vtScore := len(result.VTMaliciousBy) * 15
	if len(result.VTSuspiciousBy) > 0 {
		vtScore += len(result.VTSuspiciousBy) * 5 
	}
	if vtScore > 100 {
		vtScore = 100
	}

	// Combined score (weighted average: Virustotal 40%, AbuseIPDB 60%)
	combinedScore := int(float64(vtScore)*0.6 + float64(result.AbuseScore)*0.4)

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

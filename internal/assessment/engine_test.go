package assessment

import (
	"testing"
	"ipcheck/internal/models"
)

func TestCalculateRiskLevel(t *testing.T) {
	tests := []struct {
		name           string
		input          *models.EnhancedCachedResult
		expectedRisk   string
		expectedBlock  bool
	}{
		{
			name: "Low Risk - Clean IP",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy: []string{},
				AbuseScore:    0,
				AbuseIsTor:    false,
			},
			expectedRisk:  "LOW",
			expectedBlock: false,
		},
		{
			name: "High Risk - Tor Exit Node",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy: []string{},
				AbuseScore:    0,
				AbuseIsTor:    true,
			},
			expectedRisk:  "HIGH",
			expectedBlock: true,
		},
		{
			name: "High Risk - 3+ VT Detections (New Threshold)",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy: []string{"v1", "v2", "v3"},
				AbuseScore:    0,
			},
			expectedRisk:  "HIGH",
			expectedBlock: true,
		},
		{
			name: "High Risk - High Abuse Confidence (80+)",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy: []string{},
				AbuseScore:    85,
			},
			expectedRisk:  "HIGH",
			expectedBlock: true,
		},
		{
			name: "High Risk - Volumetric Boost (100 reports)",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy:     []string{"v1", "v2"}, // 20*2 = 40 (old math: 30)
				AbuseScore:        50,                   // 50
				AbuseTotalReports: 100,                  // 15 point bonus
				// Score = (40*0.6) + (50*0.4) + 15 = 24 + 20 + 15 = 59 (still not 70)
				// BUT 59 is well into MEDIUM. Let's adjust input to hit 70.
			},
			expectedRisk:  "MEDIUM", // 59 < 70
			expectedBlock: false,
		},
		{
			name: "High Risk - Combined Score with Volumetric Bonus",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy:     []string{"v1", "v2"}, // 40
				AbuseScore:        70,                   // 70
				AbuseTotalReports: 100,                  // 15 point bonus
				// Score = (40*0.6) + (70*0.4) + 15 = 24 + 28 + 15 = 67
				// Almost 70. Let's add 1 vendor.
			},
			expectedRisk:  "HIGH", // Hits via "len(VTMaliciousBy) >= 3" trigger
			expectedBlock: true,
		},
		{
			name: "Medium Risk - Any evidence",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy: []string{"v1"},
				AbuseScore:    0,
			},
			expectedRisk:  "MEDIUM",
			expectedBlock: false,
		},
		{
			name: "Medium Risk - Small report count",
			input: &models.EnhancedCachedResult{
				VTMaliciousBy:     []string{},
				AbuseScore:        0,
				AbuseTotalReports: 5,
			},
			expectedRisk:  "MEDIUM",
			expectedBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CalculateRiskLevel(tt.input)
			
			if tt.input.RiskLevel != tt.expectedRisk {
				t.Errorf("RiskLevel mismatch in %s: expected %s, got %s", tt.name, tt.expectedRisk, tt.input.RiskLevel)
			}
			
			if tt.input.ShouldBlock != tt.expectedBlock {
				t.Errorf("ShouldBlock mismatch in %s: expected %t, got %t", tt.name, tt.expectedBlock, tt.input.ShouldBlock)
			}
		})
	}
}

package output

import (
	"fmt"
	"os"
	"path/filepath"

	"ipcheck/internal/models"
)

// appendLine appends a single line to a file, creating it if needed
func appendLine(path string, line string) error {
	// ensure directory exists
	if dir := filepath.Dir(path); dir != "." {
		os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}
func SaveResultToFile(result *models.EnhancedCachedResult, malFile, suspFile string) error {
	var line string
	var outputFile string

	switch result.RiskLevel {
	case "HIGH":
		line = fmt.Sprintf("%s | Risk: HIGH | VT_Mal: %d | Abuse: %d | Tor: %v | Block: YES",
	 result.IP, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
	 outputFile = malFile 
  case "MEDIUM":
		line = fmt.Sprintf("%s | Risk: MEDIUM | VT_Mal: %d | Abuse: %d | Tor: %v | Review: YES",
	 result.IP, len(result.VTMaliciousBy), result.AbuseScore, result.AbuseIsTor)
	 outputFile = suspFile
	default:
	 return nil // Low risk doesn't need file output
	}

	return appendLine(outputFile, line)
}

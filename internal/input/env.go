package input

import (
	"bufio"
	"os"
	"strings"
)

// ParseEnvFile reads a .env file and returns a map of key-value pairs.
// It ignores empty lines and lines starting with #.
func ParseEnvFile(path string) (map[string]string, error) {
	envMap := make(map[string]string)

	file, err := os.Open(path)
	if err != nil {
		// If file doesn't exist, return empty map (not an error for our use case)
		if os.IsNotExist(err) {
			return envMap, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines or comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by first '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // skip invalid lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// Skip if key is empty (malformed line like "=value")
		if key == "" {
			continue
		}
		
		// Remove quotes if present
		value = strings.Trim(value, "\"'")
		
		envMap[key] = value
	}

	return envMap, scanner.Err()
}

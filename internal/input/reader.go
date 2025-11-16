package input

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	
)

// readLines reads lines from a file or stdin and returns deduplicated IPs
func ReadLinesFromFileOrStdin(filename string) ([]string, error) {
	set := make(map[string]struct{})
	var scanner *bufio.Scanner

	if filename == "" {
		// read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no input provided: supply -file or pipe IPs to stdin")
		}
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Allow comma-separated lists or other common separators
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == ' '
		})
		for _, p := range parts {
			ip := strings.TrimSpace(p)
			// Validate IP
			if net.ParseIP(ip) == nil {
				// skip non-IP tokens silently (or you can log)
				continue
			}
			set[ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	var out []string
	for ip := range set {
		out = append(out, ip)
	}
	return out, nil
}

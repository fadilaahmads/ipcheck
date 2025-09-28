# VirusTotal IP Checker

A Go-based command-line tool for SOC analysts and security professionals to automate IP address reputation checking against VirusTotal. This tool helps streamline the process of analyzing suspicious IPs found in SIEM alerts by batch querying VirusTotal's API and categorizing results.

## Features

- **Batch IP Processing**: Check multiple IP addresses from file or stdin
- **Smart Caching**: Avoids redundant API calls with persistent JSON cache
- **Rate Limiting**: Respects VirusTotal API limits with configurable intervals
- **Private IP Filtering**: Automatically skips RFC 1918 private IP ranges
- **Categorized Output**: Separates results into malicious, suspicious, and clean categories
- **Quota Monitoring**: Displays current API usage against daily limits
- **Flexible Input**: Supports various input formats (newline, comma, space, tab separated)

## Prerequisites

- Go 1.16 or higher
- VirusTotal API key (free or premium)

## Installation

1. Clone or download the source code
2. Build the binary:
```bash
go build -o vtcheck main.go
```

## Configuration

### API Key Setup
Set your VirusTotal API key as an environment variable:
```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

### Default Settings
- **Request Interval**: 15 seconds (4 requests/minute for free tier)
- **Daily Cap**: 500 requests per run
- **Cache File**: `vt_cache.json`
- **Output Files**: 
  - `malicious.txt` - IPs flagged as malicious by vendors
  - `suspicious.txt` - IPs flagged as suspicious by vendors

## Usage

### Basic Usage

**From file:**
```bash
./vtcheck -file ips.txt
```

**From stdin (pipe):**
```bash
cat ips.txt | ./vtcheck
echo "192.168.1.1,10.0.0.1,8.8.8.8" | ./vtcheck
```

### Command Line Options

```bash
./vtcheck [options]

Options:
  -file string        Path to file with IPs (one per line). If empty, reads from stdin
  -interval duration  Interval between requests for rate limiting (default 15s)
  -daily int         Daily request cap per run (default 500)
  -cache string      Path to cache JSON file (default "vt_cache.json")
  -mal string        Malicious output file (default "malicious.txt")
  -susp string       Suspicious output file (default "suspicious.txt")
```

### Input Format Examples

The tool accepts various input formats:

**Line-separated:**
```
8.8.8.8
1.1.1.1
malicious-ip.com
```

**Comma-separated:**
```
8.8.8.8,1.1.1.1,suspicious-ip.com
```

**Mixed format:**
```
8.8.8.8, 1.1.1.1; suspicious-ip.com	another-ip.com
```

## Output

### Console Output
```
[*] Total VirusTotal Quota: 1250 out of 15k
[*] Used request: 45 / 500 daily
[skip] private/internal IP: 192.168.1.1
[skip] cached: 8.8.8.8
[query] 203.0.113.1
[malicious] 203.0.113.1 -> [Vendor1 Vendor2]
[suspicious] 198.51.100.1 -> [Vendor3]
[clean] 8.8.4.4
[*] Summary results
[>] Malicious: 1
203.0.113.1 
[>] Suspicious: 1
198.51.100.1 
[>] Clean: 1
8.8.4.4 
[>] Done. requests made: 3
```

### Output Files

**malicious.txt:**
```
203.0.113.1 Vendor1
203.0.113.1 Vendor2
```

**suspicious.txt:**
```
198.51.100.1 Vendor3
```

### Cache File Structure
The tool maintains a JSON cache (`vt_cache.json`) to avoid repeated API calls:
```json
{
  "8.8.8.8": {
    "ip": "8.8.8.8",
    "malicious_by": [],
    "suspicious_by": [],
    "last_queried_at": 1640995200,
    "raw": {...}
  }
}
```

## SOC Workflow Integration

### Typical SOC Use Case
1. **SIEM Alert Analysis**: Extract suspicious IPs from Wazuh/SIEM alerts
2. **Batch Processing**: Feed IPs to this tool for reputation checking
3. **Decision Making**: Use categorized results to make blocking/allowing decisions
4. **Documentation**: Output files serve as evidence for incident reports

### Example Workflow
```bash
# Extract IPs from SIEM logs and check reputation
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/siem/alerts.log | \
sort -u | \
./vtcheck

# Review results
cat malicious.txt suspicious.txt

# Apply firewall rules based on results
# (implementation depends on your firewall solution)
```

## Rate Limiting & Quotas

### Free Tier Limits
- 15,000 requests per month
- 4 requests per minute
- The tool defaults are optimized for free tier usage

### Premium Tier
For higher throughput, adjust the interval:
```bash
./vtcheck -interval 1s -daily 1000 -file ips.txt
```

## Best Practices

1. **Cache Management**: The cache persists between runs to minimize API usage
2. **Private IP Handling**: Tool automatically skips RFC 1918 ranges
3. **Error Handling**: Non-fatal errors continue processing remaining IPs
4. **Rate Limit Respect**: Built-in throttling prevents API key suspension
5. **Incremental Processing**: Process IPs in batches to stay within daily limits

## Troubleshooting

### Common Issues

**"VIRUSTOTAL_API_KEY env var not set"**
- Solution: Set the environment variable with your API key

**"rate limited" errors**
- Solution: Increase the `-interval` parameter or wait before retrying

**"no valid IPs found"**
- Solution: Check input format and ensure IPs are properly formatted

**Permission errors on output files**
- Solution: Ensure write permissions in the current directory

### Debug Tips
- Check quota usage with the initial output
- Review cache file for previously processed IPs
- Validate input IP format (tool skips invalid IPs silently)

## Security Considerations

- Store API keys securely (environment variables, not in code)
- Review output files before applying blocking rules
- Consider false positive rates when making blocking decisions
- Regularly rotate API keys following security best practices

## Contributing

This tool is designed for SOC operations and can be extended with:
- Additional threat intelligence sources
- Integration with SIEM APIs
- Automated firewall rule generation
- Custom output formats (JSON, CSV)

## License

MIT License

Copyright (c) 2024 Fadila Ahmad S

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Support

For SOC-specific use cases or integration questions, please refer to your organization's cybersecurity documentation or contact your security team leads.

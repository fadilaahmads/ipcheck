# IP Reputation Checker

A Go-based command-line tool for SOC analysts and security professionals to automate IP address reputation checking against multiple threat intelligence platforms. This tool helps streamline the process of analyzing suspicious IPs found in SIEM alerts by batch querying APIs and categorizing results.

## Features

- **Multi-provider Support**: Check IP addresses against VirusTotal and AbuseIPDB.
- **Batch IP Processing**: Check multiple IP addresses from file or stdin.
- **Smart Caching**: Avoids redundant API calls with a persistent JSON cache.
- **Rate Limiting**: Respects API limits with configurable intervals.
- **Private IP Filtering**: Automatically skips RFC 1918 private IP ranges.
- **Categorized Output**: Separates results into malicious and suspicious categories.
- **Flexible Input**: Supports various input formats (newline, comma, space, tab separated).

## Installation

1.  **Prerequisites**:
    *   Go 1.16 or higher
    *   VirusTotal API key (free or premium)
    *   AbuseIPDB API key

2.  **Build from source**:
    ```bash
    git clone https://github.com/fadilaahmads/ipcheck.git
    cd ipcheck
    make build
    ```
    This will create the `ipcheck` binary in the current directory.

## Quick Start

1.  **Set API Keys**:
    Set your API keys as environment variables:
    ```bash
    export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
    export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
    ```

2.  **Run a Scan**:
    You can run `ipcheck` with a file containing IPs or by piping them from stdin.

    *   **From a file:**
        Create a file named `ips.txt` with one or more IPs per line:
        ```
        8.8.8.8
        1.1.1.1
        ```
        Then run:
        ```bash
        ./ipcheck -file ips.txt
        ```

    *   **From stdin:**
        ```bash
        echo "8.8.8.8 1.1.1.1" | ./ipcheck
        ```

## Usage/Flags

```
./ipcheck [options]
```

| Flag | Description | Default |
|---|---|---|
| `-file` | Path to a file with IPs. If empty, reads from stdin. | `""` |
| `-provider` | Threat intelligence provider: `vt` (VirusTotal), `abuse` (AbuseIPDB), or `both`. | `"both"` |
| `-interval` | Interval between requests for rate limiting. | `15s` |
| `-daily` | Daily request cap per run. | `50` |
| `-cache` | Path to the cache JSON file. | `"threat_intel_cache.json"` |
| `-mal` | Malicious output file. | `"malicious.txt"` |
| `-susp` | Suspicious output file. | `"suspicious.txt"` |

## Contributor

-   Fadila Ahmad S

## LICENSE

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

## Troubleshooting/FAQ

**Q: I'm getting "API key not set" errors.**

A: Make sure you have set both `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` environment variables.

**Q: The tool is running slowly.**

A: The default request interval is 15 seconds to comply with the free tier of VirusTotal's API. You can adjust this with the `-interval` flag if you have a premium key.

**Q: How do I choose which provider to use?**

A: Use the `-provider` flag. For example, to use only AbuseIPDB, run `./ipcheck -provider abuse`.

**Q: I'm getting "no valid IPs found" but my file has IPs.**

A: Ensure your IPs are correctly formatted and separated by newlines, commas, spaces, or tabs. The tool will silently skip any invalid entries.

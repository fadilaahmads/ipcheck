# IP Reputation Checker

A Go-based command-line tool for SOC analysts and security professionals to automate IP address reputation checking against multiple threat intelligence platforms. Designed as a building block for **SOAR (Security Orchestration, Automation, and Response)** stacks.

## Features

- **Multi-provider Support**: Check IP addresses against VirusTotal and AbuseIPDB.
- **SOAR-Ready Architecture**: Uses a Repository pattern to support both local JSON and high-concurrency PostgreSQL backends.
- **SOC-Grade Scoring**: Aggressive risk assessment logic with volumetric boosting based on report counts and vendor consensus.
- **Smart Caching**: Avoids redundant API calls with persistent storage (JSON or SQL).
- **Environment Configuration**: Securely manage credentials via `.env` files or system environment variables.
- **Rate Limiting**: Respects API limits with configurable intervals and daily caps.
- **Private IP Filtering**: Automatically skips RFC 1918 private IP ranges and loopbacks.
- **Historical Tracking**: When using PostgreSQL, every scan is recorded for time-series analysis of IP reputation.

## Installation

1.  **Prerequisites**:
    *   Go 1.24 or higher
    *   VirusTotal API key
    *   AbuseIPDB API key
    *   PostgreSQL (Optional, for high-concurrency usage)

2.  **Build from source**:
    ```bash
    git clone https://github.com/fadilaahmads/ipcheck.git
    cd ipcheck
    make build
    ```

## Configuration

The tool prioritizes configuration in the following order: `.env` file > CLI Flags > Environment Variables.

Create a `.env` file in the project root:
```bash
# API Keys
VIRUSTOTAL_API_KEY="your_vt_key"
ABUSEIPDB_API_KEY="your_abuse_key"

# Database (Optional)
IPCHECK_DB_URL="postgres://user:pass@localhost:5432/ipcheck_db"
```

## Database Setup (PostgreSQL)

If you are using PostgreSQL for centralized storage, initialize the schema:
```bash
make migrate DB_CONN="postgres://user:pass@localhost:5432/ipcheck_db"
```

## Quick Start

1.  **Basic Scan (JSON Cache):**
    ```bash
    ./ipcheck -file ips.txt
    ```

2.  **SQL-Backed Scan:**
    ```bash
    ./ipcheck -db "postgres://..." -file ips.txt
    ```

3.  **Piped Input:**
    ```bash
    echo "8.8.8.8" | ./ipcheck
    ```

## Usage/Flags

| Flag | Description | Default |
|---|---|---|
| `-file` | Path to a file with IPs. If empty, reads from stdin. | `""` |
| `-db` | PostgreSQL connection string. Overrides JSON cache. | `""` |
| `-provider` | Threat intel provider: `vt`, `abuse`, or `both`. | `"both"` |
| `-interval` | Interval between requests (Rate Limiting). | `15s` |
| `-daily` | Daily request cap per run. | `50` |
| `-cache` | Path to the cache JSON file (if not using SQL). | `"threat_intel_cache.json"` |
| `-mal` | Malicious output file (txt). | `"malicious.txt"` |
| `-susp` | Suspicious output file (txt). | `"suspicious.txt"` |

## Testing

The project includes a comprehensive suite of unit tests for models, the assessment engine, and configuration parsers.
```bash
go test ./...
```

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

A: Ensure you have set your API keys in the `.env` file or environment variables.

**Q: How do I migrate my existing JSON cache to PostgreSQL?**

A: Currently, migration is manual. You can use the `-db` flag for new scans, and they will populate the database while referencing your JSON cache is disabled.

## > [!NOTE]
> Some of the earliest commit message are in Indonesian Language. As the project became public in 20 December 2025, the commit message will be using English Language.

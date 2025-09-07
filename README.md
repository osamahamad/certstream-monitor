# CertStream Monitor

A Go-based tool that monitors Certificate Transparency (CT) logs via CertStream to discover subdomains. The tool automatically probes discovered subdomains for liveness and extracts page titles. Inspired by https://github.com/nashcontrol/bounty-monitor

## Features

- **Real-time CT Log Monitoring**: Connects to CertStream WebSocket to monitor certificate updates
- **Target Filtering**: Only monitors subdomains matching your target domains
- **Liveness Probing**: Automatically checks if discovered subdomains are live via HTTP/HTTPS
- **Page Title Extraction**: Extracts and logs page titles from live subdomains
- **SQLite Database**: Stores subdomain history with first/last seen timestamps
- **CSV Logging**: Outputs both all subdomains and live subdomains to CSV files
- **Configurable Age Filtering**: Only logs subdomains with certificates seen within specified days
- **Automatic Reconnection**: Handles connection drops with exponential backoff

## Installation

1. **Prerequisites**:
   - Go 1.22 or later

2. **Build from source**:
   ```bash
   git clone https://github.com/osamahamad/certstream-monitor
   cd certstream-monitor
   go mod tidy
   go build -o certstream-monitor certstream.go
   ```

## Usage

### Basic Usage

```bash
# Create a targets file
echo "apple.com" > targets.txt
echo "target.com" >> targets.txt

# Run the monitor
./certstream-monitor -list targets.txt -out ./output
```

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-list` | `targets.txt` | Path to file containing target domains (one per line) |
| `-out` | `.` | Output directory for database and log files |
| `-age` | `90` | Only log to live_subdomains if cert seen within N days |
| `-insecure` | `true` | Skip TLS verification when probing HTTPS |
| `-probe-timeout` | `5s` | Timeout for HTTP/HTTPS liveness probes |
| `-https-only` | `false` | Probe only HTTPS (default: tries HTTP then HTTPS) |
| `-ws-timeout` | `15` | WebSocket dial timeout in seconds |
| `-run-for` | `0` (unlimited) | How long to stream before exiting (0 = unlimited) |
| `-certstream-url` | `wss://certstream.calidog.io` | CertStream WebSocket URL |

### Environment Variables

- `CERTSTREAM_URL`: Override the default CertStream URL

### Example Commands

```bash
# Monitor for 1 hour, HTTPS only, 30-day age filter
./certstream-monitor -list targets.txt -out ./results -run-for 1h -https-only -age 30

# Use custom CertStream endpoint
CERTSTREAM_URL=wss://your-certstream.com ./certstream-monitor -list targets.txt

# Run with TLS verification (insecure is true by default)
./certstream-monitor -list targets.txt -insecure=false
```

## Target File Format

Create a text file with one domain per line. The tool accepts both bare domains and URLs:

```
# Comments start with #
example.com
target.com
https://another-target.com
*.wildcard.com
```

## Output Files

The tool generates several output files in the specified output directory:

- **`subdomains.db`**: SQLite database containing subdomain history
- **`all_subdomains.log`**: CSV log of all discovered subdomains
- **`live_subdomains.log`**: CSV log of only live subdomains

### CSV Format

**all_subdomains.log**:
```
timestamp,host,first_seen,last_seen,domain_age_days,status,title,scheme
2024-01-15T10:30:00Z,subdomain.example.com,1705312200,1705312200,5,200,"Welcome to Example",https
```

**live_subdomains.log**:
```
timestamp,host,domain_age_days,status,title,scheme
2024-01-15T10:30:00Z,subdomain.example.com,5,200,"Welcome to Example",https
```

## Database Schema

The SQLite database contains a single table:

```sql
CREATE TABLE subdomains(
  host TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,  -- Unix timestamp
  last_seen  INTEGER NOT NULL,  -- Unix timestamp
  live       INTEGER NOT NULL DEFAULT 0  -- 1 if live, 0 if not
);
```

## Dependencies

- [certstream-go](https://github.com/bl4ko/certstream-go): CertStream WebSocket client
- [modernc.org/sqlite](https://modernc.org/sqlite): Pure Go SQLite driver
- [golang.org/x/net](https://golang.org/x/net): Public suffix list utilities

## How It Works

1. **Connection**: Connects to CertStream WebSocket endpoint
2. **Filtering**: Filters certificate updates for domains matching your targets
3. **Age Check**: Only processes certificates seen within the specified age window
4. **DNS Resolution**: Performs quick DNS lookup to filter out obvious non-existent domains
5. **HTTP Probing**: Attempts HTTP and HTTPS connections to verify liveness
6. **Title Extraction**: Extracts page titles from successful HTTP responses
7. **Logging**: Records findings to database and CSV files
8. **Reconnection**: Automatically reconnects on connection drops

## Troubleshooting

### Common Issues

1. **No subdomains found**: Check your targets file and ensure domains are properly formatted
2. **Connection timeouts**: Increase `-ws-timeout` or check network connectivity
3. **TLS errors**: Use `-insecure` flag for internal/self-signed certificates
4. **High memory usage**: Reduce `-run-for` duration or add more specific domain filters


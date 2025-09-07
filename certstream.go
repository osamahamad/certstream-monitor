package main

import (
        "bufio"
        "context"
        "crypto/tls"
        "database/sql"
        "errors"
        "flag"
        "fmt"
        "io"
        "log"
        "math/rand"
        "net"
        "net/http"
        "net/url"
        "os"
        "path/filepath"
        "regexp"
        "strings"
        "time"

        certstream "github.com/bl4ko/certstream-go"
        _ "modernc.org/sqlite"
        "golang.org/x/net/publicsuffix"
)

const (
        // Public CertStream endpoint; set CERTSTREAM_URL to override if you self-host.
        certstreamURLDefault = "wss://certstream.calidog.io"

        // Default filters/paths
        defaultAgeDays = 90

        allLogName  = "all_subdomains.log"
        liveLogName = "live_subdomains.log"
        dbFileName  = "subdomains.db"

        // Cap body read when parsing <title>
        maxBodyBytes = 256 * 1024
)

var (
        titleRe = regexp.MustCompile(`(?is)<\s*title[^>]*>(.*?)</\s*title\s*>`)
)

// Flags
var (
        flagListPath  string
        flagOutDir    string
        flagAgeDays   int
        flagSkipTLS   bool
        flagHTTPTO    time.Duration
        flagHTTPSOnly bool
        flagWSTimeout int
        flagRunFor    time.Duration
        flagCSURL     string
)

func init() {
        flag.StringVar(&flagListPath, "list", "targets.txt", "Path to bb/vdp programs list (URLs or domains)")
        flag.StringVar(&flagOutDir, "out", ".", "Output directory for DB and logs")
        flag.IntVar(&flagAgeDays, "age", defaultAgeDays, "Only log to live_subdomains if cert seen within <= N days")
	flag.BoolVar(&flagSkipTLS, "insecure", true, "Skip TLS verification when probing HTTPS")
        flag.DurationVar(&flagHTTPTO, "probe-timeout", 5*time.Second, "Timeout for liveness HTTP/HTTPS probes")
        flag.BoolVar(&flagHTTPSOnly, "https-only", false, "Probe only HTTPS (by default probes HTTP then HTTPS)")
        flag.IntVar(&flagWSTimeout, "ws-timeout", 15, "WebSocket dial timeout (seconds)")
	flag.DurationVar(&flagRunFor, "run-for", 0, "How long to stream before exiting (0 = unlimited, e.g., 5h30m)")
        flag.StringVar(&flagCSURL, "certstream-url", envOr("CERTSTREAM_URL", certstreamURLDefault), "CertStream WSS URL")
}

func main() {
        flag.Parse()
        log.Printf("Certstream Monitor starting…")

        if err := os.MkdirAll(flagOutDir, 0o755); err != nil {
                log.Fatalf("creating output dir: %v", err)
        }

        targets, err := loadTargets(flagListPath)
        if err != nil {
                log.Fatalf("load targets: %v", err)
        }
        log.Printf("Loaded %d target roots", len(targets))

        dbPath := filepath.Join(flagOutDir, dbFileName)
        db, err := openDB(dbPath)
        if err != nil {
                log.Fatalf("open db: %v", err)
        }
        defer db.Close()

        allLog, err := os.OpenFile(filepath.Join(flagOutDir, allLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
        if err != nil {
                log.Fatalf("open %s: %v", allLogName, err)
        }
        defer allLog.Close()

        liveLog, err := os.OpenFile(filepath.Join(flagOutDir, liveLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
        if err != nil {
                log.Fatalf("open %s: %v", liveLogName, err)
        }
        defer liveLog.Close()

	ageCutoff := time.Now().AddDate(0, 0, -flagAgeDays)
	var deadline time.Time
	if flagRunFor == 0 {
		// Unlimited runtime - set deadline far in the future
		deadline = time.Now().AddDate(100, 0, 0)
	} else {
		deadline = time.Now().Add(flagRunFor)
	}

        // Connect/consume with jittery exponential backoff until deadline.
        backoff := time.Second
        for time.Now().Before(deadline) {
                stream, errStream := certstream.EventStream(true, flagCSURL, flagWSTimeout)
                log.Printf("Connected to CertStream (timeout=%ds) at %s", flagWSTimeout, flagCSURL)

                remain := time.Until(deadline)
                if remain <= 0 {
                        break
                }
                ctx, cancel := context.WithTimeout(context.Background(), remain)
                err := consumeLoopWithContext(ctx, stream, errStream, ageCutoff, targets, db, allLog, liveLog, flagHTTPTO, flagSkipTLS, flagHTTPSOnly)
                cancel()

                if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
                        log.Printf("stream error: %v (will reconnect)", err)
                }

                // If we’re near the end, don’t start another reconnect cycle.
                if time.Now().Add(backoff).After(deadline) {
                        break
                }
                time.Sleep(backoff + time.Duration(rand.Intn(500))*time.Millisecond)
                if backoff < 60*time.Second {
                        backoff *= 2
                }
        }

        log.Printf("Certstream Monitor finished run window; exiting cleanly.")
        
        // Final flush to ensure all data is written to files
        if allLog != nil {
                allLog.Sync()
        }
        if liveLog != nil {
                liveLog.Sync()
        }
}

func consumeLoopWithContext(
        ctx context.Context,
        stream <-chan certstream.Message,
        errStream <-chan error,
        ageCutoff time.Time,
        targets map[string]bool,
        db *sql.DB,
        allLog, liveLog *os.File,
        httpTO time.Duration,
        skipTLS, httpsOnly bool,
) error {
        for {
                select {
                case <-ctx.Done():
                        return ctx.Err()

                case msg, ok := <-stream:
                        if !ok {
                                return errors.New("certstream closed")
                        }
                        if msg.MessageType != "certificate_update" {
                                continue
                        }

                        // Domain age (days) from leaf_cert.not_before (Unix seconds; int -> cast to int64)
                        notBefore := time.Unix(int64(msg.Data.LeafCert.NotBefore), 0)
                        domainAgeDays := int(time.Since(notBefore).Hours() / 24)

                        // Seen (Unix seconds; float64 -> cast)
                        seenTs := int64(msg.Data.Seen)
                        seen := time.Unix(seenTs, 0)
                        if seen.Before(ageCutoff) {
                                continue
                        }

                        for _, d := range msg.Data.LeafCert.AllDomains {
                                host := strings.ToLower(strings.TrimSpace(d))
                                host = strings.TrimPrefix(host, "*.")
                                if host == "" || strings.ContainsAny(host, " \t\r\n") {
                                        continue
                                }
                                root, err := registrableRoot(host)
                                if err != nil || !targets[root] {
                                        continue
                                }

                                firstSeen, lastSeen, known := upsertHost(db, host, seenTs)

                                // Probe for status + title (and which scheme answered)
                                live, status, title, scheme := probeHostDetails(host, httpTO, skipTLS, httpsOnly)

                                // CSV (all): ts,host,first_seen,last_seen,domain_age_days,status,title,scheme
                                fmt.Fprintf(allLog, "%s,%s,%d,%d,%d,%d,%q,%s\n",
                                        time.Now().Format(time.RFC3339),
                                        host, firstSeen, lastSeen, domainAgeDays, status, sanitizeCSV(title), scheme)
                                allLog.Sync() // Ensure data is written to disk

                                // CSV (live): ts,host,domain_age_days,status,title,scheme
                                if live && seen.After(ageCutoff) {
                                        fmt.Fprintf(liveLog, "%s,%s,%d,%d,%q,%s\n",
                                                time.Now().Format(time.RFC3339),
                                                host, domainAgeDays, status, sanitizeCSV(title), scheme)
                                        liveLog.Sync() // Ensure data is written to disk
                                        markLive(db, host)
                                }

                                if !known {
                                        log.Printf("[NEW] %s (root %s) age=%dd status=%d title=%s",
                                                host, root, domainAgeDays, status, oneLine(title))
                                }
                        }

                case err := <-errStream:
                        if err == nil {
                                return errors.New("certstream error channel closed")
                        }
                        return err
                }
        }
}

func loadTargets(path string) (map[string]bool, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()

        targets := make(map[string]bool)
        sc := bufio.NewScanner(f)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                // Accept URLs or bare domains; normalize to registrable root
                domain := line
                if u, err := url.Parse(line); err == nil && u.Host != "" {
                        domain = u.Host
                }
                domain = strings.TrimPrefix(domain, "*.")
                domain = strings.TrimPrefix(domain, ".")
                root, err := registrableRoot(domain)
                if err != nil {
                        continue
                }
                targets[root] = true
        }
        return targets, sc.Err()
}

func registrableRoot(host string) (string, error) {
        eTLD, _ := publicsuffix.PublicSuffix(host)
        if eTLD == "" || !strings.Contains(host, ".") {
                return "", errors.New("invalid host")
        }
        parts := strings.Split(host, ".")
        suffixParts := strings.Split(eTLD, ".")
        if len(parts) < len(suffixParts)+1 {
                return "", errors.New("short host")
        }
        root := strings.Join(parts[len(parts)-len(suffixParts)-1:], ".")
        return root, nil
}

func openDB(path string) (*sql.DB, error) {
        // modernc.org/sqlite driver name is "sqlite"
        db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
        if err != nil {
                return nil, err
        }
        schema := `
CREATE TABLE IF NOT EXISTS subdomains(
  host TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  live       INTEGER NOT NULL DEFAULT 0
);`
        if _, err := db.Exec(schema); err != nil {
                db.Close()
                return nil, err
        }
        return db, nil
}

func upsertHost(db *sql.DB, host string, seen int64) (firstSeen int64, lastSeen int64, known bool) {
        tx, _ := db.Begin()
        defer tx.Commit()

        var fs, ls int64
        err := tx.QueryRow(`SELECT first_seen,last_seen FROM subdomains WHERE host=?`, host).Scan(&fs, &ls)
        switch {
        case errors.Is(err, sql.ErrNoRows):
                _, _ = tx.Exec(`INSERT INTO subdomains(host,first_seen,last_seen,live) VALUES(?,?,?,0)`, host, seen, seen)
                return seen, seen, false
        case err == nil:
                if seen > ls {
                        _, _ = tx.Exec(`UPDATE subdomains SET last_seen=? WHERE host=?`, seen, host)
                        ls = seen
                }
                return fs, ls, true
        default:
                return seen, seen, true
        }
}

func markLive(db *sql.DB, host string) {
        _, _ = db.Exec(`UPDATE subdomains SET live=1 WHERE host=?`, host)
}

// probeHostDetails returns (live, status, title, schemeUsed)
func probeHostDetails(host string, to time.Duration, insecure bool, httpsOnly bool) (bool, int, string, string) {
        // quick DNS check to skip obvious garbage
        if _, err := net.LookupHost(host); err != nil {
                return false, 0, "", ""
        }

        client := &http.Client{
                Timeout: to,
                Transport: &http.Transport{
                        Proxy:           http.ProxyFromEnvironment,
                        TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
                },
        }

        try := func(scheme string) (bool, int, string) {
                u := scheme + "://" + host
                req, _ := http.NewRequest("GET", u, nil)
                req.Header.Set("User-Agent", "certstream-monitor/1.0")
                resp, err := client.Do(req)
                if err != nil {
                        return false, 0, ""
                }
                defer resp.Body.Close()

                limited := io.LimitReader(resp.Body, maxBodyBytes)
                b, _ := io.ReadAll(limited)
                title := extractTitle(string(b))
                return true, resp.StatusCode, title
        }

        if httpsOnly {
                live, code, title := try("https")
                if live {
                        return true, code, title, "https"
                }
                return false, 0, "", ""
        }

        // try HTTP first then HTTPS
        if live, code, title := try("http"); live {
                return true, code, title, "http"
        }
        if live, code, title := try("https"); live {
                return true, code, title, "https"
        }
        return false, 0, "", ""
}

func extractTitle(body string) string {
        if len(body) == 0 {
                return ""
        }
        m := titleRe.FindStringSubmatch(body)
        if len(m) >= 2 {
                // collapse whitespace and trim
                s := strings.TrimSpace(m[1])
                s = strings.ReplaceAll(s, "\n", " ")
                s = strings.ReplaceAll(s, "\r", " ")
                s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
                return s
        }
        return ""
}

func sanitizeCSV(s string) string {
        // already quoted with %q in fmt, but double-quote safety for CSV
        return strings.ReplaceAll(s, `"`, `""`)
}

func oneLine(s string) string {
        s = strings.ReplaceAll(s, "\n", " ")
        s = strings.ReplaceAll(s, "\r", " ")
        return regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
}

func envOr(key, def string) string {
        if v := os.Getenv(key); v != "" {
                return v
        }
        return def
}


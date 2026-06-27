// Package secrets provides an embedded secret scanner that detects hardcoded
// credentials, API keys, private keys, and other sensitive data in source files.
//
// The scanner uses curated regex patterns (derived from gosec v2.27.1 and
// gitleaks) plus Shannon entropy detection for high-entropy strings.
// No external tools or dependencies are required.
package secrets

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

// SecretPattern defines a regex pattern for detecting a specific type of secret.
type SecretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Severity   analysis.Severity
	Confidence analysis.Confidence
}

// IgnoreMatcher is the interface implemented by the gitignore matcher.
// If set on a Scanner, files matching .gitignore patterns are skipped.
type IgnoreMatcher interface {
	Match(path string, isDir bool) bool
	IsEmpty() bool
}

// Scanner is the embedded secret scanner.
type Scanner struct {
	patterns          []SecretPattern
	entropyThreshold  float64
	minEntropyLength  int
	ignoredExtensions map[string]bool
	ignoredDirs       map[string]bool
	maxFileSize       int64
	ignoreMatcher     IgnoreMatcher
}

// SetIgnoreMatcher sets the .gitignore matcher for this scanner. When set,
// files matching .gitignore patterns are skipped during scanning.
func (s *Scanner) SetIgnoreMatcher(m IgnoreMatcher) {
	s.ignoreMatcher = m
}

// SecretRuleInfo provides metadata about a secret pattern for listing purposes.
type SecretRuleInfo struct {
	Name       string
	Severity   analysis.Severity
	Confidence analysis.Confidence
}

// Rules returns metadata for all registered secret patterns.
func (s *Scanner) Rules() []SecretRuleInfo {
	result := make([]SecretRuleInfo, len(s.patterns))
	for i, p := range s.patterns {
		result[i] = SecretRuleInfo{
			Name:       p.Name,
			Severity:   p.Severity,
			Confidence: p.Confidence,
		}
	}
	return result
}

// NewScanner creates a new secret scanner with all built-in patterns.
func NewScanner() *Scanner {
	s := &Scanner{
		entropyThreshold: 4.5,
		minEntropyLength: 20,
		maxFileSize:      2 * 1024 * 1024, // 2MB
		ignoredExtensions: map[string]bool{
			".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
			".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".bz2": true,
			".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
			".mp4": true, ".mp3": true, ".avi": true, ".mov": true,
			".lock": true, ".sum": true, ".min.js": true, ".min.css": true,
			".pyc": true, ".pyo": true, ".so": true, ".dll": true, ".dylib": true,
			".wasm": true, ".o": true, ".a": true, ".class": true, ".jar": true,
		},
		ignoredDirs: map[string]bool{
			"node_modules": true, "vendor": true, ".git": true, "dist": true,
			"build": true, "target": true, ".next": true, ".cache": true,
			".venv": true, "venv": true, "env": true, ".env": true,
			".tox": true, ".pytest_cache": true, ".mypy_cache": true,
			"site-packages": true, "__pycache__": true, ".eggs": true,
			".eggs-info": true, ".ruff_cache": true,
			// Test fixtures and documentation dirs contain example secrets
			// that are not real credentials.
			"testdata": true, "test_data": true, "fixtures": true,
			"docs": true, "doc": true, "examples": true, "example": true,
		},
	}
	s.registerPatterns()
	return s
}

// registerPatterns registers all built-in secret detection patterns.
// Patterns derived from gosec v2.27.1 (Apache 2.0) and gitleaks.
func (s *Scanner) registerPatterns() {
	s.patterns = []SecretPattern{
		// Cloud provider keys
		{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "AWS Secret Access Key", Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?(secret|sk)[^\w]{0,5}['"=][0-9a-zA-Z/+]{40}['"]`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Google OAuth Access Token", Pattern: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Google Cloud Service Account", Pattern: regexp.MustCompile(`"type":\s*"service_account"`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Azure Storage Key", Pattern: regexp.MustCompile(`AccountKey=[a-zA-Z0-9+/=]{88}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},

		// Version control tokens
		{Name: "GitHub Personal Access Token", Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "GitHub Fine-grained Token", Pattern: regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "GitHub Action Token", Pattern: regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "GitHub OAuth Token", Pattern: regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "GitHub Refresh Token", Pattern: regexp.MustCompile(`ghr_[a-zA-Z0-9]{76}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "GitLab Personal Access Token", Pattern: regexp.MustCompile(`glpat-[a-zA-Z0-9\-_]{20}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},

		// SaaS tokens
		{Name: "Slack Token", Pattern: regexp.MustCompile(`xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Stripe Live API Key", Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Stripe Restricted Key", Pattern: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Twilio API Key", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Square Access Token", Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Square OAuth Secret", Pattern: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Heroku API Key", Pattern: regexp.MustCompile(`(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceMedium},
		{Name: "Mailgun API Key", Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "MailChimp API Key", Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},
		{Name: "Telegram Bot Token", Pattern: regexp.MustCompile(`[0-9]+:AA[0-9A-Za-z\-_]{33}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},

		// Private keys
		{Name: "RSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "EC Private Key", Pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "DSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "OpenSSH Private Key", Pattern: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "PGP Private Key", Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},

		// Database connection strings
		{Name: "Database Connection URL", Pattern: regexp.MustCompile(`(postgres|postgresql|mysql|mongodb|redis|amqp)://\S+:\S+@\S+`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},
		{Name: "Password in URL", Pattern: regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@[a-zA-Z0-9\.\-]+`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},

		// JWT tokens
		{Name: "JWT Token", Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`), Severity: analysis.SeverityHigh, Confidence: analysis.ConfidenceHigh},

		// Generic patterns
		{Name: "Generic API Key assignment", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{32,}['"]`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},
		{Name: "Generic Secret assignment", Pattern: regexp.MustCompile(`(?i)(secret|client[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9]{32,}['"]`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},
		{Name: "Generic Password assignment", Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"][^\s'"]{8,}['"]`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},
		{Name: "Generic Token assignment", Pattern: regexp.MustCompile(`(?i)(token|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9]{32,}['"]`), Severity: analysis.SeverityMedium, Confidence: analysis.ConfidenceMedium},
	}
}

// Analyze scans all files in the root directory for secrets.
func (s *Scanner) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	var findings []analysis.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			name := filepath.Base(path)
			if s.ignoredDirs[name] {
				return filepath.SkipDir
			}
			// Check .gitignore for directories
			if s.ignoreMatcher != nil && !s.ignoreMatcher.IsEmpty() {
				if s.ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check .gitignore for files
		if s.ignoreMatcher != nil && !s.ignoreMatcher.IsEmpty() {
			if s.ignoreMatcher.Match(path, false) {
				return nil
			}
		}

		// Check extension
		ext := filepath.Ext(path)
		if s.ignoredExtensions[ext] {
			return nil
		}

		// Skip example/template env files (they contain placeholder secrets)
		baseName := filepath.Base(path)
		if isExampleFile(baseName) {
			return nil
		}

		// Skip large files
		if info.Size() > s.maxFileSize {
			return nil
		}

		// Skip binary files (quick check)
		if isBinaryFile(path) {
			return nil
		}

		fileFindings, err := s.scanFile(path, root)
		if err != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return findings, nil
}

// ScanFilePublic is the exported version of scanFile for use by the
// parallel file scanner. It scans a single file for secrets.
// It applies the same example-file and binary-file filtering as Analyze.
func (s *Scanner) ScanFilePublic(absPath, root string) ([]analysis.Finding, error) {
	// Skip files in documentation/example directories — these contain
	// example secrets that are not real credentials.
	if isDocOrExamplePath(absPath) {
		return nil, nil
	}
	baseName := filepath.Base(absPath)
	if isExampleFile(baseName) {
		return nil, nil
	}
	if isBinaryFile(absPath) {
		return nil, nil
	}
	ext := filepath.Ext(absPath)
	if s.ignoredExtensions[ext] {
		return nil, nil
	}
	return s.scanFile(absPath, root)
}

// isDocOrExamplePath returns true if the file path contains a documentation
// or examples directory component. These directories contain example secrets
// that are not real credentials.
func isDocOrExamplePath(absPath string) bool {
	parts := strings.Split(filepath.ToSlash(absPath), "/")
	for _, part := range parts {
		switch part {
		case "docs", "doc", "examples", "example":
			return true
		}
	}
	return false
}

// scanFile scans a single file for secrets.
func (s *Scanner) scanFile(absPath, root string) ([]analysis.Finding, error) {
	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line size

	var findings []analysis.Finding
	lineNum := 0
	skipEntropy := isLockfile(absPath)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comment lines that are clearly not secrets
		if isCommentLine(line) {
			// But still check for private key markers which might be in comments
			for _, p := range s.patterns {
				if p.Pattern.MatchString(line) && strings.Contains(p.Name, "Private Key") {
					findings = append(findings, s.makeFinding(p, absPath, root, lineNum, line))
				}
			}
			continue
		}

		for _, p := range s.patterns {
			matches := p.Pattern.FindAllString(line, -1)
			for _, match := range matches {
				// Skip false positives
				if s.isFalsePositive(match, line) {
					continue
				}
				findings = append(findings, s.makeFinding(p, absPath, root, lineNum, line))
			}
		}

		// Entropy-based detection for high-entropy strings. Lockfiles contain
		// integrity hashes that are expected to be high entropy and are not
		// credentials.
		if !skipEntropy {
			s.checkEntropy(line, absPath, root, lineNum, &findings)
		}
	}

	return findings, nil
}

// makeFinding creates a finding for a detected secret.
func (s *Scanner) makeFinding(p SecretPattern, absPath, root string, lineNum int, line string) analysis.Finding {
	relPath, _ := filepath.Rel(root, absPath)
	return analysis.Finding{
		ID:          fmt.Sprintf("secret-%s-%s-%d", sanitizeName(p.Name), filepath.Base(relPath), lineNum),
		Type:        analysis.TypeSAST,
		Analyzer:    "secrets-embedded",
		Severity:    p.Severity,
		Confidence:  p.Confidence,
		Title:       fmt.Sprintf("Hardcoded secret detected: %s", p.Name),
		Description: fmt.Sprintf("Potential %s found in source code. This should be moved to an environment variable or secret manager.", p.Name),
		FilePath:    relPath,
		LineStart:   lineNum,
		RuleID:      "SECRET-" + sanitizeName(p.Name),
		Evidence:    redactEvidence(line),
		DetectedAt:  time.Now(),
	}
}

// checkEntropy checks a line for high-entropy strings that might be secrets.
func (s *Scanner) checkEntropy(line, absPath, root string, lineNum int, findings *[]analysis.Finding) {
	// Look for quoted strings or assignments
	stringRe := regexp.MustCompile(`['"]([a-zA-Z0-9+/=_\-]{20,})['"]`)
	matches := stringRe.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		str := m[1]
		if len(str) < s.minEntropyLength {
			continue
		}
		entropy := shannonEntropy(str)
		if entropy >= s.entropyThreshold {
			// Check if it's near a secret-like keyword
			if hasSecretKeyword(line) {
				*findings = append(*findings, analysis.Finding{
					ID:          fmt.Sprintf("secret-entropy-%s-%d", filepath.Base(absPath), lineNum),
					Type:        analysis.TypeSAST,
					Analyzer:    "secrets-embedded",
					Severity:    analysis.SeverityMedium,
					Confidence:  analysis.ConfidenceMedium,
					Title:       "High-entropy string near secret keyword",
					Description: fmt.Sprintf("High-entropy string (entropy: %.2f) detected near a secret-related keyword. This may be a hardcoded credential.", entropy),
					FilePath:    relPath(absPath, root),
					LineStart:   lineNum,
					RuleID:      "SECRET-HIGH-ENTROPY",
					Evidence:    redactEvidence(line),
					DetectedAt:  time.Now(),
				})
			}
		}
	}
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	for _, count := range freq {
		p := count / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isFalsePositive checks common false positive patterns.
func (s *Scanner) isFalsePositive(match, line string) bool {
	// Skip example/placeholder values
	lower := strings.ToLower(match)
	falsePositives := []string{
		"example", "placeholder", "your-", "xxx", "yyy", "zzz",
		"test-key", "dummy", "sample", "changeme", "todo",
		"akiaxxxxxxxxxxxxxx", "xxxxxxxxxxxx",
	}
	for _, fp := range falsePositives {
		if strings.Contains(lower, fp) {
			return true
		}
	}

	// Skip if the line is a comment (but not if it contains a URL scheme like postgres://)
	trimmed := strings.TrimSpace(line)
	if (strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#")) &&
		!strings.Contains(match, "-----BEGIN") {
		return true
	}

	return false
}

// isExampleFile checks if a file is an example/template file that contains
// placeholder secrets (not real credentials).
func isExampleFile(name string) bool {
	// .env.example, .env.prod.example, .env.example.local
	if strings.HasPrefix(name, ".env.") && strings.Contains(name, "example") {
		return true
	}
	// *.example, *.sample, *.template
	if strings.HasSuffix(name, ".example") || strings.HasSuffix(name, ".sample") ||
		strings.HasSuffix(name, ".template") || strings.HasSuffix(name, ".dist") {
		return true
	}
	return false
}

func isLockfile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"poetry.lock", "pipfile.lock", "gemfile.lock", "cargo.lock", "composer.lock",
		"go.sum":
		return true
	}
	return strings.HasSuffix(base, ".lock")
}

// isCommentLine checks if a line is a comment.
func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*")
}

// isBinaryFile does a quick check if the file is binary.
func isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".so": true, ".dll": true, ".dylib": true, ".exe": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".wasm": true, ".o": true, ".a": true, ".class": true,
		".jar": true, ".pyc": true, ".pyo": true,
	}
	return binaryExts[ext]
}

// hasSecretKeyword checks if a line contains secret-related keywords.
func hasSecretKeyword(line string) bool {
	lower := strings.ToLower(line)
	keywords := []string{"secret", "password", "token", "key", "credential", "auth", "api"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// redactEvidence redacts the actual secret value from the evidence line.
func redactEvidence(line string) string {
	// Replace long sequences of potential secret characters with [REDACTED]
	re := regexp.MustCompile(`['"][a-zA-Z0-9+/=_\-]{20,}['"]`)
	return re.ReplaceAllStringFunc(line, func(s string) string {
		if len(s) > 4 {
			return s[:2] + "[REDACTED]" + s[len(s)-2:]
		}
		return s
	})
}

// relPath returns the relative path from root.
func relPath(absPath, root string) string {
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return absPath
	}
	return rel
}

// sanitizeName converts a pattern name to a safe ID component.
func sanitizeName(name string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	return re.ReplaceAllString(name, "-")
}

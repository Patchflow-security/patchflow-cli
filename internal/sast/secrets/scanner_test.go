package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/patchflow/patchflow-cli/internal/analysis"
)

func TestSecretScanner_DetectsAWSKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.py", `api_key = "AKIA0123456789ABCDEF"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SECRET-AWS-Access-Key-ID" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find AWS Access Key ID, got %d findings", len(findings))
	}
}

func TestSecretScanner_DetectsGitHubToken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SECRET-GitHub-Personal-Access-Token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find GitHub PAT, got %d findings", len(findings))
	}
}

func TestSecretScanner_DetectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...")

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SECRET-RSA-Private-Key" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find RSA private key, got %d findings", len(findings))
	}
}

func TestSecretScanner_DetectsStripeKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "payment.py", `stripe_key = "sk_live_1234567890abcdefghijklmn"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SECRET-Stripe-Live-API-Key" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find Stripe key, got %d findings", len(findings))
	}
}

func TestSecretScanner_DetectsDatabaseURL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "db.py", `DATABASE_URL = "postgres://user:secretpass@localhost:5432/mydb"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SECRET-Database-Connection-URL" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find database URL, got %d findings", len(findings))
	}
}

func TestSecretScanner_SkipsFalsePositives(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "example.py", `# Example: api_key = "AKIAxxxxxxxxxxxxxx"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "SECRET-AWS-Access-Key-ID" {
			t.Errorf("should not detect example/placeholder AWS key")
		}
	}
}

func TestSecretScanner_SkipsIgnoredDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/lib.js", `const key = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("should not scan node_modules/, got %d findings", len(findings))
	}
}

func TestSecretScanner_SkipsEntropyInLockfiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `"integrity": "sha512-XJw9Kq2nP7vLmR8sT4uY6zAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "SECRET-HIGH-ENTROPY" {
			t.Fatalf("lockfile integrity hashes should not trigger entropy findings: %#v", findings)
		}
	}
}

func TestSecretScanner_RedactsEvidence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.py", `api_key = "AKIAIOSFODNN7EXAMPLE"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "SECRET-AWS-Access-Key-ID" {
			if !contains(f.Evidence, "[REDACTED]") {
				t.Errorf("evidence should be redacted, got: %s", f.Evidence)
			}
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// Low entropy string
	low := shannonEntropy("aaaaaaaaaa")
	if low > 1.0 {
		t.Errorf("low entropy string should have entropy < 1.0, got %f", low)
	}

	// High entropy string
	high := shannonEntropy("aB3$xZ9!kQ2#mN7@vR5")
	if high < 3.0 {
		t.Errorf("high entropy string should have entropy > 3.0, got %f", high)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestSecretScannerAllPatterns tests all remaining secret patterns in a
// table-driven fashion. Each case writes a file with a secret that should
// trigger the corresponding pattern, scans it, and asserts the expected
// RuleID appears in the findings.
func TestSecretScannerAllPatterns(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		file    string
		content string
	}{
		// Cloud provider keys
		{"AWS Secret Access Key", "SECRET-AWS-Secret-Access-Key", "config.py",
			`aws_secret'abcdefghijklmnopqrstuvwxyz0123456789ABCD'`},
		{"Google API Key", "SECRET-Google-API-Key", "config.py",
			`google_key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"`},
		{"Google OAuth Access Token", "SECRET-Google-OAuth-Access-Token", "config.py",
			`token = "ya29.ABcdEFGhIJKlmNoPQRsTUVwxyZ0123456789abcdef"`},
		{"Google Cloud Service Account", "SECRET-Google-Cloud-Service-Account", "config.json",
			`{"type": "service_account", "project_id": "my-project"}`},
		{"Azure Storage Key", "SECRET-Azure-Storage-Key", "config.py",
			`conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB=="`},

		// Version control tokens
		{"GitHub Fine-grained Token", "SECRET-GitHub-Fine-grained-Token", "app.js",
			`const token = "github_pat_1234567890abcdefghijkl_12345678901234567890123456789012345678901234567890123456789";`},
		{"GitHub Action Token", "SECRET-GitHub-Action-Token", "app.js",
			`const token = "ghs_1234567890abcdefghijklmnopqrstuvwxyz1234";`},
		{"GitHub OAuth Token", "SECRET-GitHub-OAuth-Token", "app.js",
			`const token = "gho_1234567890abcdefghijklmnopqrstuvwxyz1234";`},
		{"GitHub Refresh Token", "SECRET-GitHub-Refresh-Token", "app.js",
			`const token = "ghr_1234567890123456789012345678901234567890123456789012345678901234567890123456";`},
		{"GitLab Personal Access Token", "SECRET-GitLab-Personal-Access-Token", "app.js",
			`const token = "glpat-1234567890abcdefghij";`},

		// SaaS tokens
		{"Slack Token", "SECRET-Slack-Token", "app.js",
			`const token = "xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz123456";`},
		{"Slack Webhook", "SECRET-Slack-Webhook", "app.js",
			`const url = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx";`},
		{"Stripe Restricted Key", "SECRET-Stripe-Restricted-Key", "config.py",
			`stripe_key = "rk_live_1234567890abcdefghijklmn"`},
		{"Twilio API Key", "SECRET-Twilio-API-Key", "config.py",
			`twilio_key = "SK1234567890abcdef0123456789abcdef"`},
		{"Square Access Token", "SECRET-Square-Access-Token", "config.py",
			`square_token = "sq0atp-1234567890abcdefghijkl"`},
		{"Square OAuth Secret", "SECRET-Square-OAuth-Secret", "config.py",
			`square_secret = "sq0csp-1234567890abcdefghijklmnopqrstuvwxyz12345678"`},
		{"Heroku API Key", "SECRET-Heroku-API-Key", "config.py",
			`heroku_key = "12345678-1234-1234-1234-123456789012"`},
		{"Mailgun API Key", "SECRET-Mailgun-API-Key", "config.py",
			`mailgun_key = "key-1234567890abcdefghijklmnopqrstuvwxyz1234"`},
		{"MailChimp API Key", "SECRET-MailChimp-API-Key", "config.py",
			`mailchimp_key = "1234567890abcdef0123456789abcdef-us12"`},
		{"Telegram Bot Token", "SECRET-Telegram-Bot-Token", "config.py",
			`telegram_token = "123456789:AAabcdefghijklmnopqrstuvwxyz123456789"`},

		// Private keys
		{"EC Private Key", "SECRET-EC-Private-Key", "id_ec", "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE..."},
		{"DSA Private Key", "SECRET-DSA-Private-Key", "id_dsa", "-----BEGIN DSA PRIVATE KEY-----\nMIIBuw..."},
		{"OpenSSH Private Key", "SECRET-OpenSSH-Private-Key", "id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz..."},
		{"PGP Private Key", "SECRET-PGP-Private-Key", "private.key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG..."},

		// JWT tokens
		{"JWT Token", "SECRET-JWT-Token", "config.py",
			`jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`},

		// Generic patterns
		{"Generic API Key", "SECRET-Generic-API-Key-assignment", "config.py",
			`api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},
		{"Generic Secret", "SECRET-Generic-Secret-assignment", "config.py",
			`secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},
		{"Generic Password", "SECRET-Generic-Password-assignment", "config.py",
			`password = "supersecret123"`},
		{"Generic Token", "SECRET-Generic-Token-assignment", "config.py",
			`token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},

		// High entropy
		{"High Entropy String", "SECRET-HIGH-ENTROPY", "config.py",
			`credential = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file, tc.content)

			s := NewScanner()
			findings, err := s.Analyze(context.Background(), dir)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			found := false
			for _, f := range findings {
				if f.RuleID == tc.ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s, got %d findings: %v", tc.ruleID, len(findings), secretFindingIDs(findings))
			}
		})
	}
}

func secretFindingIDs(findings []analysis.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
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
		// Cloud provider keys — test fixtures use all-zeros to avoid triggering GitHub Push Protection
		{"AWS Secret Access Key", "SECRET-AWS-Secret-Access-Key", "config.py",
			`aws_secret'0000000000000000000000000000000000000000'`},
		{"Google API Key", "SECRET-Google-API-Key", "config.py",
			`google_key = "AIza00000000000000000000000000000000000"`},
		{"Google OAuth Access Token", "SECRET-Google-OAuth-Access-Token", "config.py",
			`token = "ya29.0000000000000000000000000000000000000000"`},
		{"Google Cloud Service Account", "SECRET-Google-Cloud-Service-Account", "config.json",
			`{"type": "service_account", "project_id": "my-project"}`},
		{"Azure Storage Key", "SECRET-Azure-Storage-Key", "config.py",
			`conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB=="`},

		// Version control tokens
		{"GitHub Fine-grained Token", "SECRET-GitHub-Fine-grained-Token", "app.js",
			`const token = "github_pat_0000000000000000000000_000000000000000000000000000000000000000000000000000000000000";`},
		{"GitHub Action Token", "SECRET-GitHub-Action-Token", "app.js",
			`const token = "ghs_000000000000000000000000000000000000";`},
		{"GitHub OAuth Token", "SECRET-GitHub-OAuth-Token", "app.js",
			`const token = "gho_000000000000000000000000000000000000";`},
		{"GitHub Refresh Token", "SECRET-GitHub-Refresh-Token", "app.js",
			`const token = "ghr_0000000000000000000000000000000000000000000000000000000000000000000000000000";`},
		{"GitLab Personal Access Token", "SECRET-GitLab-Personal-Access-Token", "app.js",
			`const token = "glpat-00000000000000000000";`},

		// SaaS tokens
		{"Slack Token", "SECRET-Slack-Token", "app.js",
			`const token = "xoxp-000000000000-000000000000-000000000000-0000000000000000000000000000000000";`},
		{"Slack Webhook", "SECRET-Slack-Webhook", "app.js",
			`const url = "https://hooks.slack.com/services/T00000000/B00000000/000000000000000000000000";`},
		{"Stripe Restricted Key", "SECRET-Stripe-Restricted-Key", "config.py",
			`stripe_key = "rk_live_000000000000000000000000"`},
		{"Twilio API Key", "SECRET-Twilio-API-Key", "config.py",
			`twilio_key = "SK00000000000000000000000000000000"`},
		{"Square Access Token", "SECRET-Square-Access-Token", "config.py",
			`square_token = "sq0atp-0000000000000000000000"`},
		{"Square OAuth Secret", "SECRET-Square-OAuth-Secret", "config.py",
			`square_secret = "sq0csp-0000000000000000000000000000000000000000000"`},
		{"Heroku API Key", "SECRET-Heroku-API-Key", "config.py",
			`heroku_key = "00000000-0000-0000-0000-000000000000"`},
		{"Mailgun API Key", "SECRET-Mailgun-API-Key", "config.py",
			`mailgun_key = "key-00000000000000000000000000000000"`},
		{"MailChimp API Key", "SECRET-MailChimp-API-Key", "config.py",
			`mailchimp_key = "00000000000000000000000000000000-us12"`},
		{"Telegram Bot Token", "SECRET-Telegram-Bot-Token", "config.py",
			`telegram_token = "000000000:AA000000000000000000000000000000000"`},

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

func TestSecretFindingsUseSecretType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.sh", `PASSWORD="supersecret123"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a secret finding")
	}
	for _, finding := range findings {
		if finding.Type != analysis.TypeSecret {
			t.Fatalf("expected TypeSecret, got %s", finding.Type)
		}
	}
}

func TestVariableBackedPasswordAssignmentSuppressed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "setup.sh", `kubectl create secret generic grafana-admin-credentials --from-literal=admin-password="$GRAFANA_PASSWORD"`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SECRET-Generic-Password-assignment" {
			t.Fatalf("expected variable-backed password assignment to be suppressed, got %+v", finding)
		}
	}
}

func TestUISecretLabelsSuppressed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "common.ts", `
export default {
  password: 'New password',
  confirmPassword: '••••••••',
  frPassword: 'Au moins 8 caractères',
  arPassword: 'كلمة مرور جديدة',
}
`)

	s := NewScanner()
	findings, err := s.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SECRET-Generic-Password-assignment" {
			t.Fatalf("expected UI password labels to be suppressed, got %+v", finding)
		}
	}
}

func secretFindingIDs(findings []analysis.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

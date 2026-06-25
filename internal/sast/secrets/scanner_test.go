package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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

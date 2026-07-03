// Package reviewers provides reviewer suggestion based on CODEOWNERS
// files, git blame analysis, and file expertise mapping.
package reviewers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Reviewer represents a suggested reviewer.
type Reviewer struct {
	Username  string   `json:"username"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons"`
	Files     []string `json:"files"`
	IsOwner   bool     `json:"is_owner"`
}

// SuggestionResult holds the result of reviewer suggestion.
type SuggestionResult struct {
	Reviewers    []Reviewer `json:"reviewers"`
	CodeownersFound bool    `json:"codeowners_found"`
	BlameUsed    bool       `json:"blame_used"`
	FilesAnalyzed int       `json:"files_analyzed"`
}

// SuggestOptions controls reviewer suggestion behavior.
type SuggestOptions struct {
	RepoRoot      string
	ChangedFiles  []string
	MaxReviewers  int
	UseBlame      bool
	UseCodeowners bool
}

// Suggest recommends reviewers based on CODEOWNERS and git blame.
func Suggest(opts SuggestOptions) (*SuggestionResult, error) {
	if opts.MaxReviewers == 0 {
		opts.MaxReviewers = 3
	}

	result := &SuggestionResult{
		FilesAnalyzed: len(opts.ChangedFiles),
	}

	// Track reviewer scores
	reviewerMap := make(map[string]*Reviewer)

	// 1. Parse CODEOWNERS
	if opts.UseCodeowners {
		owners, found := parseCodeowners(opts.RepoRoot)
		result.CodeownersFound = found
		if found {
			for _, file := range opts.ChangedFiles {
				matchedOwners := matchCodeowners(file, owners)
				for _, owner := range matchedOwners {
					rev := getOrCreateReviewer(reviewerMap, owner)
					rev.Score += 10
					rev.IsOwner = true
					rev.Reasons = appendUnique(rev.Reasons, "CODEOWNERS match")
					rev.Files = appendUnique(rev.Files, file)
				}
			}
		}
	}

	// 2. Git blame analysis
	if opts.UseBlame {
		result.BlameUsed = true
		blameResults, err := gitBlameFiles(opts.RepoRoot, opts.ChangedFiles)
		if err == nil {
			for file, authors := range blameResults {
				for author, lineCount := range authors {
					rev := getOrCreateReviewer(reviewerMap, author)
					rev.Score += lineCount
					if !rev.IsOwner {
						rev.Reasons = appendUnique(rev.Reasons,
							fmt.Sprintf("Authored %d lines in %s", lineCount, file))
					}
					rev.Files = appendUnique(rev.Files, file)
				}
			}
		}
	}

	// 3. Expertise-based scoring (file type patterns)
	for _, file := range opts.ChangedFiles {
		expertise := detectExpertise(file)
		if expertise != "" {
			// This is a heuristic — reviewers who touched similar files
			// get a small bonus. We skip this if no blame data.
			_ = expertise
		}
	}

	// Convert to sorted slice
	for _, rev := range reviewerMap {
		result.Reviewers = append(result.Reviewers, *rev)
	}
	sort.Slice(result.Reviewers, func(i, j int) bool {
		if result.Reviewers[i].Score != result.Reviewers[j].Score {
			return result.Reviewers[i].Score > result.Reviewers[j].Score
		}
		return result.Reviewers[i].Username < result.Reviewers[j].Username
	})

	// Limit to max
	if len(result.Reviewers) > opts.MaxReviewers {
		result.Reviewers = result.Reviewers[:opts.MaxReviewers]
	}

	return result, nil
}

// CodeownerRule represents a single CODEOWNERS rule.
type CodeownerRule struct {
	Pattern string
	Owners  []string
}

// parseCodeowners finds and parses the CODEOWNERS file.
func parseCodeowners(root string) ([]CodeownerRule, bool) {
	paths := []string{
		filepath.Join(root, "CODEOWNERS"),
		filepath.Join(root, ".github", "CODEOWNERS"),
		filepath.Join(root, "docs", "CODEOWNERS"),
		filepath.Join(root, ".gitlab", "CODEOWNERS"),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		return parseCodeownersContent(string(data)), true
	}
	return nil, false
}

// parseCodeownersContent parses CODEOWNERS file content.
func parseCodeownersContent(content string) []CodeownerRule {
	var rules []CodeownerRule
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		pattern := parts[0]
		owners := parts[1:]
		rules = append(rules, CodeownerRule{
			Pattern: pattern,
			Owners:  owners,
		})
	}
	return rules
}

// matchCodeowners finds owners for a given file path.
func matchCodeowners(filePath string, rules []CodeownerRule) []string {
	var matched []string
	// CODEOWNERS rules are matched in order, last match wins.
	// But we collect all unique owners from matching rules.
	seen := make(map[string]bool)
	for _, rule := range rules {
		if matchPattern(rule.Pattern, filePath) {
			for _, owner := range rule.Owners {
				cleaned := cleanOwner(owner)
				if cleaned != "" && !seen[cleaned] {
					seen[cleaned] = true
					matched = append(matched, cleaned)
				}
			}
		}
	}
	return matched
}

// matchPattern checks if a file path matches a CODEOWNERS pattern.
func matchPattern(pattern, path string) bool {
	// Handle directory patterns (ending with /)
	if strings.HasSuffix(pattern, "/") {
		dirPattern := strings.TrimSuffix(pattern, "/")
		// Remove leading / from pattern for matching
		dirPattern = strings.TrimPrefix(dirPattern, "/")
		return strings.HasPrefix(path, dirPattern+"/") || path == dirPattern
	}

	// Handle glob patterns with *
	if strings.Contains(pattern, "*") {
		pattern = strings.TrimPrefix(pattern, "/")
		return globMatch(pattern, path)
	}

	// Handle root-level patterns (starting with /)
	if strings.HasPrefix(pattern, "/") {
		cleanPattern := pattern[1:]
		return path == cleanPattern || strings.HasPrefix(path, cleanPattern+"/")
	}

	// Simple suffix match
	return path == pattern || strings.HasSuffix(path, "/"+pattern)
}

// globMatch does simple glob matching with * wildcard.
func globMatch(pattern, path string) bool {
	// Convert glob to prefix/suffix matching
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return path == pattern
	}
	// Check prefix
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	// Check suffix
	if !strings.HasSuffix(path, parts[len(parts)-1]) {
		return false
	}
	return true
}

// cleanOwner removes @ prefix and GitHub team prefix from owner strings.
func cleanOwner(owner string) string {
	owner = strings.TrimPrefix(owner, "@")
	// Remove GitHub org prefix (e.g., "org/team" -> "team")
	if idx := strings.Index(owner, "/"); idx > 0 {
		owner = owner[idx+1:]
	}
	return owner
}

// gitBlameFiles runs git blame on changed files and returns author -> line count.
func gitBlameFiles(root string, files []string) (map[string]map[string]int, error) {
	result := make(map[string]map[string]int)

	for _, file := range files {
		// Skip deleted files
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			continue
		}

		cmd := exec.Command("git", "blame", "--line-porcelain", "HEAD", "--", file)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			continue
		}

		authors := make(map[string]int)
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "author ") {
				author := strings.TrimPrefix(line, "author ")
				authors[author]++
			}
		}

		if len(authors) > 0 {
			result[file] = authors
		}
	}

	return result, nil
}

// detectExpertise maps file patterns to expertise domains.
func detectExpertise(filePath string) string {
	// Check path-based patterns first (more specific than extension)
	lower := strings.ToLower(filePath)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "login") {
		return "security"
	}
	if strings.Contains(lower, "test") {
		return "testing"
	}
	if strings.Contains(lower, "api") {
		return "api"
	}

	// Then check by extension
	ext := filepath.Ext(filePath)
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".ts", ".tsx":
		return "javascript"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".yml", ".yaml":
		return "ci-cd"
	case ".tf":
		return "infrastructure"
	}

	// Check for Dockerfile by basename
	if filepath.Base(filePath) == "Dockerfile" {
		return "docker"
	}
	return ""
}

// getOrCreateReviewer gets an existing reviewer or creates a new one.
func getOrCreateReviewer(m map[string]*Reviewer, username string) *Reviewer {
	if rev, ok := m[username]; ok {
		return rev
	}
	rev := &Reviewer{
		Username: username,
	}
	m[username] = rev
	return rev
}

// appendUnique appends a string to a slice only if it's not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// RenderMarkdown renders the reviewer suggestions as markdown.
func RenderMarkdown(result *SuggestionResult) string {
	if len(result.Reviewers) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("### Suggested Reviewers\n\n")

	for i, rev := range result.Reviewers {
		ownerBadge := ""
		if rev.IsOwner {
			ownerBadge = " (CODEOWNER)"
		}
		b.WriteString(fmt.Sprintf("%d. **@%s**%s — %d pts\n", i+1, rev.Username, ownerBadge, rev.Score))
		if len(rev.Reasons) > 0 {
			for _, reason := range rev.Reasons {
				b.WriteString(fmt.Sprintf("   - %s\n", reason))
			}
		}
		if len(rev.Files) > 0 && len(rev.Files) <= 5 {
			b.WriteString("   - Files: " + strings.Join(rev.Files, ", ") + "\n")
		} else if len(rev.Files) > 5 {
			b.WriteString(fmt.Sprintf("   - Files: %d files\n", len(rev.Files)))
		}
	}

	if !result.CodeownersFound && !result.BlameUsed {
		b.WriteString("\n_No CODEOWNERS file found and git blame not used._\n")
	}

	return b.String()
}

// Fix application logic — applies fix proposals to source files.
package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ApplyOptions controls fix application behavior.
type ApplyOptions struct {
	DryRun     bool   // If true, don't write changes, just preview
	Backup     bool   // If true, create a backup before applying
	NoConfirm  bool   // If true, skip confirmation prompt
	BackupDir  string // Directory for backups (default: .patchflow/backups/)
}

// ApplyResult holds the result of applying fixes.
type ApplyResult struct {
	TotalProposals  int          `json:"total_proposals"`
	Applied         int          `json:"applied"`
	Skipped         int          `json:"skipped"`
	Failed          int          `json:"failed"`
	Results         []FixResult  `json:"results"`
	DryRun          bool         `json:"dry_run"`
}

// Apply applies a single fix proposal to the source file.
func Apply(proposal FixProposal, opts ApplyOptions) (*FixResult, error) {
	if proposal.FilePath == "" {
		return nil, fmt.Errorf("proposal has no file path")
	}

	if proposal.Strategy == StrategyUpgrade {
		// SCA upgrades are not code fixes — they require manifest changes
		return &FixResult{
			ProposalID: proposal.ID,
			Applied:    false,
			Error:      "Dependency upgrades require manual manifest changes. See the proposal for details.",
		}, nil
	}

	if proposal.FixedCode == "" {
		return nil, fmt.Errorf("proposal has no fixed code")
	}

	// Read the current file
	source, err := os.ReadFile(proposal.FilePath)
	if err != nil {
		return &FixResult{
			ProposalID: proposal.ID,
			Applied:    false,
			FilePath:   proposal.FilePath,
			Error:      fmt.Sprintf("failed to read file: %v", err),
		}, nil
	}

	// For dry-run, just report what would change
	if opts.DryRun {
		return &FixResult{
			ProposalID:  proposal.ID,
			Applied:     false,
			FilePath:    proposal.FilePath,
			BytesChanged: len(proposal.FixedCode) - len(extractLines(string(source), proposal.LineStart, proposal.LineEnd)),
			LinesChanged: 1,
		}, nil
	}

	// Create backup if requested
	backupPath := ""
	if opts.Backup {
		backupPath = createBackup(proposal.FilePath, opts.BackupDir)
	}

	// Apply the fix
	fixedSource := replaceLine(string(source), proposal.LineStart, proposal.FixedCode)

	// Preserve original file permissions
	perm := os.FileMode(0644)
	if info, err := os.Stat(proposal.FilePath); err == nil {
		perm = info.Mode().Perm()
	}

	// Write the fixed file
	if err := os.WriteFile(proposal.FilePath, []byte(fixedSource), perm); err != nil {
		return &FixResult{
			ProposalID: proposal.ID,
			Applied:    false,
			FilePath:   proposal.FilePath,
			Error:      fmt.Sprintf("failed to write file: %v", err),
			BackupPath: backupPath,
		}, nil
	}

	return &FixResult{
		ProposalID:  proposal.ID,
		Applied:     true,
		FilePath:    proposal.FilePath,
		BytesChanged: len(fixedSource) - len(source),
		LinesChanged: 1,
		BackupPath:  backupPath,
	}, nil
}

// ApplyAll applies multiple fix proposals.
func ApplyAll(proposals []FixProposal, opts ApplyOptions) *ApplyResult {
	result := &ApplyResult{
		TotalProposals: len(proposals),
		DryRun:         opts.DryRun,
	}

	for _, proposal := range proposals {
		fr, err := Apply(proposal, opts)
		if err != nil {
			result.Failed++
			result.Results = append(result.Results, FixResult{
				ProposalID: proposal.ID,
				Applied:    false,
				Error:      err.Error(),
			})
			continue
		}

		if fr.Applied {
			result.Applied++
		} else {
			result.Skipped++
		}
		result.Results = append(result.Results, *fr)
	}

	return result
}

// createBackup creates a backup of a file before applying a fix.
func createBackup(filePath, backupDir string) string {
	if backupDir == "" {
		backupDir = ".patchflow/backups"
	}

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return ""
	}

	source, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	baseName := filepath.Base(filePath)
	backupPath := filepath.Join(backupDir, baseName+".bak")
	if err := os.WriteFile(backupPath, source, 0600); err != nil {
		return ""
	}

	return backupPath
}

// RenderProposalMarkdown renders a fix proposal as markdown for terminal display.
func RenderProposalMarkdown(p FixProposal) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("### Fix: %s\n\n", p.Title))
	b.WriteString(fmt.Sprintf("**Finding:** %s\n", p.FindingID))
	b.WriteString(fmt.Sprintf("**Severity:** %s\n", p.Severity))
	b.WriteString(fmt.Sprintf("**Confidence:** %s\n", p.Confidence))
	b.WriteString(fmt.Sprintf("**Strategy:** %s\n", p.Strategy))
	b.WriteString(fmt.Sprintf("**Auto-applicable:** %t\n\n", p.AutoApplicable))

	b.WriteString(fmt.Sprintf("**File:** `%s:%d`\n\n", p.FilePath, p.LineStart))

	if p.Description != "" {
		b.WriteString(fmt.Sprintf("%s\n\n", p.Description))
	}

	if p.OriginalCode != "" {
		b.WriteString("**Original:**\n```")
		lang := detectLanguage(p.FilePath)
		if lang != "" {
			b.WriteString(lang)
		}
		b.WriteString("\n")
		b.WriteString(p.OriginalCode)
		b.WriteString("\n```\n\n")
	}

	if p.FixedCode != "" {
		b.WriteString("**Fixed:**\n```")
		if lang := detectLanguage(p.FilePath); lang != "" {
			b.WriteString(lang)
		}
		b.WriteString("\n")
		b.WriteString(p.FixedCode)
		b.WriteString("\n```\n\n")
	}

	if p.Rationale != "" {
		b.WriteString(fmt.Sprintf("**Why:** %s\n\n", p.Rationale))
	}

	if len(p.References) > 0 {
		b.WriteString("**References:**\n")
		for _, ref := range p.References {
			b.WriteString(fmt.Sprintf("- %s\n", ref))
		}
		b.WriteString("\n")
	}

	if p.Patch != "" {
		b.WriteString("**Patch:**\n```diff\n")
		b.WriteString(p.Patch)
		b.WriteString("```\n")
	}

	return b.String()
}

// RenderSummary renders a summary of all proposals.
func RenderSummary(proposals []FixProposal) string {
	if len(proposals) == 0 {
		return "No fix proposals available for the current findings."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("### Fix Proposals (%d)\n\n", len(proposals)))

	byConfidence := map[string]int{}
	byStrategy := map[string]int{}
	autoApplicable := 0

	for _, p := range proposals {
		byConfidence[string(p.Confidence)]++
		byStrategy[string(p.Strategy)]++
		if p.AutoApplicable {
			autoApplicable++
		}
	}

	b.WriteString(fmt.Sprintf("- **Auto-applicable:** %d\n", autoApplicable))
	b.WriteString(fmt.Sprintf("- **Manual review needed:** %d\n", len(proposals)-autoApplicable))
	b.WriteString("\n**By confidence:**\n")
	for _, c := range []string{"high", "medium", "low"} {
		if count, ok := byConfidence[c]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("  - %s: %d\n", c, count))
		}
	}
	b.WriteString("\n**By strategy:**\n")
	for s, c := range byStrategy {
		b.WriteString(fmt.Sprintf("  - %s: %d\n", s, c))
	}

	b.WriteString("\n---\n\n")
	for i, p := range proposals {
		b.WriteString(fmt.Sprintf("%d. **[%s]** %s\n", i+1,
			strings.ToUpper(p.Severity), p.Title))
		if p.FilePath != "" {
			b.WriteString(fmt.Sprintf("   - File: `%s:%d`\n", p.FilePath, p.LineStart))
		}
		if p.PackageName != "" {
			b.WriteString(fmt.Sprintf("   - Package: %s@%s", p.PackageName, p.PackageVersion))
			if p.FixedVersion != "" {
				b.WriteString(fmt.Sprintf(" → %s", p.FixedVersion))
			}
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("   - Confidence: %s, Auto-applicable: %t\n",
			p.Confidence, p.AutoApplicable))
	}

	return b.String()
}

// RenderApplyResult renders the result of applying fixes.
func RenderApplyResult(result *ApplyResult) string {
	var b strings.Builder

	if result.DryRun {
		b.WriteString("### Dry Run Results\n\n")
	} else {
		b.WriteString("### Apply Results\n\n")
	}

	b.WriteString(fmt.Sprintf("- **Total:** %d\n", result.TotalProposals))
	b.WriteString(fmt.Sprintf("- **Applied:** %d\n", result.Applied))
	b.WriteString(fmt.Sprintf("- **Skipped:** %d\n", result.Skipped))
	b.WriteString(fmt.Sprintf("- **Failed:** %d\n\n", result.Failed))

	if len(result.Results) > 0 {
		b.WriteString("| # | File | Status | Details |\n")
		b.WriteString("|---|------|--------|---------|\n")
		for i, r := range result.Results {
			status := "✓ Applied"
			if !r.Applied {
				if r.Error != "" {
					status = "✗ Failed"
				} else {
					status = "⊘ Skipped"
				}
			}
			details := r.Error
			if details == "" && r.BackupPath != "" {
				details = "backup: " + r.BackupPath
			}
			b.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s |\n",
				i+1, r.FilePath, status, details))
		}
	}

	return b.String()
}

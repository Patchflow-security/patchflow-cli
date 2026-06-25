package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/analysis"
	"github.com/patchflow/patchflow-cli/internal/git"
	"github.com/patchflow/patchflow-cli/internal/manifest"
	"github.com/patchflow/patchflow-cli/internal/output"
	osvclient "github.com/patchflow/patchflow-cli/internal/osv"
	"github.com/spf13/cobra"
)

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Analyze dependencies",
	Long:  `Analyze project dependencies: list, diff against a base branch, find vulnerable packages, or check licenses.`,
}

var depsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all dependencies",
	RunE:  runDepsList,
}

var depsVulnerableCmd = &cobra.Command{
	Use:   "vulnerable",
	Short: "List vulnerable dependencies",
	RunE:  runDepsVulnerable,
}

var depsDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show dependency changes against base branch",
	RunE:  runDepsDiff,
}

var depsTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Show dependency tree by ecosystem",
	RunE:  runDepsTree,
}

func init() {
	depsCmd.AddCommand(depsListCmd)
	depsCmd.AddCommand(depsVulnerableCmd)
	depsCmd.AddCommand(depsDiffCmd)
	depsCmd.AddCommand(depsTreeCmd)
	rootCmd.AddCommand(depsCmd)
}

func runDepsList(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, _, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	if output.IsJSON(formatter) {
		return formatter.Print(deps)
	}

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Total dependencies: %d", len(deps)))
	_ = formatter.Print("")

	headers := []string{"NAME", "VERSION", "ECOSYSTEM", "DIRECT", "MANIFEST"}
	rows := make([][]string, 0, len(deps))
	for _, dep := range deps {
		direct := "yes"
		if !dep.IsDirect {
			direct = "no"
		}
		rows = append(rows, []string{
			truncateStr(dep.Name, 40),
			dep.Version,
			string(dep.Ecosystem),
			direct,
			dep.ManifestPath,
		})
	}
	return formatter.PrintTable(headers, rows)
}

func runDepsVulnerable(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, _, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print(fmt.Sprintf("Querying OSV.dev for %d dependencies...", len(deps)))
	}

	osv := osvclient.NewClient()
	vulnResults, err := osv.QueryBatch(ctx, deps)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("OSV query failed: %w", err))
	}

	type vulnDep struct {
		Dependency analysis.Dependency   `json:"dependency"`
		Vulns      []osvclient.Vulnerability `json:"vulns"`
	}

	var vulnerableDeps []vulnDep
	for i, vulns := range vulnResults {
		if i >= len(deps) {
			break
		}
		if len(vulns) > 0 {
			vulnerableDeps = append(vulnerableDeps, vulnDep{
				Dependency: deps[i],
				Vulns:      vulns,
			})
		}
	}

	if output.IsJSON(formatter) {
		return formatter.Print(vulnerableDeps)
	}

	if len(vulnerableDeps) == 0 {
		_ = formatter.PrintSuccess("No vulnerable dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Vulnerable dependencies: %d", len(vulnerableDeps)))
	_ = formatter.Print("")

	for _, vd := range vulnerableDeps {
		dep := vd.Dependency
		_ = formatter.Print(fmt.Sprintf("%s@%s (%s) — %d vulnerability(ies)",
			dep.Name, dep.Version, dep.Ecosystem, len(vd.Vulns)))
		for _, v := range vd.Vulns {
			severity := osvclient.ExtractSeverity(v)
			cve := osvclient.ExtractCVEID(v)
			fixed := osvclient.ExtractFixedVersion(v, dep.Name, dep.Version)
			line := fmt.Sprintf("  [%s] %s", strings.ToUpper(string(severity)), v.ID)
			if cve != "" {
				line += " (" + cve + ")"
			}
			if fixed != "" {
				line += " — fixed in " + fixed
			}
			_ = formatter.Print(line)
		}
		_ = formatter.Print("")
	}

	return nil
}

func runDepsDiff(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, err := git.Detect()
	if err != nil {
		return formatter.PrintError(err)
	}

	// Current dependencies
	currentDeps, _, err := manifest.ParseAll(repo.Root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Get changed manifest files
	_ = repo.DetectChangedFiles()
	changedManifests := make(map[string]bool)
	for _, f := range repo.ChangedFiles {
		if _, ok := manifest.KnownManifests[filepath.Base(f)]; ok {
			changedManifests[f] = true
		}
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			ChangedManifests []string                `json:"changed_manifests"`
			Dependencies     []analysis.Dependency    `json:"dependencies"`
			TotalCount       int                     `json:"total_count"`
		}{
			ChangedManifests: keysFromMap(changedManifests),
			Dependencies:     currentDeps,
			TotalCount:       len(currentDeps),
		})
	}

	if len(changedManifests) == 0 {
		_ = formatter.Print("No dependency manifest files changed.")
		return nil
	}

	_ = formatter.Print("Changed dependency manifests:")
	for f := range changedManifests {
		_ = formatter.Print("  " + f)
	}
	_ = formatter.Print("")

	// Show dependencies from changed manifests
	var changedDeps []analysis.Dependency
	for _, dep := range currentDeps {
		if changedManifests[dep.ManifestPath] {
			changedDeps = append(changedDeps, dep)
		}
	}

	if len(changedDeps) > 0 {
		_ = formatter.Print(fmt.Sprintf("Dependencies in changed manifests: %d", len(changedDeps)))
		headers := []string{"NAME", "VERSION", "ECOSYSTEM", "MANIFEST"}
		rows := make([][]string, 0, len(changedDeps))
		for _, dep := range changedDeps {
			rows = append(rows, []string{
				truncateStr(dep.Name, 40),
				dep.Version,
				string(dep.Ecosystem),
				dep.ManifestPath,
			})
		}
		_ = formatter.PrintTable(headers, rows)
	}

	return nil
}

func runDepsTree(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, manifests, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Group by ecosystem
	byEcosystem := make(map[analysis.Ecosystem][]analysis.Dependency)
	for _, dep := range deps {
		byEcosystem[dep.Ecosystem] = append(byEcosystem[dep.Ecosystem], dep)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			Manifests  []manifest.ManifestInfo       `json:"manifests"`
			ByEcosystem map[string][]analysis.Dependency `json:"by_ecosystem"`
			TotalCount  int                          `json:"total_count"`
		}{
			Manifests:   manifests,
			ByEcosystem: ecosystemMapToStringMap(byEcosystem),
			TotalCount:  len(deps),
		})
	}

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Dependency Tree (%d total)", len(deps)))
	_ = formatter.Print("")

	// Sort ecosystems for stable output
	ecosystems := make([]string, 0, len(byEcosystem))
	for eco := range byEcosystem {
		ecosystems = append(ecosystems, string(eco))
	}
	sort.Strings(ecosystems)

	for _, ecoStr := range ecosystems {
		ecoDeps := byEcosystem[analysis.Ecosystem(ecoStr)]
		_ = formatter.Print(fmt.Sprintf("├─ %s (%d)", ecoStr, len(ecoDeps)))

		// Group by manifest within ecosystem
		byManifest := make(map[string][]analysis.Dependency)
		for _, dep := range ecoDeps {
			byManifest[dep.ManifestPath] = append(byManifest[dep.ManifestPath], dep)
		}

		manifestPaths := make([]string, 0, len(byManifest))
		for mp := range byManifest {
			manifestPaths = append(manifestPaths, mp)
		}
		sort.Strings(manifestPaths)

		for _, mp := range manifestPaths {
			_ = formatter.Print(fmt.Sprintf("│  ├─ %s (%d)", mp, len(byManifest[mp])))
			for _, dep := range byManifest[mp] {
				direct := ""
				if dep.IsDirect {
					direct = " *"
				}
				_ = formatter.Print(fmt.Sprintf("│  │  ├─ %s@%s%s", dep.Name, dep.Version, direct))
			}
		}
	}

	return nil
}

func keysFromMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ecosystemMapToStringMap(m map[analysis.Ecosystem][]analysis.Dependency) map[string][]analysis.Dependency {
	result := make(map[string][]analysis.Dependency, len(m))
	for k, v := range m {
		result[string(k)] = v
	}
	return result
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

// Ensure context is used
var _ = context.Background

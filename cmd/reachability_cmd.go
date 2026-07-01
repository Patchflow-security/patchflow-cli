package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/reachability"
	"github.com/Patchflow-security/patchflow-cli/internal/sca"
	"github.com/spf13/cobra"
)

var (
	reachPackage string
	reachCVE     string
	reachExplain bool
)

var reachabilityCmd = &cobra.Command{
	Use:   "reachability",
	Short: "Analyze whether vulnerable dependencies are actually used",
	Long: `Determine whether a vulnerable dependency is reachable — i.e., actually
imported and used in the codebase. This helps prioritize which vulnerabilities
to fix first.

Reachability confidence levels:
  HIGH       directly imported or invoked
  MEDIUM     direct dependency, possible runtime usage
  LOW        transitive dependency, no direct usage found
  NONE       not present in dependency graph
  UNKNOWN    analysis incomplete`,
	RunE: runReachability,
}

func init() {
	reachabilityCmd.Flags().StringVar(&reachPackage, "package", "", "Check reachability for a specific package")
	reachabilityCmd.Flags().StringVar(&reachCVE, "cve", "", "Check reachability for a specific CVE (finds the package first)")
	reachabilityCmd.Flags().BoolVar(&reachExplain, "explain", false, "Show evidence for the reachability assessment")

	rootCmd.AddCommand(reachabilityCmd)
}

func runReachability(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	analyzer := reachability.NewAnalyzer()

	// If --cve is specified, find the package from SCA findings
	pkgName := reachPackage
	if reachCVE != "" && pkgName == "" {
		if !output.IsJSON(formatter) {
			_ = formatter.Print(fmt.Sprintf("Searching for package with CVE %s...", reachCVE))
		}

		scaAnalyzer := sca.NewAnalyzer()
		scaResult, err := scaAnalyzer.Analyze(ctx, root)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("failed to find package for CVE: %w", err))
		}

		for _, f := range scaResult.Findings {
			if f.CVEID == reachCVE || strings.Contains(f.CVEID, reachCVE) {
				pkgName = f.PackageName
				if !output.IsJSON(formatter) {
					_ = formatter.Print(fmt.Sprintf("Found: %s@%s has %s", f.PackageName, f.PackageVersion, f.CVEID))
				}
				break
			}
		}

		if pkgName == "" {
			return formatter.PrintError(fmt.Errorf("no package found with CVE %s in this repository", reachCVE))
		}
	}

	if pkgName == "" {
		return formatter.PrintError(fmt.Errorf("specify --package <name> or --cve <cve-id>"))
	}

	// Assess reachability
	status, evidence, err := analyzer.AssessPackage(root, pkgName)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("reachability analysis failed: %w", err))
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			Package  string                       `json:"package"`
			Status   analysis.ReachabilityStatus  `json:"status"`
			Evidence []string                     `json:"evidence,omitempty"`
		}{
			Package:  pkgName,
			Status:   status,
			Evidence: evidence,
		})
	}

	// Human output
	_ = formatter.Print(fmt.Sprintf("Package:      %s", pkgName))
	_ = formatter.Print(fmt.Sprintf("Reachability: %s", strings.ToUpper(string(status))))
	_ = formatter.Print("")

	if reachExplain && len(evidence) > 0 {
		_ = formatter.Print("Evidence:")
		for _, e := range evidence {
			_ = formatter.Print("  " + e)
		}
		_ = formatter.Print("")
	}

	switch status {
	case analysis.ReachabilityHigh:
		_ = formatter.Print("This package is directly imported in the codebase.")
		_ = formatter.Print("Vulnerabilities in this package are likely exploitable.")
	case analysis.ReachabilityMedium:
		_ = formatter.Print("This package is a direct dependency but no direct imports found.")
		_ = formatter.Print("Vulnerabilities may be exploitable at runtime.")
	case analysis.ReachabilityLow:
		_ = formatter.Print("This package appears to be a transitive dependency.")
		_ = formatter.Print("Vulnerabilities have lower exploitability.")
	case analysis.ReachabilityNone:
		_ = formatter.Print("This package is not present in the import graph.")
		_ = formatter.Print("Vulnerabilities are likely not exploitable.")
	default:
		_ = formatter.Print("Reachability could not be determined.")
	}

	return nil
}

// Ensure context is used
var _ = context.Background

package version

import "fmt"

var (
	Version = "0.1.0"
	Commit  = "dev"
	Date    = "unknown"
)

func BuildInfo() string {
	return fmt.Sprintf("patchflow version %s (commit: %s, built: %s)", Version, Commit, Date)
}

package version

import "fmt"

var (
	Version = "0.1.1"
	Commit  = "dev"
	Date    = "unknown"
)

func BuildInfo() string {
	return fmt.Sprintf("patchflow version %s (commit: %s, built: %s)", Version, Commit, Date)
}

// Short returns just the version string (e.g. "0.1.1") for embedding in scan
// metadata without the full build info banner.
func Short() string {
	return Version
}

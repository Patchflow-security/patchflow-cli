// Package exitcode defines structured exit codes for PatchFlow CLI.
//
// These codes allow CI/CD systems to distinguish between different failure
// modes and take appropriate action (e.g., retry on network errors, fail
// builds on security findings, alert on internal errors).
//
//	0 = scan completed, no blocking findings
//	1 = blocking findings found
//	2 = config error
//	3 = scanner internal error
//	4 = network/API error
//	5 = license/auth error
//	6 = timeout exceeded
package exitcode

const (
	// Success means the scan completed with no blocking findings.
	Success = 0

	// FindingsFound means blocking findings were detected (severity >= threshold).
	FindingsFound = 1

	// ConfigError means the configuration is invalid or missing.
	ConfigError = 2

	// InternalError means a scanner encountered an internal error.
	InternalError = 3

	// NetworkError means a network/API call failed (OSV, backend, etc.).
	NetworkError = 4

	// AuthError means authentication or license validation failed.
	AuthError = 5

	// Timeout means the scan exceeded its time budget.
	Timeout = 6
)

// String returns a human-readable description of the exit code.
func String(code int) string {
	switch code {
	case Success:
		return "success"
	case FindingsFound:
		return "blocking findings found"
	case ConfigError:
		return "configuration error"
	case InternalError:
		return "internal scanner error"
	case NetworkError:
		return "network or API error"
	case AuthError:
		return "authentication or license error"
	case Timeout:
		return "timeout exceeded"
	default:
		return "unknown error"
	}
}

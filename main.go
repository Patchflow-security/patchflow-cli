package main

import (
	"os"

	"github.com/patchflow/patchflow-cli/cmd"
	"github.com/patchflow/patchflow-cli/internal/exitcode"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// If the error implements ExitCoder, use its specific code.
		if ec, ok := err.(cmd.ExitCoder); ok {
			os.Exit(ec.ExitCode())
		}
		os.Exit(exitcode.InternalError)
	}
}

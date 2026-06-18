package main

import (
	"os"

	"github.com/patchflow/patchflow-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

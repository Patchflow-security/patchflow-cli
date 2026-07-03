package cmd

import (
	"errors"

	"github.com/Patchflow-security/patchflow-cli/internal/auth"
	"github.com/spf13/cobra"
)

func requireAuthToken(cmd *cobra.Command) (string, error) {
	token := auth.NewManager(ConfigFromContext(cmd.Context())).Token()
	if token == "" {
		return "", errors.New("Not authenticated. Run 'patchflow login --token <token>' first.")
	}
	return token, nil
}

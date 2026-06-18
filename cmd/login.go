package cmd

import (
	"errors"
	"fmt"

	"github.com/patchflow/patchflow-cli/internal/auth"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with PatchFlow",
	Long:  `Authenticate with the PatchFlow platform using an API token or GitHub OAuth device flow.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		logger := LoggerFromContext(cmd.Context())

		useDevice, _ := cmd.Flags().GetBool("device")
		token, _ := cmd.Flags().GetString("token")

		mgr := auth.NewManager(ConfigFromContext(cmd.Context()))

		if useDevice {
			clientID, _ := cmd.Flags().GetString("client-id")
			if clientID == "" {
				return formatter.PrintError(errors.New("--device requires --client-id to be set"))
			}
			flow := auth.NewDeviceFlow(clientID)
			resp, err := flow.Start()
			if err != nil {
				logger.Error("device flow start failed", zap.Error(err))
				return formatter.PrintError(err)
			}
			_ = formatter.Print(fmt.Sprintf("Please visit %s and enter code: %s", resp.VerificationURI, resp.UserCode))
			tokenResp, err := flow.Poll(resp.DeviceCode, resp.Interval)
			if err != nil {
				logger.Error("device flow poll failed", zap.Error(err))
				return formatter.PrintError(err)
			}
			if err := mgr.Login(tokenResp.AccessToken); err != nil {
				return formatter.PrintError(err)
			}
			return formatter.PrintSuccess("Authenticated with PatchFlow via GitHub device flow.")
		}

		if token != "" {
			if err := mgr.Login(token); err != nil {
				return formatter.PrintError(err)
			}
			return formatter.PrintSuccess("Authenticated with PatchFlow.")
		}

		return formatter.PrintError(errors.New("Use --token or --device to authenticate"))
	},
}

func init() {
	loginCmd.Flags().String("token", "", "API token")
	loginCmd.Flags().Bool("device", false, "Use GitHub OAuth device flow")
	loginCmd.Flags().String("client-id", "", "GitHub OAuth app client ID (required with --device)")
	rootCmd.AddCommand(loginCmd)
}

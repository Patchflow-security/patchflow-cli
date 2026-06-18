package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/patchflow/patchflow-cli/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage PatchFlow CLI configuration",
	Long:  `View and modify PatchFlow CLI configuration settings.`,
}

type configShowOutput struct {
	APIURL   string `json:"api_url"`
	Token    string `json:"token"`
	Org      string `json:"org"`
	LogLevel string `json:"log_level"`
}

func (c configShowOutput) String() string {
	var lines []string
	lines = append(lines, fmt.Sprintf("api_url:   %s", c.APIURL))
	lines = append(lines, fmt.Sprintf("token:     %s", c.Token))
	lines = append(lines, fmt.Sprintf("org:       %s", c.Org))
	lines = append(lines, fmt.Sprintf("log_level: %s", c.LogLevel))
	return strings.Join(lines, "\n")
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())
		cfg := ConfigFromContext(cmd.Context())

		out := configShowOutput{
			APIURL:   cfg.APIURL,
			Org:      cfg.Org,
			LogLevel: cfg.LogLevel,
		}
		if cfg.Token != "" {
			out.Token = "***"
		}

		return formatter.Print(out)
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		formatter := FormatterFromContext(cmd.Context())
		key := args[0]
		value := args[1]

		if key == "token" {
			return formatter.PrintError(errors.New("Use 'patchflow login --token' to set the token."))
		}

		cfg := ConfigFromContext(cmd.Context())

		switch key {
		case "api_url":
			cfg.APIURL = value
		case "org":
			cfg.Org = value
		case "log_level":
			cfg.LogLevel = value
		default:
			return formatter.PrintError(fmt.Errorf("unknown config key: %s", key))
		}

		if err := config.Save(cfg); err != nil {
			return formatter.PrintError(err)
		}

		return formatter.Print(fmt.Sprintf("Set %s = %s", key, value))
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}

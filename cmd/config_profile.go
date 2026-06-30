package cmd

import (
	"errors"
	"fmt"

	"github.com/Patchflow-security/patchflow-cli/internal/config"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage configuration profiles",
	Long:  `Create, switch, and manage multiple configuration profiles for different org/workspace contexts.`,
}

// profileListOutput is used for JSON output of the list command.
type profileListOutput struct {
	Name     string `json:"name"`
	Active   bool   `json:"active"`
	APIURL   string `json:"api_url"`
	Org      string `json:"org"`
	LogLevel string `json:"log_level"`
}

// profileShowOutput is used for JSON output of the show command.
type profileShowOutput struct {
	Name     string `json:"name"`
	APIURL   string `json:"api_url"`
	Org      string `json:"org"`
	LogLevel string `json:"log_level"`
}

func (p profileShowOutput) String() string {
	return fmt.Sprintf("name:      %s\napi_url:   %s\norg:       %s\nlog_level: %s", p.Name, p.APIURL, p.Org, p.LogLevel)
}

var profileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		formatter := FormatterFromContext(cmd.Context())
		cfg := ConfigFromContext(cmd.Context())
		name := args[0]

		profiles, err := config.LoadProfiles()
		if err != nil {
			return formatter.PrintError(err)
		}

		apiURL, _ := cmd.Flags().GetString("api-url")
		org, _ := cmd.Flags().GetString("org")
		logLevel, _ := cmd.Flags().GetString("log-level")

		// Fall back to current config values when flags are not provided.
		if apiURL == "" {
			apiURL = cfg.APIURL
		}
		if org == "" {
			org = cfg.Org
		}
		if logLevel == "" {
			logLevel = cfg.LogLevel
		}

		profiles.Set(name, config.Profile{
			APIURL:   apiURL,
			Org:      org,
			LogLevel: logLevel,
		})

		if err := config.SaveProfiles(profiles); err != nil {
			return formatter.PrintError(err)
		}

		return formatter.Print(fmt.Sprintf("Profile '%s' created", name))
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Switch active configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		formatter := FormatterFromContext(cmd.Context())
		name := args[0]

		profiles, err := config.LoadProfiles()
		if err != nil {
			return formatter.PrintError(err)
		}

		if _, ok := profiles.Get(name); !ok {
			return formatter.PrintError(fmt.Errorf("profile '%s' does not exist", name))
		}

		profiles.Active = name
		if err := config.SaveProfiles(profiles); err != nil {
			return formatter.PrintError(err)
		}

		return formatter.Print(fmt.Sprintf("Active profile set to '%s'", name))
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration profiles",
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		profiles, err := config.LoadProfiles()
		if err != nil {
			return formatter.PrintError(err)
		}

		names := profiles.List()
		if len(names) == 0 {
			return formatter.Print("No profiles configured")
		}

		// JSON mode: marshal structured output
		if output.IsJSON(formatter) {
			var out []profileListOutput
			for _, name := range names {
				prof, _ := profiles.Get(name)
				out = append(out, profileListOutput{
					Name:     name,
					Active:   profiles.Active == name,
					APIURL:   prof.APIURL,
					Org:      prof.Org,
					LogLevel: prof.LogLevel,
				})
			}
			return formatter.Print(out)
		}

		// Human mode: print table
		headers := []string{"NAME", "ACTIVE", "API_URL", "ORG", "LOG_LEVEL"}
		rows := make([][]string, 0, len(names))
		for _, name := range names {
			prof, _ := profiles.Get(name)
			active := ""
			if profiles.Active == name {
				active = "*"
			}
			rows = append(rows, []string{
				name,
				active,
				prof.APIURL,
				prof.Org,
				prof.LogLevel,
			})
		}
		return formatter.PrintTable(headers, rows)
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		formatter := FormatterFromContext(cmd.Context())
		name := args[0]

		if name == config.DefaultProfileName {
			return formatter.PrintError(errors.New("cannot delete the default profile"))
		}

		profiles, err := config.LoadProfiles()
		if err != nil {
			return formatter.PrintError(err)
		}

		if _, ok := profiles.Get(name); !ok {
			return formatter.PrintError(fmt.Errorf("profile '%s' does not exist", name))
		}

		if profiles.Active == name {
			return formatter.PrintError(fmt.Errorf("cannot delete the active profile '%s'", name))
		}

		profiles.Delete(name)
		if err := config.SaveProfiles(profiles); err != nil {
			return formatter.PrintError(err)
		}

		return formatter.Print(fmt.Sprintf("Profile '%s' deleted", name))
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show configuration profile details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		formatter := FormatterFromContext(cmd.Context())
		name := args[0]

		profiles, err := config.LoadProfiles()
		if err != nil {
			return formatter.PrintError(err)
		}

		prof, ok := profiles.Get(name)
		if !ok {
			return formatter.PrintError(fmt.Errorf("profile '%s' does not exist", name))
		}

		out := profileShowOutput{
			Name:     name,
			APIURL:   prof.APIURL,
			Org:      prof.Org,
			LogLevel: prof.LogLevel,
		}
		return formatter.Print(out)
	},
}

func init() {
	profileCreateCmd.Flags().String("api-url", "", "API URL for the profile")
	profileCreateCmd.Flags().String("org", "", "Organization for the profile")
	profileCreateCmd.Flags().String("log-level", "", "Log level for the profile")

	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	profileCmd.AddCommand(profileShowCmd)
}

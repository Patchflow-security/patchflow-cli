package cmd

import (
	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for patchflow.

To load completions:

Bash:
  source <(patchflow completion bash)

  # To load completions for each session, add the above line to your ~/.bashrc

Zsh:
  # If shell completion is not already enabled in your environment,
  # enable it by running:
  echo "autoload -U compinit; compinit" >> ~/.zshrc

  source <(patchflow completion zsh)

  # To load completions for each session, add the above line to your ~/.zshrc

Fish:
  patchflow completion fish | source

  # To load completions for each session, add the above line to your ~/.config/fish/config.fish

PowerShell:
  patchflow completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, add the output of the above
  # command to your PowerShell profile.
`,
	Args:              cobra.ExactValidArgs(1),
	ValidArgs:         []string{"bash", "zsh", "fish", "powershell"},
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			_ = cmd.Root().GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			_ = cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

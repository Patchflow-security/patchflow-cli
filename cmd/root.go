package cmd

import (
	"context"

	"github.com/patchflow/patchflow-cli/internal/config"
	"github.com/patchflow/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type contextKey string

const (
	formatterKey contextKey = "formatter"
	configKey    contextKey = "config"
	loggerKey    contextKey = "logger"
)

var rootCmd = &cobra.Command{
	Use:   "patchflow",
	Short: "PatchFlow CLI - Change Intelligence for engineering teams",
	Long: `PatchFlow CLI provides change intelligence for engineering teams.

Use this tool to scan, review, and analyze code changes in your repositories.`,
	PersistentPreRunE: persistentPreRun,
}

func persistentPreRun(cmd *cobra.Command, _ []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	apiURL, _ := cmd.Flags().GetString("api-url")
	jsonMode, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noColor, _ := cmd.Flags().GetBool("no-color")

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if apiURL != "" {
		cfg.APIURL = apiURL
	}

	logger, err := initLogger(verbose)
	if err != nil {
		return err
	}

	formatter := output.NewFormatter(jsonMode, noColor)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, formatterKey, formatter)
	ctx = context.WithValue(ctx, configKey, cfg)
	ctx = context.WithValue(ctx, loggerKey, logger)
	cmd.SetContext(ctx)

	return nil
}

func init() {
	rootCmd.PersistentFlags().String("config", "", "config file path")
	rootCmd.PersistentFlags().String("api-url", "", "PatchFlow API URL")
	rootCmd.PersistentFlags().Bool("json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func initLogger(verbose bool) (*zap.Logger, error) {
	if verbose {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

// FormatterFromContext retrieves the output formatter from context.
func FormatterFromContext(ctx context.Context) output.Formatter {
	f, ok := ctx.Value(formatterKey).(output.Formatter)
	if !ok {
		return output.NewFormatter(false, false)
	}
	return f
}

// ConfigFromContext retrieves the config from context.
func ConfigFromContext(ctx context.Context) *config.Config {
	c, ok := ctx.Value(configKey).(*config.Config)
	if !ok {
		return &config.Config{}
	}
	return c
}

// LoggerFromContext retrieves the logger from context.
func LoggerFromContext(ctx context.Context) *zap.Logger {
	l, ok := ctx.Value(loggerKey).(*zap.Logger)
	if !ok {
		logger, _ := zap.NewProduction()
		return logger
	}
	return l
}

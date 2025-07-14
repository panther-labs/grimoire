package main

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	// Common flags
	timeout            time.Duration
	lookupInterval     time.Duration
	maxEvents          int
	includeEvents      []string
	excludeEvents      []string
	writeEventsOnly    bool
	extendSearchWindow time.Duration
	outputDir          string

	// Log source selection
	logSource string

	// Panther-specific flags
	pantherEndpoint  string
	pantherApiToken  string
	pantherTableName string
)

// CLI flags shared between 'shell' and 'stratus-red-team' commands
func initLookupFlags(cmd *cobra.Command) {
	// Load environment variables first (if they exist)
	// Values loaded from environment will be overridden by command-line flags
	loadEnvVars()

	// Common flags
	cmd.Flags().DurationVarP(&timeout, "timeout", "", 15*time.Minute, "Maximum time to wait for events")
	cmd.Flags().DurationVarP(&lookupInterval, "interval", "", time.Minute, "Time to wait between event lookups")
	cmd.Flags().DurationVarP(&extendSearchWindow, "extend-search-window", "", 10*time.Minute, "Extend the search window by this duration to account for event delays")
	cmd.Flags().IntVarP(&maxEvents, "max-events", "", 0, "Maximum number of events to wait for (0 means no limit)")
	cmd.Flags().BoolVarP(&writeEventsOnly, "write-events-only", "", false, "Only keep write events (i.e., non-read-only events)")
	cmd.Flags().StringSliceVarP(&includeEvents, "include-events", "", []string{}, "Only include specific events in the search. Event names should be in the format [service]:[eventName], e.g. sts:GetCallerIdentity")
	cmd.Flags().StringSliceVarP(&excludeEvents, "exclude-events", "", []string{}, "Exclude specific events from the search. Event names should be in the format [service]:[eventName], e.g. sts:GetCallerIdentity")
	cmd.MarkFlagsMutuallyExclusive("include-events", "exclude-events")

	// Set default output directory to "./output"
	cmd.Flags().StringVarP(&outputDir, "output", "o", "./output", "Output directory to write CloudTrail events and alerts. If not specified, uses './output' directory.")

	// Log source selection
	cmd.Flags().StringVarP(&logSource, "log-source", "", "cloudtrail", "Log source to use (cloudtrail or panther)")

	// Panther-specific flags
	cmd.Flags().StringVarP(&pantherEndpoint, "panther-api-host", "", pantherEndpoint, "Panther GraphQL endpoint")
	cmd.Flags().StringVarP(&pantherApiToken, "panther-api-token", "", pantherApiToken, "Panther API token")
	cmd.Flags().StringVarP(&pantherTableName, "panther-table", "", "aws_cloudtrail", "Panther table name to query")
}

// loadEnvVars loads values from environment variables if they exist
func loadEnvVars() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// It's okay if no .env file exists - we'll use environment variables or defaults
		fmt.Println("Note: No .env file found. Using environment variables and defaults.")
	}

	// Panther credentials
	if value := os.Getenv("PANTHER_API_HOST"); value != "" {
		pantherEndpoint = value
	}
	if value := os.Getenv("PANTHER_API_TOKEN"); value != "" {
		pantherApiToken = value
	}
}

// ValidateFlags checks if the required flags are set based on the log source
func ValidateFlags() error {
	// Auto-detect panther as log source if Panther API flags are supplied
	if pantherEndpoint != "" || pantherApiToken != "" {
		logSource = "panther"
		fmt.Println("Auto-detected Panther as log source based on provided Panther API flags")
	}

	if logSource == "panther" {
		if pantherEndpoint == "" {
			return fmt.Errorf("--panther-api-host is required when using panther as log source")
		}
		if pantherApiToken == "" {
			return fmt.Errorf("--panther-api-token is required when using panther as log source")
		}
	}
	return nil
}

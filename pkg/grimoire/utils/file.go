package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func CreateOrTruncateJSONFile(outputFile string) error {
	if outputFile == "" || outputFile == "-" {
		return nil // nothing to do
	}
	return os.WriteFile(outputFile, []byte("[]"), 0600)
}

// AppendToJsonFileArray assumes that 'outputFile' is an existing JSON file containing an array of JSON objects, and appends 'payload' to it
func AppendToJsonFileArray(outputFile string, payload map[string]interface{}) error {
	if outputFile == "" {
		return nil // nothing to do
	}

	// print to stdout, nothing else to do
	if outputFile == "-" {
		outputBytes, err := json.MarshalIndent(payload, "", "   ")
		if err != nil {
			return err
		}
		fmt.Println(string(outputBytes))
		return nil
	}

	// Read file contents and parse the JSON
	var events []map[string]interface{}
	inputBytes, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("unable to read output file %s: %v", outputFile, err)
	}
	if err := json.Unmarshal(inputBytes, &events); err != nil {
		return fmt.Errorf("unable to unmarshal output file contents %s: %v", outputFile, err)
	}

	// Append our payload
	events = append(events, payload)

	// Re-convert it back to JSON
	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return fmt.Errorf("unable to marshal JSON to output file %s: %v", outputFile, err)
	}

	// Write back ot the output file
	if err := os.WriteFile(outputFile, outputBytes, 0600); err != nil {
		return fmt.Errorf("unable to write to output file %s for writing: %v", outputFile, err)
	}

	return nil
}

// CreateLogFiles creates and initializes the log and alert files with the given timestamp and optional suffix
// If outputDir is provided, files will be created inside that directory
// If createAlertsFile is false, no alerts file will be created (returns empty string for alertsFile)
func CreateLogFiles(outputDir, timestamp, suffix string, createAlertsFile bool) (string, string, error) {
	var logsFilename, alertsFilename string

	if suffix != "" {
		logsFilename = fmt.Sprintf("%s_%s_logs.json", timestamp, suffix)
		alertsFilename = fmt.Sprintf("%s_%s_alerts.json", timestamp, suffix)
	} else {
		logsFilename = fmt.Sprintf("%s_grimoire_logs.json", timestamp)
		alertsFilename = fmt.Sprintf("%s_grimoire_alerts.json", timestamp)
	}

	// If outputDir is provided, create the directory if it doesn't exist
	// and prepend the directory to the filenames
	var logsFile, alertsFile string
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", "", fmt.Errorf("unable to create output directory %s: %v", outputDir, err)
		}
		logsFile = filepath.Join(outputDir, logsFilename)
		alertsFile = filepath.Join(outputDir, alertsFilename)
	} else {
		logsFile = logsFilename
		alertsFile = alertsFilename
	}

	// Initialize logs file
	if err := CreateOrTruncateJSONFile(logsFile); err != nil {
		return "", "", fmt.Errorf("failed to create logs file: %w", err)
	}

	// Initialize alerts file only if needed
	if createAlertsFile {
		if err := CreateOrTruncateJSONFile(alertsFile); err != nil {
			return "", "", fmt.Errorf("failed to create alerts file: %w", err)
		}
	} else {
		alertsFile = "" // Return empty string when no alerts file is created
	}

	return logsFile, alertsFile, nil
}

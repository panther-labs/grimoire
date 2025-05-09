package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"slices"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
	log "github.com/sirupsen/logrus"
)

// CreateEventsFinder creates the appropriate events finder based on log source and configuration
// Handles AWS config creation internally only when needed (for CloudTrail)
func CreateEventsFinder(userAgentMatchType logs.UserAgentMatchType) (logs.Searcher, error) {
	var eventsFinder logs.Searcher

	switch logSource {
	case "cloudtrail":
		// Load AWS config only when using CloudTrail
		awsConfig, err := utils.GetAWSConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to load AWS config: %w", err)
		}

		// Check AWS authentication
		err = utils.EnsureAWSAuthenticated(context.Background(), awsConfig)
		if err != nil {
			log.Errorf("It looks like you are not authenticated to AWS. Please authenticate before running Grimoire.")
			os.Exit(1)
		}

		eventsFinder = &logs.CloudTrailEventsFinder{
			CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
			Options: &logs.CloudTrailEventLookupOptions{
				Timeout:            timeout,
				LookupInterval:     lookupInterval,
				IncludeEvents:      includeEvents,
				ExcludeEvents:      excludeEvents,
				MaxEvents:          maxEvents,
				WriteEventsOnly:    writeEventsOnly,
				ExtendTimeWindow:   extendSearchWindow,
				UserAgentMatchType: userAgentMatchType,
			},
		}
		log.Info("Using CloudTrail for event lookup")
	case "panther":
		eventsFinder = &logs.PantherEventsFinder{
			Client: logs.NewPantherClient(pantherEndpoint, pantherApiToken),
			Options: &logs.PantherEventLookupOptions{
				Timeout:            timeout,
				LookupInterval:     lookupInterval,
				IncludeEvents:      includeEvents,
				ExcludeEvents:      excludeEvents,
				MaxEvents:          maxEvents,
				WriteEventsOnly:    writeEventsOnly,
				ExtendTimeWindow:   extendSearchWindow,
				UserAgentMatchType: userAgentMatchType,
				TableName:          pantherTableName,
			},
		}
		log.Info("Using Panther for event lookup")
	default:
		return nil, fmt.Errorf("unsupported log source: %s", logSource)
	}

	return eventsFinder, nil
}

// ProcessEvents processes events and alerts from the provided channels, writing them to the specified files
// Returns a summary of the events and alerts found
func ProcessEvents(ctx context.Context, eventsChannel chan *logs.LogEvent, alertsChannel chan *logs.PantherAlert,
	logsFile, alertsFile string, expectedTechnique string, cancelFunc func()) logs.SearchSummary {

	var summary logs.SearchSummary
	summary.ExpectedTechnique = expectedTechnique

	var wg sync.WaitGroup
	wg.Add(2)

	// Process events
	go func() {
		defer wg.Done()
		for evt := range eventsChannel {
			if evt.Error != nil {
				log.Errorf("Error while searching for events: %v", evt.Error)
				if cancelFunc != nil {
					cancelFunc()
				} else {
					os.Exit(1)
				}
				return
			}

			log.Infof("Found event: %s", utils.GetCloudTrailEventFullName(evt.Event))
			if err := utils.AppendToJsonFileArray(logsFile, *evt.Event); err != nil {
				log.Errorf("unable to append event to output file: %v", err)
			}
			summary.EventCount++
		}
	}()

	// Process alerts
	go func() {
		defer wg.Done()
		for alert := range alertsChannel {
			// Skip writing alerts if alertsFile is empty (when using CloudTrail)
			if alertsFile != "" {
				alertMap := map[string]any{
					"alertId":      alert.AlertID,
					"creationTime": alert.CreationTime,
					"detectionId":  alert.DetectionID,
					"title":        alert.Title,
					"severity":     alert.Severity,
					"numEvents":    alert.NumEvents,
					"techniques":   alert.Techniques,
				}
				if err := utils.AppendToJsonFileArray(alertsFile, alertMap); err != nil {
					log.Errorf("unable to append alert to output file: %v", err)
				}
			}
			summary.AlertCount++

			// Check if this alert matches our expected technique
			if expectedTechnique != "" {
				if slices.Contains(alert.Techniques, expectedTechnique) {
					summary.ExpectedAlerts++
				}
			}
		}
	}()

	wg.Wait()
	return summary
}

// LogSearchResult logs the search summary results
func LogSearchResult(summary logs.SearchSummary) {
	if summary.ExpectedTechnique != "" && summary.ExpectedAlerts > 0 {
		log.Infof("Search complete. Found %d events and %d alerts (%d alerts matched technique %s).",
			summary.EventCount, summary.AlertCount, summary.ExpectedAlerts, summary.ExpectedTechnique)
	} else if summary.ExpectedTechnique != "" {
		log.Infof("Search complete. Found %d events and %d alerts (no alerts matched technique %s).",
			summary.EventCount, summary.AlertCount, summary.ExpectedTechnique)
	} else {
		log.Infof("Search complete. Found %d events and %d alerts.", summary.EventCount, summary.AlertCount)
	}
}

// FindLogsForDetonation searches for logs related to a detonation with configurable parameters
func FindLogsForDetonation(ctx context.Context, detonation *detonators.DetonationInfo,
	suffix string, techniqueID string, userAgentMatchType logs.UserAgentMatchType, cancelFunc func()) error {

	eventsFinder, err := CreateEventsFinder(userAgentMatchType)
	if err != nil {
		return err
	}

	// Create output filenames and initialize files
	timestamp := time.Now().Format("20060102_150405")
	// Only create alerts file when using Panther
	createAlertsFile := logSource == "panther"
	logsFile, alertsFile, err := utils.CreateLogFiles(outputDir, timestamp, suffix, createAlertsFile)
	if err != nil {
		return err
	}

	log.Info("Searching for events...")
	eventsChannel, alertsChannel, err := eventsFinder.FindLogs(ctx, detonation)
	if err != nil {
		return fmt.Errorf("unable to search for events: %v", err)
	}

	summary := ProcessEvents(ctx, eventsChannel, alertsChannel, logsFile, alertsFile,
		techniqueID, cancelFunc)

	LogSearchResult(summary)
	return nil
}

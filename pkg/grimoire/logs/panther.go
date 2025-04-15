package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/hasura/go-graphql-client"
	log "github.com/sirupsen/logrus"
)

type PantherEventsFinder struct {
	Client  *graphql.Client
	Options *PantherEventLookupOptions
}

type PantherEventLookupOptions struct {
	// Timeout for the entire search operation (both events and alerts)
	Timeout time.Duration

	// Issue a new lookup query every LookupInterval
	LookupInterval time.Duration

	// Extend the search window to account for event delays
	ExtendTimeWindow time.Duration

	// Maximum number of events to retrieve (0 means no limit)
	MaxEvents int

	// Table name to query (defaults to "aws_cloudtrail")
	TableName string

	// Filter events by type
	IncludeEvents   []string // Format: "[service]:[eventName]", e.g. "sts:GetCallerIdentity"
	ExcludeEvents   []string // Format: "[service]:[eventName]", e.g. "sts:GetCallerIdentity"
	WriteEventsOnly bool     // Only include write (non-read-only) events

	// How to match the user agent string
	UserAgentMatchType UserAgentMatchType
}

// Strongly typed query structures
type executeQueryResponse struct {
	ExecuteDataLakeQuery struct {
		Id graphql.ID `json:"id"`
	} `graphql:"executeDataLakeQuery(input: {sql: $sql})"`
}

type QueryResults struct {
	DataLakeQuery struct {
		Message graphql.String `json:"message"`
		Status  graphql.String `json:"status"`
		Results struct {
			Edges []struct {
				Node json.RawMessage `json:"node"`
			} `json:"edges"`
		} `json:"results"`
	} `graphql:"dataLakeQuery(id: $id)"`
}

func NewPantherClient(endpoint string, apiToken string) *graphql.Client {
	return graphql.NewClient(endpoint, nil).
		WithRequestModifier(func(req *http.Request) {
			req.Header.Set("X-API-Key", apiToken)
		})
}

func (f *PantherEventsFinder) FindLogs(ctx context.Context, detonation *detonators.DetonationInfo) (chan *LogEvent, chan *PantherAlert, error) {
	if f.Client == nil {
		return nil, nil, errors.New("panther client not initialized")
	}
	if f.Options == nil {
		return nil, nil, errors.New("panther options not set")
	}

	eventResults := make(chan *LogEvent)
	alertResults := make(chan *PantherAlert)

	// Run both queries concurrently
	go f.findEventsAsync(ctx, detonation, eventResults)
	go f.findAlertsAsync(ctx, detonation, alertResults)

	return eventResults, alertResults, nil
}

// findEventsAsync finds events in Panther that match the detonation ID
func (f *PantherEventsFinder) findEventsAsync(ctx context.Context, detonation *detonators.DetonationInfo, results chan *LogEvent) {
	defer close(results)

	log.Info("Starting Panther events search...")
	currentStartTime := detonation.StartTime

	// Define a function to build SQL query for events
	buildQuery := func() string {
		return f.buildSQLQuery(currentStartTime, detonation)
	}

	// Define a function to process results for events
	processResults := func(data []json.RawMessage) (int, error) {
		var events []map[string]any
		var latestEventTime time.Time

		for _, node := range data {
			if len(node) == 0 {
				continue
			}

			var eventMap map[string]any
			if err := json.Unmarshal(node, &eventMap); err != nil {
				log.Debugf("Error unmarshaling node: %v", err)
				continue
			}

			events = append(events, eventMap)
		}

		if len(events) > 0 {
			log.Infof("Found %d new events in Panther", len(events))
			for _, event := range events {
				eventTimeStr, ok := event["p_event_time"].(string)
				if !ok {
					continue
				}
				eventTime, err := time.Parse("2006-01-02 15:04:05", eventTimeStr)
				if err != nil {
					continue
				}
				if eventTime.After(latestEventTime) {
					latestEventTime = eventTime
				}
				if eventName, ok := event["eventname"]; ok {
					event["eventName"] = eventName
					delete(event, "eventname")
				}
				if eventSource, ok := event["eventsource"]; ok {
					event["eventSource"] = eventSource
					delete(event, "eventsource")
				}
				if eventSource, ok := event["eventtime"]; ok {
					event["eventTime"] = eventSource
					delete(event, "eventtime")
				}

				results <- &LogEvent{Event: &event}
			}

			if !latestEventTime.IsZero() {
				// Move to the next second to avoid duplicates
				currentStartTime = latestEventTime.Add(time.Second)
				log.Debugf("Updated currentStartTime to %s", currentStartTime)
			}

			return len(events), nil
		}

		return 0, nil
	}

	// Execute common query logic
	err := f.executeQueryWithPolling(ctx, "events", buildQuery, processResults, f.Options.MaxEvents)
	if err != nil && currentStartTime == detonation.StartTime {
		results <- &LogEvent{Error: fmt.Errorf("no events found in Panther after %s", f.Options.Timeout)}
	}
}

// findAlertsAsync finds alerts in Panther that match the detonation ID
func (f *PantherEventsFinder) findAlertsAsync(ctx context.Context, detonation *detonators.DetonationInfo, results chan *PantherAlert) {
	defer close(results)

	log.Info("Starting Panther alerts search...")

	// Track alerts we've already seen
	foundAlerts := make(map[string]bool)

	// Define a function to build SQL query for alerts
	buildQuery := func() string {
		return f.buildAlertSQLQuery(detonation)
	}

	// Define a function to process results for alerts
	processResults := func(data []json.RawMessage) (int, error) {
		newAlerts := 0

		for _, node := range data {
			var alert PantherAlert
			if err := json.Unmarshal(node, &alert); err != nil {
				log.Debugf("Error unmarshaling alert: %v", err)
				continue
			}

			if !foundAlerts[alert.AlertID] {
				foundAlerts[alert.AlertID] = true
				results <- &alert
				newAlerts++
			}
		}

		if newAlerts > 0 {
			log.Infof("Found %d new alerts in Panther", newAlerts)
		}

		return newAlerts, nil
	}

	// Execute common query logic
	_ = f.executeQueryWithPolling(ctx, "alerts", buildQuery, processResults, 0)
}

// executeQueryWithPolling implements the common pattern of executing a query and polling for results
func (f *PantherEventsFinder) executeQueryWithPolling(
	ctx context.Context,
	queryType string,
	buildQuery func() string,
	processResults func([]json.RawMessage) (int, error),
	maxResults int,
) error {
	now := time.Now()
	deadline := now.Add(f.Options.Timeout)
	log.Debugf("Search deadline for %s: %s", queryType, deadline)

	for time.Now().Before(deadline) {
		sqlQuery := buildQuery()
		log.Debugf("Executing Panther %s query: %s", queryType, sqlQuery)

		// Execute query
		var executeResp executeQueryResponse
		variables := map[string]any{
			"sql": sqlQuery,
		}

		if err := f.Client.Mutate(ctx, &executeResp, variables); err != nil {
			return fmt.Errorf("failed to execute %s query: %w", queryType, err)
		}

		queryId := executeResp.ExecuteDataLakeQuery.Id
		log.Debugf("Successfully executed Panther %s query, query ID: %s", queryType, queryId)

		// Poll for results
		var resultNodes []json.RawMessage
		for {
			var resultsResp QueryResults
			// Initialize all nested structs with matching tags
			resultsResp.DataLakeQuery.Results.Edges = []struct {
				Node json.RawMessage `json:"node"`
			}{}

			variables = map[string]any{
				"id": queryId,
			}

			if err := f.Client.Query(ctx, &resultsResp, variables); err != nil {
				log.Debugf("Error querying %s results: %v", queryType, err)
				return fmt.Errorf("failed to fetch %s results: %w", queryType, err)
			}

			log.Debugf("Query response status: %s", resultsResp.DataLakeQuery.Status)

			if resultsResp.DataLakeQuery.Status == "running" {
				log.Debugf("Query still running, waiting %v", f.Options.LookupInterval)
				time.Sleep(f.Options.LookupInterval)
				continue
			}

			log.Debugf("Query returned %d %s", len(resultsResp.DataLakeQuery.Results.Edges), queryType)

			for _, edge := range resultsResp.DataLakeQuery.Results.Edges {
				if len(edge.Node) > 0 {
					resultNodes = append(resultNodes, edge.Node)
				}
			}
			break
		}

		count, err := processResults(resultNodes)
		if err != nil {
			return err
		}

		if maxResults > 0 && count >= maxResults {
			return nil
		}

		if count == 0 {
			log.Debugf("No new %s found, waiting %s before next query", queryType, f.Options.LookupInterval)
		}

		select {
		case <-ctx.Done():
			log.Debugf("Context cancelled, stopping Panther %s search", queryType)
			return ctx.Err()
		case <-time.After(f.Options.LookupInterval):
			continue
		}
	}

	return nil
}

func (f *PantherEventsFinder) buildSQLQuery(startTime time.Time, detonation *detonators.DetonationInfo) string {
	var conditions []string
	if f.Options.UserAgentMatchType == UserAgentMatchTypePartial {
		conditions = append(conditions, fmt.Sprintf("userAgent LIKE '%%%s%%'", detonation.DetonationID))
	} else {
		conditions = append(conditions, fmt.Sprintf("(userAgent = '%s' OR userAgent = '[%s]')", detonation.DetonationID, detonation.DetonationID))
	}

	// Handle IncludeEvents
	if len(f.Options.IncludeEvents) > 0 {
		var eventConditions []string
		for _, event := range f.Options.IncludeEvents {
			parts := strings.Split(strings.ToLower(event), ":")
			if len(parts) == 2 {
				eventConditions = append(eventConditions,
					fmt.Sprintf("(LOWER(eventsource) = '%s.amazonaws.com' AND LOWER(eventname) = '%s')",
						parts[0],
						parts[1]))
			}
		}
		if len(eventConditions) > 0 {
			conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(eventConditions, " OR ")))
		}
	}

	// Handle ExcludeEvents
	if len(f.Options.ExcludeEvents) > 0 {
		var eventConditions []string
		for _, event := range f.Options.ExcludeEvents {
			parts := strings.Split(strings.ToLower(event), ":")
			if len(parts) == 2 {
				eventConditions = append(eventConditions,
					fmt.Sprintf("NOT (LOWER(eventsource) = '%s.amazonaws.com' AND LOWER(eventname) = '%s')",
						parts[0],
						parts[1]))
			}
		}
		if len(eventConditions) > 0 {
			conditions = append(conditions, strings.Join(eventConditions, " AND "))
		}
	}

	query := fmt.Sprintf(`
		SELECT *
		FROM panther_logs.public.%s
		WHERE p_occurs_between('%s', '%s')
		AND %s
		ORDER BY p_event_time`,
		f.Options.TableName,
		startTime.UTC().Format(time.RFC3339),
		detonation.EndTime.Add(f.Options.ExtendTimeWindow).UTC().Format(time.RFC3339),
		strings.Join(conditions, " AND "))

	if f.Options.MaxEvents > 0 {
		query += fmt.Sprintf(" LIMIT %d", f.Options.MaxEvents)
	}

	return query
}

func (f *PantherEventsFinder) buildAlertSQLQuery(detonation *detonators.DetonationInfo) string {
	var userAgentCondition string
	switch f.Options.UserAgentMatchType {
	case UserAgentMatchTypeExact:
		userAgentCondition = fmt.Sprintf("(data:userAgent = '%s' OR data:userAgent = '[%s]')", detonation.DetonationID, detonation.DetonationID)
	case UserAgentMatchTypePartial:
		userAgentCondition = fmt.Sprintf("data:userAgent LIKE '%%%s%%'", detonation.DetonationID)
	default:
		log.Warnf("Unknown UserAgentMatchType %v, defaulting to exact match", f.Options.UserAgentMatchType)
		userAgentCondition = fmt.Sprintf("(data:userAgent = '%s' OR data:userAgent = '[%s]')", detonation.DetonationID, detonation.DetonationID)
	}

	return fmt.Sprintf(`
		SELECT 
			alertId,
			creationTime,
			detectionId, 
			title,
			severity,
			ARRAY_SIZE(ARRAY_AGG(data)) num_events,
			ARRAY_AGG(srt.value) techniques
		FROM panther_signals.public.signal_alerts alerts
		LEFT JOIN panther_signals.public.correlation_signals_variant signals 
			ON alertId = p_alert_id,
		LATERAL FLATTEN(input => data:p_rule_reports."Stratus Red Team", outer => TRUE) srt
		WHERE %s
		AND creationTime >= '%s'
		GROUP BY alertId, creationTime, detectionId, title, severity`,
		userAgentCondition,
		detonation.StartTime.UTC().Format(time.RFC3339))
}

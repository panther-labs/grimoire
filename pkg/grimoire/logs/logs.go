package logs

import (
	"context"

	"github.com/datadog/grimoire/pkg/grimoire/detonators"
)

type LogEvent struct {
	Event *map[string]interface{}
	Error error
}

type SearchSummary struct {
	EventCount        int
	AlertCount        int
	ExpectedAlerts    int    // Number of alerts that match the expected technique
	ExpectedTechnique string // The technique we're looking for
}

type PantherAlert struct {
	AlertID      string   `json:"alertId"`
	CreationTime string   `json:"creationTime"`
	DetectionID  string   `json:"detectionId"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	NumEvents    int      `json:"num_events"`
	Techniques   []string `json:"techniques"`
}

type Searcher interface {
	FindLogs(ctx context.Context, detonation *detonators.DetonationInfo) (chan *LogEvent, chan *PantherAlert, error)
}

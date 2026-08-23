package loglist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	ChromeList    = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	ChromeAllList = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	AppleList     = "https://valid.apple.com/ct/log_list/current_log_list.json"
)

type List struct {
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Name      string `json:"name"`
	Logs      []Log  `json:"logs"`
	TiledLogs []Log  `json:"tiled_logs"`
}

type Log struct {
	Description   string                 `json:"description"`
	LogID         string                 `json:"log_id"`
	Key           string                 `json:"key"`
	URL           string                 `json:"url"`
	MonitoringURL string                 `json:"monitoring_url"`
	SubmissionURL string                 `json:"submission_url"`
	State         map[string]StateDetail `json:"state"`
}

type StateDetail struct {
	Timestamp     string         `json:"timestamp"`
	FinalTreeHead *FinalTreeHead `json:"final_tree_head"`
}

type FinalTreeHead struct {
	SHA256RootHash []byte `json:"sha256_root_hash"`
	TreeSize       int64  `json:"tree_size"`
	Timestamp      int64  `json:"timestamp"`
}

var statePriority = []string{"usable", "qualified", "pending", "readonly", "retired", "rejected"}

func (l *Log) CurrentState() string {
	best := ""
	bestRank := len(statePriority)
	for s := range l.State {
		for i, p := range statePriority {
			if p == s && i < bestRank {
				bestRank = i
				best = s
			}
		}
	}
	return best
}

func (l *Log) Kind() string {
	if l.URL != "" {
		return "rfc6962"
	}
	if l.MonitoringURL != "" {
		return "staticct"
	}
	return ""
}

func (l *Log) Endpoint() string {
	switch l.Kind() {
	case "rfc6962":
		return l.URL
	case "staticct":
		return l.MonitoringURL
	default:
		return ""
	}
}

func FetchAll(ctx context.Context, client *http.Client) ([]Log, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	urls := []string{ChromeList, ChromeAllList, AppleList}
	seen := make(map[string]*Log)
	var order []string
	var fetched int
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		list, err := fetchOne(ctx, client, u)
		if err != nil {
			continue
		}
		fetched++
		for i := range list.Operators {
			for j := range list.Operators[i].Logs {
				lg := &list.Operators[i].Logs[j]
				if lg.LogID == "" || lg.Kind() == "" {
					continue
				}
				if _, ok := seen[lg.LogID]; !ok {
					order = append(order, lg.LogID)
				}
				prev, exists := seen[lg.LogID]
				if !exists {
					seen[lg.LogID] = lg
					continue
				}
				if prev.URL == "" && lg.URL != "" {
					prev.URL = lg.URL
				}
				if prev.MonitoringURL == "" && lg.MonitoringURL != "" {
					prev.MonitoringURL = lg.MonitoringURL
				}
			}
		}
	}
	out := make([]Log, 0, len(order))
	for _, id := range order {
		out = append(out, *seen[id])
	}
	if fetched == 0 {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("log list fetch canceled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("all %d log list sources failed", len(urls))
	}
	if fetched < len(urls) {
		log.Printf("loglist: %d of %d sources failed", len(urls)-fetched, len(urls))
	}
	return out, nil
}

func fetchOne(ctx context.Context, client *http.Client, url string) (*List, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: http %d", url, resp.StatusCode)
	}
	var list List
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return &list, nil
}

package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"ping/pkg/models"
)

type ClientLogEntry struct {
	ID          string               `json:"id"`
	Timestamp   time.Time            `json:"timestamp"`
	UnixMs      int64                `json:"unix_ms"`
	ClientIP    string               `json:"client_ip"`
	Port        string               `json:"port"`
	Geo         models.GeoData       `json:"geo"`
	Network     models.NetworkData   `json:"network"`
	UserAgent   models.UserAgentData `json:"user_agent"`
	Security    models.SecurityData  `json:"security"`
	Headers     map[string]string    `json:"headers"`
	JA4Digest   string               `json:"ja4_digest,omitempty"`
	QueryParams map[string]string   `json:"query_params,omitempty"`
}

type StorageEngine struct {
	mu      sync.RWMutex
	logs    []ClientLogEntry
	maxSize int
	kvURL   string
	kvToken string
}

func NewStorageEngine() *StorageEngine {
	return &StorageEngine{
		logs:    make([]ClientLogEntry, 0, 200),
		maxSize: 200,
		kvURL:   os.Getenv("KV_REST_API_URL"),
		kvToken: os.Getenv("KV_REST_API_TOKEN"),
	}
}

// SaveRecord stores client ping data in memory ring-buffer and asynchronously to Vercel KV if configured
func (s *StorageEngine) SaveRecord(resp *models.PingResponse) (string, bool) {
	now := time.Now().UTC()
	sigSnippet := "req"
	if len(resp.HeaderDetails.Signature) >= 12 {
		sigSnippet = resp.HeaderDetails.Signature[:12]
	}
	logID := fmt.Sprintf("log_%d_%s", now.UnixNano()/int64(time.Millisecond), sigSnippet)

	ja4 := ""
	if resp.Headers != nil {
		ja4 = resp.Headers["x-vercel-ja4-digest"]
	}

	entry := ClientLogEntry{
		ID:          logID,
		Timestamp:   now,
		UnixMs:      now.UnixNano() / int64(time.Millisecond),
		ClientIP:    resp.Client.IP,
		Port:        resp.Client.Port,
		Geo:         resp.Geo,
		Network:     resp.Network,
		UserAgent:   resp.UserAgent,
		Security:    resp.Security,
		Headers:     resp.Headers,
		JA4Digest:   ja4,
		QueryParams: resp.HTTP.QueryParams,
	}

	s.mu.Lock()
	if len(s.logs) >= s.maxSize {
		s.logs = s.logs[1:]
	}
	s.logs = append(s.logs, entry)
	s.mu.Unlock()

	if s.kvURL != "" && s.kvToken != "" {
		go s.saveToVercelKV(logID, entry)
	}

	return logID, true
}

func (s *StorageEngine) GetLogs(limit int) []ClientLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.logs)
	if total == 0 {
		return []ClientLogEntry{}
	}

	if limit <= 0 || limit > total {
		limit = total
	}

	result := make([]ClientLogEntry, limit)
	for i := 0; i < limit; i++ {
		result[i] = s.logs[total-1-i]
	}
	return result
}

func (s *StorageEngine) ClearLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = make([]ClientLogEntry, 0, s.maxSize)
}

func (s *StorageEngine) saveToVercelKV(id string, entry ClientLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/set/%s", s.kvURL, id)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.kvToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

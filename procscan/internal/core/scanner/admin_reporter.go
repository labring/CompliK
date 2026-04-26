package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

const (
	defaultAdminBaseURL = "http://sealos-complik-admin:8080"
	defaultAdminTimeout = 10 * time.Second
	adminViolationsPath = "/api/procscan-violations"
)

type procscanViolationRequest struct {
	Namespace      string    `json:"namespace"`
	PodName        string    `json:"pod_name,omitempty"`
	ContainerID    string    `json:"container_id,omitempty"`
	NodeName       string    `json:"node_name,omitempty"`
	PID            int       `json:"pid"`
	ProcessName    string    `json:"process_name"`
	ProcessCommand string    `json:"process_command"`
	MatchType      string    `json:"match_type,omitempty"`
	MatchRule      string    `json:"match_rule,omitempty"`
	Message        string    `json:"message"`
	IsIllegal      bool      `json:"is_illegal"`
	DetectedAt     time.Time `json:"detected_at"`
	RawPayload     any       `json:"raw_payload,omitempty"`
}

func (s *Scanner) reportProcscanViolations(processInfos []*models.ProcessInfo) {
	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}
		if err := s.reportProcscanViolation(processInfo); err != nil {
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
				"error":     err.Error(),
			}).Error("Failed to report procscan violation to admin")
		}
	}
}

func (s *Scanner) reportProcscanViolation(processInfo *models.ProcessInfo) error {
	if strings.TrimSpace(processInfo.Namespace) == "" {
		return fmt.Errorf("namespace is required")
	}

	matchType, matchRule := parseMatchDetails(processInfo.Message)
	detectedAt, err := time.Parse(time.RFC3339, processInfo.Timestamp)
	if err != nil {
		detectedAt = time.Now().UTC()
	}

	payload := procscanViolationRequest{
		Namespace:      processInfo.Namespace,
		PodName:        processInfo.PodName,
		ContainerID:    processInfo.ContainerID,
		NodeName:       currentNodeName(),
		PID:            processInfo.PID,
		ProcessName:    processInfo.ProcessName,
		ProcessCommand: processInfo.Command,
		MatchType:      matchType,
		MatchRule:      matchRule,
		Message:        processInfo.Message,
		IsIllegal:      processInfo.IsIllegal,
		DetectedAt:     detectedAt,
		RawPayload: map[string]any{
			"process_info":  processInfo,
			"reported_from": "procscan",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.adminTimeout())
	defer cancel()

	return postJSON(ctx, s.adminEndpoint(), payload)
}

func (s *Scanner) adminEndpoint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	baseURL := strings.TrimSpace(s.config.Notifications.Admin.BaseURL)
	if baseURL == "" {
		baseURL = defaultAdminBaseURL
	}
	return strings.TrimRight(baseURL, "/") + adminViolationsPath
}

func (s *Scanner) adminTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config.Notifications.Admin.Timeout > 0 {
		return s.config.Notifications.Admin.Timeout
	}
	return defaultAdminTimeout
}

func postJSON(ctx context.Context, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func parseMatchDetails(message string) (string, string) {
	message = strings.TrimSpace(message)
	if strings.HasPrefix(message, "Process name '") && strings.Contains(message, "' matched blacklist rule '") {
		parts := strings.SplitN(strings.TrimPrefix(message, "Process name '"), "' matched blacklist rule '", 2)
		if len(parts) == 2 {
			return "process_name", strings.TrimSuffix(parts[1], "'")
		}
	}
	if strings.HasPrefix(message, "Command line matched keyword blacklist rule '") {
		return "command_keyword", strings.TrimSuffix(strings.TrimPrefix(message, "Command line matched keyword blacklist rule '"), "'")
	}
	return "", ""
}

func currentNodeName() string {
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		return "unknown"
	}
	return nodeName
}

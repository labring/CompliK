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
	defaultAdminBaseURL    = "http://sealos-complik-admin:8080"
	defaultAdminTimeout    = 10 * time.Second
	procscanViolationsPath = "/api/procscan-violations"
)

type procscanViolationRequest struct {
	Namespace         string    `json:"namespace"`
	PodName           string    `json:"pod_name,omitempty"`
	ContainerID       string    `json:"container_id,omitempty"`
	NodeName          string    `json:"node_name,omitempty"`
	PID               int       `json:"pid"`
	ProcessName       string    `json:"process_name"`
	ProcessCommand    string    `json:"process_command"`
	MatchType         string    `json:"match_type,omitempty"`
	MatchRule         string    `json:"match_rule,omitempty"`
	Message           string    `json:"message"`
	LabelActionStatus string    `json:"label_action_status,omitempty"`
	LabelActionResult string    `json:"label_action_result,omitempty"`
	Status            string    `json:"status"`
	DetectedAt        time.Time `json:"detected_at"`
	RawPayload        any       `json:"raw_payload,omitempty"`
}

func (s *Scanner) reportProcscanViolations(processInfos []*models.ProcessInfo, labelResult string) {
	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}

		if err := s.reportProcscanViolation(processInfo, labelResult); err != nil {
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
				"error":     err.Error(),
			}).Error("Failed to report procscan violation to admin")
		}
	}
}

func (s *Scanner) reportProcscanViolation(processInfo *models.ProcessInfo, labelResult string) error {
	if processInfo == nil {
		return fmt.Errorf("process info is nil")
	}
	if strings.TrimSpace(processInfo.Namespace) == "" {
		return fmt.Errorf("namespace is required for admin reporting")
	}

	matchType, matchRule := parseMatchDetails(processInfo.Message)
	detectedAt, err := parseDetectedAt(processInfo.Timestamp)
	if err != nil {
		detectedAt = time.Now().UTC()
	}

	payload := procscanViolationRequest{
		Namespace:         processInfo.Namespace,
		PodName:           processInfo.PodName,
		ContainerID:       processInfo.ContainerID,
		NodeName:          currentNodeName(),
		PID:               processInfo.PID,
		ProcessName:       processInfo.ProcessName,
		ProcessCommand:    processInfo.Command,
		MatchType:         matchType,
		MatchRule:         matchRule,
		Message:           processInfo.Message,
		LabelActionStatus: normalizeLabelActionStatus(labelResult),
		LabelActionResult: labelResult,
		Status:            "open",
		DetectedAt:        detectedAt,
		RawPayload: map[string]any{
			"process_info":  processInfo,
			"label_result":  labelResult,
			"reported_from": "procscan",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.adminTimeout())
	defer cancel()

	return s.postJSON(ctx, s.adminEndpoint(), payload)
}

func (s *Scanner) adminEndpoint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	baseURL := defaultAdminBaseURL
	if strings.TrimSpace(s.config.Notifications.Admin.BaseURL) != "" {
		baseURL = strings.TrimSpace(s.config.Notifications.Admin.BaseURL)
	}

	return strings.TrimRight(baseURL, "/") + procscanViolationsPath
}

func (s *Scanner) adminTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config.Notifications.Admin.Timeout > 0 {
		return s.config.Notifications.Admin.Timeout
	}

	return defaultAdminTimeout
}

func (s *Scanner) postJSON(ctx context.Context, endpoint string, payload any) error {
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
	if message == "" {
		return "", ""
	}

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

func parseDetectedAt(timestamp string) (time.Time, error) {
	if strings.TrimSpace(timestamp) == "" {
		return time.Time{}, fmt.Errorf("timestamp is empty")
	}

	return time.Parse(time.RFC3339, timestamp)
}

func normalizeLabelActionStatus(labelResult string) string {
	lower := strings.ToLower(strings.TrimSpace(labelResult))
	switch {
	case lower == "":
		return ""
	case strings.Contains(lower, "success"):
		return "success"
	case strings.Contains(lower, "disabled"):
		return "disabled"
	case strings.Contains(lower, "cannot execute") || strings.Contains(lower, "unavailable"):
		return "unavailable"
	case strings.Contains(lower, "failed") || strings.Contains(lower, "error"):
		return "failed"
	default:
		return lower
	}
}

func currentNodeName() string {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "unknown"
	}

	return nodeName
}

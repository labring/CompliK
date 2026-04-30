package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/adminauth"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

const (
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
	endpoint, ok := s.adminEndpoint()
	if !ok {
		legacy.L.Info("Admin reporting is disabled because notifications.admin.base_url is empty")
		return
	}

	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}
		if err := s.reportProcscanViolation(endpoint, processInfo); err != nil {
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
				"error":     err.Error(),
			}).Error("Failed to report procscan violation to admin")
		}
	}
}

func (s *Scanner) reportProcscanViolation(endpoint string, processInfo *models.ProcessInfo) error {
	if strings.TrimSpace(processInfo.Namespace) == "" {
		return fmt.Errorf("namespace is required")
	}

	matchType, matchRule := parseMatchDetails(processInfo.Message)
	detectedAt, err := time.Parse(time.RFC3339, processInfo.Timestamp)
	if err != nil {
		detectedAt = time.Now().UTC()
	}
	nodeName := currentNodeName()
	localizedMessage := localizeProcscanMessage(processInfo.Message, processInfo.ProcessName, matchType, matchRule)

	payload := procscanViolationRequest{
		Namespace:      processInfo.Namespace,
		PodName:        processInfo.PodName,
		ContainerID:    processInfo.ContainerID,
		NodeName:       nodeName,
		PID:            processInfo.PID,
		ProcessName:    processInfo.ProcessName,
		ProcessCommand: processInfo.Command,
		MatchType:      matchType,
		MatchRule:      matchRule,
		Message:        localizedMessage,
		IsIllegal:      processInfo.IsIllegal,
		DetectedAt:     detectedAt,
		RawPayload:     buildProcscanRawPayload(processInfo, nodeName, matchType, matchRule, localizedMessage, detectedAt),
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.adminTimeout())
	defer cancel()

	return postJSON(ctx, endpoint, payload, s.adminBasicAuth())
}

func (s *Scanner) adminEndpoint() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	baseURL := strings.TrimSpace(s.config.Notifications.Admin.BaseURL)
	if baseURL == "" {
		return "", false
	}
	return strings.TrimRight(baseURL, "/") + adminViolationsPath, true
}

func (s *Scanner) adminTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config.Notifications.Admin.Timeout > 0 {
		return s.config.Notifications.Admin.Timeout
	}
	return defaultAdminTimeout
}

func (s *Scanner) adminBasicAuth() adminauth.BasicAuth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return adminauth.FromValues(
		s.config.Notifications.Admin.BasicAuth.Username,
		s.config.Notifications.Admin.BasicAuth.Password,
	)
}

func postJSON(ctx context.Context, endpoint string, payload any, auth adminauth.BasicAuth) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.Apply(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		bodyText := strings.TrimSpace(string(responseBody))
		if bodyText != "" {
			return fmt.Errorf("unexpected status %s: %s", resp.Status, bodyText)
		}
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

func parseMatchDetails(message string) (string, string) {
	message = strings.TrimSpace(message)
	if strings.HasPrefix(message, "进程名 '") && strings.Contains(message, "' 命中黑名单规则 '") {
		parts := strings.SplitN(strings.TrimPrefix(message, "进程名 '"), "' 命中黑名单规则 '", 2)
		if len(parts) == 2 {
			return "process_name", strings.TrimSuffix(parts[1], "'")
		}
	}
	if strings.HasPrefix(message, "命令行命中关键词黑名单规则 '") {
		return "command_keyword", strings.TrimSuffix(strings.TrimPrefix(message, "命令行命中关键词黑名单规则 '"), "'")
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

func buildProcscanRawPayload(processInfo *models.ProcessInfo, nodeName string, matchType string, matchRule string, message string, detectedAt time.Time) map[string]any {
	return map[string]any{
		"进程信息": map[string]any{
			"进程ID":  processInfo.PID,
			"进程名称":  localizeUnknown(processInfo.ProcessName),
			"命令行":   localizeUnknown(processInfo.Command),
			"命中原因":  message,
			"Pod名称": localizeUnknown(processInfo.PodName),
			"命名空间":  localizeUnknown(processInfo.Namespace),
			"容器ID":  localizeUnknown(processInfo.ContainerID),
			"节点名称":  localizeUnknown(nodeName),
			"是否违规":  processInfo.IsIllegal,
			"检测时间":  detectedAt.Format(time.RFC3339),
			"匹配类型":  localizeMatchType(matchType),
			"匹配规则":  localizeUnknown(matchRule),
		},
		"上报来源": "procscan",
	}
}

func localizeProcscanMessage(message string, processName string, matchType string, matchRule string) string {
	message = strings.TrimSpace(message)
	switch matchType {
	case "process_name":
		name := localizeUnknown(processName)
		rule := localizeUnknown(matchRule)
		return fmt.Sprintf("进程名 '%s' 命中黑名单规则 '%s'", name, rule)
	case "command_keyword":
		return fmt.Sprintf("命令行命中关键词黑名单规则 '%s'", localizeUnknown(matchRule))
	default:
		return message
	}
}

func localizeMatchType(matchType string) string {
	switch matchType {
	case "process_name":
		return "进程名"
	case "command_keyword":
		return "命令行关键词"
	default:
		return "未知"
	}
}

func localizeUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") {
		return "未知"
	}
	return value
}

func currentNodeName() string {
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		return "unknown"
	}
	return nodeName
}

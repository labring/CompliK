package postages

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/models"
)

const (
	defaultAdminBaseURL   = "http://sealos-complik-admin:8080"
	defaultAdminTimeout   = 10 * time.Second
	complikViolationsPath = "/api/complik-violations"
)

type complikViolationRequest struct {
	Namespace     string    `json:"namespace"`
	Region        string    `json:"region,omitempty"`
	DiscoveryName string    `json:"discovery_name,omitempty"`
	CollectorName string    `json:"collector_name,omitempty"`
	DetectorName  string    `json:"detector_name"`
	ResourceName  string    `json:"resource_name,omitempty"`
	Host          string    `json:"host,omitempty"`
	URL           string    `json:"url,omitempty"`
	Path          []string  `json:"path,omitempty"`
	Keywords      []string  `json:"keywords,omitempty"`
	Description   string    `json:"description,omitempty"`
	Explanation   string    `json:"explanation,omitempty"`
	IsIllegal     bool      `json:"is_illegal"`
	IsTest        bool      `json:"is_test"`
	Status        string    `json:"status"`
	DetectedAt    time.Time `json:"detected_at"`
	RawPayload    any       `json:"raw_payload,omitempty"`
}

func (p *DatabasePlugin) reportViolation(result *models.DetectorInfo) error {
	if result == nil {
		return fmt.Errorf("detector result is nil")
	}
	if strings.TrimSpace(result.Namespace) == "" {
		return fmt.Errorf("namespace is required for admin reporting")
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.adminTimeout())
	defer cancel()

	requestBody := complikViolationRequest{
		Namespace:     result.Namespace,
		Region:        result.Region,
		DiscoveryName: result.DiscoveryName,
		CollectorName: result.CollectorName,
		DetectorName:  result.DetectorName,
		ResourceName:  result.Name,
		Host:          result.Host,
		URL:           result.URL,
		Path:          result.Path,
		Keywords:      result.Keywords,
		Description:   result.Description,
		Explanation:   result.Explanation,
		IsIllegal:     result.IsIllegal,
		IsTest:        isComplikTestEvent(result),
		Status:        "open",
		DetectedAt:    time.Now().UTC(),
		RawPayload:    result,
	}

	return postJSON(ctx, p.adminEndpoint(), requestBody)
}

func (p *DatabasePlugin) adminEndpoint() string {
	baseURL := strings.TrimSpace(p.databaseConfig.AdminBaseURL)
	if baseURL == "" {
		baseURL = defaultAdminBaseURL
	}

	return strings.TrimRight(baseURL, "/") + complikViolationsPath
}

func (p *DatabasePlugin) adminTimeout() time.Duration {
	if p.databaseConfig.AdminTimeoutSecond <= 0 {
		return defaultAdminTimeout
	}

	return time.Duration(p.databaseConfig.AdminTimeoutSecond) * time.Second
}

func isComplikTestEvent(result *models.DetectorInfo) bool {
	if result == nil {
		return false
	}
	if strings.EqualFold(result.Name, "Program started, Feishu notification test") {
		return true
	}
	for _, keyword := range result.Keywords {
		if keyword == "program_start" {
			return true
		}
	}

	return false
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

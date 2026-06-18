// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//nolint:wsl_v5 // VLog parsing handles several compact schema branches.
package vlogpath

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// VLogFields maps CompliK's expected values onto the field names present in a
// specific VLog deployment.
type VLogFields struct {
	Time                string `json:"time"`
	Host                string `json:"host"`
	Path                string `json:"path"`
	Method              string `json:"method"`
	StatusCode          string `json:"statusCode"`
	ResponseContentType string `json:"responseContentType"`
}

// DefaultVLogFields matches the log schema emitted by the default Higress VLog
// pipeline.
func DefaultVLogFields() VLogFields {
	return VLogFields{
		Time:                "_time",
		Host:                "host",
		Path:                "path",
		Method:              "method",
		StatusCode:          "status_code",
		ResponseContentType: "response_content_type",
	}
}

func mergeVLogFields(base, override VLogFields) VLogFields {
	// Apply only explicit field-name overrides so partial config keeps the
	// default schema for omitted values.
	if override.Time != "" {
		base.Time = override.Time
	}
	if override.Host != "" {
		base.Host = override.Host
	}
	if override.Path != "" {
		base.Path = override.Path
	}
	if override.Method != "" {
		base.Method = override.Method
	}
	if override.StatusCode != "" {
		base.StatusCode = override.StatusCode
	}
	if override.ResponseContentType != "" {
		base.ResponseContentType = override.ResponseContentType
	}

	return base
}

// VLogEntry is the normalized subset of an access-log row needed for path
// discovery.
type VLogEntry struct {
	Time                time.Time
	Host                string
	Path                string
	Method              string
	StatusCode          int
	ResponseContentType string
}

// VLogClientConfig contains connection details and query shaping options for
// a VLog server.
type VLogClientConfig struct {
	BaseURL             string
	Username            string
	Password            string
	App                 string
	Fields              VLogFields
	HTTPTimeout         time.Duration
	QueryLimitPerBucket int
	ExtraQueryFilters   map[string]any
}

// VLogClient queries VLog's LogSQL endpoint and normalizes the response into
// VLogEntry values.
type VLogClient struct {
	baseURL           string
	username          string
	password          string
	app               string
	fields            VLogFields
	extraQueryFilters map[string]any
	client            *http.Client
}

func NewVLogClient(config VLogClientConfig) *VLogClient {
	// Always keep an HTTP timeout to prevent one slow log query from stalling a
	// full discovery cycle.
	timeout := config.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &VLogClient{
		baseURL:           strings.TrimRight(config.BaseURL, "/"),
		username:          config.Username,
		password:          config.Password,
		app:               config.App,
		fields:            mergeVLogFields(DefaultVLogFields(), config.Fields),
		extraQueryFilters: config.ExtraQueryFilters,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *VLogClient) Query(
	ctx context.Context,
	host string,
	start time.Time,
	end time.Time,
	limit int,
) ([]VLogEntry, error) {
	// Query returns normalized entries only; filtering and ranking stay in the
	// plugin layer where Ingress seed context is available.
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("VLog base URL is empty")
	}

	if limit <= 0 {
		limit = 50
	}

	query := c.buildQuery(host, start, end, limit)
	reqURL := c.baseURL + "/select/logsql/query?query=" + url.QueryEscape(query)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create VLog query request: %w", err)
	}

	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send VLog query request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("VLog query returned HTTP %d", resp.StatusCode)
	}

	entries, err := c.parseResponse(resp.Body)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (c *VLogClient) buildQuery(host string, start, end time.Time, limit int) string {
	// Build LogSQL with strict host and time predicates first, then unpack JSON
	// log payloads for field extraction.
	var builder strings.Builder

	fmt.Fprintf(&builder, `%s:"%s" `, c.fields.Host, escapeLogQLValue(host))
	if c.app != "" {
		fmt.Fprintf(&builder, `app:="%s" `, escapeLogQLValue(c.app))
	}

	for key, value := range c.extraQueryFilters {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}

		fmt.Fprintf(&builder, `%s:="%s" `, key, escapeLogQLValue(fmt.Sprint(value)))
	}

	fmt.Fprintf(
		&builder,
		`_time:[%s,%s] `,
		start.UTC().Format(time.RFC3339),
		end.UTC().Format(time.RFC3339),
	)
	builder.WriteString(`| unpack_json `)
	builder.WriteString(`| Drop _stream_id,_stream,job,node `)
	fmt.Fprintf(&builder, `| limit %d`, limit)

	return builder.String()
}

func escapeLogQLValue(value string) string {
	// Escape values embedded inside quoted LogSQL string literals.
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func (c *VLogClient) parseResponse(reader io.Reader) ([]VLogEntry, error) {
	// VLog deployments may return a JSON envelope, a raw array, or JSON Lines;
	// support all three formats to keep the plugin portable.
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read VLog response: %w", err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return []VLogEntry{}, nil
	}

	var raw any
	if err := json.Unmarshal(data, &raw); err == nil {
		if rows := findRows(raw); len(rows) > 0 {
			return c.parseRows(rows), nil
		}
	}

	return c.parseJSONLines(data), nil
}

func findRows(raw any) []map[string]any {
	// Walk common envelope keys until a slice of row objects is found.
	switch value := raw.(type) {
	case []any:
		rows := make([]map[string]any, 0, len(value))
		for _, item := range value {
			if row, ok := item.(map[string]any); ok {
				rows = append(rows, row)
			}
		}
		return rows
	case map[string]any:
		for _, key := range []string{"data", "values", "result", "hits", "logs"} {
			if rows := findRows(value[key]); len(rows) > 0 {
				return rows
			}
		}
	}

	return nil
}

func (c *VLogClient) parseJSONLines(data []byte) []VLogEntry {
	// Some log APIs stream one JSON object per line, so malformed lines are
	// skipped while valid rows still contribute candidates.
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	rows := make([]map[string]any, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}

		rows = append(rows, row)
	}

	return c.parseRows(rows)
}

func (c *VLogClient) parseRows(rows []map[string]any) []VLogEntry {
	// Use configured field names first and then known aliases from common proxy
	// access-log schemas.
	entries := make([]VLogEntry, 0, len(rows))
	for _, row := range rows {
		entry := VLogEntry{
			Time: readTime(row, c.fields.Time),
			Host: readString(row, c.fields.Host),
			Path: readFirstString(
				row,
				c.fields.Path,
				"request_path",
				"uri",
				"request_uri",
				"url_path",
			),
			Method: strings.ToUpper(
				readFirstString(row, c.fields.Method, "request_method", "http_method"),
			),
			StatusCode: readInt(
				row,
				c.fields.StatusCode,
				"status",
				"statusCode",
				"response_code",
			),
			ResponseContentType: readFirstString(
				row,
				c.fields.ResponseContentType,
				"content_type",
				"responseContentType",
				"resp_content_type",
			),
		}

		if entry.Path == "" {
			continue
		}

		entries = append(entries, entry)
	}

	return entries
}

func readFirstString(row map[string]any, keys ...string) string {
	// Return the first populated value across a field name and its aliases.
	for _, key := range keys {
		value := readString(row, key)
		if value != "" {
			return value
		}
	}

	return ""
}

func readString(row map[string]any, key string) string {
	// Convert scalar JSON values into strings because log backends often vary
	// field types between numeric and textual representations.
	if strings.TrimSpace(key) == "" {
		return ""
	}

	value, exists := row[key]
	if !exists {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func readInt(row map[string]any, keys ...string) int {
	// Treat an unreadable status as zero so callers can decide how strict their
	// filtering should be.
	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			continue
		}

		value, exists := row[key]
		if !exists {
			continue
		}

		switch typed := value.(type) {
		case int:
			return typed
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return int(parsed)
			}
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(typed))
			if err == nil {
				return parsed
			}
		}
	}

	return 0
}

func readTime(row map[string]any, key string) time.Time {
	// Accept common timestamp layouts and Unix seconds/milliseconds from log
	// backends; fall back to now so ranking can still proceed.
	value := readString(row, key)
	if value == "" {
		return time.Now()
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.DateTime,
		"2006-01-02T15:04:05.000Z",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed
		}
	}

	if unixSeconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if unixSeconds > 1_000_000_000_000 {
			return time.UnixMilli(unixSeconds)
		}

		return time.Unix(unixSeconds, 0)
	}

	return time.Now()
}

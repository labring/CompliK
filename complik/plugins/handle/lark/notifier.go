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

// Package lark implements notification functionality for Lark (Feishu) messaging.
// This file contains the notifier implementation that sends formatted messages
// to Lark webhooks with rich card formatting.
//
//nolint:wsl_v5 // Card construction keeps related branches compact.
package lark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/models"
)

type Notifier struct {
	WebhookURL string
	HTTPClient *http.Client
	Region     string
}

func NewNotifier(webhookURL string, region string) *Notifier {
	return &Notifier{
		WebhookURL: webhookURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Region: region,
	}
}

func (f *Notifier) SendAnalysisNotification(results *models.DetectorInfo) error {
	if f.WebhookURL == "" {
		fmt.Println("Webhook URL not configured, skipping notification")
		return errors.New("webhook URL not configured, skipping notification")
	}

	if results == nil {
		fmt.Println("Analysis result is empty")
		return errors.New("analysis result is empty")
	}

	if !results.IsIllegal {
		return nil
	}

	message := LarkMessage{
		MsgType: "interactive",
		Card:    f.buildAlertMessage(results),
	}

	return f.sendMessage(message)
}

func (f *Notifier) buildAlertMessage(results *models.DetectorInfo) map[string]any {
	basicInfoElements := []map[string]any{
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**地域:** " + results.Region,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**资源名称:** " + results.Name,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**命名空间:** " + results.Namespace,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**主机地址:** " + results.Host,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**完整 URL:** " + results.URL,
				"tag":     "lark_md",
			},
		},
	}

	if len(results.Path) > 0 {
		var pathContent strings.Builder
		pathContent.WriteString("**检测路径:**\n")
		for i, path := range results.Path {
			if i < 5 {
				fmt.Fprintf(&pathContent, "  • %s\n", path)
			} else if i == 5 {
				fmt.Fprintf(&pathContent, "  • 另有 %d 条路径\n", len(results.Path)-5)
				break
			}
		}

		basicInfoElements = append(basicInfoElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": pathContent.String(),
				"tag":     "lark_md",
			},
		})
	}

	basicInfoElements = append(basicInfoElements, map[string]any{
		"tag": "hr",
	})
	elements := basicInfoElements
	if results.IsIllegal {
		elements = append(elements, map[string]any{
			"tag": "hr",
		})

		violationElements := []map[string]any{
			{
				"tag": "div",
				"text": map[string]any{
					"content": "**违规详情**",
					"tag":     "lark_md",
				},
			},
		}

		if results.Description != "" {
			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**描述:** " + results.Description,
					"tag":     "lark_md",
				},
			})
		}

		if len(results.Keywords) > 0 {
			var keywordContent strings.Builder
			keywordContent.WriteString("**命中关键词:** ")
			for i, keyword := range results.Keywords {
				if i > 0 {
					keywordContent.WriteString(", ")
				}

				fmt.Fprintf(&keywordContent, "`%s`", keyword)
			}

			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": keywordContent.String(),
					"tag":     "lark_md",
				},
			})
		}

		if results.Explanation != "" {
			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**违规依据:** " + results.Explanation,
					"tag":     "lark_md",
				},
			})
		}

		elements = append(elements, violationElements...)
	}

	// Timestamp and action reminder
	elements = append(elements,
		map[string]any{
			"tag": "hr",
		},
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**检测时间:** " + time.Now().Format(time.DateTime),
				"tag":     "lark_md",
			},
		},
	)

	// Display different reminder based on violation status
	if results.IsIllegal {
		elements = append(elements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**请及时处理违规内容！**",
				"tag":     "lark_md",
			},
		})
	}

	template := "green"

	title := "网站内容检测通知"
	if results.IsIllegal {
		template = "red"
		title = "网站内容违规告警"
	}

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"template": template,
			"title": map[string]any{
				"content": title,
				"tag":     "plain_text",
			},
		},
		"elements": elements,
	}
}

func (f *Notifier) sendMessage(message LarkMessage) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.WebhookURL,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var larkResp LarkResponse
	if err := json.Unmarshal(body, &larkResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || larkResp.Code != 0 {
		return fmt.Errorf(
			"lark webhook notification failed: HTTP status %d, Lark error code %d, error message: %s",
			resp.StatusCode,
			larkResp.Code,
			larkResp.Msg,
		)
	}

	return nil
}

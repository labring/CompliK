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

// Package alert provides functionality for sending security alerts and notifications
// to external systems such as Lark (Feishu) messaging platform.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

// LarkMessage defines the card message structure sent to Lark
type LarkMessage struct {
	MsgType string         `json:"msg_type"`
	Card    map[string]any `json:"card"`
}

// NamespaceScanResult encapsulates all scan findings and operation results for a namespace
type NamespaceScanResult struct {
	Namespace    string
	ProcessInfos []*models.ProcessInfo
	LabelResult  string
}

// SendGlobalBatchAlert constructs and sends aggregated alert using Markdown format
func SendGlobalBatchAlert(results []*NamespaceScanResult, webhookURL string, region string) error {
	if webhookURL == "" {
		return fmt.Errorf("webhook URL cannot be empty")
	}
	if len(results) == 0 {
		return nil // No issues found, skip alert
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "Unknown Node"
	}

	totalProcesses := 0
	for _, r := range results {
		totalProcesses += len(r.ProcessInfos)
	}

	allElements := []map[string]any{
		newMarkdownElement(formatSummarySection(region, nodeName, totalProcesses, len(results))),
		newHrElement(),
	}

	for idx, r := range results {
		if idx > 0 {
			allElements = append(allElements, newHrElement())
		}

		allElements = append(allElements, newMarkdownElement(formatNamespaceSection(idx+1, r)))

		for processIdx, p := range r.ProcessInfos {
			allElements = append(allElements, newMarkdownElement(formatProcessSection(processIdx+1, p)))
		}
	}

	cardContent := map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"template": "red",
			"title": map[string]any{
				"content": "ProcScan 可疑进程告警",
				"tag":     "plain_text",
			},
		},
		"elements": allElements,
	}

	// Send request
	message := LarkMessage{
		MsgType: "interactive",
		Card:    cardContent,
	}
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Lark notification failed: HTTP status code %d", resp.StatusCode)
	}

	legacy.L.Info("Global Lark alert sent successfully")
	return nil
}

// newMarkdownElement creates a standard Lark card Markdown element
func newMarkdownElement(content string) map[string]any {
	return map[string]any{
		"tag": "div",
		"text": map[string]any{
			"content": content,
			"tag":     "lark_md",
		},
	}
}

// newHrElement creates a horizontal line element
func newHrElement() map[string]any {
	return map[string]any{
		"tag": "hr",
	}
}

func formatSummarySection(region, nodeName string, totalProcesses, namespaceCount int) string {
	lines := []string{
		"**告警总览**",
		fmt.Sprintf("可用区：%s", quoteValue(displayValue(region, "未配置"))),
		fmt.Sprintf("节点名称：%s", quoteValue(displayValue(nodeName, "未知"))),
		fmt.Sprintf("告警时间：%s", quoteValue(time.Now().Format(time.RFC3339))),
		fmt.Sprintf("异常进程总数：`%d`", totalProcesses),
		fmt.Sprintf("受影响命名空间数：`%d`", namespaceCount),
	}
	return strings.Join(lines, "\n")
}

func formatNamespaceSection(index int, result *NamespaceScanResult) string {
	namespace := displayValue(result.Namespace, "未知")

	lines := []string{
		fmt.Sprintf("**命名空间分组 %d**", index),
		fmt.Sprintf("命名空间：%s", quoteValue(namespace)),
		fmt.Sprintf("异常进程数量：`%d`", len(result.ProcessInfos)),
	}

	return strings.Join(lines, "\n")
}

func formatProcessSection(index int, info *models.ProcessInfo) string {
	lines := []string{
		fmt.Sprintf("**异常进程 %d**", index),
		fmt.Sprintf("发现时间：%s", quoteValue(displayValue(info.Timestamp, "未知"))),
		fmt.Sprintf("命名空间：%s", quoteValue(displayValue(info.Namespace, "未知"))),
		fmt.Sprintf("Pod 名称：%s", quoteValue(displayValue(info.PodName, "未知"))),
		fmt.Sprintf("容器 ID：%s", quoteValue(displayValue(info.ContainerID, "未知"))),
		fmt.Sprintf("进程 PID：`%d`", info.PID),
		fmt.Sprintf("进程名称：%s", quoteValue(displayValue(info.ProcessName, "未知"))),
		fmt.Sprintf("进程命令行：%s", quoteValue(displayValue(info.Command, "未知"))),
		"命中原因：",
		translateReason(info.Message),
		fmt.Sprintf("原始匹配信息：%s", quoteValue(displayValue(info.Message, "未返回"))),
	}

	return strings.Join(lines, "\n")
}

// getStatusText converts label result to user-friendly status text
func getStatusText(labelResult string) string {
	lower := strings.ToLower(strings.TrimSpace(labelResult))
	if lower == "" {
		return "未返回处置结果"
	}
	if strings.Contains(lower, "disabled") || strings.Contains(lower, "feature disabled") {
		return "未开启自动处置"
	}
	if strings.Contains(lower, "success") {
		return "已成功添加安全标签"
	}
	if strings.Contains(lower, "cannot execute") || strings.Contains(lower, "unavailable") {
		return "未执行自动处置"
	}
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
		return "自动处置失败"
	}
	return "状态待确认"
}

func buildLabelAnalysis(namespace, labelResult string) []string {
	lower := strings.ToLower(strings.TrimSpace(labelResult))
	analyses := make([]string, 0, 3)

	switch {
	case lower == "":
		analyses = append(analyses, "当前未返回命名空间处置状态，可能未开启自动处置，或本轮仅完成了告警发送。")
	case strings.Contains(lower, "disabled"):
		analyses = append(analyses, "自动打标功能当前未开启，本轮只会发送告警，不会对命名空间执行自动处置。")
	case strings.Contains(lower, "success"):
		analyses = append(analyses, "命名空间标签已经写入成功，请继续核查下游控制器是否按预期执行隔离、封禁或其他处置动作。")
	case strings.Contains(lower, "cannot execute") || strings.Contains(lower, "unavailable"):
		analyses = append(analyses, "自动处置未执行，可能是 Kubernetes 客户端未初始化、集群内凭据不可用，或当前环境不具备访问 API Server 的能力。")
	case strings.Contains(lower, "failed") || strings.Contains(lower, "error"):
		analyses = append(analyses, "命名空间打标失败，常见原因包括 RBAC 权限不足、目标命名空间不存在、API Server 不可达，或标签键值不合法。")
	default:
		analyses = append(analyses, "命名空间处置状态无法直接识别，请结合服务日志中的原始返回详情继续排查。")
	}

	if isUnknownValue(namespace) {
		analyses = append(analyses, "当前命名空间信息缺失或为未知，自动处置可能无法命中真实资源，请优先检查容器元数据解析链路。")
	}

	return analyses
}

func buildProcessAnalysis(info *models.ProcessInfo) []string {
	analyses := make([]string, 0, 3)
	message := strings.ToLower(strings.TrimSpace(info.Message))

	if strings.Contains(message, "process name") {
		analyses = append(analyses, "当前通过进程名命中黑名单规则，可能是已知恶意程序，也可能是调试、巡检或运维命令导致的误报，建议结合镜像来源和启动者继续核查。")
	}
	if strings.Contains(message, "command line") || strings.Contains(message, "keyword") {
		analyses = append(analyses, "当前通过命令行关键字命中规则，可能涉及挖矿、反弹 Shell、扫描探测等行为，也可能是测试命令或安全演练触发。")
	}

	if isUnknownValue(info.Namespace) || isUnknownValue(info.PodName) || isUnknownValue(info.ContainerID) {
		analyses = append(analyses, "容器元数据未完整获取，可能是容器已退出、容器运行时接口暂时不可用、当前进程属于宿主机，或该进程并非 Kubernetes 托管工作负载。")
	}

	if len(analyses) == 0 {
		analyses = append(analyses, "已获取到可疑进程的基础信息，建议结合进程树、镜像版本、集群审计日志和最近变更记录继续确认是否为真实威胁。")
	}

	return analyses
}

func translateReason(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "未返回命中原因"
	}

	if strings.HasPrefix(message, "Process name '") && strings.Contains(message, "' matched blacklist rule '") {
		parts := strings.SplitN(strings.TrimPrefix(message, "Process name '"), "' matched blacklist rule '", 2)
		if len(parts) == 2 {
			processName := parts[0]
			rule := strings.TrimSuffix(parts[1], "'")
			return fmt.Sprintf("进程名 %s 命中黑名单规则 %s", quoteValue(processName), quoteValue(rule))
		}
	}

	if strings.HasPrefix(message, "Command line matched keyword blacklist rule '") {
		rule := strings.TrimSuffix(strings.TrimPrefix(message, "Command line matched keyword blacklist rule '"), "'")
		return fmt.Sprintf("进程命令行命中关键字黑名单规则 %s", quoteValue(rule))
	}

	return quoteValue(message)
}

func quoteValue(value string) string {
	return fmt.Sprintf("`%s`", sanitizeValue(value))
}

func displayValue(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	if isUnknownValue(trimmed) {
		return fallback
	}
	return trimmed
}

func isUnknownValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "" || normalized == "unknown" || normalized == "unknown node"
}

func sanitizeValue(value string) string {
	replacer := strings.NewReplacer(
		"`", "'",
		"\n", " ",
		"\r", " ",
	)
	return replacer.Replace(strings.TrimSpace(value))
}

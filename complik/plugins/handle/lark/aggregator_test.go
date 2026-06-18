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

//nolint:testpackage,wsl_v5 // Tests exercise unexported aggregation helpers.
package lark

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
)

func TestMergeDetectorInfoAggregatesSitePaths(t *testing.T) {
	alert := AggregatedAlert{
		Namespace: "ns-demo",
		Host:      "example.com",
		Paths:     map[string]*AggregatedPath{},
	}
	now := time.Date(2026, time.June, 16, 14, 3, 0, 0, time.Local)

	mergeDetectorInfo(&alert, &models.DetectorInfo{
		DetectorName:  "Safety",
		Name:          "demo-ingress",
		Namespace:     "ns-demo",
		Host:          "example.com",
		Path:          []string{"/activity/a"},
		URL:           "http://example.com/activity/a",
		DeviceProfile: "desktop",
		Description:   "活动页面包含博彩充值入口",
		Keywords:      []string{"xxx"},
		IsIllegal:     true,
		Explanation:   "页面出现投注与充值提现相关文案",
	}, now, 50)
	mergeDetectorInfo(&alert, &models.DetectorInfo{
		DetectorName:  "Custom",
		Name:          "demo-ingress",
		Namespace:     "ns-demo",
		Host:          "example.com",
		Path:          []string{"/activity/a", "/admin/promo"},
		URL:           "http://example.com/activity/a",
		DeviceProfile: "mobile",
		Description:   "页面包含推广活动入口",
		Keywords:      []string{"xxx", "yyy"},
		IsIllegal:     true,
		Explanation:   "命中自定义博彩关键词规则",
	}, now.Add(time.Minute), 50)

	paths := alert.SortedPaths()
	if len(paths) != 2 {
		t.Fatalf("path count = %d, want 2", len(paths))
	}
	if paths[0].Path != "/activity/a" {
		t.Fatalf("first path = %q, want /activity/a", paths[0].Path)
	}
	if got := strings.Join(paths[0].Detectors, ","); got != "Custom,Safety" {
		t.Fatalf("detectors = %q, want Custom,Safety", got)
	}
	if got := strings.Join(paths[0].Devices, ","); got != "desktop,mobile" {
		t.Fatalf("devices = %q, want desktop,mobile", got)
	}
	if got := strings.Join(paths[0].Keywords, ","); got != "xxx,yyy" {
		t.Fatalf("keywords = %q, want xxx,yyy", got)
	}
	if got := strings.Join(paths[0].Descriptions, ","); got != "活动页面包含博彩充值入口,页面包含推广活动入口" {
		t.Fatalf("descriptions = %q, want merged descriptions", got)
	}
	if got := strings.Join(paths[0].Explanations, ","); got != "命中自定义博彩关键词规则,页面出现投注与充值提现相关文案" {
		t.Fatalf("explanations = %q, want merged explanations", got)
	}
	if paths[1].Path != "/admin/promo" {
		t.Fatalf("second path = %q, want /admin/promo", paths[1].Path)
	}
}

func TestNotificationAggregatorSendsOneAggregatedMessage(t *testing.T) {
	var (
		mu       sync.Mutex
		messages []LarkMessage
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message LarkMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Errorf("decode message: %v", err)
		}

		mu.Lock()
		messages = append(messages, message)
		mu.Unlock()

		_, _ = w.Write([]byte(`{"code":0,"msg":"ok"}`))
	}))
	defer server.Close()

	logger.Init()
	notifier := NewNotifier(server.URL, "53")
	aggregator := NewNotificationAggregator(
		20*time.Millisecond,
		1000,
		50,
		notifier,
		logger.GetLogger(),
	)

	aggregator.Add(&models.DetectorInfo{
		DetectorName:  "Safety",
		Name:          "demo-ingress",
		Namespace:     "ns-demo",
		Region:        "53",
		Host:          "example.com",
		Path:          []string{"/yellow"},
		URL:           "http://example.com/yellow",
		DeviceProfile: "desktop",
		Description:   "黄色内容落地页",
		Keywords:      []string{"adult"},
		IsIllegal:     true,
		Explanation:   "页面包含成人内容导流信息",
	})
	aggregator.Add(&models.DetectorInfo{
		DetectorName:  "Safety",
		Name:          "demo-ingress",
		Namespace:     "ns-demo",
		Region:        "53",
		Host:          "example.com",
		Path:          []string{"/gambling"},
		URL:           "http://example.com/gambling",
		DeviceProfile: "mobile",
		Description:   "博彩活动落地页",
		Keywords:      []string{"casino"},
		IsIllegal:     true,
		Explanation:   "页面含赌场和下注相关文案",
	})

	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messages))
	}

	data, err := json.Marshal(messages[0])
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	body := string(data)
	for _, want := range []string{"/yellow", "/gambling", "adult", "casino", "黄色内容落地页", "博彩活动落地页", "页面包含成人内容导流信息", "页面含赌场和下注相关文案", "发现违规路径:** 2 个"} {
		if !strings.Contains(body, want) {
			t.Fatalf("message body missing %q: %s", want, body)
		}
	}
}

func TestAggregatorLimitsPathsPerBucket(t *testing.T) {
	alert := AggregatedAlert{
		Namespace: "ns-demo",
		Host:      "example.com",
		Paths:     map[string]*AggregatedPath{},
	}
	now := time.Date(2026, time.June, 16, 14, 3, 0, 0, time.Local)

	mergeDetectorInfo(&alert, &models.DetectorInfo{
		DetectorName: "Safety",
		Namespace:    "ns-demo",
		Host:         "example.com",
		Path:         []string{"/a", "/b", "/c"},
		URL:          "http://example.com/a",
		Keywords:     []string{"casino"},
		IsIllegal:    true,
	}, now, 2)

	if len(alert.Paths) != 2 {
		t.Fatalf("path count = %d, want 2", len(alert.Paths))
	}
	if alert.OmittedPathCount != 1 {
		t.Fatalf("omitted path count = %d, want 1", alert.OmittedPathCount)
	}
}

func TestAggregatedCardShowsOmittedPathCount(t *testing.T) {
	alert := AggregatedAlert{
		Region:           "53",
		Resource:         "complik-demo-ing",
		Namespace:        "ns-demo",
		Host:             "example.com",
		FirstSeenAt:      time.Date(2026, time.June, 17, 7, 52, 38, 0, time.Local),
		LastSeenAt:       time.Date(2026, time.June, 17, 7, 57, 38, 0, time.Local),
		OmittedPathCount: 3,
		Paths: map[string]*AggregatedPath{
			"/gambling": {
				Path:      "/gambling",
				URL:       "http://example.com/gambling",
				Detectors: map[string]struct{}{"Safety": {}},
				Keywords:  map[string]struct{}{"casino": {}},
			},
		},
	}

	card := NewNotifier("http://example.com/webhook", "53").buildAggregatedAlertMessage(alert)
	data, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}

	body := string(data)
	if !strings.Contains(body, "另有 3 条违规路径已省略") {
		t.Fatalf("card body missing omitted path count: %s", body)
	}
}

func TestAggregatedCardUsesOriginalMarkdownFormat(t *testing.T) {
	firstSeen := time.Date(2026, time.June, 17, 7, 52, 38, 0, time.Local)
	alert := AggregatedAlert{
		Region:      "53",
		Resource:    "complik-demo-ing",
		Namespace:   "ns-demo",
		Host:        "example.com",
		FirstSeenAt: firstSeen,
		LastSeenAt:  firstSeen.Add(5 * time.Minute),
		Paths: map[string]*AggregatedPath{
			"/yellow": {
				Path:         "/yellow",
				URL:          "http://example.com/yellow",
				Detectors:    map[string]struct{}{"Safety": {}},
				Devices:      map[string]struct{}{"desktop": {}, "mobile": {}},
				Keywords:     map[string]struct{}{"adult": {}, "VIP": {}},
				Descriptions: map[string]struct{}{"该页面包含成人内容推广信息": {}},
				Explanations: map[string]struct{}{"页面主文案出现成人服务、VIP 引流和联系方式": {}},
			},
			"/gambling": {
				Path:         "/gambling",
				URL:          "http://example.com/gambling",
				Detectors:    map[string]struct{}{"Safety": {}},
				Devices:      map[string]struct{}{"desktop": {}, "mobile": {}},
				Keywords:     map[string]struct{}{"casino": {}, "Baccarat": {}},
				Descriptions: map[string]struct{}{"该页面是博彩娱乐落地页": {}},
				Explanations: map[string]struct{}{"页面出现 casino、Baccarat 等博彩关键词": {}},
			},
		},
	}

	card := NewNotifier("http://example.com/webhook", "53").buildAggregatedAlertMessage(alert)
	data, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"**地域:** 53",
		"**违规站点:** https://example.com",
		"**命名空间:** ns-demo",
		"**资源:** complik-demo-ing",
		"**首次发现:** 2026-06-17 07:52:38",
		"**最近发现:** 2026-06-17 07:57:38",
		"**发现违规路径:** 2 个",
		"**1. /gambling**",
		"http://example.com/gambling",
		"检测器：Safety",
		"设备：desktop,mobile",
		"描述：该页面是博彩娱乐落地页",
		"命中关键词：Baccarat,casino",
		"违规依据：页面出现 casino、Baccarat 等博彩关键词",
		"**2. /yellow**",
		"http://example.com/yellow",
		"描述：该页面包含成人内容推广信息",
		"命中关键词：VIP,adult",
		"违规依据：页面主文案出现成人服务、VIP 引流和联系方式",
		"后台违规记录已实时写入",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("card body missing %q: %s", want, body)
		}
	}
}

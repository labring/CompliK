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

package main

import (
	"flag"
	"os"
	"runtime/debug"

	"github.com/bearslyricattack/CompliK/complik/internal/app"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/compliance/collector/browser"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/compliance/detector/custom"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/compliance/detector/safety"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/discovery/cronjob/complete"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/discovery/cronjob/devbox"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/discovery/informer/deployment"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/discovery/informer/endPointSlice"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/discovery/informer/statefulset"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/handle/admin/reporter"
	_ "github.com/bearslyricattack/CompliK/complik/plugins/handle/lark"
)

func main() {
	debug.SetTraceback("all")
	os.Setenv("GOTRACEBACK", "all")

	logger.Init()

	log := logger.GetLogger()

	configPath := flag.String("config", "", "path to configuration file")

	flag.Parse()

	log.Info("Starting CompliK", logger.Fields{
		"version": "1.0.0",
		"config":  *configPath,
	})

	if err := app.Run(*configPath); err != nil {
		log.Fatal("Application failed", logger.Fields{
			"error": err.Error(),
		})
	}
}

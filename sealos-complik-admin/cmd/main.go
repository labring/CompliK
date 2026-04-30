package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/migration"
	"sealos-complik-admin/internal/router"
)

const (
	defaultConfigFile  = "/config/config.yaml"
	fallbackConfigFile = "configs/config.yaml"
)

func resolveConfigFile() string {
	if value := strings.TrimSpace(os.Getenv("CONFIG_FILE")); value != "" {
		return value
	}

	if _, err := os.Stat(defaultConfigFile); err == nil {
		return defaultConfigFile
	}

	return fallbackConfigFile
}

func main() {
	cfg := config.LoadConfig(resolveConfigFile())

	if _, err := database.Init(cfg.Database); err != nil {
		log.Fatalf("initialize database: %v", err)
	}
	defer database.CloseWithReport(log.Printf)

	if err := migration.AutoMigrate(database.Get()); err != nil {
		log.Fatalf("auto migrate tables: %v", err)
	}

	srv, err := router.InitRouter(cfg)
	if err != nil {
		log.Fatalf("initialize router: %v", err)
	}
	addr := fmt.Sprintf(":%d", cfg.Port)

	log.Printf("server listening on %s", addr)
	if err := srv.Run(addr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}

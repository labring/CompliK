package router

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/k8s"
	"sealos-complik-admin/internal/middleware"
	"sealos-complik-admin/internal/modules/autoban"
	"sealos-complik-admin/internal/modules/ban"
	"sealos-complik-admin/internal/modules/commitment"
	"sealos-complik-admin/internal/modules/complikviolation"
	"sealos-complik-admin/internal/modules/discoveredpath"
	"sealos-complik-admin/internal/modules/procscanviolation"
	"sealos-complik-admin/internal/modules/projectconfig"
	"sealos-complik-admin/internal/modules/unban"
)

func InitRouter(cfg *config.Config) (*gin.Engine, error) {
	g := gin.Default()
	g.GET("/health", HealthCheck)

	if cfg.Auth.Enabled {
		if strings.TrimSpace(cfg.Auth.Username) == "" ||
			strings.TrimSpace(cfg.Auth.Password) == "" {
			return nil, errors.New("basic auth username and password are required")
		}

		g.Use(middleware.BasicAuth(cfg.Auth))
	}

	locker := buildNamespaceLocker()

	banService, err := ban.InitBanRoutes(g, cfg, locker)
	if err != nil {
		return nil, fmt.Errorf("init ban routes: %w", err)
	}

	autobanService := autoban.NewService(projectconfig.NewRepository(database.Get()), banService)

	complikviolation.InitRoutes(g, autobanService)
	discoveredpath.InitRoutes(g)

	if err := commitment.InitCommitmentRoutes(g, cfg); err != nil {
		return nil, fmt.Errorf("init commitment routes: %w", err)
	}

	projectconfig.InitProjectConfigRoutes(g)
	procscanviolation.InitRoutes(g, autobanService)

	if _, err := unban.InitUnbanRoutes(g, locker); err != nil {
		return nil, fmt.Errorf("init unban routes: %w", err)
	}

	return g, nil
}

func buildNamespaceLocker() k8s.NamespaceLocker {
	locker, err := k8s.NewNamespaceLocker()
	if err != nil {
		log.Printf("namespace locker disabled: %v", err)
		return k8s.NewNoopNamespaceLocker()
	}

	return locker
}

func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "All is well",
	})
}

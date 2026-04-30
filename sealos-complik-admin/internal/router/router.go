package router

import (
	"errors"
	"fmt"
	"strings"

	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/middleware"
	"sealos-complik-admin/internal/modules/ban"
	"sealos-complik-admin/internal/modules/commitment"
	"sealos-complik-admin/internal/modules/complikviolation"
	"sealos-complik-admin/internal/modules/procscanviolation"
	"sealos-complik-admin/internal/modules/projectconfig"
	"sealos-complik-admin/internal/modules/unban"

	"github.com/gin-gonic/gin"
)

func InitRouter(cfg *config.Config) (*gin.Engine, error) {
	g := gin.Default()
	g.GET("/health", HealthCheck)

	if cfg.Auth.Enabled {
		if strings.TrimSpace(cfg.Auth.Username) == "" || strings.TrimSpace(cfg.Auth.Password) == "" {
			return nil, errors.New("basic auth username and password are required")
		}
		g.Use(middleware.BasicAuth(cfg.Auth))
	}

	ban.InitBanRoutes(g, cfg)
	complikviolation.InitRoutes(g)
	if err := commitment.InitCommitmentRoutes(g, cfg); err != nil {
		return nil, fmt.Errorf("init commitment routes: %w", err)
	}
	projectconfig.InitProjectConfigRoutes(g)
	procscanviolation.InitRoutes(g)
	unban.InitUnbanRoutes(g)

	return g, nil
}

func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "All is well",
	})
}

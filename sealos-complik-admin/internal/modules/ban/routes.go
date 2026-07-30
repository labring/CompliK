package ban

import (
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/k8s"
	"sealos-complik-admin/internal/infra/oss"
)

// InitBanRoutes wires module dependencies and registers ban APIs.
func InitBanRoutes(
	g *gin.Engine,
	cfg *config.Config,
	locker k8s.NamespaceLocker,
) (*Service, error) {
	repository := NewRepository(database.Get())

	var uploader *oss.Client
	if cfg != nil {
		client, err := oss.NewClient(cfg.OSS)
		if err != nil {
			log.Printf("ban screenshot uploader disabled: %v", err)
		} else {
			uploader = client
		}
	}

	service := NewService(repository, uploader, buildBanObjectPrefix(cfg), locker)
	handler := NewHandler(service)

	g.POST("/api/bans/upload", handler.UploadBan)
	g.POST("/api/bans", handler.CreateOrUploadBan)
	g.GET("/api/bans/screenshots", handler.PreviewScreenshot)
	g.DELETE("/api/bans/id/:id", handler.DeleteBanByID)
	g.GET("/api/bans/:namespace", handler.GetBans)
	g.GET("/api/bans", handler.ListBans)
	g.GET("/api/namespaces/:namespace/ban-status", handler.GetBanStatus)

	return service, nil
}

func buildBanObjectPrefix(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}

	base := normalizeObjectPrefix(cfg.OSS.ObjectPrefix)
	if base == "" {
		return ""
	}

	return strings.Trim(base+"/bans", "/")
}

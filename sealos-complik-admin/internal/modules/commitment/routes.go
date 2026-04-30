package commitment

import (
	"log"
	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/oss"

	"github.com/gin-gonic/gin"
)

// InitCommitmentRoutes wires module dependencies and registers commitment APIs.
func InitCommitmentRoutes(g *gin.Engine, cfg *config.Config) error {
	repository := NewRepository(database.Get())
	uploader, err := oss.NewClient(cfg.OSS)
	if err != nil {
		log.Printf("commitment uploader disabled: %v", err)
	}
	service := NewService(repository, uploader, cfg.OSS.ObjectPrefix)
	handler := NewHandler(service)

	// Backward-compatible upload endpoint.
	g.POST("/api/commitments/upload", handler.UploadCommitment)
	// Support both JSON create and multipart upload on the same path.
	g.POST("/api/commitments", handler.CreateOrUploadCommitment)
	g.DELETE("/api/commitments/:namespace", handler.DeleteCommitment)
	g.PUT("/api/commitments/:namespace", handler.UpdateCommitment)
	g.GET("/api/commitments/:namespace", handler.GetCommitment)
	g.GET("/api/commitments/:namespace/download", handler.DownloadCommitment)
	g.GET("/api/commitments", handler.ListCommitments)

	return nil
}

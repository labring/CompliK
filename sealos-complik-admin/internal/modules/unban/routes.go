package unban

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/k8s"
)

// InitUnbanRoutes wires module dependencies and registers unban APIs.
func InitUnbanRoutes(g *gin.Engine, locker k8s.NamespaceLocker) (*Service, error) {
	repository := NewRepository(database.Get())
	service := NewService(repository, locker)
	handler := NewHandler(service)

	g.POST("/api/unbans", handler.CreateUnban)
	g.DELETE("/api/unbans/id/:id", handler.DeleteUnbanByID)
	g.GET("/api/unbans/:namespace", handler.GetUnbans)
	g.GET("/api/unbans", handler.ListUnbans)

	return service, nil
}

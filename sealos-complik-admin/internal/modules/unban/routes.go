package unban

import (
	"sealos-complik-admin/internal/infra/database"

	"github.com/gin-gonic/gin"
)

// InitUnbanRoutes wires module dependencies and registers unban APIs.
func InitUnbanRoutes(g *gin.Engine) {
	repository := NewRepository(database.Get())
	service := NewService(repository)
	handler := NewHandler(service)

	g.POST("/api/unbans", handler.CreateUnban)
	g.DELETE("/api/unbans/id/:id", handler.DeleteUnbanByID)
	g.GET("/api/unbans/:namespace", handler.GetUnbans)
	g.GET("/api/unbans", handler.ListUnbans)
}

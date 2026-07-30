package complikviolation

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/modules/autoban"
)

func InitRoutes(g *gin.Engine, autobanHandler autoban.Handler) {
	repository := NewRepository(database.Get())
	service := NewService(repository, autobanHandler)
	handler := NewHandler(service)

	g.POST("/api/complik-violations", handler.CreateViolation)
	g.DELETE("/api/complik-violations/id/:id", handler.DeleteViolationByID)
	g.DELETE("/api/complik-violations/:namespace", handler.DeleteViolations)
	g.GET("/api/complik-violations/:namespace", handler.GetViolations)
	g.GET("/api/complik-violations", handler.ListViolations)
	g.GET("/api/namespaces/:namespace/complik-violations-status", handler.GetViolationStatus)
}

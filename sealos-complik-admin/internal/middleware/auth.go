package middleware

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"sealos-complik-admin/internal/infra/config"

	"github.com/gin-gonic/gin"
)

func BasicAuth(cfg config.AuthConfig) gin.HandlerFunc {
	username := strings.TrimSpace(cfg.Username)
	password := strings.TrimSpace(cfg.Password)
	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = "CompliK Admin"
	}

	return func(c *gin.Context) {
		requestUsername, requestPassword, ok := c.Request.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(requestUsername), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(requestPassword), []byte(password)) != 1 {
			c.Header("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, realm))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		c.Next()
	}
}

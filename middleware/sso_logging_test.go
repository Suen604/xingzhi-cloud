package middleware

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/gin-gonic/gin"
)

type requestCaptureLogger struct {
	logging.Logger
	lines []string
}

func (l *requestCaptureLogger) Info(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (*requestCaptureLogger) SupportColor() bool { return false }

func TestSSOCallbackCredentialsAreNotLogged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := &requestCaptureLogger{}
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(Logging())
	router.GET("/api/v4/sso/qq/callback", func(c *gin.Context) { c.Status(204) })
	request := httptest.NewRequest("GET", "/api/v4/sso/qq/callback?code=secret-code&state=secret-state", nil)
	request = request.WithContext(context.WithValue(request.Context(), logging.LoggerCtx{}, logger))
	router.ServeHTTP(httptest.NewRecorder(), request)
	output := strings.Join(logger.lines, "\n")
	if !strings.Contains(output, "/api/v4/sso/qq/callback") || strings.Contains(output, "secret-code") || strings.Contains(output, "secret-state") {
		t.Fatalf("unexpected request log: %s", output)
	}
}

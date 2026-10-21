package extended

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestConfigurationPersistsNewRowAndMasksSecrets(t *testing.T) {
	root, db, _ := commerceContext(t)
	dep := dependency.NewDependency(dependency.WithDbClient(db), dependency.WithSettingClient(inventory.NewSettingClient(db, nil)))
	ctx := context.WithValue(root.Request.Context(), dependency.DepCtx{}, dep)
	request := func(method string, config *Config) (*gin.Context, *httptest.ResponseRecorder) {
		body := []byte(nil)
		if config != nil {
			var err error
			body, err = json.Marshal(config)
			require.NoError(t, err)
		}
		recorder := httptest.NewRecorder()
		c, engine := gin.CreateTestContext(recorder)
		engine.ContextWithFallback = true
		c.Request = httptest.NewRequest(method, "/admin/extensions/config", bytes.NewReader(body)).WithContext(ctx)
		c.Request.Header.Set("Content-Type", "application/json")
		AdminConfig(c)
		return c, recorder
	}
	config := &Config{Audit: true, QQ: sso.Provider{ClientID: "qq-app", ClientSecret: "qq-secret"}, Logto: sso.Provider{ClientID: "logto-app", ClientSecret: "logto-secret"}}
	c, recorder := request(http.MethodPut, config)
	var saved struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &saved))
	require.Zero(t, saved.Code)
	persisted, err := readConfig(c)
	require.NoError(t, err)
	require.Equal(t, "qq-secret", persisted.QQ.ClientSecret)
	_, recorder = request(http.MethodGet, nil)
	require.NotContains(t, recorder.Body.String(), "qq-secret")
	require.NotContains(t, recorder.Body.String(), "logto-secret")
	var masked struct {
		Data Config `json:"data"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &masked))
	require.Equal(t, hidden, masked.Data.QQ.ClientSecret)
	masked.Data.Audit = false
	c, _ = request(http.MethodPut, &masked.Data)
	persisted, err = readConfig(c)
	require.NoError(t, err)
	require.False(t, persisted.Audit)
	require.Equal(t, "qq-secret", persisted.QQ.ClientSecret)
	count, err := db.Setting.Query().Count(c)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

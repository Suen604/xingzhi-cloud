package extended

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/payment"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso"
	"github.com/gin-gonic/gin"
)

const configKey = "extensions_config"
const hidden = "********"

type Product struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Amount       int64  `json:"amount"`
	StorageBytes int64  `json:"storage_bytes"`
	GroupID      int    `json:"group_id"`
}

type Config struct {
	QQ       sso.Provider   `json:"qq"`
	Logto    sso.Provider   `json:"logto"`
	Alipay   payment.Config `json:"alipay"`
	WeChat   payment.Config `json:"wechat"`
	Products []Product      `json:"products"`
	Audit    bool           `json:"audit"`
}

var externalHTTP = &http.Client{Timeout: 20 * time.Second}

func readConfig(c *gin.Context) (*Config, error) {
	values, err := dependency.FromContext(c).SettingClient().Gets(c, []string{configKey})
	if err != nil {
		return nil, err
	}
	config := &Config{Audit: true}
	if values[configKey] != "" {
		if err := json.Unmarshal([]byte(values[configKey]), config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func response(c *gin.Context, data any, err error) {
	if err != nil {
		c.JSON(200, serializer.Err(c, serializer.NewError(serializer.CodeParamErr, err.Error(), nil)))
		return
	}
	c.JSON(200, serializer.Response{Data: data})
}

func AdminConfig(c *gin.Context) {
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	if c.Request.Method == http.MethodGet {
		for _, secret := range []*string{&config.QQ.ClientSecret, &config.Logto.ClientSecret, &config.Alipay.PrivateKey, &config.WeChat.PrivateKey, &config.WeChat.APIKey} {
			if *secret != "" {
				*secret = hidden
			}
		}
		response(c, config, nil)
		return
	}
	var next Config
	if err := c.ShouldBindJSON(&next); err != nil {
		response(c, nil, err)
		return
	}
	for _, pair := range [][2]*string{
		{&next.QQ.ClientSecret, &config.QQ.ClientSecret}, {&next.Logto.ClientSecret, &config.Logto.ClientSecret},
		{&next.Alipay.PrivateKey, &config.Alipay.PrivateKey}, {&next.WeChat.PrivateKey, &config.WeChat.PrivateKey}, {&next.WeChat.APIKey, &config.WeChat.APIKey},
	} {
		if *pair[0] == hidden {
			*pair[0] = *pair[1]
		}
	}
	if next.QQ.Enabled && (next.QQ.ClientID == "" || next.QQ.ClientSecret == "") {
		response(c, nil, errors.New("QQ application ID and key are required"))
		return
	}
	if next.Logto.Enabled && (next.Logto.ClientID == "" || next.Logto.ClientSecret == "" || next.Logto.Issuer == "") {
		response(c, nil, errors.New("Logto client ID, secret and issuer are required"))
		return
	}
	for name, provider := range map[string]payment.Config{"alipay": next.Alipay, "wechat": next.WeChat} {
		if provider.AppID != "" {
			if err := payment.ValidateConfig(name, provider); err != nil {
				response(c, nil, err)
				return
			}
		}
	}
	ids := map[string]bool{}
	for _, p := range next.Products {
		if p.ID == "" || p.Name == "" || p.Amount <= 0 || p.Amount > 100000000 || p.StorageBytes < 0 || p.GroupID < 0 ||
			(p.StorageBytes == 0 && p.GroupID == 0) || ids[p.ID] {
			response(c, nil, errors.New("invalid or duplicate product"))
			return
		}
		if p.GroupID > 0 {
			group, err := dependency.FromContext(c).GroupClient().GetByID(c, p.GroupID)
			if err != nil || group.ID <= 3 || group.Permissions == nil || group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
				response(c, nil, errors.New("products must use an ordinary non-administrator group"))
				return
			}
		}
		ids[p.ID] = true
	}
	data, err := json.Marshal(next)
	if err == nil {
		ctx := context.WithValue(c, debug.SkipDbLogging{}, true)
		err = dependency.FromContext(c).DBClient().Setting.Create().SetName(configKey).SetValue(string(data)).
			OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
	}
	response(c, map[string]bool{"saved": err == nil}, err)
}

func PublicConfig(c *gin.Context) {
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	response(c, map[string]any{"qq": config.QQ.Enabled, "logto": config.Logto.Enabled, "products": config.Products,
		"alipay": config.Alipay.AppID != "", "wechat": config.WeChat.AppID != ""}, nil)
}

package extended

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

type loginState struct {
	State       string
	Nonce       string
	Verifier    string
	Provider    string
	ProviderKey string
	Expires     int64
	LinkUser    int
	ReturnTo    string
}

func providerFor(name string, config *Config) (sso.Provider, error) {
	switch name {
	case "qq":
		return config.QQ, nil
	case "logto":
		return config.Logto, nil
	}
	return sso.Provider{}, errors.New("unknown SSO provider")
}

func providerKey(name string, p sso.Provider) string {
	hash := sha256.Sum256([]byte(p.ClientID + "\n" + p.Issuer))
	return name + ":" + hex.EncodeToString(hash[:16])
}

func siteURL(c *gin.Context, path string) string {
	reference, err := url.Parse(path)
	if err != nil {
		reference = &url.URL{Path: path}
	}
	return dependency.FromContext(c).SettingProvider().SiteURL(c).ResolveReference(reference).String()
}

func SSOStart(c *gin.Context) {
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	name := c.Param("provider")
	p, err := providerFor(name, config)
	if err != nil {
		response(c, nil, err)
		return
	}
	state := loginState{State: util.RandStringRunesCrypto(64), Nonce: util.RandStringRunesCrypto(64), Verifier: util.RandStringRunesCrypto(64), Provider: name, ProviderKey: providerKey(name, p), Expires: time.Now().Add(5 * time.Minute).Unix(), ReturnTo: "/session"}
	if c.Request.ContentLength != 0 && c.Request.Body != nil {
		var input struct {
			ReturnTo string `json:"return_to"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			response(c, nil, err)
			return
		}
		if input.ReturnTo != "" {
			u, err := url.Parse(input.ReturnTo)
			if err != nil || u.IsAbs() || u.Host != "" || (u.Path != "/session" && u.Path != "/session/authorize") {
				response(c, nil, errors.New("invalid sign-in return path"))
				return
			}
			state.ReturnTo = input.ReturnTo
		}
	}
	if c.Query("link") == "1" {
		u := inventory.UserFromContext(c)
		if u == nil || inventory.IsAnonymousUser(u) {
			response(c, nil, errors.New("sign in before linking an external account"))
			return
		}
		state.LinkUser = u.ID
	}
	callback := siteURL(c, constants.APIPrefix+"/sso/"+name+"/callback")
	redirect, err := (sso.Client{HTTP: externalHTTP}).Begin(c, name, p, callback, state.State, state.Nonce, state.Verifier)
	if err != nil {
		response(c, nil, err)
		return
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		response(c, nil, err)
		return
	}
	session := sessions.Default(c)
	session.Set("sso_state", string(encoded))
	if err := session.Save(); err != nil {
		response(c, nil, err)
		return
	}
	response(c, map[string]string{"url": redirect}, nil)
}

func SSOCallback(c *gin.Context) {
	session := sessions.Default(c)
	encoded, _ := session.Get("sso_state").(string)
	var state loginState
	if json.Unmarshal([]byte(encoded), &state) != nil || state.Expires < time.Now().Unix() || state.Provider != c.Param("provider") ||
		subtle.ConstantTimeCompare([]byte(state.State), []byte(c.Query("state"))) != 1 {
		response(c, nil, errors.New("expired or invalid SSO state"))
		return
	}
	session.Delete("sso_state")
	if err := session.Save(); err != nil {
		response(c, nil, err)
		return
	}
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	p, err := providerFor(state.Provider, config)
	if err != nil || providerKey(state.Provider, p) != state.ProviderKey {
		response(c, nil, errors.New("SSO configuration changed"))
		return
	}
	identity, err := (sso.Client{HTTP: externalHTTP}).Finish(c, state.Provider, p, siteURL(c, constants.APIPrefix+"/sso/"+state.Provider+"/callback"), c.Query("code"), state.Nonce, state.Verifier)
	if err != nil {
		response(c, nil, errors.New("external identity verification failed"))
		return
	}
	dep := dependency.FromContext(c)
	linked, err := dep.DBClient().ExternalIdentity.Query().Where(externalidentity.Provider(state.ProviderKey), externalidentity.Subject(identity.Subject)).Only(c)
	uid := 0
	if err == nil {
		uid = linked.UserID
		if state.LinkUser > 0 && uid != state.LinkUser {
			response(c, nil, errors.New("external identity already belongs to another account"))
			return
		}
	} else if !ent.IsNotFound(err) {
		response(c, nil, err)
		return
	}
	if uid == 0 {
		uid = state.LinkUser
		tx, err := dep.DBClient().Tx(c)
		if err != nil {
			response(c, nil, err)
			return
		}
		defer tx.Rollback()
		if uid == 0 {
			if !p.AllowRegistration || !dep.SettingProvider().RegisterEnabled(c) {
				response(c, nil, errors.New("account is not linked and registration is disabled"))
				return
			}
			digest := sha256.Sum256([]byte(state.ProviderKey + "\n" + identity.Subject))
			email := hex.EncodeToString(digest[:20]) + "@sso.invalid"
			if identity.EmailVerified && identity.Email != "" {
				email = strings.ToLower(identity.Email)
			}
			// Never attach a new provider to an existing account merely because email matches.
			if exists, err := tx.User.Query().Where(user.Email(email)).Exist(c); err != nil || exists {
				response(c, nil, errors.New("email already belongs to an account; sign in and link this provider"))
				return
			}
			nick := identity.Name
			if nick == "" {
				nick = state.Provider + " user"
			}
			if len([]rune(nick)) > 100 {
				nick = string([]rune(nick)[:100])
			}
			created, err := tx.User.Create().SetEmail(email).SetNick(nick).SetGroupID(dep.SettingProvider().DefaultGroup(c)).Save(c)
			if err != nil {
				response(c, nil, err)
				return
			}
			uid = created.ID
		}
		if _, err := tx.ExternalIdentity.Create().SetProvider(state.ProviderKey).SetSubject(identity.Subject).SetUserID(uid).Save(c); err != nil {
			response(c, nil, err)
			return
		}
		if err := tx.Commit(); err != nil {
			response(c, nil, err)
			return
		}
	}
	if state.LinkUser > 0 {
		c.Redirect(http.StatusSeeOther, siteURL(c, "/connect"))
		return
	}
	session.Set("sso_completed", strconv.Itoa(uid))
	session.Set("sso_completed_expires", time.Now().Add(time.Minute).Unix())
	if err := session.Save(); err != nil {
		response(c, nil, err)
		return
	}
	returnTo, _ := url.Parse(state.ReturnTo)
	query := returnTo.Query()
	query.Set("sso", "1")
	c.Redirect(http.StatusSeeOther, siteURL(c, returnTo.Path)+"?"+query.Encode())
}

func SSOComplete(c *gin.Context) {
	dep := dependency.FromContext(c)
	session := sessions.Default(c)
	uidString, _ := session.Get("sso_completed").(string)
	expires, _ := session.Get("sso_completed_expires").(int64)
	uid, err := strconv.Atoi(uidString)
	if err != nil || uid <= 0 || expires < time.Now().Unix() {
		response(c, nil, errors.New("SSO login expired"))
		return
	}
	session.Delete("sso_completed")
	session.Delete("sso_completed_expires")
	if err := session.Save(); err != nil {
		response(c, nil, err)
		return
	}
	u, err := dep.UserClient().GetByID(context.WithValue(c, inventory.LoadUserGroup{}, true), uid)
	if err != nil || u.Status != user.StatusActive {
		response(c, nil, errors.New("account is not active"))
		return
	}
	if u.TwoFactorSecret != "" {
		id := uuid.Must(uuid.NewV4()).String()
		if err := dep.KV().Set(fmt.Sprintf("user_2fa_%s", id), u.ID, 600); err != nil {
			response(c, nil, err)
			return
		}
		c.JSON(200, serializer.Response{Code: serializer.CodeNotFullySuccess, Data: id})
		return
	}
	util.WithValue(c, inventory.UserCtx{}, u)
	result, err := usersvc.IssueToken(c)
	response(c, result, err)
}

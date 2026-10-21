package extended

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/ent/filepermission"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionAPIIsOwnerOnlyAndPreservesInheritedGrants(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "permission-api.db"))
	defer db.Close()
	hasher, err := hashid.New("permission-api")
	require.NoError(t, err)
	group, err := db.Group.Create().SetName("members").SetPermissions(&boolset.BooleanSet{}).Save(t.Context())
	require.NoError(t, err)
	owner, err := db.User.Create().SetEmail("owner@test.invalid").SetNick("Owner").SetGroupID(group.ID).Save(t.Context())
	require.NoError(t, err)
	member, err := db.User.Create().SetEmail("member@test.invalid").SetNick("Member").SetGroupID(group.ID).Save(t.Context())
	require.NoError(t, err)
	root, err := db.File.Create().SetName("").SetOwnerID(owner.ID).SetType(int(types.FileTypeFolder)).Save(t.Context())
	require.NoError(t, err)
	folder, err := db.File.Create().SetName("Team").SetOwnerID(owner.ID).SetParent(root).SetType(int(types.FileTypeFolder)).Save(t.Context())
	require.NoError(t, err)
	child, err := db.File.Create().SetName("Notes").SetOwnerID(owner.ID).SetParent(folder).SetType(int(types.FileTypeFile)).Save(t.Context())
	require.NoError(t, err)
	dep := dependency.NewDependency(dependency.WithDbClient(db), dependency.WithHashIDEncoder(hasher),
		dependency.WithFileClient(inventory.NewFileClient(db, conf.SQLiteDB, hasher)))
	request := func(actor *ent.User, method, uri, role string) (int, json.RawMessage) {
		t.Helper()
		body, err := json.Marshal(permissionInput{URI: uri, UserID: hashid.EncodeUserID(hasher, member.ID), Role: role})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, engine := gin.CreateTestContext(w)
		engine.ContextWithFallback = true
		ctx := context.WithValue(t.Context(), dependency.DepCtx{}, dep)
		ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
		c.Request = httptest.NewRequest(method, "/file/permissions", bytes.NewReader(body)).WithContext(ctx)
		if method == http.MethodGet {
			q := c.Request.URL.Query()
			q.Set("uri", uri)
			c.Request.URL.RawQuery = q.Encode()
		}
		FilePermissions(c)
		var response struct {
			Code int             `json:"code"`
			Data json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		return response.Code, response.Data
	}
	uri := "cloudreve://" + hashid.EncodeUserID(hasher, owner.ID) + "@my/Team"
	code, _ := request(owner, http.MethodPut, uri, "editor")
	require.Zero(t, code)
	code, _ = request(member, http.MethodPut, uri, "editor")
	require.NotZero(t, code, "an editor must not delegate permissions")
	code, _ = request(member, http.MethodDelete, uri, "")
	require.NotZero(t, code)
	code, _ = request(member, http.MethodGet, uri, "")
	require.NotZero(t, code, "member lists are private to the owner")
	code, _ = request(owner, http.MethodPut, uri, "owner")
	require.NotZero(t, code, "cannot transfer ownership via a role string")
	code, data := request(owner, http.MethodGet, uri+"/Notes", "")
	require.Zero(t, code)
	var result struct {
		Items []permissionMember `json:"items"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.Len(t, result.Items, 1)
	require.True(t, result.Items[0].Inherited)
	code, _ = request(owner, http.MethodDelete, uri+"/Notes", "")
	require.Zero(t, code)
	role, err := inventory.FilePermissionRole(t.Context(), db, child.ID, member.ID)
	require.NoError(t, err)
	require.Equal(t, inventory.FileRoleEditor, role, "removing a child grant cannot delete a parent's grant")
	code, _ = request(owner, http.MethodPut, uri, "viewer")
	require.Zero(t, code)
	count, err := db.FilePermission.Query().Where(filepermission.FileID(folder.ID), filepermission.UserID(member.ID)).Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, count, "updating a grant must not duplicate it")
	code, _ = request(owner, http.MethodDelete, uri, "")
	require.Zero(t, code)
	role, err = inventory.FilePermissionRole(t.Context(), db, child.ID, member.ID)
	require.NoError(t, err)
	require.Empty(t, role)
}

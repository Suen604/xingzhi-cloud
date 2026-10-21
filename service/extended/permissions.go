package extended

import (
	"errors"
	"net/http"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/filepermission"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type permissionInput struct {
	URI    string `json:"uri"`
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type permissionMember struct {
	UserID     string `json:"user_id"`
	Nickname   string `json:"nickname"`
	Role       string `json:"role"`
	Inherited  bool   `json:"inherited"`
	SourceID   string `json:"source_id"`
	SourceName string `json:"source_name"`
}

// Permission management deliberately resolves only the owner's My namespace.
// Collaborators cannot delegate access, even when they can edit file content.
func ownedPermissionTarget(c *gin.Context, raw string) (*ent.File, error) {
	dep := dependency.FromContext(c)
	actor := inventory.UserFromContext(c)
	uri, err := fs.NewUriFromString(raw)
	if err != nil {
		return nil, err
	}
	if actor == nil || inventory.IsAnonymousUser(actor) || uri.FileSystem() != constants.FileSystemMy ||
		uri.ID(hashid.EncodeUserID(dep.HashIDEncoder(), actor.ID)) != hashid.EncodeUserID(dep.HashIDEncoder(), actor.ID) {
		return nil, serializer.NewError(serializer.CodeNoPermissionErr, "only the owner can manage collaborators", nil)
	}
	target, err := dep.FileClient().Root(c, actor)
	if err != nil {
		return nil, err
	}
	for _, element := range uri.Elements() {
		if target.IsSymbolic {
			return nil, errors.New("symbolic folders do not support collaboration grants")
		}
		target, err = dep.FileClient().GetChildFile(c, target, actor.ID, element, false)
		if err != nil {
			return nil, err
		}
	}
	if target.OwnerID != actor.ID || target.IsSymbolic || target.FileChildren == 0 {
		return nil, errors.New("choose a file or folder inside your drive")
	}
	return target, nil
}

func permissionResponse(c *gin.Context, data any, err error) {
	if err != nil {
		c.JSON(http.StatusOK, serializer.Err(c, err))
		return
	}
	c.JSON(http.StatusOK, serializer.Response{Data: data})
}

func FilePermissions(c *gin.Context) {
	var input permissionInput
	if c.Request.Method == http.MethodGet {
		input.URI = c.Query("uri")
	} else if err := c.ShouldBindJSON(&input); err != nil {
		permissionResponse(c, nil, err)
		return
	}
	target, err := ownedPermissionTarget(c, input.URI)
	if err != nil {
		permissionResponse(c, nil, err)
		return
	}
	dep := dependency.FromContext(c)
	db, hasher := dep.DBClient(), dep.HashIDEncoder()
	if c.Request.Method == http.MethodGet {
		members := make([]permissionMember, 0)
		current := target
		for {
			grants, err := db.FilePermission.Query().Where(filepermission.FileID(current.ID)).Order(ent.Asc(filepermission.FieldUserID)).All(c)
			if err != nil {
				permissionResponse(c, nil, err)
				return
			}
			for _, grant := range grants {
				member, err := db.User.Get(c, grant.UserID)
				if ent.IsNotFound(err) {
					continue
				}
				if err != nil {
					permissionResponse(c, nil, err)
					return
				}
				members = append(members, permissionMember{
					UserID: hashid.EncodeUserID(hasher, member.ID), Nickname: member.Nick, Role: string(grant.Role),
					Inherited: current.ID != target.ID, SourceID: hashid.EncodeFileID(hasher, current.ID), SourceName: current.Name,
				})
			}
			if current.FileChildren == 0 {
				break
			}
			current, err = db.File.Get(c, current.FileChildren)
			if err != nil {
				permissionResponse(c, nil, err)
				return
			}
		}
		permissionResponse(c, map[string]any{"items": members}, nil)
		return
	}
	uid, err := hasher.Decode(input.UserID, hashid.UserID)
	if err != nil || uid <= 0 || uid == target.OwnerID {
		permissionResponse(c, nil, errors.New("select another registered user"))
		return
	}
	if c.Request.Method == http.MethodDelete {
		_, err = db.FilePermission.Delete().Where(filepermission.FileID(target.ID), filepermission.UserID(uid)).Exec(c)
		permissionResponse(c, map[string]bool{"saved": err == nil}, err)
		return
	}
	if input.Role != inventory.FileRoleViewer && input.Role != inventory.FileRoleEditor {
		permissionResponse(c, nil, errors.New("role must be viewer or editor"))
		return
	}
	if _, err := db.User.Query().Where(user.ID(uid), user.StatusEQ(user.StatusActive)).Only(c); err != nil {
		permissionResponse(c, nil, errors.New("collaborator is not an active user"))
		return
	}
	err = db.FilePermission.Create().SetFileID(target.ID).SetUserID(uid).SetRole(filepermission.Role(input.Role)).
		OnConflictColumns(filepermission.FieldFileID, filepermission.FieldUserID).UpdateNewValues().Exec(c)
	permissionResponse(c, map[string]bool{"saved": err == nil}, err)
}

package inventory

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/filepermission"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
)

const (
	FileRoleViewer = "viewer"
	FileRoleEditor = "editor"
	FileRoleOwner  = "owner"
)

// FilePermissionRole reads the current ancestry and grants from the database.
// Grants are additive: an editor grant on any ancestor includes its descendants.
// Cached navigator state is deliberately never used for authorization.
func FilePermissionRole(ctx context.Context, db *ent.Client, fileID, uid int) (string, error) {
	if uid <= 0 {
		return "", nil
	}
	current, err := db.File.Get(ctx, fileID)
	if err != nil {
		return "", err
	}
	owner := current.OwnerID
	ids := make([]int, 0, 16)
	seen := map[int]bool{}
	for {
		if current.OwnerID != owner || seen[current.ID] || len(ids) >= 512 {
			return "", fmt.Errorf("invalid file ancestry")
		}
		seen[current.ID] = true
		ids = append(ids, current.ID)
		if current.FileChildren == 0 {
			// Deleted trees have a detached, renamed root. A grant cannot revive them.
			if current.Name != RootFolderName {
				return "", nil
			}
			break
		}
		current, err = db.File.Get(ctx, current.FileChildren)
		if err != nil {
			return "", err
		}
	}
	if owner == uid {
		return FileRoleOwner, nil
	}
	active, err := db.User.Query().Where(user.IDIn(owner, uid), user.StatusEQ(user.StatusActive)).Count(ctx)
	if err != nil || active != 2 {
		return "", err
	}
	grants, err := db.FilePermission.Query().Where(filepermission.UserID(uid), filepermission.FileIDIn(ids...)).All(ctx)
	if err != nil {
		return "", err
	}
	role := ""
	for _, grant := range grants {
		if grant.Role == filepermission.RoleEditor {
			return FileRoleEditor, nil
		}
		role = FileRoleViewer
	}
	return role, nil
}

func (f *fileClient) PermissionRole(ctx context.Context, target *ent.File, uid int) (string, error) {
	return FilePermissionRole(ctx, f.client, target.ID, uid)
}

package dbfs

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
)

// Collaborators can edit content, but cannot redistribute it, change grants,
// permanently delete data or manage the owner's view settings.
func collaborationCapabilities(role string) *boolset.BooleanSet {
	caps := &boolset.BooleanSet{}
	for _, capability := range []NavigatorCapability{
		NavigatorCapabilityDownloadFile, NavigatorCapabilityListChildren,
		NavigatorCapabilityGenerateThumb, NavigatorCapabilityInfo,
		NavigatorCapabilityEnterFolder, NavigatorCapabilityLockFile,
	} {
		boolset.Set(capability, true, caps)
	}
	if role == inventory.FileRoleEditor {
		for _, capability := range []NavigatorCapability{
			NavigatorCapabilityCreateFile, NavigatorCapabilityRenameFile,
			NavigatorCapabilityUploadFile, NavigatorCapabilityUpdateMetadata,
			NavigatorCapabilitySoftDelete, NavigatorCapabilityVersionControl,
		} {
			boolset.Set(capability, true, caps)
		}
	}
	return caps
}

func (f *DBFS) canEdit(ctx context.Context, target *File) bool {
	if _, ok := ctx.Value(ByPassOwnerCheckCtxKey{}).(bool); ok || target.OwnerID() == f.user.ID {
		return true
	}
	if target.Uri(false).FileSystem() != constants.FileSystemMy {
		return false
	}
	role, err := f.fileClient.PermissionRole(ctx, target.Model, f.user.ID)
	return err == nil && role == inventory.FileRoleEditor
}

func (f *DBFS) canRead(ctx context.Context, target *File) bool {
	if _, ok := ctx.Value(ByPassOwnerCheckCtxKey{}).(bool); ok || target.OwnerID() == f.user.ID {
		return true
	}
	if target.Uri(false).FileSystem() != constants.FileSystemMy {
		return false
	}
	role, err := f.fileClient.PermissionRole(ctx, target.Model, f.user.ID)
	return err == nil && role != ""
}

package dbfs

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/ent/filepermission"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/lock"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type permissionSettings struct{ setting.Provider }

func (permissionSettings) DBFS(context.Context) *setting.DBFS {
	return &setting.DBFS{MaxPageSize: 100, MaxRecursiveSearchedFolder: 100}
}

type permissionEvents struct{ eventhub.EventHub }

func (permissionEvents) GetSubscribers(context.Context, int) []eventhub.Subscriber { return nil }

type permissionFixture struct {
	db                           *ent.Client
	owner, member                *ent.User
	root, shared, child, private *ent.File
	hasher                       hashid.Encoder
	makeFS                       func(*ent.User) *DBFS
}

func newPermissionFixture(t *testing.T) *permissionFixture {
	t.Helper()
	ctx := t.Context()
	db := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "permissions.db"))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	hasher, err := hashid.New("permissions-test")
	require.NoError(t, err)
	l := logging.NewConsoleLogger(logging.LevelWarning)
	kv := cache.NewMemoStore("", l)
	policy, err := db.StoragePolicy.Create().SetName("Local").SetType(types.PolicyTypeLocal).Save(ctx)
	require.NoError(t, err)
	group, err := db.Group.Create().SetName("Members").SetPermissions(&boolset.BooleanSet{}).
		SetMaxStorage(100).SetStoragePolicyID(policy.ID).SetSettings(&types.GroupSetting{MaxWalkedFiles: 100, TrashRetention: 3600}).Save(ctx)
	require.NoError(t, err)
	owner, err := db.User.Create().SetEmail("owner@example.com").SetNick("Owner").SetGroupID(group.ID).SetStorage(90).Save(ctx)
	require.NoError(t, err)
	member, err := db.User.Create().SetEmail("member@example.com").SetNick("Member").SetGroupID(group.ID).Save(ctx)
	require.NoError(t, err)
	owner.Edges.Group, member.Edges.Group = group, group
	root, err := db.File.Create().SetName("").SetType(int(types.FileTypeFolder)).SetOwnerID(owner.ID).Save(ctx)
	require.NoError(t, err)
	shared, err := db.File.Create().SetName("Team").SetType(int(types.FileTypeFolder)).SetOwnerID(owner.ID).SetParent(root).Save(ctx)
	require.NoError(t, err)
	child, err := db.File.Create().SetName("notes.txt").SetType(int(types.FileTypeFile)).SetOwnerID(owner.ID).SetParent(shared).Save(ctx)
	require.NoError(t, err)
	private, err := db.File.Create().SetName("Private").SetType(int(types.FileTypeFolder)).SetOwnerID(owner.ID).SetParent(root).Save(ctx)
	require.NoError(t, err)
	// The recipient's own root is required for the virtual Shared with me view.
	_, err = db.File.Create().SetName("").SetType(int(types.FileTypeFolder)).SetOwnerID(member.ID).Save(ctx)
	require.NoError(t, err)
	makeFS := func(actor *ent.User) *DBFS {
		return NewDatabaseFS(actor, inventory.NewFileClient(db, conf.SQLiteDB, hasher), nil, l,
			lock.NewMemLS(hasher, l), permissionSettings{}, inventory.NewStoragePolicyClient(db, kv), hasher,
			inventory.NewUserClient(db), kv, kv, nil, nil, permissionEvents{}).(*DBFS)
	}
	return &permissionFixture{db: db, owner: owner, member: member, root: root, shared: shared, child: child, private: private, hasher: hasher, makeFS: makeFS}
}

func (p *permissionFixture) uri(t *testing.T, path string) *fs.URI {
	t.Helper()
	uri, err := fs.NewUriFromString("cloudreve://" + hashid.EncodeUserID(p.hasher, p.owner.ID) + "@my/" + path)
	require.NoError(t, err)
	return uri
}

func (p *permissionFixture) grant(t *testing.T, id int, role filepermission.Role) {
	t.Helper()
	require.NoError(t, p.db.FilePermission.Create().SetFileID(id).SetUserID(p.member.ID).SetRole(role).
		OnConflictColumns(filepermission.FieldFileID, filepermission.FieldUserID).UpdateNewValues().Exec(t.Context()))
}

func TestCollaborationViewerCannotWriteOrReadSiblings(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleViewer)
	disk := p.makeFS(p.member)
	defer disk.Recycle()
	ctx := t.Context()
	file, err := disk.Get(ctx, p.uri(t, "Team/notes.txt"))
	require.NoError(t, err)
	require.Equal(t, p.owner.ID, file.OwnerID())
	require.True(t, file.Capabilities().Enabled(int(NavigatorCapabilityDownloadFile)))
	require.False(t, file.Capabilities().Enabled(int(NavigatorCapabilityUploadFile)))
	_, listing, err := disk.List(ctx, p.uri(t, "Team"))
	require.NoError(t, err)
	require.Len(t, listing.Files, 1)
	_, err = disk.Get(ctx, p.uri(t, "Private"))
	require.Error(t, err)
	_, _, err = disk.List(ctx, p.uri(t, ""))
	require.Error(t, err)
	_, err = disk.Create(ctx, p.uri(t, "Team/new"), types.FileTypeFolder)
	require.Error(t, err)
	_, _, err = disk.Rename(ctx, p.uri(t, "Team/notes.txt"), "changed.txt")
	require.Error(t, err)
	require.Error(t, disk.SoftDelete(ctx, p.uri(t, "Team/notes.txt")))
	require.Error(t, disk.PatchMetadata(ctx, []*fs.URI{p.uri(t, "Team/notes.txt")}, fs.MetadataPatch{Key: "tag", Value: "x"}))
	_, _, err = disk.Delete(ctx, []*fs.URI{p.uri(t, "Team/notes.txt")})
	require.Error(t, err)
	_, err = disk.VersionControl(ctx, p.uri(t, "Team/notes.txt"), 1, false)
	require.Error(t, err)
}

func TestCollaborationEditorChangesAndLiveRevocation(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleEditor)
	disk := p.makeFS(p.member)
	defer disk.Recycle()
	ctx := t.Context()
	created, err := disk.Create(ctx, p.uri(t, "Team/Sub"), types.FileTypeFolder)
	require.NoError(t, err)
	require.Equal(t, p.owner.ID, created.OwnerID())
	_, _, err = disk.Rename(ctx, p.uri(t, "Team/notes.txt"), "edited.txt")
	require.NoError(t, err)
	require.NoError(t, disk.PatchMetadata(ctx, []*fs.URI{p.uri(t, "Team/edited.txt")}, fs.MetadataPatch{Key: "tag", Value: "x"}))
	_, _, err = disk.Delete(ctx, []*fs.URI{p.uri(t, "Team/edited.txt")})
	require.Error(t, err, "editor cannot permanently delete")
	require.NoError(t, disk.SoftDelete(ctx, p.uri(t, "Team/Sub")))
	// Restoring a persisted navigator must still resolve live grants.
	oldNav, err := disk.getNavigator(ctx, p.uri(t, "Team"))
	require.NoError(t, err)
	restored := NewMyNavigator(p.member, disk.fileClient, disk.userClient, disk.l, permissionSettings{}.DBFS(ctx), p.hasher)
	require.NoError(t, restored.RestoreState(oldNav.(*myNavigator).root))
	// A cached folder in the same navigator must not preserve revoked privileges.
	_, err = p.db.FilePermission.Delete().Where(filepermission.FileID(p.shared.ID)).Exec(ctx)
	require.NoError(t, err)
	_, err = restored.To(ctx, p.uri(t, "Team/edited.txt"))
	require.Error(t, err)
	_, err = disk.Get(ctx, p.uri(t, "Team/edited.txt"))
	require.Error(t, err)
	_, err = disk.Create(ctx, p.uri(t, "Team/Sub/denied"), types.FileTypeFolder)
	require.Error(t, err)
	p.grant(t, p.shared.ID, filepermission.RoleViewer)
	_, err = disk.Get(ctx, p.uri(t, "Team/edited.txt"))
	require.NoError(t, err)
	_, _, err = disk.Rename(ctx, p.uri(t, "Team/edited.txt"), "denied.txt")
	require.Error(t, err)
}

func TestCollaborationInheritanceAndDetachedTrees(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleEditor)
	p.grant(t, p.child.ID, filepermission.RoleViewer)
	role, err := inventory.FilePermissionRole(t.Context(), p.db, p.child.ID, p.member.ID)
	require.NoError(t, err)
	require.Equal(t, inventory.FileRoleEditor, role)
	_, err = p.db.File.UpdateOne(p.child).SetParent(p.private).Save(t.Context())
	require.NoError(t, err)
	role, err = inventory.FilePermissionRole(t.Context(), p.db, p.child.ID, p.member.ID)
	require.NoError(t, err)
	require.Equal(t, inventory.FileRoleViewer, role, "moving out removes inherited editor access")
	_, err = p.db.File.UpdateOne(p.shared).ClearParent().SetName("trashed").Save(t.Context())
	require.NoError(t, err)
	role, err = inventory.FilePermissionRole(t.Context(), p.db, p.shared.ID, p.member.ID)
	require.NoError(t, err)
	require.Empty(t, role, "direct grants cannot revive deleted trees")
	_, err = p.db.User.UpdateOne(p.owner).SetStatus(user.StatusManualBanned).Save(t.Context())
	require.NoError(t, err)
	role, err = inventory.FilePermissionRole(t.Context(), p.db, p.child.ID, p.member.ID)
	require.NoError(t, err)
	require.Empty(t, role)
}

func TestCollaborationUploadChargesOwnerAndRechecksCompletion(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleEditor)
	disk := p.makeFS(p.member)
	defer disk.Recycle()
	ctx := t.Context()
	req := &fs.UploadRequest{Props: &fs.UploadProps{Uri: p.uri(t, "Team/upload.txt"), Size: 11, UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Hour)}}
	require.NoError(t, disk.PreValidateUpload(ctx, p.uri(t, "Team"), fs.PreValidateFile{Name: "upload.txt", Size: 5}))
	_, err := disk.PrepareUpload(ctx, req)
	require.ErrorIs(t, err, fs.ErrInsufficientCapacity, "use owner's used storage, not recipient's empty storage")
	req.Props.Size = 5
	session, err := disk.PrepareUpload(ctx, req)
	require.NoError(t, err)
	owner, err := p.db.User.Get(ctx, p.owner.ID)
	require.NoError(t, err)
	require.Equal(t, int64(95), owner.Storage)
	member, err := p.db.User.Get(ctx, p.member.ID)
	require.NoError(t, err)
	require.Zero(t, member.Storage)
	upload, err := p.db.File.Get(ctx, session.FileID)
	require.NoError(t, err)
	require.Equal(t, p.owner.ID, upload.OwnerID)
	p.grant(t, p.shared.ID, filepermission.RoleViewer)
	_, err = disk.CompleteUpload(ctx, session)
	require.Error(t, err, "a downgraded member cannot publish an in-flight upload")
	p.grant(t, p.shared.ID, filepermission.RoleEditor)
	completed, err := disk.CompleteUpload(ctx, session)
	require.NoError(t, err)
	require.Equal(t, p.owner.ID, completed.OwnerID())
	require.Equal(t, int64(5), completed.Size())
}

func TestSharedWithMeUsesAuthorizedCanonicalPaths(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleViewer)
	disk := p.makeFS(p.member)
	defer disk.Recycle()
	uri, err := fs.NewUriFromString("cloudreve://shared_with_me")
	require.NoError(t, err)
	_, list, err := disk.List(t.Context(), uri)
	require.NoError(t, err)
	require.Len(t, list.Files, 1)
	require.Equal(t, p.uri(t, "Team").String(), list.Files[0].Uri(false).String())
	_, err = disk.Get(t.Context(), list.Files[0].Uri(false))
	require.NoError(t, err)
	_, list, err = disk.List(t.Context(), uri.SetQuery("name=Team"))
	require.NoError(t, err)
	require.Len(t, list.Files, 1, "search must use recipient grants rather than file ownership")
	_, err = p.db.FilePermission.Delete().Exec(t.Context())
	require.NoError(t, err)
	_, list, err = disk.List(t.Context(), uri)
	require.NoError(t, err)
	require.Empty(t, list.Files)
}

func TestCollaborationMoveCopyBoundaries(t *testing.T) {
	p := newPermissionFixture(t)
	p.grant(t, p.shared.ID, filepermission.RoleEditor)
	disk := p.makeFS(p.member)
	defer disk.Recycle()
	ctx := t.Context()
	_, err := disk.MoveOrCopy(ctx, []*fs.URI{p.uri(t, "Team/notes.txt")}, p.uri(t, "Private"), false)
	require.Error(t, err, "source editor grant does not authorize private destinations")
	other, err := p.db.File.Create().SetName("Other").SetOwnerID(p.owner.ID).SetParent(p.root).SetType(int(types.FileTypeFolder)).Save(ctx)
	require.NoError(t, err)
	p.grant(t, other.ID, filepermission.RoleEditor)
	_, err = disk.MoveOrCopy(ctx, []*fs.URI{p.uri(t, "Team/notes.txt")}, p.uri(t, "Other"), false)
	require.NoError(t, err)
	moved, err := p.db.File.Get(ctx, p.child.ID)
	require.NoError(t, err)
	require.Equal(t, p.owner.ID, moved.OwnerID)
	require.Equal(t, other.ID, moved.FileChildren)
	_, err = disk.MoveOrCopy(ctx, []*fs.URI{p.uri(t, "Other/notes.txt")}, newMyUri(), false)
	require.Error(t, err, "moving cannot transfer ownership")
	p.grant(t, other.ID, filepermission.RoleViewer)
	_, err = disk.MoveOrCopy(ctx, []*fs.URI{p.uri(t, "Other/notes.txt")}, newMyUri(), true)
	require.NoError(t, err, "a viewer can save a copy to their own drive")
	copied, err := disk.Get(ctx, newMyUri().Join("notes.txt"))
	require.NoError(t, err)
	require.Equal(t, p.member.ID, copied.OwnerID())
	count, err := p.db.FilePermission.Query().Where(filepermission.FileID(copied.ID())).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count, "copying does not propagate collaboration grants")
}

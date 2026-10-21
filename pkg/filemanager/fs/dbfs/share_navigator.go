package dbfs

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
)

var (
	ErrShareNotFound = serializer.NewError(serializer.CodeNotFound, "Shared file does not exist", nil)
	ErrNotPurchased  = serializer.NewError(serializer.CodePurchaseRequired, "Purchase this share to access its contents", nil)
)

const (
	PurchaseTicketHeader = constants.CrHeaderPrefix + "Purchase-Ticket"
)

var shareNavigatorCapability = &boolset.BooleanSet{}

// NewShareNavigator creates a navigator for user's "shared" file system.
func NewShareNavigator(u *ent.User, fileClient inventory.FileClient, shareClient inventory.ShareClient,
	l logging.Logger, config *setting.DBFS, hasher hashid.Encoder) Navigator {
	n := &shareNavigator{
		user:        u,
		l:           l,
		fileClient:  fileClient,
		shareClient: shareClient,
		config:      config,
	}
	n.baseNavigator = newBaseNavigator(fileClient, defaultFilter, u, hasher, config)
	return n
}

type (
	shareNavigator struct {
		l           logging.Logger
		user        *ent.User
		fileClient  inventory.FileClient
		shareClient inventory.ShareClient
		config      *setting.DBFS

		*baseNavigator
		shareRoot       *File
		singleFileShare bool
		ownerRoot       *File
		share           *ent.Share
		owner           *ent.User
		disableRecycle  bool
		persist         func()
	}

	shareNavigatorState struct {
		ShareRoot       *File
		OwnerRoot       *File
		SingleFileShare bool
		Share           *ent.Share
		Owner           *ent.User
	}
)

func (n *shareNavigator) PersistState(kv cache.Driver, key string) {
	n.disableRecycle = true
	n.persist = func() {
		kv.Set(key, shareNavigatorState{
			ShareRoot:       n.shareRoot,
			OwnerRoot:       n.ownerRoot,
			SingleFileShare: n.singleFileShare,
			Share:           n.share,
			Owner:           n.owner,
		}, ContextHintTTL)
	}
}

func (n *shareNavigator) RestoreState(s State) error {
	n.disableRecycle = true
	if state, ok := s.(shareNavigatorState); ok {
		n.shareRoot = state.ShareRoot
		n.ownerRoot = state.OwnerRoot
		n.singleFileShare = state.SingleFileShare
		n.share = state.Share
		n.owner = state.Owner
		return nil
	}

	return fmt.Errorf("invalid state type: %T", s)
}

func (n *shareNavigator) Recycle() {
	if n.persist != nil {
		n.persist()
		n.persist = nil
	}

	if !n.disableRecycle {
		if n.ownerRoot != nil {
			n.ownerRoot.Recycle()
		} else if n.shareRoot != nil {
			n.shareRoot.Recycle()
		}
	}
}

func (n *shareNavigator) Root(ctx context.Context, path *fs.URI) (*File, error) {
	ctx = context.WithValue(ctx, inventory.LoadShareUser{}, true)
	ctx = context.WithValue(ctx, inventory.LoadUserGroup{}, true)
	ctx = context.WithValue(ctx, inventory.LoadShareFile{}, true)
	share, err := n.shareClient.GetByHashID(ctx, path.ID(hashid.EncodeUserID(n.hasher, n.user.ID)))
	if err != nil {
		return nil, ErrShareNotFound.WithError(err)
	}

	if err := inventory.IsValidShare(share); err != nil {
		return nil, ErrShareNotFound.WithError(err)
	}

	n.owner = share.Edges.User

	// Check password
	if share.Password != "" && share.Password != path.Password() {
		return nil, ErrShareIncorrectPassword
	}
	allowed, err := inventory.CanAccessPaidShare(ctx, n.shareClient.GetClient(), share, n.user)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrNotPurchased
	}

	// Share permission setting should overwrite root folder's permission
	n.shareRoot = newFile(nil, share.Edges.File)

	// Find the user side root of the file.
	ownerRoot, err := n.findRoot(ctx, n.shareRoot)
	if err != nil {
		return nil, err
	}

	if n.shareRoot.Type() == types.FileTypeFile {
		n.singleFileShare = true
		n.shareRoot = n.shareRoot.Parent
	}

	n.shareRoot.Path[pathIndexUser] = path.Root()
	n.shareRoot.OwnerModel = n.owner
	n.shareRoot.IsUserRoot = true
	n.shareRoot.disableView = (share.Props == nil || !share.Props.ShareView) && n.user.ID != n.owner.ID
	n.shareRoot.CapabilitiesBs = n.Capabilities(false).Capability

	// Check if any ancestors is deleted
	if ownerRoot.Name() != inventory.RootFolderName {
		return nil, ErrShareNotFound
	}

	if n.user.ID != n.owner.ID && !n.user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionShareDownload)) {
		if inventory.IsAnonymousUser(n.user) {
			return nil, serializer.NewError(
				serializer.CodeAnonymouseAccessDenied,
				fmt.Sprintf("You don't have permission to access share links"),
				err,
			)
		}

		return nil, serializer.NewError(
			serializer.CodeNoPermissionErr,
			fmt.Sprintf("You don't have permission to access share links"),
			err,
		)
	}

	n.ownerRoot = ownerRoot
	n.ownerRoot.Path[pathIndexRoot] = newMyIDUri(hashid.EncodeUserID(n.hasher, n.owner.ID))
	n.share = share
	return n.shareRoot, nil
}

func (n *shareNavigator) To(ctx context.Context, path *fs.URI) (*File, error) {
	if n.shareRoot == nil {
		root, err := n.Root(ctx, path)
		if err != nil {
			return nil, err
		}

		n.shareRoot = root
	}
	if err := n.checkAccess(ctx, path); err != nil {
		return nil, err
	}

	current, lastAncestor := n.shareRoot, n.shareRoot
	elements := path.Elements()
	if n.singleFileShare && len(elements) > 1 {
		return nil, fs.ErrPathNotExist
	}

	// If target is root of single file share, the root itself is the target.
	if len(elements) == 1 && n.singleFileShare {
		file, err := n.latestSharedSingleFile(ctx)
		if err != nil {
			return nil, err
		}

		if len(elements) == 1 && file.Name() != elements[0] {
			return nil, fs.ErrPathNotExist
		}

		return file, nil
	}

	var err error
	for index, element := range elements {
		lastAncestor = current
		current, err = n.walkNext(ctx, current, element, index == len(elements)-1)
		if err != nil {
			return lastAncestor, fmt.Errorf("failed to walk into %q: %w", element, err)
		}
	}

	return current, nil
}

func (n *shareNavigator) walkNext(ctx context.Context, root *File, next string, isLeaf bool) (*File, error) {
	// Resolve every segment against its current parent. Cached ancestors can
	// have moved out of the shared subtree since the navigator was persisted.
	nextFile, err := n.baseNavigator.walkNext(ctx, root, next, true)
	if err != nil {
		return nil, err
	}

	return nextFile, nil
}

func (n *shareNavigator) Children(ctx context.Context, parent *File, args *ListArgs) (*ListResult, error) {
	if err := n.checkAccess(ctx, n.shareRoot.Uri(false)); err != nil {
		return nil, err
	}
	if n.singleFileShare {
		file, err := n.latestSharedSingleFile(ctx)
		if err != nil {
			return nil, err
		}

		return &ListResult{
			Files:          []*File{file},
			Pagination:     &inventory.PaginationResults{},
			SingleFileView: true,
		}, nil
	}

	return n.baseNavigator.children(ctx, parent, args)
}

func (n *shareNavigator) latestSharedSingleFile(ctx context.Context) (*File, error) {
	if n.singleFileShare {
		file, err := n.fileClient.GetByID(ctx, n.share.Edges.File.ID)
		if err != nil {
			return nil, err
		}

		f := newFile(n.shareRoot, file)
		f.OwnerModel = n.shareRoot.OwnerModel

		return f, nil
	}

	return nil, fs.ErrPathNotExist
}

func (n *shareNavigator) Capabilities(isSearching bool) *fs.NavigatorProps {
	res := &fs.NavigatorProps{
		Capability:            shareNavigatorCapability,
		OrderDirectionOptions: fullOrderDirectionOption,
		OrderByOptions:        fullOrderByOption,
		MaxPageSize:           n.config.MaxPageSize,
	}

	if isSearching {
		res.OrderByOptions = nil
		res.OrderDirectionOptions = nil
	}

	return res
}

func (n *shareNavigator) FollowTx(ctx context.Context) (func(), error) {
	if _, ok := ctx.Value(inventory.TxCtx{}).(*inventory.Tx); !ok {
		return nil, fmt.Errorf("navigator: no inherited transaction found in context")
	}
	newFileClient, _, _, err := inventory.WithTx(ctx, n.fileClient)
	if err != nil {
		return nil, err
	}

	newSharClient, _, _, err := inventory.WithTx(ctx, n.shareClient)

	oldFileClient, oldShareClient := n.fileClient, n.shareClient
	revert := func() {
		n.fileClient = oldFileClient
		n.shareClient = oldShareClient
		n.baseNavigator.fileClient = oldFileClient
	}

	n.fileClient = newFileClient
	n.shareClient = newSharClient
	n.baseNavigator.fileClient = newFileClient
	return revert, nil
}

func (n *shareNavigator) ExecuteHook(ctx context.Context, hookType fs.HookType, file *File) error {
	if err := n.checkAccess(ctx, n.shareRoot.Uri(false)); err != nil {
		return err
	}
	switch hookType {
	case fs.HookTypeBeforeDownload:
		return n.shareClient.Downloaded(ctx, n.share)
	}
	return nil
}

func (n *shareNavigator) Walk(ctx context.Context, levelFiles []*File, limit, depth int, f WalkFunc) error {
	if err := n.checkAccess(ctx, n.shareRoot.Uri(false)); err != nil {
		return err
	}
	return n.baseNavigator.walk(ctx, levelFiles, limit, depth, f)
}

// Always query live share settings and purchase records, including for restored
// navigator state. A cached free share must not bypass a newly enabled paywall.
func (n *shareNavigator) checkAccess(ctx context.Context, path *fs.URI) error {
	ctx = context.WithValue(ctx, inventory.LoadShareUser{}, true)
	ctx = context.WithValue(ctx, inventory.LoadShareFile{}, true)
	current, err := n.shareClient.GetByID(ctx, n.share.ID)
	if err != nil || inventory.IsValidShare(current) != nil {
		return ErrShareNotFound
	}
	if current.Edges.File.ID != n.share.Edges.File.ID || current.Edges.User.ID != n.share.Edges.User.ID {
		return ErrShareNotFound
	}
	if current.Password != "" && current.Password != path.Password() {
		return ErrShareIncorrectPassword
	}
	allowed, err := inventory.CanAccessPaidShare(ctx, n.shareClient.GetClient(), current, n.user)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrNotPurchased
	}
	if n.user.ID != current.Edges.User.ID && !n.user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionShareDownload)) {
		return ErrPermissionDenied
	}
	// Check the live ancestry as well: an old navigator may point into a tree
	// moved into the recycle bin after it was cached.
	role, err := inventory.FilePermissionRole(ctx, n.shareClient.GetClient(), current.Edges.File.ID, current.Edges.User.ID)
	if err != nil || role != inventory.FileRoleOwner {
		return ErrShareNotFound
	}
	n.share = current
	return nil
}

func (n *shareNavigator) GetView(ctx context.Context, file *File) *types.ExplorerView {
	return file.View()
}

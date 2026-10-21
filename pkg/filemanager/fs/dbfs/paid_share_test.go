package dbfs

import (
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/stretchr/testify/require"
)

func paidNavigator(t *testing.T, p *permissionFixture, actor *ent.User) *shareNavigator {
	t.Helper()
	boolset.Set(types.GroupPermissionShareDownload, true, p.member.Edges.Group.Permissions)
	return NewShareNavigator(actor, inventory.NewFileClient(p.db, conf.SQLiteDB, p.hasher),
		inventory.NewShareClient(p.db, conf.SQLiteDB, p.hasher), logging.NewConsoleLogger(logging.LevelWarning), permissionSettings{}.DBFS(t.Context()), p.hasher).(*shareNavigator)
}

func paidShare(t *testing.T, p *permissionFixture, file *ent.File, price int64) (*ent.Share, *fs.URI) {
	t.Helper()
	share, err := p.db.Share.Create().SetUserID(p.owner.ID).SetFileID(file.ID).SetPrice(price).Save(t.Context())
	require.NoError(t, err)
	uri, err := fs.NewUriFromString(fs.NewShareUri(hashid.EncodeShareID(p.hasher, share.ID), ""))
	require.NoError(t, err)
	return share, uri
}

func paidReceipt(t *testing.T, p *permissionFixture, share *ent.Share, target *ent.File) *ent.PurchaseOrder {
	t.Helper()
	order, err := p.db.PurchaseOrder.Create().SetNumber("receipt").SetUserID(p.member.ID).SetProvider("alipay").
		SetProductID("share").SetProductName("Share").SetAmount(100).SetShareID(share.ID).SetFileID(target.ID).
		SetSellerID(p.owner.ID).SetExpiresAt(time.Now().Add(time.Hour)).SetStatus(purchaseorder.StatusFulfilled).Save(t.Context())
	require.NoError(t, err)
	return order
}

func TestPaidShareBlocksEveryUnpaidAccountAndAllowsOwner(t *testing.T) {
	for _, single := range []bool{false, true} {
		t.Run(map[bool]string{true: "file", false: "folder"}[single], func(t *testing.T) {
			p := newPermissionFixture(t)
			target := p.shared
			if single {
				target = p.child
			}
			_, uri := paidShare(t, p, target, 100)
			for _, actor := range []*ent.User{p.member, {ID: 0, Edges: ent.UserEdges{Group: p.member.Edges.Group}}} {
				nav := paidNavigator(t, p, actor)
				_, err := nav.To(t.Context(), uri)
				require.ErrorIs(t, err, ErrNotPurchased)
				nav.Recycle()
			}
			owner := paidNavigator(t, p, p.owner)
			_, err := owner.To(t.Context(), uri)
			require.NoError(t, err)
			owner.Recycle()
		})
	}
}

func TestPaidShareReceiptIsBoundToBuyerAndResource(t *testing.T) {
	p := newPermissionFixture(t)
	share, uri := paidShare(t, p, p.shared, 100)
	order := paidReceipt(t, p, share, p.private)
	nav := paidNavigator(t, p, p.member)
	defer nav.Recycle()
	_, err := nav.To(t.Context(), uri)
	require.ErrorIs(t, err, ErrNotPurchased, "a receipt for another resource must not unlock this share")
	_, err = p.db.PurchaseOrder.UpdateOne(order).SetFileID(p.shared.ID).SetUserID(p.owner.ID).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri)
	require.ErrorIs(t, err, ErrNotPurchased, "another buyer's receipt must not unlock the share")
	_, err = p.db.PurchaseOrder.UpdateOne(order).SetUserID(p.member.ID).SetStatus(purchaseorder.StatusPending).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri)
	require.ErrorIs(t, err, ErrNotPurchased, "pending checkouts are not payment evidence")
	_, err = p.db.PurchaseOrder.UpdateOne(order).SetStatus(purchaseorder.StatusFulfilled).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri)
	require.NoError(t, err)
	_, err = p.db.Share.UpdateOne(share).SetPrice(500).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri.Join("notes.txt"))
	require.NoError(t, err, "a price increase must preserve fulfilled purchases")
	_, err = p.db.Share.UpdateOne(share).SetFileID(p.private.ID).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri)
	require.Error(t, err, "cached navigation cannot access a retargeted share")
	fresh := paidNavigator(t, p, p.member)
	defer fresh.Recycle()
	_, err = fresh.To(t.Context(), uri)
	require.ErrorIs(t, err, ErrNotPurchased)
}

func TestPaidShareCachedFreeAccessAndMovedChildrenCannotBypassPaywall(t *testing.T) {
	p := newPermissionFixture(t)
	share, uri := paidShare(t, p, p.shared, 0)
	sub, err := p.db.File.Create().SetName("Sub").SetType(int(types.FileTypeFolder)).SetOwnerID(p.owner.ID).SetParent(p.shared).Save(t.Context())
	require.NoError(t, err)
	_, err = p.db.File.Create().SetName("secret.txt").SetType(int(types.FileTypeFile)).SetOwnerID(p.owner.ID).SetParent(sub).Save(t.Context())
	require.NoError(t, err)
	nav := paidNavigator(t, p, p.member)
	defer nav.Recycle()
	_, err = nav.To(t.Context(), uri.Join("Sub", "secret.txt"))
	require.NoError(t, err)
	state := shareNavigatorState{ShareRoot: nav.shareRoot, OwnerRoot: nav.ownerRoot, SingleFileShare: nav.singleFileShare, Share: nav.share, Owner: nav.owner}
	restored := paidNavigator(t, p, p.member)
	require.NoError(t, restored.RestoreState(state))
	_, err = p.db.Share.UpdateOne(share).SetPrice(100).Save(t.Context())
	require.NoError(t, err)
	_, err = restored.To(t.Context(), uri.Join("Sub", "secret.txt"))
	require.ErrorIs(t, err, ErrNotPurchased)
	paidReceipt(t, p, share, p.shared)
	_, err = restored.To(t.Context(), uri.Join("Sub", "secret.txt"))
	require.NoError(t, err)
	_, err = p.db.File.UpdateOne(sub).SetParent(p.private).Save(t.Context())
	require.NoError(t, err)
	_, err = restored.To(t.Context(), uri.Join("Sub", "secret.txt"))
	require.Error(t, err, "cached ancestors moved outside the shared subtree must be inaccessible")
}

func TestPaidSingleFileShareCannotExposeSiblingsAndExpiresNormally(t *testing.T) {
	p := newPermissionFixture(t)
	sibling, err := p.db.File.Create().SetName("Sibling").SetType(int(types.FileTypeFolder)).SetOwnerID(p.owner.ID).SetParent(p.shared).Save(t.Context())
	require.NoError(t, err)
	_, err = p.db.File.Create().SetName("secret.txt").SetType(int(types.FileTypeFile)).SetOwnerID(p.owner.ID).SetParent(sibling).Save(t.Context())
	require.NoError(t, err)
	share, uri := paidShare(t, p, p.child, 100)
	paidReceipt(t, p, share, p.child)
	nav := paidNavigator(t, p, p.member)
	defer nav.Recycle()
	_, err = nav.To(t.Context(), uri.Join("notes.txt"))
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri.Join("Sibling", "secret.txt"))
	require.Error(t, err)
	_, err = p.db.Share.UpdateOne(share).SetPassword("private").Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), uri)
	require.ErrorIs(t, err, ErrShareIncorrectPassword, "payment must not bypass passwords")
	passwordURI, err := fs.NewUriFromString(fs.NewShareUri(hashid.EncodeShareID(p.hasher, share.ID), "private"))
	require.NoError(t, err)
	_, err = nav.To(t.Context(), passwordURI.Join("notes.txt"))
	require.NoError(t, err)
	_, err = p.db.Share.UpdateOne(share).SetExpires(time.Now().Add(-time.Minute)).Save(t.Context())
	require.NoError(t, err)
	_, err = nav.To(t.Context(), passwordURI)
	require.ErrorIs(t, err, ErrShareNotFound)
}

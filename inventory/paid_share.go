package inventory

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
)

// CanAccessPaidShare grants a single account access for the lifetime of this
// share. A changed price does not invalidate purchases. Retargeting a share
// cannot transfer an old payment to a different file or seller.
func CanAccessPaidShare(ctx context.Context, db *ent.Client, share *ent.Share, requester *ent.User) (bool, error) {
	if share.Price == 0 || (requester != nil && share.Edges.User != nil && requester.ID == share.Edges.User.ID) {
		return true, nil
	}
	if requester == nil || IsAnonymousUser(requester) || share.Edges.File == nil || share.Edges.User == nil {
		return false, nil
	}
	return db.PurchaseOrder.Query().Where(
		purchaseorder.UserID(requester.ID), purchaseorder.ShareID(share.ID),
		purchaseorder.FileID(share.Edges.File.ID), purchaseorder.SellerID(share.Edges.User.ID),
		purchaseorder.StatusEQ(purchaseorder.StatusFulfilled),
	).Exist(ctx)
}

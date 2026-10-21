package extended

import (
	"context"
	"errors"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gin-gonic/gin"
)

func shareForCheckout(c *gin.Context, id, password string) (*ent.Share, error) {
	dep := dependency.FromContext(c)
	ctx := context.WithValue(c, inventory.LoadShareUser{}, true)
	ctx = context.WithValue(ctx, inventory.LoadShareFile{}, true)
	share, err := dep.ShareClient().GetByHashID(ctx, id)
	if err != nil {
		return nil, errors.New("share is unavailable")
	}
	if err := inventory.IsValidShare(share); err != nil {
		return nil, err
	}
	if share.Password != "" && share.Password != password {
		return nil, errors.New("incorrect share password")
	}
	role, err := inventory.FilePermissionRole(c, dep.DBClient(), share.Edges.File.ID, share.Edges.User.ID)
	if err != nil || role != inventory.FileRoleOwner {
		return nil, errors.New("shared file is unavailable")
	}
	buyer := inventory.UserFromContext(c)
	if buyer == nil || inventory.IsAnonymousUser(buyer) {
		return nil, errors.New("sign in before purchasing a share")
	}
	if buyer.Edges.Group == nil || buyer.Edges.Group.Permissions == nil || !buyer.Edges.Group.Permissions.Enabled(int(types.GroupPermissionShareDownload)) {
		return nil, errors.New("your group cannot access share links")
	}
	if buyer.ID == share.Edges.User.ID || share.Price == 0 {
		return nil, errors.New("this share does not require a purchase")
	}
	paid, err := inventory.CanAccessPaidShare(c, dep.DBClient(), share, buyer)
	if err != nil {
		return nil, err
	}
	if paid {
		return nil, errors.New("you have already purchased this share; refresh to access it")
	}
	return share, nil
}

func CreateShareOrder(c *gin.Context) {
	var input struct {
		ShareID  string `json:"share_id" binding:"required"`
		Password string `json:"password" binding:"max=32"`
		Provider string `json:"provider" binding:"required,oneof=alipay wechat"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	share, err := shareForCheckout(c, input.ShareID, input.Password)
	if err != nil {
		response(c, nil, err)
		return
	}
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	if (input.Provider == "alipay" && config.Alipay.AppID == "") || (input.Provider == "wechat" && config.WeChat.AppID == "") {
		response(c, nil, errors.New("payment provider is not configured"))
		return
	}
	db := dependency.FromContext(c).DBClient()
	uid := inventory.UserFromContext(c).ID
	// Reuse the latest active quote on a repeated checkout action. The amount,
	// resource and seller must still match the current share before reuse.
	order, err := db.PurchaseOrder.Query().Where(purchaseorder.UserID(uid), purchaseorder.ShareID(share.ID),
		purchaseorder.FileID(share.Edges.File.ID), purchaseorder.SellerID(share.Edges.User.ID),
		purchaseorder.Amount(share.Price), purchaseorder.Provider(input.Provider),
		purchaseorder.StatusEQ(purchaseorder.StatusPending), purchaseorder.ExpiresAtGT(time.Now())).
		Order(ent.Desc(purchaseorder.FieldID)).First(c)
	if ent.IsNotFound(err) {
		name := "Share: " + share.Edges.File.Name
		// Payment platforms impose short subject limits. Keep a stable summary;
		// the order also stores resource IDs for the detailed sales record.
		for len(name) > 120 {
			_, size := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-size]
		}
		order, err = db.PurchaseOrder.Create().SetNumber(util.RandStringRunesCrypto(32)).
			SetUserID(uid).SetProvider(input.Provider).SetProductID("share:" + input.ShareID).SetProductName(name).
			SetAmount(share.Price).SetShareID(share.ID).SetFileID(share.Edges.File.ID).SetSellerID(share.Edges.User.ID).
			SetExpiresAt(time.Now().Add(30 * time.Minute)).Save(c)
	}
	if err != nil {
		response(c, nil, err)
		return
	}
	// Do not send a private share's password to a payment provider in return_url.
	checkout(c, config, order, "/home?path="+url.QueryEscape(fs.NewShareUri(input.ShareID, "")))
}

// GetOrder is restricted to the buyer; knowing an order number grants no rights.
func GetOrder(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	order, err := dependency.FromContext(c).DBClient().PurchaseOrder.Query().Where(
		purchaseorder.Number(c.Param("number")), purchaseorder.UserID(inventory.UserFromContext(c).ID),
	).Only(c)
	response(c, order, err)
}

func ShareSales(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	dep := dependency.FromContext(c)
	query := dep.DBClient().PurchaseOrder.Query().Where(purchaseorder.SellerID(inventory.UserFromContext(c).ID), purchaseorder.ShareIDGT(0))
	page, size := pagination(c)
	total, err := query.Clone().Count(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	paid := query.Clone().Where(purchaseorder.StatusEQ(purchaseorder.StatusFulfilled))
	count, err := paid.Clone().Count(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	amount := int64(0)
	if count > 0 {
		var totals []int64
		err = paid.Aggregate(ent.Sum(purchaseorder.FieldAmount)).Scan(c, &totals)
		if err != nil {
			response(c, nil, err)
			return
		}
		if len(totals) == 1 {
			amount = totals[0]
		}
	}
	orders, err := query.Order(ent.Desc(purchaseorder.FieldID)).Offset((page - 1) * size).Limit(size).All(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	items := make([]map[string]any, 0, len(orders))
	for _, order := range orders {
		items = append(items, map[string]any{"number": order.Number, "share_id": hashid.EncodeShareID(dep.HashIDEncoder(), order.ShareID),
			"buyer_id": hashid.EncodeUserID(dep.HashIDEncoder(), order.UserID), "name": order.ProductName, "amount": order.Amount,
			"provider": order.Provider, "status": order.Status, "created_at": order.CreatedAt})
	}
	response(c, map[string]any{"items": items, "total": total, "paid_orders": count, "paid_amount": amount}, nil)
}

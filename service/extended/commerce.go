package extended

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/giftcode"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/payment"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gin-gonic/gin"
)

func CreateOrder(c *gin.Context) {
	var input struct {
		Product  string `json:"product" binding:"required"`
		Provider string `json:"provider" binding:"required,oneof=alipay wechat"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	var product *Product
	for i := range config.Products {
		if config.Products[i].ID == input.Product {
			product = &config.Products[i]
			break
		}
	}
	if product == nil {
		response(c, nil, errors.New("product not found"))
		return
	}
	buyer := inventory.UserFromContext(c)
	if product.GroupID > 0 && buyer.Edges.Group != nil && buyer.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
		response(c, nil, errors.New("administrator accounts cannot purchase group changes"))
		return
	}
	if (input.Provider == "alipay" && config.Alipay.AppID == "") || (input.Provider == "wechat" && config.WeChat.AppID == "") {
		response(c, nil, errors.New("payment provider is not configured"))
		return
	}
	dep := dependency.FromContext(c)
	order, err := dep.DBClient().PurchaseOrder.Create().SetNumber(util.RandStringRunesCrypto(32)).
		SetUserID(inventory.UserFromContext(c).ID).SetProvider(input.Provider).SetProductID(product.ID).SetProductName(product.Name).
		SetAmount(product.Amount).SetStorageBytes(product.StorageBytes).SetGroupID(product.GroupID).SetExpiresAt(time.Now().Add(30 * time.Minute)).Save(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	checkout(c, config, order, "/shop")
}

// checkout uses only the server-side order snapshot for gateway requests.
func checkout(c *gin.Context, config *Config, order *ent.PurchaseOrder, returnPath string) {
	args := payment.Order{Number: order.Number, Name: order.ProductName, Amount: order.Amount,
		NotifyURL: siteURL(c, constants.APIPrefix+"/payments/"+order.Provider+"/notify"), ReturnURL: siteURL(c, returnPath)}
	var paymentURL string
	var err error
	if order.Provider == "alipay" {
		paymentURL, err = payment.AlipayURL(config.Alipay, args)
	} else {
		paymentURL, err = payment.WeChatURL(c, externalHTTP, config.WeChat, args)
	}
	if err != nil {
		_, _ = dependency.FromContext(c).DBClient().PurchaseOrder.Update().Where(purchaseorder.ID(order.ID), purchaseorder.StatusEQ(purchaseorder.StatusPending)).SetStatus(purchaseorder.StatusCancelled).Save(c)
		response(c, nil, err)
		return
	}
	response(c, map[string]any{"order": order, "url": paymentURL}, nil)
}

func ListOrders(c *gin.Context) {
	listOrders(c, false)
}

func listOrders(c *gin.Context, admin bool) {
	query := dependency.FromContext(c).DBClient().PurchaseOrder.Query()
	if !admin {
		query.Where(purchaseorder.UserID(inventory.UserFromContext(c).ID))
	}
	page, size := pagination(c)
	total, err := query.Clone().Count(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	orders, err := query.Order(ent.Desc(purchaseorder.FieldID)).Offset((page - 1) * size).Limit(size).All(c)
	response(c, map[string]any{"items": orders, "total": total}, err)
}

func AdminListOrders(c *gin.Context) {
	listOrders(c, true)
}

func applyBenefit(c *gin.Context, tx *ent.Tx, uid int, storage int64, groupID int) error {
	query := tx.User.Update().Where(user.ID(uid))
	if storage < 0 {
		return errors.New("invalid storage benefit")
	}
	if storage > 0 {
		query.Where(user.ExtraStorageLTE(math.MaxInt64 - storage)).AddExtraStorage(storage)
	}
	if groupID > 0 {
		group, err := tx.Group.Get(c, groupID)
		if err != nil || group.ID <= 3 || group.Permissions == nil || group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
			return errors.New("invalid product group")
		}
		beneficiary, err := tx.User.Query().Where(user.ID(uid)).WithGroup().Only(c)
		if err != nil {
			return err
		}
		// A pending checkout must not demote an account elevated in the meantime.
		if beneficiary.Edges.Group == nil || !beneficiary.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
			query.SetGroupID(groupID)
		}
	}
	count, err := query.Save(c)
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("beneficiary missing or capacity overflow")
	}
	return nil
}

func fulfill(c *gin.Context, provider string, notice *payment.Notification) error {
	dep := dependency.FromContext(c)
	tx, err := dep.DBClient().Tx(c)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	order, err := tx.PurchaseOrder.Query().Where(purchaseorder.Number(notice.Number)).Only(c)
	if err != nil {
		return err
	}
	if order.Provider != provider || order.Amount != notice.Amount || order.Currency != notice.Currency {
		return errors.New("payment does not match the stored order")
	}
	if order.Status == purchaseorder.StatusFulfilled {
		if order.TransactionID != notice.TransactionID {
			return errors.New("conflicting payment transaction")
		}
		return nil
	}
	// The provider's verified paid notification is authoritative even when delivery
	// arrives after the checkout expiration. Credit the customer exactly once.
	if order.Status != purchaseorder.StatusPending {
		return errors.New("order is not payable")
	}
	count, err := tx.PurchaseOrder.Update().Where(purchaseorder.ID(order.ID), purchaseorder.StatusEQ(purchaseorder.StatusPending)).
		SetStatus(purchaseorder.StatusFulfilled).SetTransactionID(notice.TransactionID).Save(c)
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("order is being fulfilled; retry notification")
	}
	if order.ShareID > 0 {
		if order.FileID <= 0 || order.SellerID <= 0 || order.SellerID == order.UserID || order.StorageBytes != 0 || order.GroupID != 0 {
			return errors.New("invalid share order snapshot")
		}
		// A verified payment is recorded even if the seller has since removed
		// or changed the share. Access checks bind to the original resource.
	} else if err := applyBenefit(c, tx, order.UserID, order.StorageBytes, order.GroupID); err != nil {
		return err
	}
	return tx.Commit()
}

func PaymentNotify(c *gin.Context) {
	config, err := readConfig(c)
	if err != nil {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	provider := c.Param("provider")
	var notice *payment.Notification
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	switch provider {
	case "alipay":
		err = c.Request.ParseForm()
		if err == nil {
			notice, err = payment.ParseAlipay(config.Alipay, c.Request.PostForm)
		}
	case "wechat":
		var body []byte
		body, err = io.ReadAll(c.Request.Body)
		if err == nil {
			notice, err = payment.ParseWeChat(config.WeChat, c.Request.Header, body)
		}
	default:
		c.Status(http.StatusNotFound)
		return
	}
	if err == nil {
		err = fulfill(c, provider, notice)
	}
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if provider == "alipay" {
		c.String(http.StatusOK, "success")
	} else {
		c.Status(http.StatusNoContent)
	}
}

func codeHash(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}

func AdminGiftCodes(c *gin.Context) {
	db := dependency.FromContext(c).DBClient()
	if c.Request.Method == http.MethodGet {
		page, size := pagination(c)
		total, err := db.GiftCode.Query().Count(c)
		if err != nil {
			response(c, nil, err)
			return
		}
		items, err := db.GiftCode.Query().Order(ent.Desc(giftcode.FieldID)).Offset((page - 1) * size).Limit(size).All(c)
		response(c, map[string]any{"items": items, "total": total}, err)
		return
	}
	var input struct {
		Product string `json:"product" binding:"required"`
		Count   int    `json:"count" binding:"min=1,max=100"`
		Days    int    `json:"days" binding:"min=1,max=3650"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	config, err := readConfig(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	var product *Product
	for i := range config.Products {
		if config.Products[i].ID == input.Product {
			product = &config.Products[i]
			break
		}
	}
	if product == nil {
		response(c, nil, errors.New("product not found"))
		return
	}
	tx, err := db.Tx(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	defer tx.Rollback()
	codes := make([]string, 0, input.Count)
	for i := 0; i < input.Count; i++ {
		code := util.RandStringRunesCrypto(32)
		_, err := tx.GiftCode.Create().SetCodeHash(codeHash(code)).SetProductName(product.Name).SetStorageBytes(product.StorageBytes).SetGroupID(product.GroupID).
			SetExpiresAt(time.Now().AddDate(0, 0, input.Days)).Save(c)
		if err != nil {
			response(c, nil, err)
			return
		}
		codes = append(codes, code)
	}
	if err := tx.Commit(); err != nil {
		response(c, nil, err)
		return
	}
	response(c, map[string]any{"codes": codes}, nil)
}

func Redeem(c *gin.Context) {
	var input struct {
		Code string `json:"code" binding:"required,min=32,max=32"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	dep := dependency.FromContext(c)
	tx, err := dep.DBClient().Tx(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	defer tx.Rollback()
	code, err := tx.GiftCode.Query().Where(giftcode.CodeHash(codeHash(input.Code)), giftcode.RedeemedBy(0), giftcode.ExpiresAtGT(time.Now())).Only(c)
	if err != nil {
		response(c, nil, errors.New("gift code is invalid, expired or already redeemed"))
		return
	}
	uid := inventory.UserFromContext(c).ID
	count, err := tx.GiftCode.Update().Where(giftcode.ID(code.ID), giftcode.RedeemedBy(0)).SetRedeemedBy(uid).SetRedeemedAt(time.Now()).Save(c)
	if err != nil || count != 1 {
		response(c, nil, errors.New("gift code is already being redeemed"))
		return
	}
	if err := applyBenefit(c, tx, uid, code.StorageBytes, code.GroupID); err != nil {
		response(c, nil, err)
		return
	}
	response(c, map[string]bool{"redeemed": true}, tx.Commit())
}

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	size, _ := strconv.Atoi(c.Query("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	if page > 100000 {
		page = 100000
	}
	return page, size
}

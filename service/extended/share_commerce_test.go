package extended

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/payment"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type sharePaymentSettings struct{ setting.Provider }

func (sharePaymentSettings) SiteURL(context.Context) *url.URL {
	u, _ := url.Parse("https://drive.example.test")
	return u
}

type shareCommerceFixture struct {
	db            *ent.Client
	buyer, seller *ent.User
	share         *ent.Share
	file          *ent.File
	dep           dependency.Dep
	hasher        hashid.Encoder
}

func newShareCommerceFixture(t *testing.T) *shareCommerceFixture {
	t.Helper()
	_, db, uid := commerceContext(t)
	buyer, err := db.User.Query().WithGroup().Only(t.Context())
	require.NoError(t, err)
	require.Equal(t, uid, buyer.ID)
	boolset.Set(types.GroupPermissionShareDownload, true, buyer.Edges.Group.Permissions)
	_, err = db.Group.UpdateOne(buyer.Edges.Group).SetPermissions(buyer.Edges.Group.Permissions).Save(t.Context())
	require.NoError(t, err)
	seller, err := db.User.Create().SetEmail("seller@example.test").SetNick("Seller").SetGroupID(buyer.GroupUsers).Save(t.Context())
	require.NoError(t, err)
	seller.Edges.Group = buyer.Edges.Group
	root, err := db.File.Create().SetName("").SetOwnerID(seller.ID).SetType(int(types.FileTypeFolder)).Save(t.Context())
	require.NoError(t, err)
	file, err := db.File.Create().SetName("Paid folder").SetOwnerID(seller.ID).SetType(int(types.FileTypeFolder)).SetParent(root).Save(t.Context())
	require.NoError(t, err)
	share, err := db.Share.Create().SetUserID(seller.ID).SetFileID(file.ID).SetPrice(199).SetPassword("private").Save(t.Context())
	require.NoError(t, err)
	hasher, err := hashid.New("paid-share-api-test")
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	config := Config{Alipay: payment.Config{AppID: "app", MerchantID: "merchant", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))}}
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	_, err = db.Setting.Create().SetName(configKey).SetValue(string(encoded)).Save(t.Context())
	require.NoError(t, err)
	dep := dependency.NewDependency(dependency.WithDbClient(db), dependency.WithHashIDEncoder(hasher), dependency.WithSettingClient(inventory.NewSettingClient(db, nil)),
		dependency.WithShareClient(inventory.NewShareClient(db, conf.SQLiteDB, hasher)), dependency.WithSettingProvider(sharePaymentSettings{}))
	return &shareCommerceFixture{db: db, buyer: buyer, seller: seller, share: share, file: file, dep: dep, hasher: hasher}
}

func (f *shareCommerceFixture) request(t *testing.T, actor *ent.User, method string, input any, handler gin.HandlerFunc, number string) (*gin.Context, int, json.RawMessage) {
	t.Helper()
	body, err := json.Marshal(input)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	engine.ContextWithFallback = true
	ctx := context.WithValue(t.Context(), dependency.DepCtx{}, f.dep)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
	c.Request = httptest.NewRequest(method, "/commerce/share-orders", bytes.NewReader(body)).WithContext(ctx)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "number", Value: number}}
	handler(c)
	var response struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if w.Body.Len() > 0 {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	}
	return c, response.Code, response.Data
}

func (f *shareCommerceFixture) input() map[string]any {
	return map[string]any{"share_id": hashid.EncodeShareID(f.hasher, f.share.ID), "password": "private", "provider": "alipay", "amount": 1}
}

func TestPaidShareCheckoutUsesServerPriceAndVerifiedPayment(t *testing.T) {
	f := newShareCommerceFixture(t)
	c, code, data := f.request(t, f.buyer, http.MethodPost, f.input(), CreateShareOrder, "")
	require.Zero(t, code)
	var checkout struct {
		Order ent.PurchaseOrder `json:"order"`
		URL   string            `json:"url"`
	}
	require.NoError(t, json.Unmarshal(data, &checkout))
	require.Equal(t, int64(199), checkout.Order.Amount, "browser-supplied totals are ignored")
	require.Equal(t, f.seller.ID, checkout.Order.SellerID)
	require.Equal(t, f.share.ID, checkout.Order.ShareID)
	gateway, err := url.Parse(checkout.URL)
	require.NoError(t, err)
	returnURL, err := url.Parse(gateway.Query().Get("return_url"))
	require.NoError(t, err)
	require.Equal(t, "/home", returnURL.Path)
	require.NotEmpty(t, returnURL.Query().Get("path"))
	require.NotContains(t, returnURL.String(), "private", "share passwords must not be sent to the payment provider")
	_, code, second := f.request(t, f.buyer, http.MethodPost, f.input(), CreateShareOrder, "")
	require.Zero(t, code)
	var duplicate struct {
		Order ent.PurchaseOrder `json:"order"`
	}
	require.NoError(t, json.Unmarshal(second, &duplicate))
	require.Equal(t, checkout.Order.Number, duplicate.Order.Number, "repeat checkout should reuse an active matching quote")
	notice := &payment.Notification{Number: checkout.Order.Number, TransactionID: "verified-transaction", Amount: 1, Currency: "CNY"}
	require.Error(t, fulfill(c, "alipay", notice))
	notice.Amount = checkout.Order.Amount
	require.Error(t, fulfill(c, "wechat", notice))
	notice.Currency = "USD"
	require.Error(t, fulfill(c, "alipay", notice))
	notice.Currency = "CNY"
	_, err = f.db.Share.UpdateOne(f.share).SetPrice(299).Save(t.Context())
	require.NoError(t, err)
	require.NoError(t, fulfill(c, "alipay", notice), "fulfillment uses the checkout quote, not a later price")
	require.NoError(t, fulfill(c, "alipay", notice), "replayed callbacks must be idempotent")
	buyer, err := f.db.User.Get(t.Context(), f.buyer.ID)
	require.NoError(t, err)
	require.Zero(t, buyer.ExtraStorage)
	require.Equal(t, f.buyer.GroupUsers, buyer.GroupUsers)
	_, code, _ = f.request(t, f.buyer, http.MethodPost, f.input(), CreateShareOrder, "")
	require.NotZero(t, code, "an already purchased share must not create another order")
	notice.TransactionID = "conflicting-transaction"
	require.Error(t, fulfill(c, "alipay", notice))
}

func TestPaidShareOrderVisibilityAndSalesOwnership(t *testing.T) {
	f := newShareCommerceFixture(t)
	c, code, data := f.request(t, f.buyer, http.MethodPost, f.input(), CreateShareOrder, "")
	require.Zero(t, code)
	var result struct {
		Order ent.PurchaseOrder `json:"order"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.NoError(t, fulfill(c, "alipay", &payment.Notification{Number: result.Order.Number, TransactionID: "paid", Amount: 199, Currency: "CNY"}))
	_, code, _ = f.request(t, f.buyer, http.MethodGet, nil, GetOrder, result.Order.Number)
	require.Zero(t, code)
	_, code, _ = f.request(t, f.seller, http.MethodGet, nil, GetOrder, result.Order.Number)
	require.NotZero(t, code, "only the buyer can poll their payment order")
	_, code, data = f.request(t, f.seller, http.MethodGet, nil, ShareSales, "")
	require.Zero(t, code)
	var sales struct {
		Items      []map[string]any `json:"items"`
		PaidAmount int64            `json:"paid_amount"`
		PaidOrders int              `json:"paid_orders"`
	}
	require.NoError(t, json.Unmarshal(data, &sales))
	require.Len(t, sales.Items, 1)
	require.Equal(t, int64(199), sales.PaidAmount)
	require.Equal(t, 1, sales.PaidOrders)
	require.NotContains(t, string(data), f.buyer.Email)
	_, code, data = f.request(t, f.buyer, http.MethodGet, nil, ShareSales, "")
	require.Zero(t, code)
	require.NoError(t, json.Unmarshal(data, &sales))
	require.Empty(t, sales.Items)
	require.Zero(t, sales.PaidAmount)
}

func TestPaidShareCheckoutRejectsInvalidPasswordOwnerAndDeletedSource(t *testing.T) {
	f := newShareCommerceFixture(t)
	input := f.input()
	input["password"] = "incorrect"
	_, code, _ := f.request(t, f.buyer, http.MethodPost, input, CreateShareOrder, "")
	require.NotZero(t, code)
	_, code, _ = f.request(t, f.seller, http.MethodPost, f.input(), CreateShareOrder, "")
	require.NotZero(t, code)
	_, err := f.db.File.UpdateOne(f.file).SetName("trashed").ClearParent().Save(t.Context())
	require.NoError(t, err)
	_, code, _ = f.request(t, f.buyer, http.MethodPost, f.input(), CreateShareOrder, "")
	require.NotZero(t, code)
	count, err := f.db.PurchaseOrder.Query().Where(purchaseorder.ShareID(f.share.ID)).Count(t.Context())
	require.NoError(t, err)
	require.Zero(t, count)
}

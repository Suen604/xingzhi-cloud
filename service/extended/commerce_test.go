package extended

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/ent/purchaseorder"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/payment"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func commerceContext(t *testing.T) (*gin.Context, *ent.Client, int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "commerce.db"))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	group, err := db.Group.Create().SetName("members").SetPermissions(&boolset.BooleanSet{}).Save(t.Context())
	require.NoError(t, err)
	user, err := db.User.Create().SetEmail("buyer@example.com").SetNick("Buyer").SetGroupID(group.ID).Save(t.Context())
	require.NoError(t, err)
	c, engine := gin.CreateTestContext(httptest.NewRecorder())
	engine.ContextWithFallback = true
	c.Request = httptest.NewRequest("POST", "/notify", nil).WithContext(context.WithValue(t.Context(), dependency.DepCtx{}, dependency.NewDependency(dependency.WithDbClient(db))))
	return c, db, user.ID
}

func TestPaymentFulfillmentIsIdempotentAndChecksOrder(t *testing.T) {
	c, db, uid := commerceContext(t)
	order, err := db.PurchaseOrder.Create().SetNumber("order").SetUserID(uid).SetProvider("alipay").SetProductID("storage").SetProductName("Storage").SetAmount(123).
		SetStorageBytes(4096).SetExpiresAt(time.Now().Add(-time.Minute)).Save(c)
	require.NoError(t, err)
	notice := &payment.Notification{Number: "order", TransactionID: "transaction", Amount: 123, Currency: "CNY"}
	wrong := *notice
	wrong.Amount = 1
	require.Error(t, fulfill(c, "alipay", &wrong))
	require.Error(t, fulfill(c, "wechat", notice))
	unchanged, err := db.User.Get(c, uid)
	require.NoError(t, err)
	require.Zero(t, unchanged.ExtraStorage)
	require.NoError(t, fulfill(c, "alipay", notice))
	require.NoError(t, fulfill(c, "alipay", notice))
	beneficiary, err := db.User.Get(c, uid)
	require.NoError(t, err)
	require.Equal(t, int64(4096), beneficiary.ExtraStorage)
	stored, err := db.PurchaseOrder.Get(c, order.ID)
	require.NoError(t, err)
	require.Equal(t, purchaseorder.StatusFulfilled, stored.Status)
	wrong = *notice
	wrong.TransactionID = "other-transaction"
	require.Error(t, fulfill(c, "alipay", &wrong))
}

func TestFailedBenefitRollsBackPayment(t *testing.T) {
	c, db, uid := commerceContext(t)
	_, err := db.PurchaseOrder.Create().SetNumber("order").SetUserID(uid).SetProvider("alipay").SetProductID("group").SetProductName("Group").SetAmount(100).
		SetStorageBytes(4096).SetGroupID(999).SetExpiresAt(time.Now().Add(time.Minute)).Save(c)
	require.NoError(t, err)
	require.Error(t, fulfill(c, "alipay", &payment.Notification{Number: "order", TransactionID: "transaction", Amount: 100, Currency: "CNY"}))
	stored, err := db.PurchaseOrder.Query().Where(purchaseorder.Number("order")).Only(c)
	require.NoError(t, err)
	require.Equal(t, purchaseorder.StatusPending, stored.Status)
	beneficiary, err := db.User.Get(c, uid)
	require.NoError(t, err)
	require.Zero(t, beneficiary.ExtraStorage)
}

func TestGiftCodeCanOnlyBeRedeemedOnce(t *testing.T) {
	c, db, uid := commerceContext(t)
	user, err := db.User.Get(c, uid)
	require.NoError(t, err)
	code := strings.Repeat("A", 32)
	_, err = db.GiftCode.Create().SetCodeHash(codeHash(code)).SetProductName("Storage").SetStorageBytes(1024).SetExpiresAt(time.Now().Add(time.Hour)).Save(c)
	require.NoError(t, err)
	for attempt := 0; attempt < 2; attempt++ {
		body, err := json.Marshal(map[string]string{"code": code})
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodPost, "/commerce/redeem", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(context.WithValue(c.Request.Context(), inventory.UserCtx{}, user))
		recorder := httptest.NewRecorder()
		next, engine := gin.CreateTestContext(recorder)
		engine.ContextWithFallback = true
		next.Request = request
		Redeem(next)
		var response struct {
			Code int `json:"code"`
		}
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		if attempt == 0 {
			require.Zero(t, response.Code)
		} else {
			require.NotZero(t, response.Code)
		}
	}
	beneficiary, err := db.User.Get(c, uid)
	require.NoError(t, err)
	require.Equal(t, int64(1024), beneficiary.ExtraStorage)
}

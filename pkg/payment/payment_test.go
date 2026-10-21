package payment

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

func TestAlipaySignaturesAndExactAmount(t *testing.T) {
	private, public := keys(t)
	cfg := Config{AppID: "app", MerchantID: "seller", PrivateKey: private, PublicKey: public}
	redirect, err := AlipayURL(cfg, Order{Number: "order", Name: "容量", Amount: 123, NotifyURL: "https://example.org/notify", ReturnURL: "https://example.org/shop"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	values := u.Query()
	message, err := canonicalParameters(values, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(public, message, values.Get("sign")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "sign_type=RSA2") {
		t.Fatal("request signature must include the signature algorithm")
	}
	if !strings.Contains(values.Get("biz_content"), `"total_amount":"1.23"`) {
		t.Fatal("checkout amount lost precision")
	}
	base := url.Values{"app_id": {"app"}, "seller_id": {"seller"}, "sign_type": {"RSA2"}, "trade_status": {"TRADE_SUCCESS"}, "total_amount": {"1.23"}, "out_trade_no": {"order"}, "trade_no": {"transaction"}}
	for _, tc := range []struct {
		name, key, value string
		valid            bool
	}{
		{"paid", "", "", true}, {"tampered amount", "total_amount", "9.99", false}, {"wrong app", "app_id", "other", false}, {"wrong seller", "seller_id", "other", false}, {"not paid", "trade_status", "WAIT_BUYER_PAY", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := url.Values{}
			for k, v := range base {
				values[k] = append([]string(nil), v...)
			}
			if tc.key != "" && tc.key != "total_amount" {
				values.Set(tc.key, tc.value)
			}
			message, _ := canonical(values)
			signature, err := sign(private, message)
			if err != nil {
				t.Fatal(err)
			}
			values.Set("sign", signature)
			if tc.key == "total_amount" {
				values.Set(tc.key, tc.value)
			}
			notice, err := ParseAlipay(cfg, values)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected verification result: %v", err)
			}
			if tc.valid && (notice.Amount != 123 || notice.Number != "order") {
				t.Fatalf("unexpected payment: %+v", notice)
			}
		})
	}
	base["total_amount"] = []string{"1.23", "99.99"}
	if _, err := ParseAlipay(cfg, base); err == nil {
		t.Fatal("duplicate amount was accepted")
	}
}

func TestWeChatSignatureAndAuthenticatedResource(t *testing.T) {
	private, public := keys(t)
	cfg := Config{AppID: "app", MerchantID: "merchant", PublicKey: public, PlatformSerial: "platform", APIKey: strings.Repeat("x", 32)}
	block, _ := aes.NewCipher([]byte(cfg.APIKey))
	gcm, _ := cipher.NewGCM(block)
	nonce := "123456789012"
	trade := []byte(`{"appid":"app","mchid":"merchant","out_trade_no":"order","transaction_id":"transaction","trade_state":"SUCCESS","amount":{"total":123,"currency":"CNY"}}`)
	encrypted := gcm.Seal(nil, []byte(nonce), trade, []byte("transaction"))
	body, err := json.Marshal(map[string]any{"event_type": "TRANSACTION.SUCCESS", "resource": map[string]string{"algorithm": "AEAD_AES_256_GCM", "nonce": nonce, "associated_data": "transaction", "ciphertext": base64.StdEncoding.EncodeToString(encrypted)}})
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{"Wechatpay-Serial": {"platform"}, "Wechatpay-Nonce": {"notification"}, "Wechatpay-Timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}}
	signBody := func() {
		signature, err := sign(private, header.Get("Wechatpay-Timestamp")+"\n"+header.Get("Wechatpay-Nonce")+"\n"+string(body)+"\n")
		if err != nil {
			t.Fatal(err)
		}
		header.Set("Wechatpay-Signature", signature)
	}
	signBody()
	notice, err := ParseWeChat(cfg, header, body)
	if err != nil || notice.Amount != 123 {
		t.Fatalf("valid payment rejected: %+v %v", notice, err)
	}
	if _, err := ParseWeChat(cfg, header, append(body, ' ')); err == nil {
		t.Fatal("tampered notification accepted")
	}
	wrong := cfg
	wrong.MerchantID = "other"
	if _, err := ParseWeChat(wrong, header, body); err == nil {
		t.Fatal("another merchant's payment accepted")
	}
	wrong = cfg
	wrong.APIKey = strings.Repeat("y", 32)
	if _, err := ParseWeChat(wrong, header, body); err == nil {
		t.Fatal("resource authentication failure ignored")
	}
	header.Set("Wechatpay-Timestamp", strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10))
	signBody()
	if _, err := ParseWeChat(cfg, header, body); err == nil {
		t.Fatal("expired signature accepted")
	}
}

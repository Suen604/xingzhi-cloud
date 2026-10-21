// Package payment implements Alipay RSA2 page payments and WeChat Pay API v3 native payments.
package payment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppID          string `json:"app_id"`
	MerchantID     string `json:"merchant_id,omitempty"`
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"public_key"`
	Serial         string `json:"serial,omitempty"`
	PlatformSerial string `json:"platform_serial,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
	Sandbox        bool   `json:"sandbox,omitempty"`
}

type Order struct {
	Number    string
	Name      string
	Amount    int64 // Integer fen; never accept a browser-supplied total.
	NotifyURL string
	ReturnURL string
}

type Notification struct {
	Number        string
	TransactionID string
	Amount        int64
	Currency      string
}

func ValidateConfig(provider string, cfg Config) error {
	if cfg.AppID == "" {
		return errors.New("payment application ID is required")
	}
	private, err := privateKey(cfg.PrivateKey)
	if err != nil {
		return err
	}
	if private.N.BitLen() < 2048 {
		return errors.New("payment private keys must be at least 2048 bits")
	}
	if _, err := publicKey(cfg.PublicKey); err != nil {
		return err
	}
	switch provider {
	case "alipay":
		if cfg.MerchantID == "" {
			return errors.New("Alipay seller ID is required")
		}
	case "wechat":
		if cfg.MerchantID == "" || cfg.Serial == "" || cfg.PlatformSerial == "" || len(cfg.APIKey) != 32 {
			return errors.New("WeChat merchant ID, certificate serials and 32-byte API v3 key are required")
		}
	default:
		return errors.New("unknown payment provider")
	}
	return nil
}

func privateKey(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("missing PEM private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func publicKey(text string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("missing PEM public key or certificate")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return nil, errors.New("payment platform certificate is not currently valid")
		}
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func sign(keyText, message string) (string, error) {
	key, err := privateKey(keyText)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return base64.StdEncoding.EncodeToString(sig), err
}

func verify(keyText, message, signature string) error {
	key, err := publicKey(keyText)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(message))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)
}

func canonical(values url.Values) (string, error) {
	return canonicalParameters(values, false)
}

// Alipay includes sign_type when signing requests, but omits it when checking
// notification signatures (rsaCheckV1).
func canonicalParameters(values url.Values, includeSignType bool) (string, error) {
	keys := make([]string, 0, len(values))
	for k, v := range values {
		if len(v) != 1 {
			return "", errors.New("duplicate payment parameter")
		}
		if k != "sign" && (k != "sign_type" || includeSignType) && v[0] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+values.Get(k))
	}
	return strings.Join(parts, "&"), nil
}

func AlipayURL(cfg Config, order Order) (string, error) {
	if cfg.AppID == "" || order.Amount <= 0 {
		return "", errors.New("invalid Alipay configuration or order")
	}
	biz, err := json.Marshal(map[string]string{
		"out_trade_no": order.Number, "product_code": "FAST_INSTANT_TRADE_PAY", "subject": order.Name,
		"total_amount": fmt.Sprintf("%d.%02d", order.Amount/100, order.Amount%100), "timeout_express": "30m",
	})
	if err != nil {
		return "", err
	}
	values := url.Values{
		"app_id": {cfg.AppID}, "method": {"alipay.trade.page.pay"}, "charset": {"utf-8"}, "sign_type": {"RSA2"},
		"timestamp": {time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")},
		"version":   {"1.0"}, "notify_url": {order.NotifyURL}, "return_url": {order.ReturnURL}, "biz_content": {string(biz)},
	}
	message, err := canonicalParameters(values, true)
	if err != nil {
		return "", err
	}
	signature, err := sign(cfg.PrivateKey, message)
	if err != nil {
		return "", err
	}
	values.Set("sign", signature)
	endpoint := "https://openapi.alipay.com/gateway.do"
	if cfg.Sandbox {
		endpoint = "https://openapi-sandbox.dl.alipaydev.com/gateway.do"
	}
	return endpoint + "?" + values.Encode(), nil
}

func ParseAlipay(cfg Config, values url.Values) (*Notification, error) {
	message, err := canonical(values)
	if err != nil {
		return nil, err
	}
	if values.Get("sign_type") != "RSA2" || values.Get("app_id") != cfg.AppID ||
		(cfg.MerchantID != "" && values.Get("seller_id") != cfg.MerchantID) {
		return nil, errors.New("unexpected Alipay merchant or signature algorithm")
	}
	if err := verify(cfg.PublicKey, message, values.Get("sign")); err != nil {
		return nil, err
	}
	if status := values.Get("trade_status"); status != "TRADE_SUCCESS" && status != "TRADE_FINISHED" {
		return nil, errors.New("Alipay trade has not been paid")
	}
	parts := strings.Split(values.Get("total_amount"), ".")
	if len(parts) != 2 || len(parts[1]) != 2 {
		return nil, errors.New("invalid payment amount")
	}
	for _, digit := range parts[0] + parts[1] {
		if digit < '0' || digit > '9' {
			return nil, errors.New("invalid payment amount")
		}
	}
	amount, err := strconv.ParseInt(parts[0]+parts[1], 10, 64)
	if err != nil || amount <= 0 {
		return nil, errors.New("invalid payment amount")
	}
	if values.Get("out_trade_no") == "" || values.Get("trade_no") == "" {
		return nil, errors.New("missing trade number")
	}
	return &Notification{values.Get("out_trade_no"), values.Get("trade_no"), amount, "CNY"}, nil
}

func WeChatURL(ctx context.Context, client *http.Client, cfg Config, order Order) (string, error) {
	if cfg.AppID == "" || cfg.MerchantID == "" || cfg.Serial == "" || order.Amount <= 0 {
		return "", errors.New("invalid WeChat merchant configuration or order")
	}
	body, err := json.Marshal(map[string]any{
		"appid": cfg.AppID, "mchid": cfg.MerchantID, "description": order.Name, "out_trade_no": order.Number,
		"notify_url": order.NotifyURL, "amount": map[string]any{"total": order.Amount, "currency": "CNY"},
		"time_expire": time.Now().Add(30 * time.Minute).Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	path := "/v3/pay/transactions/native"
	signature, err := sign(cfg.PrivateKey, "POST\n"+path+"\n"+timestamp+"\n"+nonce+"\n"+string(body)+"\n")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.mch.weixin.qq.com"+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",timestamp="%s",serial_no="%s",signature="%s"`, cfg.MerchantID, nonce, timestamp, cfg.Serial, signature))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WeChat payment request failed (%d)", resp.StatusCode)
	}
	if err := verifyWeChat(cfg, resp.Header, data, time.Now()); err != nil {
		return "", err
	}
	var result struct {
		CodeURL string `json:"code_url"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	if !strings.HasPrefix(result.CodeURL, "weixin://wxpay/") {
		return "", errors.New("invalid WeChat payment URL")
	}
	return result.CodeURL, nil
}

func verifyWeChat(cfg Config, header http.Header, body []byte, now time.Time) error {
	ts, err := strconv.ParseInt(header.Get("Wechatpay-Timestamp"), 10, 64)
	if err != nil || ts < now.Unix()-300 || ts > now.Unix()+300 {
		return errors.New("expired WeChat signature")
	}
	if cfg.PlatformSerial == "" || header.Get("Wechatpay-Serial") != cfg.PlatformSerial {
		return errors.New("unknown WeChat platform key")
	}
	return verify(cfg.PublicKey, header.Get("Wechatpay-Timestamp")+"\n"+header.Get("Wechatpay-Nonce")+"\n"+string(body)+"\n", header.Get("Wechatpay-Signature"))
}

func ParseWeChat(cfg Config, header http.Header, body []byte) (*Notification, error) {
	if err := verifyWeChat(cfg, header, body, time.Now()); err != nil {
		return nil, err
	}
	var envelope struct {
		EventType string `json:"event_type"`
		Resource  struct {
			Algorithm      string `json:"algorithm"`
			Ciphertext     string `json:"ciphertext"`
			Nonce          string `json:"nonce"`
			AssociatedData string `json:"associated_data"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if envelope.EventType != "TRANSACTION.SUCCESS" || envelope.Resource.Algorithm != "AEAD_AES_256_GCM" || len(cfg.APIKey) != 32 {
		return nil, errors.New("unexpected WeChat event or API key")
	}
	block, err := aes.NewCipher([]byte(cfg.APIKey))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(envelope.Resource.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid WeChat nonce")
	}
	encrypted, err := base64.StdEncoding.DecodeString(envelope.Resource.Ciphertext)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, []byte(envelope.Resource.Nonce), encrypted, []byte(envelope.Resource.AssociatedData))
	if err != nil {
		return nil, err
	}
	var trade struct {
		AppID         string `json:"appid"`
		MerchantID    string `json:"mchid"`
		Number        string `json:"out_trade_no"`
		TransactionID string `json:"transaction_id"`
		State         string `json:"trade_state"`
		Amount        struct {
			Total    int64  `json:"total"`
			Currency string `json:"currency"`
		} `json:"amount"`
	}
	if err := json.Unmarshal(plain, &trade); err != nil {
		return nil, err
	}
	if trade.AppID != cfg.AppID || trade.MerchantID != cfg.MerchantID || trade.State != "SUCCESS" ||
		trade.Amount.Total <= 0 || trade.Amount.Currency != "CNY" || trade.Number == "" || trade.TransactionID == "" {
		return nil, errors.New("unexpected WeChat merchant or trade")
	}
	return &Notification{trade.Number, trade.TransactionID, trade.Amount.Total, trade.Amount.Currency}, nil
}

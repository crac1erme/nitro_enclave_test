package req

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
}

// DecryptRequest 解密接口请求结构体
type DecryptRequest struct {
	KeyID         string `json:"key_id"`         // 加密时使用的密钥ID
	EncryptedData string `json:"encrypted_data"` // 加密后的密文
}

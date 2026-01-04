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

type BackupRequest struct {
	KeyID          string `json:"key_id"`          //标识
	CiphertextBlob string `json:"ciphertext_blob"` //密文data key
	Encrypt_Aeskey string `json:"aes_key"`         //密文 aeskey 使用datakey加密的
}

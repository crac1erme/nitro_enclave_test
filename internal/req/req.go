package req

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
}

type KMSDecryptRequest struct {
	CiphertextBlob string `json:"ciphertext_blob"` // Base64 编码的密文
	AttestationDoc string `json:"attestation_doc"` // Enclave已获取的远程证明文档（Base64）
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

type S3PullAllRequest struct {
	Bucket string `json:"bucket"` // S3桶名
	Prefix string `json:"prefix"` // 密钥前缀（如aes-key-）
}

type S3FullFetchRequest struct {
	Prefix string `json:"prefix,omitempty"` // 可选：拉取指定前缀的密钥，空则全量
}

package resp

type KMSDecryptResponse struct {
	Status    string `json:"status"`
	Plaintext string `json:"plaintext,omitempty"` // Base64 编码的明文
	Msg       string `json:"msg,omitempty"`
}

type S3KeyItem struct {
	KeyID          string `json:"key_id"`
	EncryptAesKey  string `json:"encrypt_aeskey"`  // 加密的AES密钥（Base64）
	CiphertextBlob string `json:"ciphertext_blob"` // DataKey密文（Base64）
}

type S3PullAllResponse struct {
	Success  bool        `json:"success"`
	Data     []S3KeyItem `json:"data"`
	ErrorMsg string      `json:"error_msg"`
}

type GenerateKeyResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"` // 错误信息
	// 移除CostMs字段，不修改JSON响应
}

type ErrorResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"` // 错误信息
	// 移除CostMs字段，不修改JSON响应
}

type DatakeyResponse struct {
	Key    string `json:"key_id"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"` // 错误信息
	// 移除CostMs字段，不修改JSON响应
}

type BackupKeyResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"` // 错误信息
	// 移除CostMs字段，不修改JSON响应
}

type EncryptStatusResponse struct {
	Status string `json:"status"`
	KeyID  string `json:"KeyID"`
	Msg    string `json:"msg,omitempty"` // 错误信息
	// 移除CostMs字段，不修改JSON响应
}

type EncryptResponse struct {
	Status        string `json:"status"`
	EncryptedData string `json:"EncryptedData"`
	KeyID         string `json:"KeyID"`
}

// DecryptStatusResponse 解密接口错误响应结构体
type DecryptStatusResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
}

// DecryptResponse 解密接口成功响应结构体
type DecryptResponse struct {
	KeyID         string `json:"key_id"`         // 密钥ID
	Status        string `json:"status"`         // 状态：success/error
	DecryptedData string `json:"decrypted_data"` // 解密后的明文
}

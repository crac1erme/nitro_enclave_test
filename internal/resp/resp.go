package resp

type GenerateKeyResponse struct {
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

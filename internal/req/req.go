package req

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	plaintext string `json:"plaintext"`
}

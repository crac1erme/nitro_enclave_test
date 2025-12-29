package req

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
}

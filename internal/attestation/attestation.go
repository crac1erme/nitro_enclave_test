package attestation

import (
	"fmt"
	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
)

// MakeAttestation 生成并返回 attestation document
func MakeAttestation() ([]byte, error) {
	handle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("初始化 enclave handle 失败: %w", err)
	}

	attDoc, err := handle.Attest(enclave.AttestationOptions{})
	if err != nil {
		return nil, fmt.Errorf("生成 attestation 失败: %w", err)
	}

	return attDoc, nil
}

// DecryptKMSEnvelopedKey 使用 Enclave 内私钥解密 CiphertextForRecipient
// 输入: ciphertextForRecipient (来自 KMS Decrypt 响应的 CiphertextForRecipient 字段)
// 输出: 明文数据密钥 (如 AES-256 密钥)
func DecryptKMSEnvelopedKey(ciphertextForRecipient []byte) ([]byte, error) {
	handle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("获取 enclave handle 失败: %w", err)
	}

	plaintext, err := handle.DecryptKMSEnvelopedKey(ciphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("Enclave 私钥解密失败: %w", err)
	}

	return plaintext, nil
}

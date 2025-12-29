package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
)

// KeyCache 密钥缓存（抽离为结构体，方便复用）
type KeyCache struct {
	keys map[string][]byte
}

// NewKeyCache 创建密钥缓存
func NewKeyCache() *KeyCache {
	return &KeyCache{
		keys: make(map[string][]byte),
	}
}

// GenerateKey 生成 AES-256 密钥，返回 KeyID
func (c *KeyCache) GenerateKey() string {
	key := make([]byte, 32)
	rand.Read(key) // 忽略错误（简化示例）
	keyID := uuid.NewString()
	c.keys[keyID] = key
	return keyID
}

// Encrypt 加密数据（返回密文、nonce、tag，均为十六进制字符串）
func (c *KeyCache) Encrypt(keyID, plaintext string) (string, error) {
	key, ok := c.keys[keyID]
	if !ok {
		return "", fmt.Errorf("密钥ID不存在: %s", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce) // 忽略错误

	plaintextBytes := []byte(plaintext)
	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]

	ciphertextHex := hex.EncodeToString(ciphertext)
	nonceHex := hex.EncodeToString(nonce)
	tagHex := hex.EncodeToString(tag)

	fullEncryptedStr := fmt.Sprintf("%s$%s$%s", ciphertextHex, nonceHex, tagHex)

	return fullEncryptedStr, nil
}

func (c *KeyCache) Decrypt(keyID, fullEncryptedStr string) (string, error) {
	// 1. 空参数校验
	if keyID == "" || fullEncryptedStr == "" {
		return "", fmt.Errorf("密钥ID或加密字符串不能为空")
	}

	// 2. 读取密钥（与 Encrypt 逻辑一致，无锁）
	key, ok := c.keys[keyID]
	if !ok {
		return "", fmt.Errorf("密钥ID不存在: %s", keyID)
	}

	// 3. 按 $ 拆分加密字符串，还原 ciphertextHex/nonceHex/tagHex
	parts := strings.Split(fullEncryptedStr, "$")
	if len(parts) != 3 {
		return "", fmt.Errorf("加密字符串格式错误，需为 ciphertextHex$nonceHex$tagHex，当前：%s", fullEncryptedStr)
	}
	ciphertextHex := parts[0]
	nonceHex := parts[1]
	tagHex := parts[2]

	// 4. hex 解码（与 Encrypt 的 hex.EncodeToString 反向操作）
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("密文 hex 解码失败: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("nonce hex 解码失败: %w", err)
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", fmt.Errorf("tag hex 解码失败: %w", err)
	}

	// 5. 创建 AES-GCM 实例（与 Encrypt 逻辑一致）
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES 加密器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 GCM 模式失败: %w", err)
	}

	// 6. 还原完整密文（Encrypt 中拆分了 tag，解密需拼接回去）
	// Encrypt: ciphertext = 完整密文[:len-Overhead], tag = 完整密文[len-Overhead:]
	// Decrypt: 完整密文 = ciphertext + tag
	fullCiphertext := append(ciphertext, tag...)

	// 7. 执行 GCM 解密（与 Encrypt 的 Seal 反向操作）
	plaintextBytes, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return "", fmt.Errorf("GCM 解密失败: %w", err)
	}

	// 8. 转换为明文字符串返回
	return string(plaintextBytes), nil
}

// Decrypt 解密数据（传入密文、nonce、tag，均为十六进制字符串）
//func (c *KeyCache) Decrypt(keyID, ciphertextHex, nonceHex, tagHex string) (string, error) {
//	key, ok := c.keys[keyID]
//	if !ok {
//		return "", fmt.Errorf("密钥ID不存在: %s", keyID)
//	}
//
//	ciphertext, err := hex.DecodeString(ciphertextHex)
//	if err != nil {
//		return "", err
//	}
//	nonce, err := hex.DecodeString(nonceHex)
//	if err != nil {
//		return "", err
//	}
//	tag, err := hex.DecodeString(tagHex)
//	if err != nil {
//		return "", err
//	}
//
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return "", err
//	}
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		return "", err
//	}
//
//	fullCiphertext := append(ciphertext, tag...)
//	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
//	if err != nil {
//		return "", err
//	}
//
//	return string(plaintext), nil
//}

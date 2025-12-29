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
func (c *KeyCache) Encrypt(keyID, plaintext string) (string, string, string, error) {
	key, ok := c.keys[keyID]
	if !ok {
		return "", "", "", fmt.Errorf("密钥ID不存在: %s", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce) // 忽略错误

	plaintextBytes := []byte(plaintext)
	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]

	return hex.EncodeToString(ciphertext), hex.EncodeToString(nonce), hex.EncodeToString(tag), nil
}

func (c *KeyCache) Decrypt(keyID, encryptedData string) (string, string, string, error) {
	// 1. 空参数快速校验（避免后续解码失败）
	if keyID == "" || encryptedData == "" {
		return "", "", "", fmt.Errorf("keyID或加密数据不能为空")
	}

	// 2. 读取密钥（无锁，保持原有逻辑）
	key, ok := c.keys[keyID]
	if !ok {
		return "", "", "", fmt.Errorf("密钥ID不存在: %s", keyID)
	}

	// 3. 拆分加密数据（ciphertextHex|nonceHex|tagHex）
	parts := strings.Split(encryptedData, "|")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("加密数据格式错误，需为ciphertextHex|nonceHex|tagHex")
	}
	ciphertextHex := parts[0]
	nonceHex := parts[1]
	tagHex := parts[2]

	// 4. 十六进制解码（补充错误上下文，便于调试）
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", "", "", fmt.Errorf("密文解码失败: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", "", "", fmt.Errorf("nonce解码失败: %w", err)
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", "", "", fmt.Errorf("tag解码失败: %w", err)
	}

	// 5. 创建AES-GCM实例（保留原有逻辑）
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", fmt.Errorf("创建AES加密器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", fmt.Errorf("创建GCM模式失败: %w", err)
	}

	// 6. 校验nonce/tag长度（避免解密失败）
	if len(nonce) != gcm.NonceSize() {
		return "", "", "", fmt.Errorf("nonce长度非法：%d字节（需%d字节）", len(nonce), gcm.NonceSize())
	}
	if len(tag) != gcm.Overhead() {
		return "", "", "", fmt.Errorf("tag长度非法：%d字节（需%d字节）", len(tag), gcm.Overhead())
	}

	// 7. 解密逻辑（保留原有）
	fullCiphertext := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("GCM解密失败: %w", err)
	}

	// 8. 返回：明文 + 空占位（匹配4个返回值，兼容调用）
	return string(plaintext), "", "", nil
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

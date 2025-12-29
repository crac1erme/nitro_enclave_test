package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

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

// Decrypt 解密数据（传入密文、nonce、tag，均为十六进制字符串）
func (c *KeyCache) Decrypt(keyID, ciphertextHex, nonceHex, tagHex string) (string, error) {
	key, ok := c.keys[keyID]
	if !ok {
		return "", fmt.Errorf("密钥ID不存在: %s", keyID)
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	fullCiphertext := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

package nitro_enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// 全局密钥缓存（飞地内内存存储，永不外泄）
var (
	keyCache = struct {
		sync.RWMutex
		keys map[string][]byte // keyID -> AES-256 密钥
	}{
		keys: make(map[string][]byte),
	}
)

// -------------------------- 定义 HTTP 请求/响应结构体 --------------------------
type GenerateKeyResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

type DecryptRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// -------------------------- HTTP 处理器函数 --------------------------
func generateKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 生成 32 字节 AES-256 密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		resp := GenerateKeyResponse{
			Status: "error",
			Error:  fmt.Sprintf("生成 AES 密钥失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	keyID := uuid.NewString()
	keyCache.Lock()
	keyCache.keys[keyID] = key
	keyCache.Unlock()

	log.Printf("生成 AES 密钥成功，密钥ID: %s", keyID)
	resp := GenerateKeyResponse{
		KeyID:  keyID,
		Status: "success",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp := EncryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解析请求体失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if req.KeyID == "" || req.Plaintext == "" {
		resp := EncryptResponse{
			Status: "error",
			Error:  "密钥ID/明文不能为空",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	keyCache.RLock()
	key, ok := keyCache.keys[req.KeyID]
	keyCache.RUnlock()
	if !ok {
		resp := EncryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("密钥ID不存在: %s", req.KeyID),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// AES-GCM 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		resp := EncryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("初始化 AES 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		resp := EncryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("初始化 GCM 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		resp := EncryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("生成 nonce 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	plaintextBytes := []byte(req.Plaintext)
	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]

	resp := EncryptResponse{
		Ciphertext: hex.EncodeToString(ciphertext),
		Nonce:      hex.EncodeToString(nonce),
		Tag:        hex.EncodeToString(tag),
		Status:     "success",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解析请求体失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if req.KeyID == "" || req.Ciphertext == "" || req.Nonce == "" || req.Tag == "" {
		resp := DecryptResponse{
			Status: "error",
			Error:  "密钥ID/密文/nonce/tag 不能为空",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	keyCache.RLock()
	key, ok := keyCache.keys[req.KeyID]
	keyCache.RUnlock()
	if !ok {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("密钥ID不存在: %s", req.KeyID),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// 解码十六进制数据
	ciphertext, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解析密文失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解析 nonce 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}
	tag, err := hex.DecodeString(req.Tag)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解析 tag 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// AES-GCM 解密
	block, err := aes.NewCipher(key)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("初始化 AES 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("初始化 GCM 失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if len(nonce) != gcm.NonceSize() {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("nonce 长度错误，期望 %d 字节，实际 %d 字节", gcm.NonceSize(), len(nonce)),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	fullCiphertext := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		resp := DecryptResponse{
			Status: "error",
			Error:  fmt.Sprintf("解密失败: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := DecryptResponse{
		Plaintext: string(plaintext),
		Status:    "success",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// -------------------------- 主函数 --------------------------
func main() {
	// 注册 HTTP 路由
	http.HandleFunc("/generate-key", generateKeyHandler)
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	// 启动 VSOCK HTTP 服务
	listenAddr := ":8080"
	lis, err := net.Listen("vsock", listenAddr)
	if err != nil {
		log.Fatalf("监听 VSOCK 失败: %v", err)
	}
	log.Printf("AES 加解密服务启动，监听 VSOCK %s", listenAddr)

	// 启动服务
	if err := http.Serve(lis, nil); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

// cmd/enclave-server/main.go
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"nitro_enclave/internal/aes"
)

var keyCache = aes.NewKeyCache() // 复用内部包的密钥缓存

// 定义 HTTP 请求/响应结构体（简化示例）
type GenerateKeyResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
}

func main() {
	// 注册 HTTP 路由
	http.HandleFunc("/generate-key", func(w http.ResponseWriter, r *http.Request) {
		keyID := keyCache.GenerateKey()
		resp := GenerateKeyResponse{
			KeyID:  keyID,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// 其他路由（encrypt/decrypt）复用 keyCache.Encrypt/Decrypt...

	// 监听 VSOCK 端口
	lis, err := net.Listen("vsock", ":8080")
	if err != nil {
		log.Fatalf("监听 VSOCK 失败: %v", err)
	}
	log.Println("Enclave AES 服务启动，监听 VSOCK :8080")
	http.Serve(lis, nil)
}

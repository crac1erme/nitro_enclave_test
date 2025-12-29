package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"nitro_enclave/internal/aes"
)

var keyCache = aes.NewKeyCache()

type GenerateKeyResponse struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"` // 新增：错误信息
}

func main() {
	// 新增：监听退出信号，输出日志（便于排查是否被强制终止）
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("收到退出信号: %v，程序退出", sig)
		os.Exit(0)
	}()

	// 优化：增加请求方法校验，避免非法请求导致逻辑异常
	http.HandleFunc("/generate-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := GenerateKeyResponse{
				Status: "error",
				Msg:    "仅支持 GET 请求",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		keyID := keyCache.GenerateKey()
		if keyID == "" { // 新增：容错密钥生成失败
			resp := GenerateKeyResponse{
				Status: "error",
				Msg:    "密钥生成失败",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp := GenerateKeyResponse{
			KeyID:  keyID,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// 优化：增强错误日志，添加排查方向
	lis, err := net.Listen("vsock", ":8080")
	if err != nil {
		log.Fatalf("监听 VSOCK 失败: %v\n排查提示：1. 仅 Nitro Enclave 内支持 vsock 协议 2. 端口 8080 是否被占用 3. Enclave 资源是否充足", err)
	}
	defer lis.Close() // 新增：确保退出时关闭监听

	log.Println("Enclave AES 服务启动，监听 VSOCK :8080")
	// 原有阻塞逻辑保留（核心）
	if err := http.Serve(lis, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
}

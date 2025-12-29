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
	"time" // 新增：引入时间包

	"nitro_enclave/internal/aes"
	"nitro_enclave/internal/resp"
)

var keyCache = aes.NewKeyCache()

//request

type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	plaintext string `json:"plaintext"`
}

func main() {
	// 监听退出信号，输出日志（便于排查是否被强制终止）
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("收到退出信号: %v，程序退出", sig)
		os.Exit(0)
	}()

	// 增加请求方法校验，避免非法请求导致逻辑异常
	http.HandleFunc("/generate-key", func(w http.ResponseWriter, r *http.Request) {
		// ========== 核心新增：记录请求开始时间 ==========
		startTime := time.Now()

		if r.Method != http.MethodGet {
			resp := resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "仅支持 GET 请求",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			// ========== 计算耗时并打印日志 ==========
			costMs := time.Since(startTime).Seconds() * 1000 // 转毫秒
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		keyID := keyCache.GenerateKey()
		if keyID == "" { // 容错密钥生成失败
			resp := resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "密钥生成失败",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			// ========== 计算耗时并打印日志 ==========
			costMs := time.Since(startTime).Seconds() * 1000 // 转毫秒
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		resp := resp.GenerateKeyResponse{
			KeyID:  keyID,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

		// ========== 核心新增：计算耗时并打印日志 ==========
		costMs := time.Since(startTime).Seconds() * 1000 // 纳秒转毫秒（保留3位小数）
		log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
	})

	// 增加请求方法校验，避免非法请求导致逻辑异常
	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
		// ========== 核心新增：记录请求开始时间 ==========
		startTime := time.Now()

		if r.Method != http.MethodPost {
			resp := resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "仅支持 POST 请求",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			// ========== 计算耗时并打印日志 ==========
			costMs := time.Since(startTime).Seconds() * 1000 // 转毫秒
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		var req EncryptRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "JSON 绑定失败: " + err.Error(),
			})
			return
		}

		if req.KeyID == "" || req.plaintext == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.EncryptStatusResponse{
				Status: "error",
				Msg:    "key_id 或 data 不能为空",
			})
			return
		}

		encryptData, _, _, err := keyCache.Encrypt(req.KeyID, req.plaintext)
		if err != nil {
			resp := resp.EncryptStatusResponse{
				Status: "error",
				Msg:    "加密失败",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			// ========== 计算耗时并打印日志 ==========
			costMs := time.Since(startTime).Seconds() * 1000 // 转毫秒
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}
		//返回
		resp := resp.EncryptResponse{
			KeyID:         req.KeyID,
			Status:        "success",
			EncryptedData: encryptData,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

		// ========== 核心新增：计算耗时并打印日志 ==========
		costMs := time.Since(startTime).Seconds() * 1000 // 纳秒转毫秒（保留3位小数）
		log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
	})

	// 核心修改：监听 TCP 8080 端口（纯 HTTP，移除所有 VSOCK 逻辑）
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("监听 HTTP 端口失败: %v\n排查提示：1. 端口 8080 是否被占用 2. 是否有端口监听权限", err)
	}
	defer lis.Close() // 确保退出时关闭监听

	log.Println("Enclave AES 服务启动，监听 HTTP :8080")
	// 原有阻塞逻辑保留（核心）
	if err := http.Serve(lis, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
}

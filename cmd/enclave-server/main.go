package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"nitro_enclave/internal/req"
	"os"
	"os/signal"
	"syscall"
	"time" // 新增：引入时间包

	"nitro_enclave/internal/aes"
	"nitro_enclave/internal/resp"
	"nitro_enclave/internal/tools"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var keyCache = aes.NewKeyCache()

//request

func main() {

	awsRegion := "ap-southeast-1"                                                                  // 你的AWS区域（如us-east-1、eu-west-1）
	kmsKeyId := "arn:aws:kms:ap-southeast-2:389405924691:key/feb73b5b-2218-45f3-8dc9-a332dea6631b" // 替换为已存在的KMS主密钥ID/ARN
	dataKeySpec := types.DataKeySpecAes256                                                         // 数据密钥规格（AES_256/AES_128）

	// -------------------------- 调用生成DataKey --------------------------
	log.Println("开始调用AWS KMS生成数据密钥...")
	result, err := tools.GenerateKMSDataKey(awsRegion, kmsKeyId, dataKeySpec)
	if err != nil {
		log.Fatalf("生成DataKey失败: %v", err)
	}

	// -------------------------- 打印结果 --------------------------
	log.Println("✅ 数据密钥生成成功！")
	log.Printf("🔑 使用的KMS主密钥ID: %s", aws.ToString(result.KeyId))
	log.Printf("📝 明文数据密钥（十六进制）: %x", result.Plaintext) // 注意：明文密钥仅本地使用，不要泄露
	log.Printf("🔒 加密后的密钥Blob（十六进制）: %x", result.CiphertextBlob)
	log.Printf("📏 明文密钥长度: %d 字节（AES-256=32字节，AES-128=16字节）", len(result.Plaintext))

	// 可选：将明文密钥转为字符串（谨慎使用，仅演示）
	plaintextStr := string(result.Plaintext)
	log.Printf("⚠️ 明文密钥（字符串）: %s（仅演示，生产环境请勿打印/存储）", plaintextStr)

	// 监听退出信号，输出日志（便于排查是否被强制终止）
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("收到退出信号: %v，程序退出", sig)
		os.Exit(0)
	}()

	// 增加请求方法校验，避免非法请求导致逻辑异常
	http.HandleFunc("/aes/generate-key", func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/aes/encrypt", func(w http.ResponseWriter, r *http.Request) {
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

		var request req.EncryptRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "JSON 绑定失败: " + err.Error(),
			})
			return
		}

		if request.KeyID == "" || request.Plaintext == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.EncryptStatusResponse{
				Status: "error",
				Msg:    "key_id 或 Plaintext 不能为空",
			})
			return
		}

		encryptData, err := keyCache.Encrypt(request.KeyID, request.Plaintext)
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
			KeyID:         request.KeyID,
			Status:        "success",
			EncryptedData: encryptData,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

		// ========== 核心新增：计算耗时并打印日志 ==========
		costMs := time.Since(startTime).Seconds() * 1000 // 纳秒转毫秒（保留3位小数）
		log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
	})

	// 解密接口（与加密接口逻辑对齐）
	http.HandleFunc("/aes/decrypt", func(w http.ResponseWriter, r *http.Request) {
		// ========== 核心新增：记录请求开始时间 ==========
		startTime := time.Now()

		// 非POST请求拦截
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

		// 解析JSON请求体到DecryptRequest结构体
		var request req.DecryptRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.GenerateKeyResponse{
				Status: "error",
				Msg:    "JSON 绑定失败: " + err.Error(),
			})
			// 补充耗时日志（加密接口此处遗漏，需补齐）
			costMs := time.Since(startTime).Seconds() * 1000
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		// 参数非空校验
		if request.KeyID == "" || request.EncryptedData == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.DecryptStatusResponse{
				Status: "error",
				Msg:    "key_id 或 encrypted_data 不能为空",
			})
			// 补充耗时日志
			costMs := time.Since(startTime).Seconds() * 1000
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		// 调用密钥缓存的解密方法（需确保 keyCache.Decrypt 方法返回4个值，与 Encrypt 对齐）
		decryptData, err := keyCache.Decrypt(request.KeyID, request.EncryptedData)
		if err != nil {
			resp := resp.DecryptStatusResponse{
				Status: "error",
				Msg:    "解密失败",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			// ========== 计算耗时并打印日志 ==========
			costMs := time.Since(startTime).Seconds() * 1000 // 转毫秒
			log.Printf("URL: %s | 耗时: %.3fms", r.URL.Path, costMs)
			return
		}

		// 解密成功响应
		resp := resp.DecryptResponse{
			KeyID:         request.KeyID,
			Status:        "success",
			DecryptedData: decryptData,
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

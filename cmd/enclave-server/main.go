package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"nitro_enclave/internal/req"
	"nitro_enclave/internal/s3"
	"os"
	"os/signal"
	"syscall"
	"time" // 新增：引入时间包

	"nitro_enclave/internal/aes"
	"nitro_enclave/internal/resp"
	"nitro_enclave/internal/tools"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var keyCache = aes.NewKeyCache()

//request

func main() {
	//kms配置

	s3Bucket := "aeskeybackup"
	awsRegion := "ap-southeast-2"                                                                  // 你的AWS区域（如us-east-1、eu-west-1）
	kmsKeyId := "arn:aws:kms:ap-southeast-2:389405924691:key/feb73b5b-2218-45f3-8dc9-a332dea6631b" // 替换为已存在的KMS主密钥ID/ARN
	dataKeySpec := types.DataKeySpecAes256                                                         // 数据密钥规格（AES_256/AES_128）

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

		keyID, aes_key := keyCache.GenerateKey()

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

		//kms datakey加密aes key

		result, err := tools.GenerateKMSDataKey(awsRegion, kmsKeyId, dataKeySpec)
		if err != nil {
			log.Fatalf("生成DataKey失败: %v", err)
		}

		kms_aes_key_Plaintext := result.Plaintext

		blob := keyCache.AESKeyToBase64(result.CiphertextBlob)
		encrypt_aeskey, err := keyCache.Encrypt_backup_to_s3(kms_aes_key_Plaintext, aes_key)
		base64_aes_Key := keyCache.AESKeyToBase64(encrypt_aeskey)
		bak_key := fmt.Sprintf("%s|%s", blob, base64_aes_Key)
		//backup s3
		s3client, err := s3.InitS3Client(awsRegion)

		s3key := keyID

		s3.UploadStringToS3(s3client, s3Bucket, s3key, bak_key)

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

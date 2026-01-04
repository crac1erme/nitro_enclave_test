package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"nitro_enclave/internal/aes"
	"nitro_enclave/internal/req"
	"nitro_enclave/internal/resp"
	"nitro_enclave/internal/s3"
	"nitro_enclave/internal/tools"
	"os"
	"os/signal"
	"syscall"

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
	http.HandleFunc("/backupkey", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			resp := resp.BackupKeyResponse{
				Status: "error",
				Msg:    "仅支持 POST 请求",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		var request req.BackupRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.BackupKeyResponse{
				Status: "error",
				Msg:    "JSON 绑定失败: " + err.Error(),
			})
			return
		}

		//kms加密备份s3流程
		//kms datakey加密aes key
		//kms datakey生成
		result, err := tools.GenerateKMSDataKey(awsRegion, kmsKeyId, dataKeySpec)
		if err != nil {
			log.Fatalf("生成DataKey失败: %v", err)
		}

		kms_aes_key_Plaintext := result.Plaintext

		blob := keyCache.AESKeyToBase64(result.CiphertextBlob)
		encrypt_aeskey, err := keyCache.Encrypt_backup_to_s3(kms_aes_key_Plaintext, request.Aeskey)
		base64_aes_Key := keyCache.AESKeyToBase64(encrypt_aeskey)
		bak_key := fmt.Sprintf("%s|%s", blob, base64_aes_Key)
		//backup s3
		s3client, err := s3.InitS3Client(awsRegion)

		s3key := request.KeyID

		s3.UploadStringToS3(s3client, s3Bucket, s3key, bak_key)

		resp := resp.BackupKeyResponse{
			KeyID:  request.KeyID,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	})

	// 核心修改：监听 TCP 8080 端口（纯 HTTP，移除所有 VSOCK 逻辑）
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("监听 HTTP 端口失败: %v\n排查提示：1. 端口 8081 是否被占用 2. 是否有端口监听权限", err)
	}
	defer lis.Close() // 确保退出时关闭监听

	log.Println("host proxy 服务启动，监听 HTTP :8081")
	// 原有阻塞逻辑保留（核心）
	if err := http.Serve(lis, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
}

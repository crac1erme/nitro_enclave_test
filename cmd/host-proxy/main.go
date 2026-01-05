package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	"github.com/mdlayher/vsock"
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

	http.HandleFunc("/kms/decrypt", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			json.NewEncoder(w).Encode(resp.KMSDecryptResponse{
				Status: "error",
				Msg:    "仅支持 POST 请求",
			})
			return
		}

		var decryptReq req.KMSDecryptRequest
		if err := json.NewDecoder(r.Body).Decode(&decryptReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.KMSDecryptResponse{
				Status: "error",
				Msg:    "解析请求失败: " + err.Error(),
			})
			return
		}

		// 校验必填参数
		if decryptReq.CiphertextBlob == "" || decryptReq.AttestationDoc == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.KMSDecryptResponse{
				Status: "error",
				Msg:    "ciphertext_blob 和 attestation_doc 为必填参数",
			})
			return
		}

		ciphertextBlob, err := keyCache.Base64ToAESKey(decryptReq.CiphertextBlob)
		if err != nil {
			log.Printf("密文Base64解码失败: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp.KMSDecryptResponse{
				Status: "error",
				Msg:    "密文Base64解码失败: " + err.Error(),
			})
			return
		}

		AttestationDoc, err := keyCache.Base64ToAESKey(decryptReq.AttestationDoc)

		key, err := tools.DecryptDataKey(awsRegion, ciphertextBlob, AttestationDoc)

		log.Printf("decrypted data key: %v", key)

		resp := resp.DecryptResponse{
			Status:        "success",
			DecryptedData: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	//kms-datakey生成 enclave调用加密备份key用 保障明文密钥不出enclave
	http.HandleFunc("/kms/datakey", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
			resp := resp.ErrorResponse{
				Status: "error",
				Msg:    "仅支持 Get 请求",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		//kms加密备份s3流程
		//kms datakey加密aes key
		//kms datakey生成
		result, err := tools.GenerateKMSDataKey(awsRegion, kmsKeyId, dataKeySpec)
		if err != nil {
			log.Printf("生成DataKey失败: %v", err)
		}

		kms_aes_key_Plaintext := keyCache.AESKeyToBase64(result.Plaintext)
		blob := keyCache.AESKeyToBase64(result.CiphertextBlob)

		aes_result := fmt.Sprintf("%s|%s", kms_aes_key_Plaintext, blob)

		resp := resp.DatakeyResponse{
			Key:    aes_result,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	})

	// enclave调用 加密后key备份到s3 防止丢失 keyid/
	http.HandleFunc("/s3/upload", func(w http.ResponseWriter, r *http.Request) {

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

		bak_key := fmt.Sprintf("%s|%s", request.Encrypt_Aeskey, request.CiphertextBlob) //aeskey|datakey

		s3key := request.KeyID
		s3client, _ := s3.InitS3Client(awsRegion)

		s3.UploadStringToS3(s3client, s3Bucket, s3key, bak_key)

		resp := resp.BackupKeyResponse{
			KeyID:  request.KeyID,
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	})

	listenCID, _ := vsock.ContextID()
	listenPort := uint32(8081)

	listener, err := vsock.ListenContextID(listenCID, listenPort, nil)

	if err != nil {
		log.Fatalf("监听 HTTP 端口失败: %v\n排查提示：1. 端口 8081 是否被占用 2. 是否有端口监听权限", err)
	}
	defer listener.Close() // 确保退出时关闭监听

	log.Println("host proxy 服务启动，监听 HTTP :8081")
	// 原有阻塞逻辑保留（核心）
	if err := http.Serve(listener, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
}

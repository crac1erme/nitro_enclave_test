package tools

import (
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func main() {
	// -------------------------- 配置参数（替换为你的真实信息） --------------------------
	awsRegion := "ap-southeast-1"                                                                  // 你的AWS区域（如us-east-1、eu-west-1）
	kmsKeyId := "arn:aws:kms:ap-southeast-2:389405924691:key/feb73b5b-2218-45f3-8dc9-a332dea6631b" // 替换为已存在的KMS主密钥ID/ARN
	dataKeySpec := types.DataKeySpecAes256                                                         // 数据密钥规格（AES_256/AES_128）

	// -------------------------- 调用生成DataKey --------------------------
	log.Println("开始调用AWS KMS生成数据密钥...")
	result, err := GenerateKMSDataKey(awsRegion, kmsKeyId, dataKeySpec)
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
}

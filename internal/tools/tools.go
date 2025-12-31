package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMS客户端构造函数（复用，确保配置正确）
func newKMSClient(region string) (*kms.Client, error) {
	// 加载AWS配置（自动读取凭证、区域等）
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithRetryMaxAttempts(3), // 自定义重试次数
	)
	if err != nil {
		return nil, fmt.Errorf("加载AWS配置失败: %w", err)
	}

	// 创建KMS客户端
	return kms.NewFromConfig(cfg), nil
}

// GenerateKMSDataKey 生成KMS数据密钥（仅生成DataKey，无主密钥创建逻辑）
// 参数说明：
//
//	region: AWS区域（如ap-southeast-1、us-east-1）
//	keyId: 已存在的KMS主密钥ID/ARN（必须指定，用于加密数据密钥）
//	keySpec: 数据密钥规格（仅支持AES_128/AES_256，默认AES_256）
//
// 返回值：
//
//	GenerateDataKeyOutput: 包含明文数据密钥、加密后的密钥Blob
//	error: 错误信息（非nil则生成失败）
func GenerateKMSDataKey(region string, keyId string, keySpec types.DataKeySpec) (*kms.GenerateDataKeyOutput, error) {
	// 校验必填参数
	if region == "" {
		return nil, errors.New("区域(region)不能为空")
	}
	if keyId == "" {
		return nil, errors.New("KMS主密钥ID/ARN(keyId)不能为空（必须是已存在的主密钥）")
	}

	// 设置默认数据密钥规格（AES-256）
	if keySpec == "" {
		keySpec = types.DataKeySpecAes256
	}

	// 校验数据密钥规格合法性
	if keySpec != types.DataKeySpecAes128 && keySpec != types.DataKeySpecAes256 {
		return nil, fmt.Errorf("不支持的DataKey规格: %s，仅支持AES_128/AES_256", keySpec)
	}

	// 创建KMS客户端
	client, err := newKMSClient(region)
	if err != nil {
		return nil, fmt.Errorf("创建KMS客户端失败: %w", err)
	}

	// 构造GenerateDataKey请求参数（仅保留DataKey所需字段）
	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyId), // 核心：指定已存在的KMS主密钥
		KeySpec: keySpec,           // 数据密钥规格（AES_128/AES_256）
	}

	// 调用GenerateDataKey API生成数据密钥
	result, err := client.GenerateDataKey(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("调用KMS GenerateDataKey失败: %w", err)
	}

	return result, nil
}

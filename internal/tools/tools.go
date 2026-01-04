package tools

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// 全局单例KMS客户端（缓存已创建的客户端，避免重复初始化）
var kmsSingletonClient *kms.Client

// 记录当前客户端对应的区域（防止跨区域复用）
var kmsClientRegion string

var (
	kmsClientMap = make(map[string]*kms.Client)
	kmsClientMu  sync.RWMutex
)

func vsockDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	// VSock协议连接：宿主机CID固定为3，代理端口8000（对应vsock-proxy 8000）
	return net.Dial("vsock", "16:8000")
}

func newKMSClient(region string) (*kms.Client, error) {
	// 先查缓存
	kmsClientMu.RLock()
	client, ok := kmsClientMap[region]
	kmsClientMu.RUnlock()
	if ok {
		return client, nil
	}

	// 自定义VSock Dialer（带超时/保活）
	vsockDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second, // VSock连接超时
			KeepAlive: 30 * time.Second, // 连接保活
		}
		return dialer.DialContext(ctx, "vsock", "3:8000")
	}

	// 正确配置HTTP Client（无爆红）
	vsockHTTPClient := &http.Client{
		Timeout: 30 * time.Second, // 整个HTTP请求的超时
		Transport: &http.Transport{
			DialContext: vsockDialer,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         fmt.Sprintf("kms.%s.amazonaws.com", region),
			},
			// Transport合法字段
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// 加载AWS配置
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithHTTPClient(vsockHTTPClient),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, reg string, options ...interface{}) (aws.Endpoint, error) {
				if service == kms.ServiceID {
					return aws.Endpoint{
						URL:           fmt.Sprintf("https://kms.%s.amazonaws.com", reg),
						SigningRegion: reg,
					}, nil
				}
				return aws.Endpoint{}, fmt.Errorf("不支持的服务: %s", service)
			},
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("加载AWS配置失败: %w", err)
	}

	// 缓存客户端
	newClient := kms.NewFromConfig(cfg)
	kmsClientMu.Lock()
	kmsClientMap[region] = newClient
	kmsClientMu.Unlock()

	return newClient, nil
}

// KMS客户端构造函数（改造为单例逻辑）
//func newKMSClient(region string) (*kms.Client, error) {
//	// 1. 如果客户端已存在且区域匹配，直接复用
//	if kmsSingletonClient != nil && kmsClientRegion == region {
//		return kmsSingletonClient, nil
//	}
//
//	// 2. 加载AWS配置（自动读取凭证、区域等）
//	cfg, err := config.LoadDefaultConfig(context.TODO(),
//		config.WithRegion(region),
//		config.WithRetryMaxAttempts(3), // 自定义重试次数
//	)
//	if err != nil {
//		return nil, fmt.Errorf("加载AWS配置失败: %w", err)
//	}
//
//	// 3. 创建新客户端并更新单例和区域
//	client := kms.NewFromConfig(cfg)
//	kmsSingletonClient = client
//	kmsClientRegion = region
//
//	return client, nil
//}

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

	// 创建KMS客户端（现在会复用单例）
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

// 可选：重置单例（测试/切换区域时使用）
func ResetKMSClientSingleton() {
	kmsSingletonClient = nil
	kmsClientRegion = ""
}

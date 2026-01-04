package s3

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// vsockDialer 创建VSock拨号器，连接宿主机的vsock-proxy
func vsockDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 配置拨号超时和保活（解决之前的字段爆红问题）
		dialer := &net.Dialer{
			Timeout:   10 * time.Second, // VSock连接超时
			KeepAlive: 30 * time.Second, // TCP保活（VSock复用该逻辑）
		}
		// 宿主机VSock CID固定为3，端口为预定义的S3代理端口
		return dialer.DialContext(ctx, "vsock", "3:8001")
	}
}

func InitS3Client(region string) (*s3.Client, error) {
	// 1. 自定义HTTP Client（走VSock代理）
	vsockHTTPClient := &http.Client{
		Timeout: 30 * time.Second, // 整个HTTP请求总超时
		Transport: &http.Transport{
			// 核心：替换为VSock拨号器
			DialContext: vsockDialer(),
			// TLS配置：必须指定S3的ServerName，避免证书验证失败
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,                                      // 生产环境禁止设为true
				ServerName:         fmt.Sprintf("s3.%s.amazonaws.com", region), // S3域名
			},
			// Transport合法字段（避免爆红）
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// 2. 加载 AWS 配置（注入VSock的HTTP Client）
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithHTTPClient(vsockHTTPClient), // 关键：使用VSock代理的Client
		// 可选：固定S3端点，增强稳定性
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, reg string, options ...interface{}) (aws.Endpoint, error) {
				if service == s3.ServiceID {
					return aws.Endpoint{
						URL:           fmt.Sprintf("https://s3.%s.amazonaws.com", reg),
						SigningRegion: reg,
					}, nil
				}
				return aws.Endpoint{}, fmt.Errorf("不支持的服务: %s", service)
			},
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("加载 AWS 配置失败: %w", err)
	}

	// 3. 创建 S3 客户端（流量自动走VSock代理）
	return s3.NewFromConfig(cfg), nil
}

// 初始化 S3 客户端（单例复用，减少资源占用）
//func InitS3Client(region string) (*s3.Client, error) {
//	// 加载 AWS 配置（自动读取凭证、区域）
//	cfg, err := config.LoadDefaultConfig(context.TODO(),
//		config.WithRegion(region),
//		// 可选：自定义超时、重试策略
//		// config.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
//	)
//	if err != nil {
//		return nil, fmt.Errorf("加载 AWS 配置失败: %w", err)
//	}
//
//	// 创建 S3 客户端
//	return s3.NewFromConfig(cfg), nil
//}

// 场景1：上传字符串（适配你的 Base64 拼接字符串场景）
func UploadStringToS3(s3Client *s3.Client, bucket, key, content string) error {
	// 构造上传请求
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),         // S3 桶名
		Key:         aws.String(key),            // 存储路径/文件名
		Body:        strings.NewReader(content), // 字符串转为 Reader
		ContentType: aws.String("text/plain"),   // 设置 Content-Type
		// 可选：开启服务器端加密（推荐）
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	}

	// 执行上传
	_, err := s3Client.PutObject(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("上传字符串失败: %w", err)
	}

	fmt.Printf("✅ 字符串已上传至 s3://%s/%s\n", bucket, key)
	return nil
}

// 场景2：上传本地文件（如需要上传文件而非字符串）
func UploadFileToS3(s3Client *s3.Client, bucket, key, localFilePath string) error {
	// 打开本地文件
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("打开本地文件失败: %w", err)
	}
	defer file.Close()

	// 获取文件大小（可选，用于进度展示）
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	// 构造上传请求
	input := &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          file,
		ContentLength: aws.Int64(fileInfo.Size()), // 指定文件大小
		ContentType:   aws.String("application/octet-stream"),
		// 可选：设置存储类别（如低频访问）
		StorageClass: types.StorageClassStandardIa,
	}

	// 执行上传
	_, err = s3Client.PutObject(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("上传文件失败: %w", err)
	}

	fmt.Printf("✅ 文件已上传至 s3://%s/%s\n", bucket, key)
	return nil
}

// 场景3：上传大文件（分块上传，适用于 >5GB 文件）
// 注：小文件无需分块，SDK 会自动处理，此方法仅用于超大文件
func UploadLargeFileToS3(s3Client *s3.Client, bucket, key, localFilePath string) error {
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 初始化分块上传
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	createResp, err := s3Client.CreateMultipartUpload(context.TODO(), createInput)
	if err != nil {
		return fmt.Errorf("初始化分块上传失败: %w", err)
	}

	// 分块大小（5MB，可调整）
	chunkSize := int64(5 * 1024 * 1024)
	fileInfo, _ := file.Stat()
	fileSize := fileInfo.Size()
	partNumber := 1
	var completedParts []types.CompletedPart

	// 读取并上传分块
	for offset := int64(0); offset < fileSize; offset += chunkSize {
		end := offset + chunkSize
		if end > fileSize {
			end = fileSize
		}

		// 读取分块数据
		chunk := make([]byte, end-offset)
		_, err := file.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取分块失败: %w", err)
		}

		// 上传分块
		uploadInput := &s3.UploadPartInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(key),
			UploadId:   createResp.UploadId,
			PartNumber: aws.Int32(int32(partNumber)),
			Body:       strings.NewReader(string(chunk)),
		}
		uploadResp, err := s3Client.UploadPart(context.TODO(), uploadInput)
		if err != nil {
			return fmt.Errorf("上传分块 %d 失败: %w", partNumber, err)
		}

		// 记录已完成分块
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(partNumber)),
			ETag:       uploadResp.ETag,
		})
		partNumber++
	}

	// 完成分块上传
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: createResp.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}
	_, err = s3Client.CompleteMultipartUpload(context.TODO(), completeInput)
	if err != nil {
		return fmt.Errorf("完成分块上传失败: %w", err)
	}

	fmt.Printf("✅ 大文件已分块上传至 s3://%s/%s\n", bucket, key)
	return nil
}

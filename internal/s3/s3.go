package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type FullFetchResult struct {
	Data    map[string]string // KeyID -> 内容（aeskey|datakey格式）
	Failed  []string          // 拉取失败的KeyID列表
	Total   int               // 总对象数量
	Success int               // 成功拉取数量
}

// 初始化 S3 客户端（单例复用，减少资源占用）
func InitS3Client(region string) (*s3.Client, error) {
	// 加载 AWS 配置（自动读取凭证、区域）
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		// 可选：自定义超时、重试策略
		// config.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	)
	if err != nil {
		return nil, fmt.Errorf("加载 AWS 配置失败: %w", err)
	}

	// 创建 S3 客户端
	return s3.NewFromConfig(cfg), nil
}

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

// pull all
func FullFetchFromS3(s3Client *s3.Client, bucket, prefix string) (*FullFetchResult, error) {
	result := &FullFetchResult{
		Data:    make(map[string]string),
		Failed:  []string{},
		Total:   0,
		Success: 0,
	}

	var continuationToken *string // 分页标记

	// 循环分页拉取（处理超过1000个对象的场景）
	for {
		// 构造ListObjectsV2请求
		listInput := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: continuationToken,
			MaxKeys:           aws.Int32(1000), // 每页最多1000个
		}

		// 调用S3列出对象
		listResult, err := s3Client.ListObjectsV2(context.TODO(), listInput)
		if err != nil {
			return result, fmt.Errorf("列出S3对象失败: %w", err)
		}

		// 遍历当前页的对象，逐个下载
		for _, obj := range listResult.Contents {
			keyID := aws.ToString(obj.Key)
			result.Total++

			// 跳过目录（S3中目录以/结尾）
			if strings.HasSuffix(keyID, "/") {
				continue
			}

			// 下载单个对象内容
			getInput := &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(keyID),
			}
			getResult, err := s3Client.GetObject(context.TODO(), getInput)
			if err != nil {
				fmt.Printf("❌ 下载S3对象 %s 失败: %v\n", keyID, err)
				result.Failed = append(result.Failed, keyID)
				continue
			}

			// 读取对象内容
			contentBytes, err := io.ReadAll(getResult.Body)
			getResult.Body.Close() // 必须关闭Body，避免连接泄漏
			if err != nil {
				fmt.Printf("❌ 读取S3对象 %s 内容失败: %v\n", keyID, err)
				result.Failed = append(result.Failed, keyID)
				continue
			}

			// 存储到结果中
			result.Data[keyID] = string(contentBytes)
			result.Success++
		}

		isTruncated := false
		if listResult.IsTruncated != nil {
			isTruncated = *listResult.IsTruncated
		}
		if !isTruncated {
			break // 所有对象遍历完成
		}

		continuationToken = listResult.NextContinuationToken
	}

	fmt.Printf("✅ S3全量拉取完成：总计%d个，成功%d个，失败%d个\n", result.Total, result.Success, len(result.Failed))
	return result, nil
}

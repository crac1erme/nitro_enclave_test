package attestation

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// 官方 API 固定端点（Enclave 内本地唯一可访问）
const attestationEndpoint = "http://169.254.170.2/v1/attestation/document"

// AttestationRequest API 请求体结构（AWS 官方定义）
type AttestationRequest struct {
	Nonce      string  `json:"nonce"`       // Base64 编码的 32 字节随机数（防重放）
	PCRIndices []int32 `json:"pcr_indices"` // 要包含的 PCR 索引（0-15）
}

// AttestationResponse API 响应体结构（AWS 官方定义）
type AttestationResponse struct {
	Document         string   `json:"document"`                    // Base64 编码的远程证明文档（核心）
	Signature        string   `json:"signature,omitempty"`         // 证明文档签名（可选）
	CertificateChain []string `json:"certificate_chain,omitempty"` // AWS 证书链（可选）
}

// GenerateAttestationDocument 原生 HTTP 调用获取远程证明文档（Base64 编码）
// region：仅为兼容原有逻辑，实际无作用；返回 Base64 编码的证明文档 + 错误
func GenerateAttestationDocument(region string) (string, error) {
	// 1. 生成 32 字节 Nonce（AWS 强制要求，防重放攻击）
	nonceRaw := make([]byte, 32)
	_, err := rand.Read(nonceRaw)
	if err != nil {
		return "", fmt.Errorf("生成 Nonce 失败: %v", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonceRaw)

	// 2. 构造 API 请求体（严格对齐 AWS 官方规范）
	reqBody := AttestationRequest{
		Nonce:      nonceB64,
		PCRIndices: []int32{0, 1, 2}, // 核心校验 PCR0，可选 1/2
	}
	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化请求体失败: %v", err)
	}

	// 3. 初始化 HTTP 客户端（禁用代理/保持连接，适配 Enclave 本地调用）
	client := &http.Client{
		Timeout: 15 * time.Second, // 超时保护（Enclave 内调用快，15 秒足够）
		Transport: &http.Transport{
			DisableKeepAlives: true, // 禁用长连接（避免资源泄漏）
			// 禁用 TLS（169.254.170.2 是 HTTP 端点）
			TLSClientConfig: nil,
		},
	}

	// 4. 发送 POST 请求（原生 HTTP，无任何封装）
	log.Printf("调用 Enclave 本地 API: %s, 请求体: %s", attestationEndpoint, string(reqBodyJSON))
	resp, err := client.Post(
		attestationEndpoint,
		"application/json", // 强制指定 Content-Type
		bytes.NewBuffer(reqBodyJSON),
	)
	if err != nil {
		return "", fmt.Errorf("HTTP 调用失败: %v\n排查提示：1. 是否在 Enclave 内运行？2. 实例是否为 Nitro 架构？3. 169.254.170.2 是否被屏蔽？", err)
	}
	defer resp.Body.Close() // 确保响应体关闭

	// 5. 校验响应状态码（仅 200 OK 为成功）
	if resp.StatusCode != http.StatusOK {
		// 读取错误响应内容，便于排查
		errBody := make([]byte, 1024)
		n, _ := resp.Body.Read(errBody)
		return "", fmt.Errorf("API 返回非 200 状态码: %d, 错误信息: %s", resp.StatusCode, string(errBody[:n]))
	}

	// 6. 解析响应体
	var attResp AttestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return "", fmt.Errorf("解析响应体失败: %v", err)
	}

	// 7. 校验证明文档非空
	if attResp.Document == "" {
		return "", fmt.Errorf("响应中无远程证明文档（Document 字段为空）")
	}

	// 8. 验证 Base64 合法性（可选，避免传输错误）
	_, err = base64.StdEncoding.DecodeString(attResp.Document)
	if err != nil {
		return "", fmt.Errorf("证明文档 Base64 解码失败: %v", err)
	}

	log.Printf("远程证明文档生成成功，Base64 长度: %d 字节", len(attResp.Document))
	return attResp.Document, nil
}

// Base64Decode 解码 Base64 格式的证明文档（工具函数）
func Base64Decode(b64Doc string) ([]byte, error) {
	doc, err := base64.StdEncoding.DecodeString(b64Doc)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %v", err)
	}
	return doc, nil
}

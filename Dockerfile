# 阶段1：编译 Enclave 服务（Go 编译环境）
FROM golang:1.24-alpine AS builder

RUN apk --no-cache add socat
# 设置工作目录
WORKDIR /app

COPY run.sh ./
# 复制 go.mod/go.sum 并下载依赖（利用缓存，加速构建）
COPY go.mod go.sum ./
RUN go mod download

# 复制项目源码（仅复制 Enclave 服务相关代码，减少构建上下文）
COPY cmd/enclave-server ./cmd/enclave-server
COPY internal ./internal

# 编译 Enclave 服务（静态编译，无外部依赖，适配 Enclave 极简环境）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /enclave-server ./cmd/enclave-server

RUN chmod +x /enclave-server

RUN chmod +x /app/run.sh

EXPOSE 8080

CMD ["/app/run.sh"]

# 阶段2：构建 Enclave 运行镜像（极简 Alpine 镜像，仅保留可执行文件）
FROM alpine:3.19

# 安装必要依赖（Enclave 内运行无需额外依赖，仅需基础系统）
RUN apk add --no-cache ca-certificates tzdata

# 设置时区（可选，根据需要调整）
ENV TZ=Asia/Shanghai

# 复制编译好的 Enclave 服务可执行文件
COPY --from=builder /enclave-server /usr/local/bin/

# 赋予执行权限
RUN chmod +x /usr/local/bin/enclave-server

# 暴露 VSOCK 端口（仅为声明，Enclave 内无需映射，宿主机通过 VSOCK 访问）
EXPOSE 8080

# 启动 Enclave 服务（直接运行，前台执行）
ENTRYPOINT ["/usr/local/bin/enclave-server"]
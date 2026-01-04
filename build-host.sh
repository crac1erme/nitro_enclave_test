CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /host-proxy ./cmd/host-proxy/main.go
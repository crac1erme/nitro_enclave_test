// cmd/host-proxy/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

func main() {
	// 命令行参数
	var cid = flag.Int("cid", 16, "Enclave CID")
	var enclavePort = flag.Int("enclave-port", 8080, "Enclave VSOCK 端口")
	var hostPort = flag.Int("host-port", 8081, "宿主机 HTTP 端口")
	flag.Parse()

	// 反向代理配置
	target, _ := url.Parse(fmt.Sprintf("http://localhost:%d", *enclavePort))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			sockPath := filepath.Join("/run/nitro_enclaves/vsock", fmt.Sprintf("%d", *cid), fmt.Sprintf("%d.sock", *enclavePort))
			if _, err := os.Stat(sockPath); os.IsNotExist(err) {
				return nil, fmt.Errorf("VSOCK 套接字不存在: %s", sockPath)
			}
			return net.Dial("unix", sockPath)
		},
	}

	// 启动代理
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
	log.Printf("宿主机 VSOCK 代理启动，监听 :%d → Enclave CID:%d Port:%d", *hostPort, *cid, *enclavePort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *hostPort), nil))
}

##### 宿主机启动

tcp 8080 -> enclave vsock 8001
```
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
docker run -d --name enclave-vsock-proxy --network host --privileged alpine/socat TCP-LISTEN:8080,fork,reuseaddr VSOCK-CONNECT:${ENCLAVE_CID}:8001
```

本机
curl 127.0.0.1:8001
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
sudo yum install -y socat

#访问enclave
socat TCP-LISTEN:8080,fork,reuseaddr VSOCK-CONNECT:${ENCLAVE_CID}:8001 > /var/log/enclave-vsock-proxy.log 2>&1 &
#host proxy提供给enclave访问
socat VSOCK-LISTEN:8003,fork,reuseaddr TCP:127.0.0.1:8081 > /var/log/host-vsock-proxy.log 2>&1 &

#docker run -d --name enclave-vsock-proxy --network host --privileged alpine/socat TCP-LISTEN:8080,fork,reuseaddr VSOCK-CONNECT:${ENCLAVE_CID}:8001

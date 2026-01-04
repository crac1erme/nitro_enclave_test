#enclave cli install
sudo yum install -y git make gcc rustc cargo
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo dnf install -y aws-nitro-enclaves-cli
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
#vsock build & run

git clone https://github.com/aws/aws-nitro-enclaves-cli.git
cd aws-nitro-enclaves-cli/
#磁盘要大一点 不然会构建失败
make vsock-proxy

#kms
#vsock-proxy 8000 kms.ap-southeast-2.amazonaws.com 443
#enclave build
docker build -f Dockerfile -t nitro-aes-enclave:latest .
mkdir eif
#build enclave-os
sudo nitro-cli build-enclave --docker-uri nitro-aes-enclave:latest --output-file eif/nitro-aes-enclave.eif
#run enclave-os
nitro-cli run-enclave --eif-path eif/nitro-aes-enclave.eif --cpu-count 2 --memory 1500 --enclave-cid 16 --debug-mode

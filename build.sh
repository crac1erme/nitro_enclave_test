docker build -f Dockerfile -t nitro-aes-enclave:latest .
mkdir eif
#build enclave-os
sudo nitro-cli build-enclave --docker-uri nitro-aes-enclave:latest --output-file eif/nitro-aes-enclave.eif
#run enclave-os
nitro-cli run-enclave --eif-path eif/nitro-aes-enclave.eif --cpu-count 2 --memory 1500 --enclave-cid 16 --debug-mode

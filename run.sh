# Assign an IP address to local loopback
ip addr add 127.0.0.1/32 dev lo

ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   dynamodb.us-west-2.amazonaws.com" >> /etc/hosts

/enclave-server &
socat VSOCK-LISTEN:8001,fork,reuseaddr TCP:127.0.0.1:8080
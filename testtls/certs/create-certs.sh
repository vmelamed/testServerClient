#!/bin/bash
set +x

script_dir=$(dirname $0)
pushd $script_dir
rm *.pem *.cnf

case $1 in
    RSA|rsa|RSA2048|rsa2048 )
        openssl genrsa -out ca-key.pem 2048
        openssl genrsa -out server-key.pem 2048
        ;;
    RSA4096|rsa4096 )
        openssl genrsa -out ca-key.pem 4096
        openssl genrsa -out server-key.pem 4096
        ;;
    P256|p256 )
        openssl ecparam -genkey -name secp256k1 -out ca-key.pem
        openssl ecparam -genkey -name secp256k1 -out server-key.pem
        ;;
    P384|p384 )
        openssl ecparam -genkey -name secp384r1 -out ca-key.pem
        openssl ecparam -genkey -name secp384r1 -out server-key.pem
        ;;
    ECDSA|ecdsa|P521|p521 )
        openssl ecparam -genkey -name secp521r1 -out ca-key.pem
        openssl ecparam -genkey -name secp521r1 -out server-key.pem
        ;;
    EDDSA|eddsa|ED25519|ed25519|X25519|x25519|"" )
        openssl genpkey -algorithm ED25519 -out ca-key.pem
        openssl genpkey -algorithm ED25519 -out server-key.pem
        ;;
    * )
        echo Unknown curve/algorithm
        ;;
esac

echo "CREATE CA CERTIFICATE"
cat > ca.cnf << EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = NY
L = New York City
O = test ca
CN = test-ca

[v3_req]
keyUsage=critical,keyCertSign
basicConstraints = critical,CA:TRUE
subjectAltName = @alt_names
subjectKeyIdentifier = hash

[alt_names]
DNS.1 = test-ca
EOF

openssl req \
    -x509 \
    -new \
    -days 1 \
    -nodes \
    -config ca.cnf \
    -key ca-key.pem \
    -out ca-cert.pem -verbose

echo "CREATE SERVER CSR"
cat > server-csr.cnf << EOF
[req]
prompt = no
default_bits = 4096
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = NY
L = New York City
O = server
CN = localhost

[v3_req]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
basicConstraints = critical,CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req \
    -new \
    -nodes \
    -config server-csr.cnf \
    -key server-key.pem \
    -out server-csr.pem -verbose

echo "CREATE SERVER CERTIFICATE"
# https://mta.openssl.org/pipermail/openssl-users/2016-January/002764.html
cat > server-req.cnf << EOF
[req]
prompt = no
default_bits = 4096
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = NY
L = New York City
O = server
CN = localhost

[v3_req]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
basicConstraints = critical,CA:FALSE
subjectAltName = @alt_names
authorityKeyIdentifier = keyid,issuer

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 \
    -req \
    -days 1 \
    -in server-csr.pem \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -extfile server-req.cnf \
    -extensions v3_req \
    -out server-cert.pem

echo "CA CERTIFICATE"
openssl x509 -in ca-cert.pem -text -noout
echo "SERVER CERTIFICATE"
openssl x509 -in server-cert.pem -text -noout

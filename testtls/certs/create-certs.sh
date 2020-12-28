#!/bin/bash
set +x

script_dir=$(dirname $0)
pushd $script_dir

echo "CREATE CA CERTIFICATE"
rm -f *
cat > ca.cnf << EOF
[req]
prompt = no
default_bits = 4096
default_md = sha256
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
# ,critical,digitalSignature,keyEncipherment
# extendedKeyUsage=serverAuth,clientAuth
basicConstraints = critical,CA:TRUE
# subjectKeyIdentifier = hash
subjectAltName = @alt_names

[alt_names]
DNS.1 = test-ca
EOF

openssl req \
    -x509 \
    -new \
    -newkey rsa:4096 \
    -days 1 \
    -nodes \
    -sha256 \
    -config ca.cnf \
    -keyout ca-key.pem \
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
# subjectKeyIdentifier = hash
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req \
    -new \
    -nodes \
    -sha256 \
    -newkey rsa:4096 \
    -config server-csr.cnf \
    -keyout server-key.pem \
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
# subjectKeyIdentifier = hash
# authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 \
    -req \
    -days 1 \
    -sha256 \
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

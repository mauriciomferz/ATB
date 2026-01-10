#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

TRUST_DOMAIN="${SPIFFE_TRUST_DOMAIN:-example.org}"
CLIENT_SPIFFE_URI="${CLIENT_SPIFFE_URI:-spiffe://${TRUST_DOMAIN}/ns/default/sa/agent/connector}"

echo "[+] Generating CA"
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -subj "/CN=atb-dev-ca" \
  -keyout ca.key -out ca.crt

echo "[+] Generating server key + CSR"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=atb-dev-server" -out server.csr

echo "[+] Signing server cert"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile server_ext.cnf

echo "[+] Generating client key + CSR"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=atb-dev-client" -out client.csr

echo "[+] Writing client SPIFFE URI to client_ext.cnf"
cat > client_ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
URI.1 = ${CLIENT_SPIFFE_URI}
EOF

echo "[+] Signing client cert"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 \
  -extfile client_ext.cnf

echo "[+] Done"
echo "    Client SPIFFE URI: ${CLIENT_SPIFFE_URI}"
echo "    Files: ca.crt server.crt/server.key client.crt/client.key"

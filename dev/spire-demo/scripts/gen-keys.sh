#!/bin/bash
# Generate keys for SPIRE demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$DEMO_DIR/keys"
CONF_DIR="$DEMO_DIR/conf"

mkdir -p "$KEYS_DIR"
mkdir -p "$CONF_DIR/server"

echo "Generating SPIRE demo keys..."

# Generate upstream CA for SPIRE Server
if [ ! -f "$CONF_DIR/server/dummy_upstream_ca.key" ]; then
    echo "  Generating upstream CA..."
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$CONF_DIR/server/dummy_upstream_ca.key"
    openssl req -new -x509 -days 365 \
        -key "$CONF_DIR/server/dummy_upstream_ca.key" \
        -out "$CONF_DIR/server/dummy_upstream_ca.crt" \
        -subj "/CN=SPIRE Demo CA"
fi

# Generate Ed25519 key for PoA signing
if [ ! -f "$KEYS_DIR/poa_ed25519.key" ]; then
    echo "  Generating PoA signing key (Ed25519)..."
    openssl genpkey -algorithm ed25519 -out "$KEYS_DIR/poa_ed25519.key"
    openssl pkey -in "$KEYS_DIR/poa_ed25519.key" -pubout -out "$KEYS_DIR/poa_ed25519.pub"
fi

echo ""
echo "Keys generated in $KEYS_DIR:"
ls -la "$KEYS_DIR"

echo ""
echo "SPIRE CA generated in $CONF_DIR/server:"
ls -la "$CONF_DIR/server"/*.crt "$CONF_DIR/server"/*.key 2>/dev/null || true

echo ""
echo "Done!"

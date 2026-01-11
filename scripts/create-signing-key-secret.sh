#!/bin/bash
# =============================================================================
# Create ATB AgentAuth Signing Key Secret
# =============================================================================
# This script generates an Ed25519 signing key and creates a Kubernetes secret.
#
# Usage:
#   ./create-signing-key-secret.sh [namespace]
#
# Examples:
#   ./create-signing-key-secret.sh atb-staging
#   ./create-signing-key-secret.sh atb-prod
#
# The secret is named "atb-agentauth-signing-key" and contains the Ed25519
# private key in PKCS8 PEM format.
# =============================================================================

set -euo pipefail

NAMESPACE="${1:-atb-staging}"
SECRET_NAME="atb-agentauth-signing-key"
KEY_FILE=$(mktemp)
PUBKEY_FILE=$(mktemp)

cleanup() {
    rm -f "$KEY_FILE" "$PUBKEY_FILE"
}
trap cleanup EXIT

echo "=== ATB AgentAuth Signing Key Setup ==="
echo ""

# Check if secret already exists
if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "⚠️  Secret '$SECRET_NAME' already exists in namespace '$NAMESPACE'"
    read -p "Do you want to rotate the key? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing secret."
        exit 0
    fi
    echo "Rotating key..."
    kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE"
fi

# Create namespace if it doesn't exist
if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "Creating namespace '$NAMESPACE'..."
    kubectl create namespace "$NAMESPACE"
fi

# Generate Ed25519 key pair
echo "Generating Ed25519 key pair..."
openssl genpkey -algorithm ED25519 -out "$KEY_FILE" 2>/dev/null
openssl pkey -in "$KEY_FILE" -pubout -out "$PUBKEY_FILE" 2>/dev/null

# Create Kubernetes secret
echo "Creating secret '$SECRET_NAME' in namespace '$NAMESPACE'..."
kubectl create secret generic "$SECRET_NAME" \
    --namespace="$NAMESPACE" \
    --from-file=ed25519_privkey_pem="$KEY_FILE" \
    --from-file=ed25519_pubkey_pem="$PUBKEY_FILE"

# Add labels
kubectl label secret "$SECRET_NAME" \
    --namespace="$NAMESPACE" \
    app.kubernetes.io/name=atb-agentauth \
    app.kubernetes.io/component=signing-key \
    app.kubernetes.io/managed-by=script

echo ""
echo "✅ Secret created successfully!"
echo ""
echo "Public key (for verification/federation):"
echo "-------------------------------------------"
cat "$PUBKEY_FILE"
echo "-------------------------------------------"
echo ""
echo "Next steps:"
echo "  1. Deploy ATB with Helm:"
echo "     helm upgrade --install atb-staging ./charts/atb \\"
echo "       -n $NAMESPACE \\"
echo "       -f charts/atb/values-staging.yaml \\"
echo "       -f charts/atb/values-observability.yaml"
echo ""
echo "  2. Store the public key for external systems that need to verify PoA tokens"
echo ""

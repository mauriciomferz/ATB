#!/bin/sh
# Extract token from SPIRE server output and save it
# The token generate command outputs: Token: <value>

echo "Generating join token..."
OUTPUT=$(/opt/spire/bin/spire-server token generate \
  -socketPath /tmp/spire-server/private/api.sock \
  -spiffeID spiffe://atb.example.org/spire/agent/demo \
  -ttl 86400 2>&1)

echo "Raw output: $OUTPUT"

# Extract token value (format: "Token: xxxxx")
TOKEN=$(echo "$OUTPUT" | grep -o 'Token: [^ ]*' | cut -d' ' -f2)

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to extract token"
  exit 1
fi

echo "Token generated: ${TOKEN:0:10}..."
echo "$TOKEN" > /token/join_token
echo "Token saved to /token/join_token"

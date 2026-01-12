#!/bin/sh
# Wait for token file to be created
echo "Waiting for join token..."
while [ ! -f /token/join_token ]; do
  sleep 1
done

TOKEN=$(cat /token/join_token)
echo "Got join token, starting SPIRE Agent..."

exec /opt/spire/bin/spire-agent run \
  -config /opt/spire/conf/agent/agent.conf \
  -joinToken "$TOKEN"

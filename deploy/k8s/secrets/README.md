# Secret Templates
# ================
# DO NOT commit real secrets to version control!
# These are templates showing the required secret structure.

# TLS Certificate Secret
# ----------------------
# Create with:
#   kubectl create secret tls atb-tls \
#     --cert=server.crt \
#     --key=server.key \
#     -n atb
#
# Or apply this template after adding your base64-encoded certs:

# apiVersion: v1
# kind: Secret
# metadata:
#   name: atb-tls
#   namespace: atb
# type: kubernetes.io/tls
# data:
#   tls.crt: <base64-encoded-cert>
#   tls.key: <base64-encoded-key>
#   ca.crt: <base64-encoded-ca-cert>

---
# PoA Signing Key Secret
# ----------------------
# Create with:
#   kubectl create secret generic poa-signing-key \
#     --from-file=private.key=poa_rsa.key \
#     --from-file=public.key=poa_rsa.pub \
#     -n atb
#
# Or apply this template:

# apiVersion: v1
# kind: Secret
# metadata:
#   name: poa-signing-key
#   namespace: atb
# type: Opaque
# data:
#   private.key: <base64-encoded-private-key>
#   public.key: <base64-encoded-public-key>

---
# SPIRE Agent Socket (if using SPIFFE)
# ------------------------------------
# Mount the SPIRE agent socket into pods that need workload identity:
#
# volumes:
#   - name: spire-agent-socket
#     hostPath:
#       path: /run/spire/sockets
#       type: Directory
#
# volumeMounts:
#   - name: spire-agent-socket
#     mountPath: /run/spire/sockets
#     readOnly: true

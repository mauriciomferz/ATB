# OT Action Registration Entries for SPIRE
# These entries map industrial workloads to SPIFFE IDs

# ==============================================================================
# PLC Controller Workloads
# ==============================================================================

# Siemens S7 PLC Controller
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/device/plc/siemens-s7/line-1 \
    -parentID spiffe://industrial.atb.example.com/agent/edge-gateway-01 \
    -selector tpm_devid:subject:CN=plc-line-1.site-a.local \
    -selector unix:uid:0 \
    -ttl 3600

# Allen-Bradley PLC
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/device/plc/allen-bradley/line-2 \
    -parentID spiffe://industrial.atb.example.com/agent/edge-gateway-01 \
    -selector tpm_devid:subject:CN=plc-line-2.site-a.local \
    -ttl 3600

# ==============================================================================
# HMI/SCADA Workloads
# ==============================================================================

# SCADA Server
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/device/scada/ignition \
    -parentID spiffe://industrial.atb.example.com/agent/scada-server \
    -selector tpm_devid:subject:CN=scada.site-a.local \
    -selector unix:user:scada \
    -ttl 3600

# HMI Panel
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/device/hmi/panel-01 \
    -parentID spiffe://industrial.atb.example.com/agent/hmi-01 \
    -selector tpm_devid:subject:CN=hmi-01.site-a.local \
    -ttl 3600

# ==============================================================================
# OPC-UA Gateway
# ==============================================================================

spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/gateway/opcua \
    -parentID spiffe://industrial.atb.example.com/agent/edge-gateway-01 \
    -selector docker:label:app:opcua-gateway \
    -ttl 3600

# ==============================================================================
# Edge AI Agents
# ==============================================================================

# Predictive Maintenance Agent
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/agent/predictive-maintenance \
    -parentID spiffe://industrial.atb.example.com/agent/edge-gateway-01 \
    -selector docker:label:app:pred-maintenance \
    -selector docker:label:tier:ai-agent \
    -ttl 1800

# Quality Control Vision Agent
spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/agent/quality-vision \
    -parentID spiffe://industrial.atb.example.com/agent/edge-gateway-01 \
    -selector docker:label:app:quality-vision \
    -selector docker:label:tier:ai-agent \
    -ttl 1800

# ==============================================================================
# Historian/Data Collector
# ==============================================================================

spire-server entry create \
    -spiffeID spiffe://industrial.atb.example.com/service/historian \
    -parentID spiffe://industrial.atb.example.com/agent/historian-server \
    -selector unix:user:historian \
    -ttl 3600

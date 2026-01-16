# OT/Industrial Edge TPM Attestation for ATB

This directory contains configuration and documentation for extending ATB to industrial/OT environments using TPM-based attestation.

## Overview

ATB can be extended to support industrial edge devices using:

1. **TPM DevID Attestation** - Hardware-backed device identity via TPM 2.0
2. **Nested SPIRE** - Hierarchical trust with site-level SPIRE servers  
3. **Edge Broker Mode** - Lightweight broker for constrained environments
4. **Offline Operation** - Pre-provisioned trust bundles for air-gapped networks

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Enterprise Cloud                            │
│  ┌─────────────────┐      ┌─────────────────┐                   │
│  │  SPIRE Server   │◄────►│   ATB Broker    │                   │
│  │    (Root)       │      │   (Central)     │                   │
│  └────────┬────────┘      └────────┬────────┘                   │
└───────────┼────────────────────────┼────────────────────────────┘
            │ Trust Bundle           │ Federation
            ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Industrial Site                             │
│  ┌─────────────────┐      ┌─────────────────┐                   │
│  │  SPIRE Server   │◄────►│  Edge Broker    │                   │
│  │   (Nested)      │      │   (Local)       │                   │
│  └────────┬────────┘      └─────────────────┘                   │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐      ┌─────────────────┐                   │
│  │  SPIRE Agent    │      │  SPIRE Agent    │                   │
│  │  (Device 1)     │      │  (Device 2)     │                   │
│  │  TPM Attested   │      │  TPM Attested   │                   │
│  └────────┬────────┘      └────────┬────────┘                   │
│           │                        │                            │
│           ▼                        ▼                            │
│  ┌─────────────────┐      ┌─────────────────┐                   │
│  │    PLC / HMI    │      │  Edge Gateway   │                   │
│  │   Workload      │      │   Workload      │                   │
│  └─────────────────┘      └─────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

## TPM DevID Attestation

### Prerequisites

- TPM 2.0 module on edge device
- Device certificate (DevID) provisioned in TPM
- SPIRE configured with TPM attestor plugin

### SPIRE Agent Configuration for TPM

See `spire-agent-tpm.conf` for a complete configuration example.

## Supported Industrial Protocols

ATB can proxy and authorize actions for:

| Protocol | Action Examples |
|----------|-----------------|
| OPC-UA | `opcua.node.read`, `opcua.node.write`, `opcua.method.call` |
| Modbus | `modbus.register.read`, `modbus.coil.write` |
| MQTT | `mqtt.publish`, `mqtt.subscribe` |
| S7 (Siemens) | `s7.db.read`, `s7.db.write`, `s7.plc.start`, `s7.plc.stop` |

## Security Considerations

1. **Physical Security** - TPM protects identity even if device is compromised
2. **Network Segmentation** - Edge broker in DMZ between IT and OT
3. **Offline Resilience** - Pre-cached policies for network outages
4. **Audit Trail** - All OT actions logged centrally when connected

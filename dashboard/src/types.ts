// API types for ATB Dashboard

export interface AuditEvent {
  id: string;
  timestamp: string;
  action: string;
  agent: string;
  decision: 'allow' | 'deny';
  reason?: string;
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH';
  accountableParty: {
    type: string;
    id: string;
    displayName?: string;
  };
  jurisdiction: string;
  durationMs: number;
}

export interface MetricsSummary {
  totalRequests: number;
  allowedRequests: number;
  deniedRequests: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  errorRate: number;
}

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface PolicyStats {
  name: string;
  evaluations: number;
  allowRate: number;
  avgLatencyMs: number;
}

export interface AgentInfo {
  spiffeId: string;
  lastSeen: string;
  requestCount: number;
  allowRate: number;
  riskProfile: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface SystemHealth {
  broker: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    uptime: number;
    version: string;
  };
  opa: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    policyCount: number;
    lastSync: string;
  };
  spire: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    trustDomain: string;
    workloadCount: number;
  };
}

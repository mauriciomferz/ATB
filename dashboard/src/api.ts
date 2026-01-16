import type { AuditEvent, MetricsSummary, SystemHealth, AgentInfo, PolicyStats, ApprovalRequest } from './types';

const API_BASE = '/api';

// Mock data for development
const MOCK_MODE = true;

function generateMockAuditEvents(count: number): AuditEvent[] {
  const actions = [
    'sap.vendor.change',
    'sap.vendor.read',
    'crm.contact.update',
    'salesforce.bulk.export',
    'sap.payment.approve',
  ];
  const agents = [
    'spiffe://atb.example/agent/copilot-prod',
    'spiffe://atb.example/agent/finance-bot',
    'spiffe://atb.example/agent/data-sync',
  ];
  const tiers: Array<'LOW' | 'MEDIUM' | 'HIGH'> = ['LOW', 'MEDIUM', 'HIGH'];

  return Array.from({ length: count }, (_, i) => ({
    id: `audit_${Date.now()}_${i}`,
    timestamp: new Date(Date.now() - i * 60000).toISOString(),
    action: actions[Math.floor(Math.random() * actions.length)],
    agent: agents[Math.floor(Math.random() * agents.length)],
    decision: Math.random() > 0.1 ? 'allow' : 'deny',
    reason: Math.random() > 0.1 ? undefined : 'liability_cap exceeded',
    riskTier: tiers[Math.floor(Math.random() * tiers.length)],
    accountableParty: {
      type: 'user',
      id: `user${i % 5}@example.com`,
      displayName: `User ${i % 5}`,
    },
    jurisdiction: ['DE', 'US', 'GB', 'GLOBAL'][Math.floor(Math.random() * 4)],
    durationMs: Math.floor(Math.random() * 50) + 5,
  }));
}

export async function fetchAuditEvents(limit = 50): Promise<AuditEvent[]> {
  if (MOCK_MODE) {
    return generateMockAuditEvents(limit);
  }
  const res = await fetch(`${API_BASE}/audit?limit=${limit}`);
  return res.json();
}

export async function fetchMetrics(): Promise<MetricsSummary> {
  if (MOCK_MODE) {
    return {
      totalRequests: 12543,
      allowedRequests: 11892,
      deniedRequests: 651,
      avgLatencyMs: 23,
      p95LatencyMs: 45,
      errorRate: 0.052,
    };
  }
  const res = await fetch(`${API_BASE}/metrics/summary`);
  return res.json();
}

export async function fetchSystemHealth(): Promise<SystemHealth> {
  if (MOCK_MODE) {
    return {
      broker: {
        status: 'healthy',
        uptime: 86400 * 7,
        version: '0.1.0',
      },
      opa: {
        status: 'healthy',
        policyCount: 12,
        lastSync: new Date().toISOString(),
      },
      spire: {
        status: 'healthy',
        trustDomain: 'atb.example.com',
        workloadCount: 8,
      },
    };
  }
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchAgents(): Promise<AgentInfo[]> {
  if (MOCK_MODE) {
    return [
      {
        spiffeId: 'spiffe://atb.example/agent/copilot-prod',
        lastSeen: new Date(Date.now() - 30000).toISOString(),
        requestCount: 4521,
        allowRate: 0.98,
        riskProfile: 'LOW',
      },
      {
        spiffeId: 'spiffe://atb.example/agent/finance-bot',
        lastSeen: new Date(Date.now() - 120000).toISOString(),
        requestCount: 1832,
        allowRate: 0.92,
        riskProfile: 'HIGH',
      },
      {
        spiffeId: 'spiffe://atb.example/agent/data-sync',
        lastSeen: new Date(Date.now() - 60000).toISOString(),
        requestCount: 6190,
        allowRate: 0.95,
        riskProfile: 'MEDIUM',
      },
    ];
  }
  const res = await fetch(`${API_BASE}/agents`);
  return res.json();
}

export async function fetchPolicyStats(): Promise<PolicyStats[]> {
  if (MOCK_MODE) {
    return [
      { name: 'poa/allow', evaluations: 12543, allowRate: 0.948, avgLatencyMs: 12 },
      { name: 'poa/risk_tier', evaluations: 12543, allowRate: 1.0, avgLatencyMs: 5 },
      { name: 'poa/leg_valid', evaluations: 12543, allowRate: 0.992, avgLatencyMs: 8 },
    ];
  }
  const res = await fetch(`${API_BASE}/policies/stats`);
  return res.json();
}

export async function fetchRequestsTimeSeries(): Promise<Array<{ timestamp: string; allowed: number; denied: number }>> {
  if (MOCK_MODE) {
    return Array.from({ length: 24 }, (_, i) => ({
      timestamp: new Date(Date.now() - (23 - i) * 3600000).toISOString(),
      allowed: Math.floor(Math.random() * 500) + 400,
      denied: Math.floor(Math.random() * 30) + 10,
    }));
  }
  const res = await fetch(`${API_BASE}/metrics/requests`);
  return res.json();
}

// Approval workflow API functions

function generateMockApprovals(): ApprovalRequest[] {
  const actions = [
    'sap.vendor.bank_change',
    'sap.payment.approve',
    'salesforce.refund.process',
    'sap.journal.post',
    'crm.opportunity.close',
  ];

  return [
    {
      id: 'apr_001',
      action: 'sap.vendor.bank_change',
      agentSpiffeId: 'spiffe://atb.example/agent/finance-bot',
      requestedBy: 'alice@example.com',
      requestedAt: new Date(Date.now() - 300000).toISOString(),
      expiresAt: new Date(Date.now() + 180000).toISOString(),
      riskTier: 'HIGH',
      dualControlRequired: true,
      approvalCount: 1,
      requiredApprovals: 2,
      constraints: {
        vendor_id: '1000',
        max_amount: 50000,
        currency: 'EUR',
      },
      legalBasis: {
        basis: 'contract',
        jurisdiction: 'DE',
        accountableParty: {
          type: 'human',
          id: 'alice@example.com',
        },
      },
      status: 'pending',
    },
    {
      id: 'apr_002',
      action: 'sap.payment.approve',
      agentSpiffeId: 'spiffe://atb.example/agent/payment-processor',
      requestedBy: 'bob@example.com',
      requestedAt: new Date(Date.now() - 120000).toISOString(),
      expiresAt: new Date(Date.now() + 240000).toISOString(),
      riskTier: 'HIGH',
      dualControlRequired: true,
      approvalCount: 0,
      requiredApprovals: 2,
      constraints: {
        payment_id: 'PAY-2026-001234',
        amount: 25000,
        currency: 'USD',
      },
      legalBasis: {
        basis: 'contract',
        jurisdiction: 'US',
        accountableParty: {
          type: 'human',
          id: 'bob@example.com',
        },
      },
      status: 'pending',
    },
    {
      id: 'apr_003',
      action: 'crm.opportunity.close',
      agentSpiffeId: 'spiffe://atb.example/agent/copilot-prod',
      requestedBy: 'carol@example.com',
      requestedAt: new Date(Date.now() - 60000).toISOString(),
      expiresAt: new Date(Date.now() + 300000).toISOString(),
      riskTier: 'MEDIUM',
      dualControlRequired: false,
      approvalCount: 0,
      requiredApprovals: 1,
      constraints: {
        opportunity_id: 'OPP-123456',
        amount: 150000,
        stage: 'Closed Won',
      },
      legalBasis: {
        basis: 'legitimate_interest',
        jurisdiction: 'GB',
        accountableParty: {
          type: 'human',
          id: 'carol@example.com',
        },
      },
      status: 'pending',
    },
  ];
}

export async function fetchPendingApprovals(): Promise<ApprovalRequest[]> {
  if (MOCK_MODE) {
    return generateMockApprovals();
  }
  const res = await fetch(`${API_BASE}/approvals/pending`);
  return res.json();
}

export async function approveRequest(requestId: string): Promise<{ success: boolean }> {
  if (MOCK_MODE) {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500));
    return { success: true };
  }
  const res = await fetch(`${API_BASE}/approvals/${requestId}/approve`, {
    method: 'POST',
  });
  return res.json();
}

export async function rejectRequest(requestId: string, reason: string): Promise<{ success: boolean }> {
  if (MOCK_MODE) {
    await new Promise(resolve => setTimeout(resolve, 500));
    return { success: true };
  }
  const res = await fetch(`${API_BASE}/approvals/${requestId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
  return res.json();
}

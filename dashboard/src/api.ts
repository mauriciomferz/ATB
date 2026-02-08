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

// POA Verification API
export interface PoaVerificationResult {
  valid: boolean;
  signatureValid: boolean;
  expired: boolean;
  revoked: boolean;
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  checks: {
    name: string;
    passed: boolean;
    message: string;
  }[];
  policyEvaluation?: {
    decision: 'allow' | 'deny';
    reason?: string;
    timePolicyViolations?: string[];
  };
}

export async function verifyPoa(token: string, action?: string): Promise<PoaVerificationResult> {
  if (MOCK_MODE) {
    await new Promise(resolve => setTimeout(resolve, 300));

    // Parse token to determine mock result
    const parts = token.split('.');
    if (parts.length !== 3) {
      return {
        valid: false,
        signatureValid: false,
        expired: false,
        revoked: false,
        riskTier: 'LOW',
        checks: [
          { name: 'Format', passed: false, message: 'Invalid JWT format' },
        ],
      };
    }

    try {
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      const isExpired = payload.exp && payload.exp < Date.now() / 1000;
      const isRevoked = Math.random() < 0.05; // 5% chance of revoked for demo

      // Determine risk tier from action
      const riskTier = action?.includes('vendor.bank_change') ? 'HIGH'
        : action?.includes('org.structure') ? 'CRITICAL'
        : action?.includes('vendor') ? 'MEDIUM'
        : 'LOW';

      // Helper to check if an object has actual content (not empty)
      const hasContent = (obj: unknown): boolean => {
        if (!obj || typeof obj !== 'object') return false;
        return Object.keys(obj as object).length > 0;
      };

      const hasLegalGrounding = hasContent(payload.leg);
      const hasConstraints = hasContent(payload.con);

      // Build checks list
      const checks = [
        { name: 'Format', passed: true, message: 'Valid JWT structure' },
        { name: 'Signature', passed: !isRevoked, message: isRevoked ? 'Signature verification failed' : 'ES256 signature verified' },
        { name: 'Expiration', passed: !isExpired, message: isExpired ? `Token expired at ${new Date(payload.exp * 1000).toISOString()}` : 'Token is not expired' },
        { name: 'Revocation', passed: !isRevoked, message: isRevoked ? 'Token has been revoked' : 'Token is not revoked' },
        { name: 'Legal Grounding', passed: hasLegalGrounding, message: hasLegalGrounding ? 'Legal basis present' : 'Missing or empty legal grounding claim' },
        { name: 'Constraints', passed: true, message: hasConstraints ? 'Constraints defined' : 'No constraints (unrestricted)' },
        { name: 'Issuer', passed: !!payload.iss, message: payload.iss ? `Issued by ${payload.iss}` : 'Missing issuer claim' },
      ];

      // Add risk tier checks
      if (riskTier === 'CRITICAL') {
        const hasExecutiveApproval = payload.leg?.executive_control?.approvers?.length >= 2;
        checks.push({
          name: 'Executive Approval',
          passed: hasExecutiveApproval,
          message: hasExecutiveApproval ? '2+ executive approvers present' : 'Critical actions require executive approval',
        });
      }

      if (riskTier === 'HIGH') {
        const hasDualControl = payload.leg?.dual_control?.approvers?.length >= 2;
        checks.push({
          name: 'Dual Control',
          passed: hasDualControl,
          message: hasDualControl ? 'Dual control requirement met' : 'High-risk actions require dual control',
        });
      }

      const valid = !isExpired && !isRevoked && checks.every(c => c.passed);

      return {
        valid,
        signatureValid: !isRevoked,
        expired: isExpired,
        revoked: isRevoked,
        riskTier,
        checks,
        policyEvaluation: {
          decision: valid ? 'allow' : 'deny',
          reason: !valid ? checks.find(c => !c.passed)?.message : undefined,
          timePolicyViolations: isExpired ? ['approval_expired'] : [],
        },
      };
    } catch {
      return {
        valid: false,
        signatureValid: false,
        expired: false,
        revoked: false,
        riskTier: 'LOW',
        checks: [
          { name: 'Format', passed: false, message: 'Failed to parse token payload' },
        ],
      };
    }
  }

  const res = await fetch(`${API_BASE}/poa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, action }),
  });
  return res.json();
}

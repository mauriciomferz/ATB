// =============================================================================
// ATB Stress Test
// =============================================================================
// High-intensity load to find breaking points and resource limits.
// Gradually ramps up to extreme load and measures degradation.
//
// Usage:
//   k6 run tests/load/stress_test.js
//   k6 run --env BROKER_URL=http://broker:8080 tests/load/stress_test.js
//
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const requestsTotal = new Counter('requests_total');
const successfulRequests = new Counter('successful_requests');
const failedRequests = new Counter('failed_requests');

// Stress test configuration - aggressive ramp-up
export const options = {
  stages: [
    // Ramp-up phase
    { duration: '2m', target: 100 },   // Warm up
    { duration: '3m', target: 200 },   // Normal load
    { duration: '2m', target: 300 },   // High load
    { duration: '3m', target: 400 },   // Stress load
    { duration: '2m', target: 500 },   // Breaking point test
    { duration: '3m', target: 500 },   // Sustained stress
    // Ramp-down phase
    { duration: '2m', target: 200 },   // Recovery
    { duration: '1m', target: 0 },     // Cooldown
  ],
  thresholds: {
    // More lenient thresholds for stress testing
    'http_req_duration': ['p(95)<2000', 'p(99)<5000'],
    'http_req_failed': ['rate<0.10'],  // Allow up to 10% errors under stress
    'errors': ['rate<0.10'],
    'response_time': ['avg<1000', 'max<10000'],
  },
};

const OPA_URL = __ENV.OPA_URL || 'http://localhost:8182';
const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://localhost:9001';

// Generate PoA-like payload
function generatePoA(action, riskTier) {
  const now = Math.floor(Date.now() / 1000);
  return {
    input: {
      poa: {
        sub: `spiffe://atb.example/agent/stress-test-${__VU}`,
        act: action,
        con: {
          params: {
            request_id: `stress-${__VU}-${__ITER}`,
            timestamp: now,
          },
          constraints: {
            liability_cap: riskTier === 'HIGH' ? 100000 : 10000,
          },
        },
        leg: {
          jurisdiction: 'GLOBAL',
          accountable_party: {
            type: 'user',
            id: `stress-user-${__VU}@example.com`,
          },
        },
        iat: now,
        exp: now + 300,
        jti: `stress_${__VU}_${__ITER}_${now}`,
      },
    },
  };
}

// Actions with different risk tiers
const STRESS_ACTIONS = [
  { action: 'sap.vendor.read', tier: 'LOW' },
  { action: 'crm.contact.list', tier: 'LOW' },
  { action: 'sap.order.create', tier: 'MEDIUM' },
  { action: 'salesforce.bulk.export', tier: 'MEDIUM' },
  { action: 'sap.payment.approve', tier: 'HIGH' },
];

export default function () {
  // Select random action
  const actionConfig = STRESS_ACTIONS[Math.floor(Math.random() * STRESS_ACTIONS.length)];
  const payload = generatePoA(actionConfig.action, actionConfig.tier);

  // Test OPA policy evaluation
  const opaStart = Date.now();
  const opaRes = http.post(
    `${OPA_URL}/v1/data/poa/allow`,
    JSON.stringify(payload),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'OPA Policy Check' },
    }
  );
  responseTime.add(Date.now() - opaStart);
  requestsTotal.add(1);

  const opaSuccess = check(opaRes, {
    'OPA status is 200': (r) => r.status === 200,
    'OPA response time < 500ms': (r) => r.timings.duration < 500,
    'OPA returns result': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.result !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (opaSuccess) {
    successfulRequests.add(1);
  } else {
    failedRequests.add(1);
    errorRate.add(1);
  }

  // Also hit upstream under stress
  if (Math.random() < 0.3) {  // 30% of requests
    const upstreamRes = http.post(
      UPSTREAM_URL,
      JSON.stringify({ action: actionConfig.action, stress: true }),
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { name: 'Upstream Echo' },
      }
    );

    check(upstreamRes, {
      'Upstream status is 200': (r) => r.status === 200,
    });
  }

  // Minimal sleep to maximize stress
  sleep(0.1);
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'stress_test',
    metrics: {
      total_requests: data.metrics.requests_total?.values?.count || 0,
      successful_requests: data.metrics.successful_requests?.values?.count || 0,
      failed_requests: data.metrics.failed_requests?.values?.count || 0,
      error_rate: data.metrics.errors?.values?.rate || 0,
      avg_response_time: data.metrics.response_time?.values?.avg || 0,
      p95_response_time: data.metrics.response_time?.values?.['p(95)'] || 0,
      p99_response_time: data.metrics.response_time?.values?.['p(99)'] || 0,
      max_response_time: data.metrics.response_time?.values?.max || 0,
    },
    thresholds: data.thresholds,
  };

  return {
    'stdout': JSON.stringify(summary, null, 2) + '\n',
    'tests/load/results/stress_test_summary.json': JSON.stringify(summary, null, 2),
  };
}

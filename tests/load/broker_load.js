// =============================================================================
// ATB Broker Load Test
// =============================================================================
// Tests the broker authorization endpoint under load.
//
// Usage:
//   k6 run broker_load.js
//   k6 run --vus 50 --duration 5m broker_load.js
//   k6 run -e BROKER_URL=http://localhost:8080 broker_load.js
//
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const authLatency = new Trend('auth_latency');

// Test configuration
export const options = {
  // Default: ramp up to 100 VUs over 1 minute, sustain for 5 minutes, ramp down
  stages: [
    { duration: '1m', target: 50 },   // Ramp up
    { duration: '5m', target: 100 },  // Sustain
    { duration: '1m', target: 0 },    // Ramp down
  ],
  
  // Thresholds - test fails if these aren't met
  thresholds: {
    'http_req_duration': ['p(95)<200', 'p(99)<500'],  // 95th percentile < 200ms
    'http_req_failed': ['rate<0.01'],                  // Error rate < 1%
    'errors': ['rate<0.01'],                           // Custom error rate < 1%
  },
};

// Configuration from environment variables
const BROKER_URL = __ENV.BROKER_URL || 'http://localhost:8080';
const OPA_URL = __ENV.OPA_URL || 'http://localhost:8181';

// Sample PoA tokens for different risk tiers
const POA_TOKENS = {
  low: generateMockPoAToken('LOW'),
  medium: generateMockPoAToken('MEDIUM'),
  high: generateMockPoAToken('HIGH'),
};

// Sample actions for different risk tiers
const ACTIONS = [
  // LOW risk actions (should auto-approve)
  { verb: 'read', resource: 'logs/application', tier: 'low' },
  { verb: 'read', resource: 'metrics/system', tier: 'low' },
  { verb: 'list', resource: 'deployments/dev', tier: 'low' },
  
  // MEDIUM risk actions (require approval)
  { verb: 'modify', resource: 'config/feature-flags', tier: 'medium' },
  { verb: 'create', resource: 'deployment/staging', tier: 'medium' },
  
  // HIGH risk actions (require multi-party approval)
  { verb: 'delete', resource: 'deployment/production', tier: 'high' },
  { verb: 'execute', resource: 'admin/shutdown', tier: 'high' },
];

// Setup function - runs once before the test
export function setup() {
  // Verify services are reachable
  const brokerHealth = http.get(`${BROKER_URL}/health`);
  const opaHealth = http.get(`${OPA_URL}/health`);
  
  if (brokerHealth.status !== 200) {
    console.warn(`Broker health check failed: ${brokerHealth.status}`);
  }
  if (opaHealth.status !== 200) {
    console.warn(`OPA health check failed: ${opaHealth.status}`);
  }
  
  return {
    startTime: new Date().toISOString(),
  };
}

// Main test function - runs for each virtual user
export default function() {
  // Select random action
  const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
  const poaToken = POA_TOKENS[action.tier];
  
  // Build request
  const payload = JSON.stringify({
    action: {
      verb: action.verb,
      resource: action.resource,
      parameters: {},
    },
    reason: `Load test action: ${action.verb} ${action.resource}`,
    correlation_id: `loadtest-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  });
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${poaToken}`,
      'X-Request-ID': `k6-${__VU}-${__ITER}`,
    },
    tags: {
      action_type: action.verb,
      risk_tier: action.tier,
    },
  };
  
  // Make authorization request
  const startTime = Date.now();
  const response = http.post(`${BROKER_URL}/v1/authorize`, payload, params);
  const duration = Date.now() - startTime;
  
  // Record custom metrics
  authLatency.add(duration, { tier: action.tier });
  
  // Validate response
  const success = check(response, {
    'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
    'response has decision': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.allowed !== undefined || body.decision !== undefined;
      } catch {
        return false;
      }
    },
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  errorRate.add(!success);
  
  // Small sleep between requests
  sleep(0.1 + Math.random() * 0.2);
}

// Teardown function - runs once after the test
export function teardown(data) {
  console.log(`Test started at: ${data.startTime}`);
  console.log(`Test ended at: ${new Date().toISOString()}`);
}

// Helper function to generate mock PoA tokens
function generateMockPoAToken(riskTier) {
  // In real tests, you'd use actual tokens from AgentAuth
  // This is a placeholder for load testing
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({
    sub: 'load-test-agent',
    iss: 'atb-agentauth',
    aud: 'atb-broker',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    risk_tier: riskTier,
    action: '*',
  }));
  const signature = 'mock-signature-for-load-testing';
  
  return `${header}.${payload}.${signature}`;
}

// Helper function for base64 encoding
function btoa(str) {
  return __ENV.K6_BROWSER ? 
    globalThis.btoa(str) : 
    encoding.b64encode(str);
}

import encoding from 'k6/encoding';

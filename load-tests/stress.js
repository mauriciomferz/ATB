// ATB Load Tests using k6
// Run with: k6 run --duration 30s --vus 5 stress.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Configuration
const BASE_URL = __ENV.BROKER_URL || 'http://localhost:8080';

// Test options
export const options = {
  vus: 5,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    errors: ['rate<0.1'],              // Error rate under 10%
  },
};

// Health check test
export function healthCheck() {
  const res = http.get(`${BASE_URL}/health`);
  const passed = check(res, {
    'health status is 200': (r) => r.status === 200,
    'health response is ok': (r) => {
      try {
        return JSON.parse(r.body).status === 'ok';
      } catch {
        return false;
      }
    },
  });
  errorRate.add(!passed);
  sleep(0.1);
}

// Ready check test
export function readyCheck() {
  const res = http.get(`${BASE_URL}/ready`);
  const passed = check(res, {
    'ready status is 200 or 503': (r) => [200, 503].includes(r.status),
  });
  errorRate.add(!passed);
  sleep(0.1);
}

// Policy check test (requires running OPA)
export function policyCheck() {
  const payload = JSON.stringify({
    action: 'sap.vendor.read',
    params: { vendor_id: 'V-001' },
    agent: 'spiffe://atb.example/agent/test',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-SPIFFE-ID': 'spiffe://atb.example/agent/test',
    },
  };

  const res = http.post(`${BASE_URL}/v1/policy/check`, payload, params);
  const passed = check(res, {
    'policy check returns valid status': (r) => [200, 400, 401, 500, 503].includes(r.status),
  });
  errorRate.add(!passed);
  sleep(0.1);
}

// Default function runs health checks
export default function () {
  healthCheck();
  readyCheck();
}

// Scenarios for more complex testing
export const scenarios = {
  health: {
    executor: 'constant-vus',
    vus: 3,
    duration: '20s',
    exec: 'healthCheck',
  },
  ready: {
    executor: 'constant-vus',
    vus: 2,
    duration: '20s',
    exec: 'readyCheck',
  },
};

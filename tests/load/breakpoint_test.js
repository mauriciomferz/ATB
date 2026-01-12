// =============================================================================
// ATB Breakpoint Test
// =============================================================================
// Finds the exact breaking point where the system starts failing.
// Increases load linearly until error rate exceeds threshold.
//
// Usage:
//   k6 run tests/load/breakpoint_test.js
//
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Gauge } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const currentVUs = new Gauge('current_vus');
const breakpointVUs = new Gauge('breakpoint_vus');

// Configuration for breakpoint detection
const MAX_VUS = 1000;  // Maximum VUs to test
const RAMP_DURATION = '30m';  // Time to reach max VUs

export const options = {
  stages: [
    { duration: RAMP_DURATION, target: MAX_VUS },  // Linear ramp to max
  ],
  thresholds: {
    // These are for reporting - not for pass/fail
    'http_req_duration': ['p(95)<5000'],
    'http_req_failed': ['rate<0.50'],
  },
};

const OPA_URL = __ENV.OPA_URL || 'http://localhost:8182';

// Track breakpoint detection
let breakpointDetected = false;
let breakpointVUCount = null;
let errorWindow = [];
const ERROR_WINDOW_SIZE = 100;
const ERROR_THRESHOLD = 0.10;  // 10% error rate triggers breakpoint

function generatePoA() {
  const now = Math.floor(Date.now() / 1000);
  return {
    input: {
      poa: {
        sub: `spiffe://atb.example/agent/breakpoint-test`,
        act: 'sap.vendor.read',
        con: {
          params: {
            vendor_id: `V-${Math.floor(Math.random() * 100000)}`,
          },
          constraints: {
            liability_cap: 5000,
          },
        },
        leg: {
          jurisdiction: 'GLOBAL',
          accountable_party: {
            type: 'user',
            id: 'breakpoint@example.com',
          },
        },
        iat: now,
        exp: now + 300,
        jti: `breakpoint_${__VU}_${__ITER}_${now}`,
      },
    },
  };
}

export default function () {
  currentVUs.add(__VU);

  const payload = generatePoA();

  const res = http.post(
    `${OPA_URL}/v1/data/poa/allow`,
    JSON.stringify(payload),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'OPA Policy Check' },
    }
  );

  responseTime.add(res.timings.duration);

  const success = check(res, {
    'Status is 200': (r) => r.status === 200,
    'Response time < 2s': (r) => r.timings.duration < 2000,
  });

  // Track errors in sliding window
  errorWindow.push(success ? 0 : 1);
  if (errorWindow.length > ERROR_WINDOW_SIZE) {
    errorWindow.shift();
  }

  // Calculate rolling error rate
  const rollingErrorRate = errorWindow.reduce((a, b) => a + b, 0) / errorWindow.length;

  if (!success) {
    errorRate.add(1);
  }

  // Detect breakpoint
  if (!breakpointDetected && rollingErrorRate > ERROR_THRESHOLD) {
    breakpointDetected = true;
    breakpointVUCount = __VU;
    breakpointVUs.add(__VU);
    console.log(`[BREAKPOINT] Detected at ${__VU} VUs with ${(rollingErrorRate * 100).toFixed(1)}% error rate`);
  }

  // Minimal sleep for maximum load
  sleep(0.1);
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'breakpoint_test',
    breakpoint: {
      detected: breakpointDetected,
      vu_count: breakpointVUCount || 'Not reached',
      error_threshold: `${ERROR_THRESHOLD * 100}%`,
    },
    metrics: {
      max_vus_tested: MAX_VUS,
      total_requests: data.metrics.http_reqs?.values?.count || 0,
      final_error_rate: data.metrics.errors?.values?.rate || 0,
      avg_response_time: data.metrics.response_time?.values?.avg || 0,
      p95_response_time: data.metrics.response_time?.values?.['p(95)'] || 0,
      p99_response_time: data.metrics.response_time?.values?.['p(99)'] || 0,
      max_response_time: data.metrics.response_time?.values?.max || 0,
    },
    recommendations: [],
    thresholds: data.thresholds,
  };

  // Add recommendations based on results
  if (breakpointVUCount) {
    if (breakpointVUCount < 100) {
      summary.recommendations.push('Consider scaling horizontally - breakpoint reached early');
    } else if (breakpointVUCount < 300) {
      summary.recommendations.push('System handles moderate load - review resource allocation');
    } else {
      summary.recommendations.push('System handles high load well');
    }
  } else {
    summary.recommendations.push(`System stable up to ${MAX_VUS} VUs - consider testing higher`);
  }

  return {
    'stdout': JSON.stringify(summary, null, 2) + '\n',
    'tests/load/results/breakpoint_test_summary.json': JSON.stringify(summary, null, 2),
  };
}

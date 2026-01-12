// =============================================================================
// ATB Soak Test
// =============================================================================
// Long-duration test to detect memory leaks, resource exhaustion, and
// performance degradation over time.
//
// Usage:
//   k6 run tests/load/soak_test.js
//   k6 run --env DURATION=1h tests/load/soak_test.js
//
// Recommended: Run for 1-4 hours in staging environment
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const requestsTotal = new Counter('requests_total');
const currentRPS = new Gauge('current_rps');

// Track degradation over time
const degradationTrend = new Trend('degradation_trend');

// Soak test configuration - steady load over long duration
const DURATION = __ENV.DURATION || '30m';  // Default 30 minutes, recommend 1-4 hours

export const options = {
  stages: [
    { duration: '5m', target: 50 },    // Ramp up to steady state
    { duration: DURATION, target: 50 }, // Maintain steady state
    { duration: '5m', target: 0 },     // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],
    'http_req_failed': ['rate<0.01'],  // Very low error tolerance for soak test
    'errors': ['rate<0.01'],
    'response_time': ['avg<300', 'p(99)<800'],
  },
};

const OPA_URL = __ENV.OPA_URL || 'http://localhost:8182';
const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://localhost:9001';

// Baseline response time (set during warm-up)
let baselineResponseTime = null;

function generatePoA(iteration) {
  const now = Math.floor(Date.now() / 1000);
  return {
    input: {
      poa: {
        sub: `spiffe://atb.example/agent/soak-test`,
        act: 'crm.contact.read',
        con: {
          params: {
            contact_id: `C-${iteration % 10000}`,
            fields: ['name', 'email'],
          },
          constraints: {
            liability_cap: 5000,
          },
        },
        leg: {
          jurisdiction: 'GLOBAL',
          accountable_party: {
            type: 'user',
            id: 'soak-test@example.com',
          },
        },
        iat: now,
        exp: now + 300,
        jti: `soak_${__VU}_${iteration}_${now}`,
      },
    },
  };
}

// Track metrics over time windows
let windowStart = Date.now();
let windowRequests = 0;
const WINDOW_SIZE = 60000;  // 1 minute windows

export default function () {
  const iteration = __ITER;
  const payload = generatePoA(iteration);

  // OPA policy evaluation
  const start = Date.now();
  const res = http.post(
    `${OPA_URL}/v1/data/poa/allow`,
    JSON.stringify(payload),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'OPA Policy Check' },
    }
  );
  const duration = Date.now() - start;

  responseTime.add(duration);
  requestsTotal.add(1);
  windowRequests++;

  // Set baseline during first 100 requests
  if (iteration < 100) {
    if (baselineResponseTime === null) {
      baselineResponseTime = duration;
    } else {
      baselineResponseTime = (baselineResponseTime * iteration + duration) / (iteration + 1);
    }
  } else if (baselineResponseTime !== null) {
    // Track degradation as percentage above baseline
    const degradation = ((duration - baselineResponseTime) / baselineResponseTime) * 100;
    degradationTrend.add(Math.max(0, degradation));
  }

  // Calculate RPS every minute
  if (Date.now() - windowStart > WINDOW_SIZE) {
    currentRPS.add(windowRequests / (WINDOW_SIZE / 1000));
    windowRequests = 0;
    windowStart = Date.now();
  }

  const success = check(res, {
    'Status is 200': (r) => r.status === 200,
    'Response time < 500ms': (r) => r.timings.duration < 500,
    'No memory errors': (r) => !r.body.includes('out of memory'),
    'Valid JSON response': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    errorRate.add(1);
  }

  // Occasional upstream check
  if (iteration % 10 === 0) {
    const upstreamRes = http.get(`${UPSTREAM_URL}/health`, {
      tags: { name: 'Upstream Health' },
    });
    check(upstreamRes, {
      'Upstream healthy': (r) => r.status === 200,
    });
  }

  // Steady pacing
  sleep(1);
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'soak_test',
    duration: DURATION,
    metrics: {
      total_requests: data.metrics.requests_total?.values?.count || 0,
      error_rate: data.metrics.errors?.values?.rate || 0,
      avg_response_time: data.metrics.response_time?.values?.avg || 0,
      p95_response_time: data.metrics.response_time?.values?.['p(95)'] || 0,
      p99_response_time: data.metrics.response_time?.values?.['p(99)'] || 0,
      baseline_response_time: baselineResponseTime,
      degradation_percent: data.metrics.degradation_trend?.values?.avg || 0,
    },
    analysis: {
      memory_leak_suspected: (data.metrics.degradation_trend?.values?.avg || 0) > 50,
      performance_stable: (data.metrics.response_time?.values?.['p(99)'] || 0) < 1000,
      error_rate_acceptable: (data.metrics.errors?.values?.rate || 0) < 0.01,
    },
    thresholds: data.thresholds,
  };

  const verdict = summary.analysis.performance_stable && 
                  summary.analysis.error_rate_acceptable &&
                  !summary.analysis.memory_leak_suspected;

  summary.verdict = verdict ? 'PASS' : 'FAIL';

  return {
    'stdout': JSON.stringify(summary, null, 2) + '\n',
    'tests/load/results/soak_test_summary.json': JSON.stringify(summary, null, 2),
  };
}

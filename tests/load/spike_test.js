// =============================================================================
// ATB Spike Test
// =============================================================================
// Tests system behavior under sudden, extreme load spikes.
// Simulates traffic bursts (e.g., batch job triggers, incident response).
//
// Usage:
//   k6 run tests/load/spike_test.js
//
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const spikeRecoveryTime = new Trend('spike_recovery_time');
const requestsDuringSpike = new Counter('requests_during_spike');

// Spike test configuration - sudden bursts
export const options = {
  stages: [
    // Baseline
    { duration: '1m', target: 20 },    // Normal load
    
    // First spike
    { duration: '10s', target: 200 },  // Sudden spike to 10x
    { duration: '30s', target: 200 },  // Sustain spike
    { duration: '10s', target: 20 },   // Return to normal
    
    // Recovery period
    { duration: '2m', target: 20 },    // Monitor recovery
    
    // Second spike (larger)
    { duration: '10s', target: 400 },  // Spike to 20x
    { duration: '30s', target: 400 },  // Sustain spike
    { duration: '10s', target: 20 },   // Return to normal
    
    // Final recovery
    { duration: '2m', target: 20 },    // Monitor recovery
    { duration: '30s', target: 0 },    // Cooldown
  ],
  thresholds: {
    'http_req_duration': ['p(95)<1000', 'p(99)<3000'],
    'http_req_failed': ['rate<0.15'],  // Allow more errors during spikes
    'errors': ['rate<0.15'],
    'spike_recovery_time': ['avg<30000'],  // Recovery within 30 seconds
  },
};

const OPA_URL = __ENV.OPA_URL || 'http://localhost:8182';
const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://localhost:9001';

// Track spike state
let isInSpike = false;
let spikeStartTime = null;
let preSpikeLatecy = null;

// Detect spike based on VU count
function updateSpikeState(vuCount) {
  const wasInSpike = isInSpike;
  isInSpike = vuCount > 100;  // Threshold for spike detection
  
  if (isInSpike && !wasInSpike) {
    // Spike started
    spikeStartTime = Date.now();
  } else if (!isInSpike && wasInSpike && spikeStartTime) {
    // Spike ended - record recovery time
    const recoveryTime = Date.now() - spikeStartTime;
    spikeRecoveryTime.add(recoveryTime);
    spikeStartTime = null;
  }
}

function generateBatchPoA(batchId) {
  const now = Math.floor(Date.now() / 1000);
  return {
    input: {
      poa: {
        sub: `spiffe://atb.example/agent/batch-processor`,
        act: 'salesforce.bulk.export',
        con: {
          params: {
            batch_id: batchId,
            record_count: 10000,
            object_type: 'Contact',
          },
          constraints: {
            max_rows: 50000,
            time_limit: 3600,
          },
        },
        leg: {
          jurisdiction: 'GLOBAL',
          accountable_party: {
            type: 'service_account',
            id: 'batch-service@example.com',
          },
          regulation_refs: ['GDPR'],
        },
        iat: now,
        exp: now + 300,
        jti: `spike_${batchId}_${now}`,
      },
    },
  };
}

export default function () {
  // Estimate current VU count (approximate)
  const estimatedVUs = __VU;
  updateSpikeState(estimatedVUs);

  if (isInSpike) {
    requestsDuringSpike.add(1);
  }

  const batchId = `batch-${__VU}-${__ITER}`;
  const payload = generateBatchPoA(batchId);

  // OPA policy evaluation
  const start = Date.now();
  const res = http.post(
    `${OPA_URL}/v1/data/poa/allow`,
    JSON.stringify(payload),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { 
        name: 'OPA Policy Check',
        spike: isInSpike ? 'true' : 'false',
      },
    }
  );
  const duration = Date.now() - start;

  responseTime.add(duration);

  // Track pre-spike latency for comparison
  if (!isInSpike && preSpikeLatecy === null && __ITER > 10) {
    preSpikeLatecy = duration;
  }

  const success = check(res, {
    'Status is 200': (r) => r.status === 200,
    'Response under spike threshold': (r) => r.timings.duration < (isInSpike ? 2000 : 500),
  });

  if (!success) {
    errorRate.add(1);
  }

  // Simulate batch job behavior - some VUs hit upstream
  if (__VU % 5 === 0) {
    const upstreamRes = http.post(
      UPSTREAM_URL,
      JSON.stringify({ batch_id: batchId, action: 'process' }),
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { name: 'Batch Processing' },
      }
    );
    check(upstreamRes, {
      'Batch processed': (r) => r.status === 200,
    });
  }

  // Variable sleep - faster during spikes to maximize load
  sleep(isInSpike ? 0.1 : 0.5);
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'spike_test',
    metrics: {
      total_requests: data.metrics.http_reqs?.values?.count || 0,
      requests_during_spike: data.metrics.requests_during_spike?.values?.count || 0,
      error_rate: data.metrics.errors?.values?.rate || 0,
      avg_response_time: data.metrics.response_time?.values?.avg || 0,
      p95_response_time: data.metrics.response_time?.values?.['p(95)'] || 0,
      p99_response_time: data.metrics.response_time?.values?.['p(99)'] || 0,
      max_response_time: data.metrics.response_time?.values?.max || 0,
      avg_spike_recovery_time: data.metrics.spike_recovery_time?.values?.avg || 0,
    },
    analysis: {
      handled_spike_gracefully: (data.metrics.errors?.values?.rate || 0) < 0.15,
      recovered_quickly: (data.metrics.spike_recovery_time?.values?.avg || 0) < 30000,
      max_latency_acceptable: (data.metrics.response_time?.values?.max || 0) < 10000,
    },
    thresholds: data.thresholds,
  };

  const verdict = summary.analysis.handled_spike_gracefully && 
                  summary.analysis.recovered_quickly &&
                  summary.analysis.max_latency_acceptable;

  summary.verdict = verdict ? 'PASS' : 'FAIL';

  return {
    'stdout': JSON.stringify(summary, null, 2) + '\n',
    'tests/load/results/spike_test_summary.json': JSON.stringify(summary, null, 2),
  };
}

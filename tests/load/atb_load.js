// =============================================================================
// ATB Load Test Suite
// =============================================================================
// Tests ATB components under load:
// - OPA policy decisions
// - Upstream service (echo server)
// - Broker health/metrics
// - AgentAuth endpoints
//
// Usage:
//   k6 run atb_load.js
//   k6 run --vus 50 --duration 5m atb_load.js
//
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const opaLatency = new Trend('opa_latency');
const upstreamLatency = new Trend('upstream_latency');

// Test configuration
export const options = {
  stages: [
    { duration: '1m', target: 50 },
    { duration: '5m', target: 100 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],
    'http_req_failed': ['rate<0.05'],
    'errors': ['rate<0.05'],
    'opa_latency': ['p(95)<100'],
    'upstream_latency': ['p(95)<200'],
  },
};

const BROKER_URL = __ENV.BROKER_URL || 'http://localhost:8080';
const OPA_URL = __ENV.OPA_URL || 'http://localhost:8181';
const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://localhost:9000';
const AGENTAUTH_URL = __ENV.AGENTAUTH_URL || 'http://localhost:8444';

const ACTIONS = [
  { verb: 'read', resource: 'logs/application', tier: 'LOW' },
  { verb: 'read', resource: 'metrics/system', tier: 'LOW' },
  { verb: 'list', resource: 'deployments/dev', tier: 'LOW' },
  { verb: 'modify', resource: 'config/feature-flags', tier: 'MEDIUM' },
  { verb: 'create', resource: 'deployment/staging', tier: 'MEDIUM' },
  { verb: 'delete', resource: 'deployment/production', tier: 'HIGH' },
];

export function setup() {
  console.log('=== ATB Load Test Setup ===');
  const services = [
    { name: 'Broker', url: BROKER_URL + '/health' },
    { name: 'OPA', url: OPA_URL + '/health' },
    { name: 'Upstream', url: UPSTREAM_URL + '/health' },
    { name: 'AgentAuth', url: AGENTAUTH_URL + '/health' },
  ];
  
  let allHealthy = true;
  for (const svc of services) {
    const res = http.get(svc.url, { timeout: '5s' });
    const status = res.status === 200 ? 'OK' : 'FAIL';
    console.log(svc.name + ': ' + status + ' (' + res.status + ')');
    if (res.status !== 200) allHealthy = false;
  }
  
  return { startTime: new Date().toISOString(), allHealthy: allHealthy };
}

export default function() {
  const testType = Math.random();
  
  if (testType < 0.4) {
    testOPADecision();
  } else if (testType < 0.7) {
    testUpstream();
  } else if (testType < 0.9) {
    testBrokerHealth();
  } else {
    testAgentAuth();
  }
  
  sleep(0.05 + Math.random() * 0.1);
}

function testOPADecision() {
  const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
  
  const opaInput = {
    input: {
      poa: {
        act: action.verb + ':' + action.resource,
        sub: 'load-test-agent',
        iss: 'atb-agentauth',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        leg: {
          approval_chain: [{
            approver: 'spiffe://atb.local/user/tester',
            ts: new Date().toISOString()
          }]
        },
        con: { max_amount: 1000 }
      },
      request: {
        method: action.verb.toUpperCase(),
        path: '/' + action.resource
      }
    }
  };
  
  const startTime = Date.now();
  const response = http.post(
    OPA_URL + '/v1/data/atb/poa/decision',
    JSON.stringify(opaInput),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'OPA Decision' },
    }
  );
  opaLatency.add(Date.now() - startTime, { tier: action.tier });
  
  const success = check(response, {
    'OPA status is 200': (r) => r.status === 200,
    'OPA returns result': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.result !== undefined;
      } catch (e) {
        return false;
      }
    },
  });
  errorRate.add(!success);
}

function testUpstream() {
  const startTime = Date.now();
  let response;
  
  if (Math.random() < 0.5) {
    response = http.get(UPSTREAM_URL + '/api/test', {
      tags: { name: 'Upstream GET' }
    });
  } else {
    response = http.post(
      UPSTREAM_URL + '/api/test',
      JSON.stringify({ test: true, timestamp: Date.now() }),
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { name: 'Upstream POST' },
      }
    );
  }
  
  upstreamLatency.add(Date.now() - startTime);
  
  const success = check(response, {
    'Upstream status is 200': (r) => r.status === 200,
    'Upstream returns JSON': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch (e) {
        return false;
      }
    },
  });
  errorRate.add(!success);
}

function testBrokerHealth() {
  const endpoints = ['/health', '/ready', '/metrics'];
  const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
  
  const response = http.get(BROKER_URL + endpoint, {
    tags: { name: 'Broker ' + endpoint }
  });
  
  const success = check(response, {
    'Broker responds 200': (r) => r.status === 200
  });
  errorRate.add(!success);
}

function testAgentAuth() {
  const endpoints = ['/health', '/.well-known/jwks.json'];
  const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
  
  const response = http.get(AGENTAUTH_URL + endpoint, {
    tags: { name: 'AgentAuth ' + endpoint }
  });
  
  let success;
  if (endpoint === '/.well-known/jwks.json') {
    success = check(response, {
      'AgentAuth JWKS responds': (r) => r.status === 200,
      'AgentAuth JWKS has keys': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.keys !== undefined;
        } catch (e) {
          return false;
        }
      },
    });
  } else {
    success = check(response, {
      'AgentAuth health responds': (r) => r.status === 200
    });
  }
  errorRate.add(!success);
}

export function teardown(data) {
  console.log('');
  console.log('=== ATB Load Test Complete ===');
  console.log('Started: ' + data.startTime);
  console.log('Ended: ' + new Date().toISOString());
  console.log('All services healthy at start: ' + data.allHealthy);
}
